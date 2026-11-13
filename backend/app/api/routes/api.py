import asyncio
import time
import logging
from datetime import timezone
import httpx
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.models.entities import AIReport, ChatMessage, ChatSession, ProviderResult, RiskAnalysis, RiskProfile, Transaction, now_utc
from app.schemas.ai import AIReportBody, AIReportContent, AIReportRead, ChatHistoryRead, ChatRequest, ChatResponse
from app.schemas.risk import AnalyzeRequest, AnalyzeResponse, NormalizedSignal, RiskProfileCreate, RiskProfileRead, RiskProfileUpdate, TransactionInput
from app.services.fraud_providers.mock import MockProvider
from app.services.fraud_providers.ffraud import FFraudProvider
from app.services.fraud_providers.ipdb import IPDBProvider, ProviderFailure
from app.services.fraud_providers.virustotal import VirusTotalProvider
from app.services.risk_engine.category_mapping import evidence_coverage, normalize_provider
from app.services.risk_engine.report_data import build_report_data
from app.services.risk_engine.geography import country_observations, compare_transaction_country
from app.services.risk_engine.scoring import score_signals
from app.services.llm import get_llm_provider
from app.services.llm.mock import MockLLMProvider
from app.services.llm.deepseek import LLMServiceError

router = APIRouter(prefix="/api")
logger=logging.getLogger(__name__)


@router.get("/health")
def health():
    return {"status": "ok", "service": settings.app_name}


def get_profile_or_404(db: Session, profile_id: int) -> RiskProfile:
    profile = db.get(RiskProfile, profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Risk profile not found")
    return profile


@router.get("/risk-profiles", response_model=list[RiskProfileRead])
def list_profiles(db: Session = Depends(get_db)):
    return db.scalars(select(RiskProfile).order_by(RiskProfile.id)).all()


@router.post("/risk-profiles", response_model=RiskProfileRead, status_code=201)
def create_profile(payload: RiskProfileCreate, db: Session = Depends(get_db)):
    if db.scalar(select(RiskProfile).where(RiskProfile.profile_name == payload.profile_name)):
        raise HTTPException(status_code=409, detail="Profile name already exists")
    profile = RiskProfile(**payload.model_dump())
    db.add(profile)
    db.commit()
    db.refresh(profile)
    return profile


@router.put("/risk-profiles/{profile_id}", response_model=RiskProfileRead)
def update_profile(profile_id: int, payload: RiskProfileUpdate, db: Session = Depends(get_db)):
    profile = get_profile_or_404(db, profile_id)
    duplicate = db.scalar(select(RiskProfile).where(RiskProfile.profile_name == payload.profile_name, RiskProfile.id != profile_id))
    if duplicate:
        raise HTTPException(status_code=409, detail="Profile name already exists")
    for key, value in payload.model_dump().items():
        setattr(profile, key, value)
    db.commit()
    db.refresh(profile)
    return profile


def save_transaction(payload: TransactionInput, db: Session) -> Transaction:
    tx = db.scalar(select(Transaction).where(Transaction.transaction_id == payload.transaction_id))
    values = payload.model_dump()
    values.pop("risk_profile_id", None)
    values.pop("refresh_provider_data", None)
    values["ip_address"] = str(payload.ip_address)
    if tx:
        for key, value in values.items():
            setattr(tx, key, value)
    else:
        tx = Transaction(**values)
        db.add(tx)
    db.flush()
    return tx


@router.get("/transactions")
def list_transactions(db: Session = Depends(get_db)):
    transactions = db.scalars(select(Transaction).order_by(Transaction.created_at.desc())).all()
    return [{"transaction_id": tx.transaction_id, "ip_address": tx.ip_address, "transaction_amount": tx.transaction_amount, "currency": tx.currency, "user_country": tx.user_country, "transaction_country": tx.transaction_country, "transaction_velocity": tx.transaction_velocity, "account_age_days": tx.account_age_days, "created_at": tx.created_at} for tx in transactions]


@router.post("/transactions", status_code=201)
def create_transaction(payload: TransactionInput, db: Session = Depends(get_db)):
    tx = save_transaction(payload, db)
    db.commit()
    return {"transaction_id": tx.transaction_id, "status": "saved"}


def transaction_signals(payload: AnalyzeRequest, provider_results: list[dict] | None = None) -> list[NormalizedSignal]:
    signals = []
    if payload.user_country and payload.transaction_country:
        mismatch = payload.user_country.upper() != payload.transaction_country.upper()
        signals.append(NormalizedSignal(category="geographic_risk", factor="Country Mismatch", value=mismatch, risk_score=72 if mismatch else 5, confidence=1, provider="Transaction Context"))
    else:
        signals.append(NormalizedSignal(category="geographic_risk", factor="Country Mismatch", value=None, risk_score=None, provider="Transaction Context", missing=True))
    resolution=country_observations(provider_results)
    comparison=compare_transaction_country(resolution,payload.transaction_country)
    if comparison in {"MATCH","MISMATCH"}:
        mismatch=comparison=="MISMATCH"
        signals.append(NormalizedSignal(category="geographic_risk",factor="IP Country Mismatch",value={"resolved_ip_country":resolution["resolved_ip_country"],"transaction_country":payload.transaction_country.upper(),"comparison":comparison,"provider_consistency":resolution["provider_consistency"]},risk_score=72 if mismatch else 5,confidence=.75 if resolution["provider_consistency"]=="LIMITED_DATA" else 1.0,provider="Resolved IP Country"))
    if payload.transaction_velocity is not None:
        velocity_score = min(100, max(0, (payload.transaction_velocity - 3) * 15))
    else:
        velocity_score = None
    amount_score = min(100, max(0, round((payload.transaction_amount - 1000) / 150)))
    signals.append(NormalizedSignal(category="transaction_behavior", factor="Transaction Amount", value={"amount":payload.transaction_amount,"currency":payload.currency}, risk_score=amount_score, confidence=0.75, provider="Transaction Context"))
    signals.append(NormalizedSignal(category="transaction_behavior", factor="Transaction Velocity", value=payload.transaction_velocity, risk_score=velocity_score, confidence=0.75, provider="Transaction Context", missing=velocity_score is None))
    if payload.account_age_days is not None:
        score = 70 if payload.account_age_days < 7 else 35 if payload.account_age_days < 30 else 8
        signals.append(NormalizedSignal(category="account_characteristics", factor="Account Age", value=payload.account_age_days, risk_score=score, confidence=0.7, provider="Transaction Context"))
    else:
        signals.append(NormalizedSignal(category="account_characteristics", factor="Account Age", value=None, risk_score=None, provider="Transaction Context", missing=True))
    return signals


def _safe_provider_raw(provider: str, raw: dict | None) -> dict | None:
    """Project external provider data onto a small, non-secret allowlist for AI context."""
    if not isinstance(raw,dict): return None
    if provider=="FFraud":
        allowed=("fraud_score","risk","vpn","proxy","tor","relay","hosting","is_abuser","recent_abuse","connection_type","ASN","organization","confidence","threat_tags")
        result={k:raw[k] for k in allowed if k in raw}
        geo=raw.get("geo")
        if isinstance(geo,dict): result["geo"]={k:geo[k] for k in ("country","country_code","country_name") if k in geo}
    elif provider=="IP-DB":
        allowed=("abuseConfidenceScore","scoreLabel","networkType","countryCode","countryName","asn","asnName","asnOrg","isp","totalReports","distinctReporters","blacklistSources","dnsbl")
        result={k:raw[k] for k in allowed if k in raw}
    else:
        attrs=raw.get("data",{}).get("attributes",{})
        if not isinstance(attrs,dict): return None
        result={k:attrs[k] for k in ("reputation","last_analysis_stats","last_analysis_date","tags","country","asn","network") if k in attrs}
    return _bounded_data(result)


def _bounded_data(value):
    """Keep untrusted provider values small and JSON-safe before using them as prompt context."""
    if isinstance(value,str): return value[:240]
    if isinstance(value,list): return [_bounded_data(x) for x in value[:20]]
    if isinstance(value,dict): return {str(k)[:80]:_bounded_data(v) for k,v in list(value.items())[:30]}
    if isinstance(value,(int,float,bool)) or value is None: return value
    return str(value)[:240]


def _safe_signal(signal: dict) -> dict:
    return {"category":signal.get("category"),"factor":str(signal.get("factor",""))[:100],"value":_bounded_data(signal.get("value")),"risk_score":signal.get("risk_score"),"confidence":signal.get("confidence"),"provider":signal.get("provider"),"missing":bool(signal.get("missing"))}


def _safe_category(category: dict) -> dict:
    return {**category,"evidence":[{**evidence,"values":_bounded_data(evidence.get("values",[]))} for evidence in category.get("evidence",[])]}


def get_analysis_or_404(db: Session, analysis_id: int) -> RiskAnalysis:
    analysis=db.get(RiskAnalysis,analysis_id)
    if not analysis: raise HTTPException(status_code=404,detail="Risk analysis not found")
    return analysis


def build_ai_context(db: Session, analysis: RiskAnalysis) -> dict:
    if analysis.structured_result:
        context=analysis.structured_result
        context["professional_report_data"]=build_report_data(context,analysis.created_at)
        return context
    # Older analyses predate structured-result persistence; preserve their official score and mark absent details unknown.
    profile=analysis.risk_profile
    transaction=analysis.transaction
    provider_rows=db.scalars(select(ProviderResult).where(ProviderResult.analysis_id==analysis.id)).all()
    categories=[{"category":key,"score":None,"preference":getattr(profile,key),"weight":None,"evidence_strength":0,"risk_coefficient":0,"contribution":None,"evidence":[]} for key in ("ip_reputation","network_anonymity","malicious_infrastructure","geographic_risk","transaction_behavior","account_characteristics")]
    context={"transaction":{"transaction_id":transaction.transaction_id,"amount":transaction.transaction_amount,"currency":transaction.currency,"user_country":transaction.user_country,"transaction_country":transaction.transaction_country,"transaction_velocity":transaction.transaction_velocity,"account_age_days":transaction.account_age_days},"risk_assessment":{"final_score":analysis.risk_score,"risk_level":analysis.risk_level,"evidence_strength":"Limited"},"categories":categories,"provider_agreement":[],"user_risk_preferences":{"profile_name":profile.profile_name,"sensitivity":profile.sensitivity},"provider_results":[{"provider":r.provider_name,"status":r.status,"error":r.error_message,"signals":r.signals,"raw_result":_safe_provider_raw(r.provider_name,r.raw_result)} for r in provider_rows],"limitations":["This analysis predates structured evidence storage; detailed category evidence is unavailable."]}
    context["professional_report_data"]=build_report_data(context,analysis.created_at)
    return context


def build_provider_evidence_context(context: dict, analysis_id: int) -> dict:
    """Keep provider Q&A focused on this analysis's provider facts and Risk Engine mappings."""
    categories=context.get("categories",[])
    return {
        "context_type":"provider_evidence",
        "analysis_id":analysis_id,
        "transaction":{"transaction_id":context.get("transaction",{}).get("transaction_id")},
        "risk_assessment":context.get("risk_assessment"),
        "provider_evidence":[
            {
                "provider":row.get("provider"),
                "status":row.get("status"),
                "error":row.get("error"),
                "provider_reported_fields":row.get("raw_result"),
                "backend_normalized_signals":row.get("signals",[]),
            }
            for row in context.get("provider_results",[])
        ],
        "dimension_mappings":[
            {
                "category":category.get("category"),
                "dimension_name":category.get("dimension_name"),
                "score":category.get("score"),
                "weight":category.get("weight"),
                "contribution":category.get("contribution"),
                "evidence_strength":category.get("evidence_strength"),
                "evidence_status":category.get("evidence_status"),
                "evidence":category.get("evidence",[]),
            }
            for category in categories
        ],
        "provider_agreement":context.get("provider_agreement",[]),
        "limitations":context.get("limitations",[]),
        "field_semantics":{
            "provider_reported_fields":"Returned by an external provider; these are facts about that provider's response.",
            "backend_normalized_signals":"Signals normalized by Fraud Radar; only non-null risk_score values are scoreable inputs.",
            "dimension_mappings":"Risk Engine category evidence and score contributions. Do not infer that an unmapped contextual field affected a score.",
        },
    }


def llm_or_503():
    provider=get_llm_provider()
    if provider is None: raise HTTPException(status_code=503,detail={"code":"missing_api_key","message":"AI report temporarily unavailable: DeepSeek API key is not configured."})
    return provider


@router.post("/ai/report/{analysis_id}",response_model=AIReportRead)
async def create_ai_report(analysis_id:int,payload:AIReportBody=AIReportBody(),db:Session=Depends(get_db)):
    analysis=get_analysis_or_404(db,analysis_id)
    existing=db.scalar(select(AIReport).where(AIReport.analysis_id==analysis_id))
    if existing and not payload.regenerate:
        return {"id":existing.id,"analysis_id":existing.analysis_id,"model_name":existing.model_name,"report":existing.report_json,"created_at":existing.created_at,"updated_at":existing.updated_at}
    provider=llm_or_503()
    context=build_ai_context(db,analysis)
    fallback_used=False
    try:
        generated=await provider.generate_report(context)
        report=AIReportContent.model_validate(generated)
        # These values always come from RiskAnalysis, never the model response.
        report_json=report.model_dump() | {"risk_score":analysis.risk_score,"risk_level":analysis.risk_level,"evidence_strength":context["risk_assessment"]["evidence_strength"],"analysis_data":context["professional_report_data"]}
    except LLMServiceError as exc:
        logger.warning("AI report generation failed; using labelled fallback (%s)",exc.code)
        report=AIReportContent.model_validate(await MockLLMProvider().generate_report(context))
        fallback_used=True
    except Exception as exc:
        logger.warning("AI report validation failed; using labelled fallback (%s)",type(exc).__name__)
        report=AIReportContent.model_validate(await MockLLMProvider().generate_report(context))
        fallback_used=True
    report_json=report.model_dump() | {"risk_score":analysis.risk_score,"risk_level":analysis.risk_level,"evidence_strength":context["risk_assessment"]["evidence_strength"],"analysis_data":context["professional_report_data"],"generation_status":"FALLBACK" if fallback_used else "AI_GENERATED","generation_label":"Fallback Report — AI-generated analysis unavailable." if fallback_used else None}
    if existing:
        existing.model_name=provider.model_name; existing.report_json=report_json; existing.updated_at=now_utc(); row=existing
    else:
        row=AIReport(analysis_id=analysis_id,model_name=provider.model_name,report_json=report_json); db.add(row)
    try:
        db.commit(); db.refresh(row)
    except Exception as exc:
        db.rollback(); logger.exception("AI report persistence failed")
        raise HTTPException(status_code=503,detail={"code":"database_error","message":"AI report could not be saved."}) from exc
    return {"id":row.id,"analysis_id":row.analysis_id,"model_name":row.model_name,"report":row.report_json,"created_at":row.created_at,"updated_at":row.updated_at}


@router.get("/ai/report/{analysis_id}",response_model=AIReportRead)
def get_ai_report(analysis_id:int,db:Session=Depends(get_db)):
    get_analysis_or_404(db,analysis_id)
    row=db.scalar(select(AIReport).where(AIReport.analysis_id==analysis_id))
    if not row: raise HTTPException(status_code=404,detail="AI report has not been generated")
    return {"id":row.id,"analysis_id":row.analysis_id,"model_name":row.model_name,"report":row.report_json,"created_at":row.created_at,"updated_at":row.updated_at}


@router.post("/ai/chat/{analysis_id}",response_model=ChatResponse)
async def ai_chat(analysis_id:int,payload:ChatRequest,db:Session=Depends(get_db)):
    analysis=get_analysis_or_404(db,analysis_id)
    provider=llm_or_503()
    if payload.session_id:
        session=db.get(ChatSession,payload.session_id)
        if not session or session.analysis_id!=analysis_id or session.context_type!=payload.context_type: raise HTTPException(status_code=404,detail="Chat session not found for this analysis and context")
    else:
        session=ChatSession(analysis_id=analysis_id,context_type=payload.context_type); db.add(session); db.flush()
    messages=db.scalars(select(ChatMessage).where(ChatMessage.session_id==session.id).order_by(ChatMessage.created_at.desc(),ChatMessage.id.desc()).limit(10)).all()
    history=[{"role":m.role,"content":m.content} for m in reversed(messages)]
    report=db.scalar(select(AIReport).where(AIReport.analysis_id==analysis_id))
    context=build_ai_context(db,analysis)
    if payload.context_type=="provider_evidence":
        context=build_provider_evidence_context(context,analysis_id)
    else:
        context["context_type"]="report"
        context["report"]=report.report_json if report else None
    try:
        answer=await provider.answer(context,history,payload.question)
        if not answer.strip() or len(answer)>4000: raise LLMServiceError("invalid_response","DeepSeek returned an invalid answer")
    except LLMServiceError as exc:
        db.rollback()
        raise HTTPException(status_code=503,detail={"code":exc.code,"message":"Fraud Detective is temporarily unavailable."}) from exc
    except Exception as exc:
        db.rollback(); logger.exception("Fraud Detective request failed")
        raise HTTPException(status_code=503,detail={"code":"api_error","message":"Fraud Detective is temporarily unavailable."}) from exc
    user_message=ChatMessage(session_id=session.id,role="user",content=payload.question)
    assistant_message=ChatMessage(session_id=session.id,role="assistant",content=answer)
    db.add_all([user_message,assistant_message]); session.updated_at=now_utc(); db.flush()
    expired_ids=db.scalars(select(ChatMessage.id).where(ChatMessage.session_id==session.id).order_by(ChatMessage.created_at.desc(),ChatMessage.id.desc()).offset(20)).all()
    if expired_ids: db.query(ChatMessage).filter(ChatMessage.id.in_(expired_ids)).delete(synchronize_session=False)
    try:
        db.commit(); db.refresh(assistant_message)
    except Exception as exc:
        db.rollback(); logger.exception("Fraud Detective message persistence failed")
        raise HTTPException(status_code=503,detail={"code":"database_error","message":"Chat message could not be saved."}) from exc
    return ChatResponse(analysis_id=analysis_id,session_id=session.id,answer=answer,created_at=assistant_message.created_at)


@router.get("/ai/chat/{analysis_id}/{session_id}",response_model=ChatHistoryRead)
def ai_chat_history(analysis_id:int,session_id:int,db:Session=Depends(get_db)):
    session=db.get(ChatSession,session_id)
    if not session or session.analysis_id!=analysis_id: raise HTTPException(status_code=404,detail="Chat session not found for this analysis")
    messages=db.scalars(select(ChatMessage).where(ChatMessage.session_id==session_id).order_by(ChatMessage.created_at,ChatMessage.id)).all()
    return {"analysis_id":analysis_id,"session_id":session_id,"messages":[{"role":m.role,"content":m.content,"created_at":m.created_at} for m in messages]}


@router.delete("/ai/chat/{analysis_id}/{session_id}")
def clear_ai_chat(analysis_id:int,session_id:int,db:Session=Depends(get_db)):
    session=db.get(ChatSession,session_id)
    if not session or session.analysis_id!=analysis_id: raise HTTPException(status_code=404,detail="Chat session not found for this analysis")
    db.query(ChatMessage).filter(ChatMessage.session_id==session_id).delete(synchronize_session=False)
    db.delete(session); db.commit()
    return {"status":"cleared"}


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze(payload: AnalyzeRequest, db: Session = Depends(get_db)):
    profile = get_profile_or_404(db, payload.risk_profile_id)
    tx = save_transaction(payload, db)
    previous = db.scalar(select(RiskAnalysis).where(RiskAnalysis.transaction_id == tx.id).order_by(RiskAnalysis.created_at.desc()))
    stored = db.scalars(select(ProviderResult).where(ProviderResult.analysis_id == previous.id).order_by(ProviderResult.created_at.desc())).all() if previous else []
    cached = {row.provider_name: row for row in stored}
    def cache_age(row):
        created=row.created_at
        if created is None: return float("inf")
        if created.tzinfo is None: created=created.replace(tzinfo=timezone.utc)
        return time.time()-created.timestamp()
    current_mode="mock" if settings.use_mock_apis else "real"
    def cache_matches(row):
        return row.subject == str(payload.ip_address) and row.source_mode == current_mode and row.status != "disabled" and cache_age(row) < settings.provider_cache_ttl_seconds
    names = ["FFraud", "IP-DB", "VirusTotal"]
    async def fetch(provider):
        if not payload.refresh_provider_data and provider.provider_name in cached and cache_matches(cached[provider.provider_name]):
            row=cached[provider.provider_name]
            return {"provider":provider.provider_name,"status":row.status,"latency_ms":row.latency_ms,"raw_result":row.raw_result,"signals":[NormalizedSignal.model_validate(x) for x in row.signals],"error":row.error_message,"cached":True}
        if not getattr(provider,"enabled",True):
            return {"provider":provider.provider_name,"status":"disabled","latency_ms":None,"raw_result":None,"signals":[],"error":"API key not configured","cached":False}
        started=time.perf_counter()
        try:
            raw=await provider.analyze_ip(str(payload.ip_address))
            normalized=normalize_provider(provider.provider_name,raw)
            return {"provider":provider.provider_name,"status":"success","latency_ms":round((time.perf_counter()-started)*1000,1),"raw_result":raw,"signals":normalized,"error":None,"cached":False}
        except ProviderFailure as exc:
            status,error=exc.status,exc.message
        except httpx.TimeoutException:
            status,error="timeout","Provider request timed out"
        except httpx.HTTPStatusError as exc:
            status,error=("rate_limited" if exc.response.status_code==429 else "error"),f"Provider returned HTTP {exc.response.status_code}"
        except (ValueError,TypeError,KeyError):
            status,error="invalid_response","Provider response could not be parsed"
        except Exception:
            status,error="error","Provider request failed"
        return {"provider":provider.provider_name,"status":status,"latency_ms":round((time.perf_counter()-started)*1000,1),"raw_result":None,"signals":[],"error":error,"cached":False}
    async with httpx.AsyncClient(timeout=settings.provider_timeout_seconds) as client:
        providers=[MockProvider(n) for n in names] if settings.use_mock_apis else [FFraudProvider(client,settings.ffraud_api_key),IPDBProvider(client,settings.ipdb_api_key),VirusTotalProvider(client,settings.virustotal_api_key)]
        results=await asyncio.gather(*(fetch(p) for p in providers))
    signals=[sig for result in results for sig in result["signals"]]
    signals.extend(transaction_signals(payload,results))
    scored = score_signals(signals, profile)
    provider_states={r["provider"]:r["status"] for r in results}
    for category in scored["categories"]:
        coverage=evidence_coverage(category,provider_states)
        category.update(coverage)
    usable=[c for c in scored["categories"] if c["score"] is not None]
    evidence_strength=(sum(c["evidence_strength"] for c in usable)/len(usable)) if usable else 0
    ai_limitations=[f"{r['provider']} data unavailable ({r['status']})." for r in results if r["status"]!="success"]
    ai_limitations.extend(f"{c['category']}: Unknown / Insufficient Evidence." for c in scored["categories"] if c["score"] is None)
    if tx.account_age_days is None: ai_limitations.append("Insufficient account-level evidence is available.")
    ai_limitations.append("Transaction history and historical behavior data are unavailable in this prototype.")
    structured={
        "transaction":{"transaction_id":tx.transaction_id,"ip_address":tx.ip_address,"amount":tx.transaction_amount,"currency":tx.currency,"user_country":tx.user_country,"transaction_country":tx.transaction_country,"transaction_velocity":tx.transaction_velocity,"account_age_days":tx.account_age_days},
        "risk_assessment":{"final_score":scored["risk_score"],"risk_level":scored["risk_level"],"evidence_strength":"Strong" if evidence_strength>=.75 else "Moderate" if evidence_strength>=.5 else "Limited"},
        "categories":[_safe_category(c) for c in scored["categories"]],"provider_agreement":[str(x)[:300] for x in scored["provider_agreement"]],
        "user_risk_preferences":{"profile_name":profile.profile_name,"sensitivity":profile.sensitivity,**{key:getattr(profile,key) for key in ("ip_reputation","network_anonymity","malicious_infrastructure","geographic_risk","transaction_behavior","account_characteristics")}},
        "provider_results":[{"provider":r["provider"],"status":r["status"],"error":r["error"],"signals":[_safe_signal(s.model_dump()) for s in r["signals"]],"raw_result":_safe_provider_raw(r["provider"],r["raw_result"])} for r in results],
        "limitations":ai_limitations,
    }
    analysis = RiskAnalysis(transaction=tx, risk_profile=profile, risk_score=scored["risk_score"], risk_level=scored["risk_level"], explanation=scored["explanation"],structured_result=structured)
    db.add(analysis)
    db.flush()
    for result in results:
        db.add(ProviderResult(analysis_id=analysis.id,provider_name=result["provider"],signals=[s.model_dump() for s in result["signals"]],raw_result=result["raw_result"],status=result["status"],latency_ms=result["latency_ms"],error_message=result["error"],subject=str(payload.ip_address),source_mode=current_mode))
    db.commit()
    return AnalyzeResponse(analysis_id=analysis.id,transaction_id=tx.transaction_id, risk_score=scored["risk_score"], risk_level=scored["risk_level"], risk_profile=profile.profile_name, factor_scores=scored["factor_scores"], categories=scored["categories"], provider_results=[{"provider":r["provider"],"status":r["status"],"latency_ms":r["latency_ms"],"signal_count":len(r["signals"]),"signals":[s.model_dump() for s in r["signals"]],"raw_result":_safe_provider_raw(r["provider"],r["raw_result"]),"error":r["error"],"cached":r["cached"]} for r in results], provider_agreement=scored["provider_agreement"], missing_signals=scored["missing_signals"], explanation=scored["explanation"])


@router.get("/providers/status")
def provider_status(db: Session = Depends(get_db)):
    latest=db.scalars(select(ProviderResult).order_by(ProviderResult.created_at.desc())).all(); found={}
    for row in latest:
        if row.provider_name not in found: found[row.provider_name]={"provider":row.provider_name,"status":row.status,"latency_ms":row.latency_ms,"error":row.error_message,"last_checked":row.created_at,"mode":"mock" if settings.use_mock_apis else "real"}
    for name in ("FFraud","IP-DB","VirusTotal"):
        found.setdefault(name,{"provider":name,"status":"mock_ready" if settings.use_mock_apis else ("success" if name=="FFraud" else "disabled"),"latency_ms":None,"error":None if settings.use_mock_apis or name=="FFraud" else "API key not configured","last_checked":None,"mode":"mock" if settings.use_mock_apis else "real"})
    return list(found.values())
