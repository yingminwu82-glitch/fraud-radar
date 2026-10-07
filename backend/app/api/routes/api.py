from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.models.entities import ProviderResult, RiskAnalysis, RiskProfile, Transaction
from app.schemas.risk import AnalyzeRequest, AnalyzeResponse, NormalizedSignal, RiskProfileCreate, RiskProfileRead, RiskProfileUpdate, TransactionInput
from app.services.fraud_providers.mock import MockFraudProvider
from app.services.risk_engine.scoring import score_signals

router = APIRouter(prefix="/api")


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


def transaction_signals(payload: AnalyzeRequest) -> list[NormalizedSignal]:
    signals = []
    if payload.user_country and payload.transaction_country:
        mismatch = payload.user_country.upper() != payload.transaction_country.upper()
        signals.append(NormalizedSignal(category="geographic_risk", factor="Country Mismatch", value=mismatch, risk_score=72 if mismatch else 5, confidence=1, provider="Transaction Context"))
    else:
        signals.append(NormalizedSignal(category="geographic_risk", factor="Country Mismatch", value=None, risk_score=0, provider="Transaction Context", missing=True))
    if payload.transaction_velocity is not None:
        velocity_score = min(100, max(0, (payload.transaction_velocity - 3) * 15))
    else:
        velocity_score = None
    amount_score = min(100, max(0, round((payload.transaction_amount - 1000) / 150)))
    behavior_scores = [score for score in (velocity_score, amount_score) if score is not None]
    signals.append(NormalizedSignal(category="transaction_behavior", factor="Velocity / Amount", value=f"velocity={payload.transaction_velocity}, amount={payload.transaction_amount:g} {payload.currency}", risk_score=max(behavior_scores, default=0), confidence=0.75, provider="Transaction Context", missing=not behavior_scores))
    if payload.account_age_days is not None:
        score = 70 if payload.account_age_days < 7 else 35 if payload.account_age_days < 30 else 8
        signals.append(NormalizedSignal(category="account_characteristics", factor="Account Age", value=payload.account_age_days, risk_score=score, confidence=0.7, provider="Transaction Context"))
    else:
        signals.append(NormalizedSignal(category="account_characteristics", factor="Account Age", value=None, risk_score=0, provider="Transaction Context", missing=True))
    return signals


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze(payload: AnalyzeRequest, db: Session = Depends(get_db)):
    profile = get_profile_or_404(db, payload.risk_profile_id)
    if not settings.use_mock_apis:
        # No fake fallback when real integrations are not configured.
        raise HTTPException(status_code=503, detail="Real fraud providers are not configured in this stage")
    tx = save_transaction(payload, db)
    # Reuse the most recent normalized inputs for this transaction across profiles.
    previous = db.scalar(select(RiskAnalysis).where(RiskAnalysis.transaction_id == tx.id).order_by(RiskAnalysis.created_at.desc()))
    if previous:
        stored = db.scalars(select(ProviderResult).where(ProviderResult.analysis_id == previous.id)).all()
        signals = [NormalizedSignal.model_validate(signal) for row in stored for signal in row.signals]
    else:
        provider = MockFraudProvider()
        signals = await provider.analyze_ip(str(payload.ip_address))
        signals.extend(transaction_signals(payload))
    scored = score_signals(signals, profile)
    analysis = RiskAnalysis(transaction=tx, risk_profile=profile, risk_score=scored["risk_score"], risk_level=scored["risk_level"], explanation=scored["explanation"])
    db.add(analysis)
    db.flush()
    provider_names = sorted({signal.provider for signal in signals})
    for name in provider_names:
        provider_signals = [signal.model_dump() for signal in signals if signal.provider == name]
        db.add(ProviderResult(analysis_id=analysis.id, provider_name=name, signals=provider_signals))
    db.commit()
    return AnalyzeResponse(transaction_id=tx.transaction_id, risk_score=scored["risk_score"], risk_level=scored["risk_level"], risk_profile=profile.profile_name, factor_scores=scored["factor_scores"], provider_results=[{"provider": name, "signal_count": sum(signal.provider == name for signal in signals)} for name in provider_names], provider_agreement=scored["provider_agreement"], missing_signals=scored["missing_signals"], explanation=scored["explanation"])
