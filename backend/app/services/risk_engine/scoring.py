from app.models.entities import RiskProfile
from app.schemas.risk import FactorScore, NormalizedSignal
from app.services.risk_engine.preferences import PREFERENCE_FIELDS, normalize_preferences
from app.services.risk_engine.thresholds import classify_risk

CATEGORIES={"ip_reputation":"ip_reputation","network_anonymity":"network_anonymity","malicious_infrastructure":"malicious_infrastructure","geographic_risk":"geographic_risk","transaction_behavior":"transaction_behavior","account_characteristics":"account_characteristics"}

def score_signals(signals: list[NormalizedSignal], profile: RiskProfile) -> dict:
    prefs=normalize_preferences(profile); grouped={}; factors=[]; missing=[]
    for sig in signals:
        if sig.missing or sig.risk_score is None: continue
        grouped.setdefault(sig.category,{}).setdefault(sig.factor,[]).append(sig)
    category_scores=[]
    for category,field in CATEGORIES.items():
        evidence=grouped.get(category,{})
        if not evidence:
            missing.append(PREFERENCE_FIELDS[field]); category_scores.append({"category":category,"score":None,"preference":getattr(profile,field),"weight":prefs[field],"evidence_strength":0,"risk_coefficient":0,"contribution":None,"evidence":[]}); continue
        factor_data=[]
        for name, observations in evidence.items():
            score=max(float(s.risk_score) for s in observations)
            providers=sorted({s.provider for s in observations})
            strengths=[s.confidence for s in observations]
            agreement=min(.99,(sum(strengths)/len(strengths))*(.8+.2*min(1,(len(providers)-1)/2)))
            factor_data.append((name,score,providers,agreement,observations))
        # Max per factor and across distinct factors: duplicate vendors cannot inflate severity.
        score=max(item[1] for item in factor_data)
        relevant=[item for item in factor_data if item[1]==score]
        providers=sorted({p for item in relevant for p in item[2]})
        strength=sum(item[3] for item in relevant)/len(relevant)
        coefficient=prefs[field]*strength
        raw="; ".join(f"{n}: {v:g}" for n,v,_,_,_ in factor_data)
        factors.append(FactorScore(factor=PREFERENCE_FIELDS[field],raw_signal=raw,risk_score=score,user_preference=getattr(profile,field),weight=prefs[field],contribution=0,providers=providers,evidence_strength=strength,risk_coefficient=coefficient))
        category_scores.append({"category":category,"score":round(score,2),"preference":getattr(profile,field),"weight":prefs[field],"evidence_strength":round(strength,3),"risk_coefficient":round(coefficient,4),"contribution":None,"evidence":[{"factor":n,"score":v,"providers":ps,"values":[s.value for s in obs]} for n,v,ps,_,obs in factor_data]})
    coeff=sum(f.risk_coefficient for f in factors)
    score=0
    if coeff:
        for f in factors:
            f.contribution=f.risk_score*f.risk_coefficient/coeff
            row=next(x for x in category_scores if x["category"]==next(k for k,v in CATEGORIES.items() if PREFERENCE_FIELDS[v]==f.factor))
            row["contribution"]=round(f.contribution,2)
        score=sum(f.contribution for f in factors)
    agreements=[f"Multiple providers agree on {name}: {', '.join(ps)}." for cat in category_scores for item in cat["evidence"] if len(item["providers"])>1 for name,ps in [(item["factor"],item["providers"])]]
    explanation=[f"{f.factor}: signal {f.risk_score:.0f}/100, evidence strength {f.evidence_strength:.0%}, contribution {f.contribution:.1f}." for f in factors]
    return {"risk_score":round(score,2),"risk_level":classify_risk(score),"factor_scores":factors,"categories":category_scores,"provider_agreement":agreements,"missing_signals":missing,"explanation":explanation}
