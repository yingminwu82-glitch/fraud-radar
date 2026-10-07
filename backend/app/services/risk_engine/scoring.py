from app.models.entities import RiskProfile
from app.schemas.risk import FactorScore, NormalizedSignal
from app.services.risk_engine.normalization import aggregate_signals
from app.services.risk_engine.preferences import PREFERENCE_FIELDS, normalize_preferences
from app.services.risk_engine.thresholds import classify_risk

SIGNAL_TO_PREFERENCE = {
    "ip_reputation": "ip_reputation",
    "network_anonymity": "network_anonymity",
    "malicious_infrastructure": "malicious_infrastructure",
    "geographic_risk": "geographic_risk",
    "transaction_behavior": "transaction_behavior",
    "account_characteristics": "account_characteristics",
}


def score_signals(signals: list[NormalizedSignal], profile: RiskProfile) -> dict:
    weights = normalize_preferences(profile)
    aggregated = aggregate_signals(signals)
    factors = []
    missing = []
    for category, preference_field in SIGNAL_TO_PREFERENCE.items():
        item = aggregated.get(category)
        if not item:
            missing.append(PREFERENCE_FIELDS[preference_field])
            continue
        weight = weights[preference_field]
        factors.append(FactorScore(
            factor=PREFERENCE_FIELDS[preference_field], raw_signal=item["raw_signal"],
            risk_score=item["risk_score"], user_preference=getattr(profile, preference_field),
            weight=weight, contribution=item["risk_score"] * weight, providers=item["providers"],
        ))
    # Keep the score comparable if a source does not provide every category.
    observed_weight = sum(factor.weight for factor in factors)
    if observed_weight:
        for factor in factors:
            factor.weight = factor.weight / observed_weight
            factor.contribution = factor.risk_score * factor.weight
    score = sum(f.contribution for f in factors) if observed_weight else 0.0
    agreements = [f"Multiple providers detected {name}." for item in aggregated.values() if item["agreement"] > 1 for name in item["factors"]]
    explanation = [f"{f.factor} contributed {f.contribution:.1f} points (signal {f.risk_score:.0f}/100, profile weight {f.weight:.1%})." for f in sorted(factors, key=lambda x: x.contribution, reverse=True)]
    return {"risk_score": round(min(100, max(0, score)), 2), "risk_level": classify_risk(score), "factor_scores": factors, "provider_agreement": agreements, "missing_signals": missing, "explanation": explanation}
