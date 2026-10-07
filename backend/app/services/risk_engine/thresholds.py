from app.core.config import RISK_THRESHOLDS


def classify_risk(score: float) -> str:
    if score <= RISK_THRESHOLDS["low"]:
        return "Low Risk"
    if score <= RISK_THRESHOLDS["medium"]:
        return "Medium Risk"
    if score <= RISK_THRESHOLDS["high"]:
        return "High Risk"
    return "Critical Risk"
