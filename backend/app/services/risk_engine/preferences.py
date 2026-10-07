from app.models.entities import RiskProfile

PREFERENCE_FIELDS = {
    "ip_reputation": "IP Reputation",
    "network_anonymity": "Network Anonymity",
    "malicious_infrastructure": "Malicious Infrastructure",
    "geographic_risk": "Geographic Risk",
    "transaction_behavior": "Transaction Behaviour",
    "account_characteristics": "Account Characteristics",
}


def normalize_preferences(profile: RiskProfile) -> dict[str, float]:
    values = {field: getattr(profile, field) for field in PREFERENCE_FIELDS}
    total = sum(values.values())
    if total == 0:
        equal_weight = 1 / len(values)
        return {field: equal_weight for field in values}
    return {field: value / total for field, value in values.items()}
