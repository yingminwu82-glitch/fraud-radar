"""Build traceable report facts from the persisted Risk Engine context."""

DIMENSION_NAMES = {
    "ip_reputation": "IP Reputation Risk",
    "network_anonymity": "Network Anonymity Risk",
    "malicious_infrastructure": "Malicious Infrastructure Risk",
    "geographic_risk": "Geographic Consistency Risk",
    "transaction_behavior": "Transaction Behaviour Risk",
    "account_characteristics": "Account Profile Risk",
}
from app.services.risk_engine.geography import country_observations, compare_transaction_country


def build_report_data(context: dict, analysis_created_at=None) -> dict:
    transaction = context.get("transaction", {})
    assessment = context.get("risk_assessment", {})
    provider_rows = context.get("provider_results", [])
    categories = context.get("categories", [])
    preferences = context.get("user_risk_preferences", {})
    weights = {k: v for k, v in preferences.items() if k in DIMENSION_NAMES}
    scoreable = [c for c in categories if c.get("score") is not None]
    coeff_total = sum(float(c.get("risk_coefficient") or 0) for c in scoreable)
    dimensions = []
    for category in categories:
        key = category.get("category")
        dimension = dict(category)
        dimension["dimension_name"] = DIMENSION_NAMES.get(key, key)
        dimension["risk_score"] = category.get("score")
        coeff = float(category.get("risk_coefficient") or 0)
        dimension["effective_weight"] = round(coeff / coeff_total, 6) if coeff_total and category.get("score") is not None else None
        dimension["included_in_final_score"] = category.get("score") is not None
        dimension["risk_level"] = category.get("risk_level", "N/A") if category.get("score") is not None else "N/A"
        dimensions.append(dimension)

    consistency = []
    def compare(field_name, values, comparable):
        available = [(provider, value) for provider, value in values if value is not None and value != ""]
        if len(available) < 2:
            status = "Inconclusive"
        elif not comparable:
            status = "Inconclusive"
        else:
            status = "Consistent" if len({str(v).strip().casefold() for _, v in available}) == 1 else "Inconsistent"
        consistency.append({"field": field_name, "values": [{"provider": p, "value": v} for p, v in available], "status": status,
                           "affects_scoring": field_name == "IP country vs transaction country",
                           "note": "Provider definitions and update times may differ; conflicting values are unresolved." if status == "Inconsistent" else "Only directly comparable values are compared."})

    geo=country_observations(provider_rows)
    geo["comparison_status"]=compare_transaction_country(geo,transaction.get("transaction_country"))
    consistency.append({"field":"IP country","values":geo["observations"],"status":geo["provider_consistency"],"comparison_status":geo["comparison_status"],"resolved_ip_country":geo["resolved_ip_country"],"affects_scoring":geo["comparison_status"] in {"MATCH","MISMATCH"},"note":"IP geolocation is an estimate, not confirmed physical location. Conflicts remain unresolved."})
    def safe_get(raw,path):
        value=raw
        for part in path:
            if not isinstance(value,dict): return None
            value=value.get(part)
        return value
    compare("ASN",[(r.get("provider"),safe_get(r.get("raw_result") or {},path)) for r in provider_rows for path in (("ASN",),("asn",),("data","attributes","asn")) if safe_get(r.get("raw_result") or {},path) is not None],False)

    findings = []
    for c in categories:
        score = c.get("score")
        if score is None:
            continue
        for evidence in c.get("evidence", []):
            if evidence.get("score", 0) <= 0:
                continue
            findings.append({"title": evidence.get("factor"), "dimension": DIMENSION_NAMES.get(c.get("category"), c.get("category")),
                             "observed_value": evidence.get("values"), "source": evidence.get("providers", []),
                             "severity": c.get("risk_level", "Informational"), "explanation": "Observed provider or transaction-context evidence; this is an indicator, not confirmation of fraud.",
                             "further_verification": True})
    unavailable = [p.get("provider") for p in provider_rows if p.get("status") != "success"]
    missing_dimensions = [DIMENSION_NAMES.get(c.get("category"), c.get("category")) for c in categories if c.get("score") is None]
    available_weight = sum(float(weights.get(c.get("category"), 0) or 0) for c in scoreable)
    total_weight = sum(float(v or 0) for v in weights.values())
    return {
        "basic_information": {
            "customer": {"customer_id": None, "account_age_days": transaction.get("account_age_days"), "country": transaction.get("user_country"), "risk_preferences": preferences},
            "transaction": {k: transaction.get(k) for k in ("transaction_id", "amount", "currency", "transaction_country", "transaction_velocity", "timestamp")},
            "ip": {"address": transaction.get("ip_address")},
            "analysis_timestamp": analysis_created_at.isoformat() if hasattr(analysis_created_at, "isoformat") else analysis_created_at,
        },
        "provider_status": [{"provider": p.get("provider"), "status": p.get("status"), "usable_data": bool(p.get("signals")), "available_categories": sorted({s.get("category") for s in p.get("signals", []) if s.get("risk_score") is not None})} for p in provider_rows],
        "anomaly_findings": findings,
        "data_consistency": consistency,
        "geographic_resolution": geo,
        "dimensions": dimensions,
        "customer_weight_analysis": {"configured_weights": weights, "available_weight_coverage": round(available_weight / total_weight, 6) if total_weight else None,
                                     "effective_weights": {d["category"]: d["effective_weight"] for d in dimensions},
                                     "unavailable_dimensions": missing_dimensions, "provisional": bool(missing_dimensions)},
        "overall": {"risk_score": assessment.get("final_score"), "risk_level": assessment.get("risk_level"), "evidence_strength": assessment.get("evidence_strength")},
        "limitations": [*(f"Provider unavailable: {p}." for p in unavailable), *(f"Insufficient evidence: {d}." for d in missing_dimensions),
                        "Customer ID, transaction timestamp, historical transaction comparison, account history, device and biometric data are not supplied by current inputs/providers."],
    }
