from app.services.risk_engine.report_data import build_report_data


def test_report_data_preserves_official_scores_and_effective_weights():
    context = {
        "transaction": {"transaction_id": "T1", "amount": 100, "currency": "USD", "transaction_country": "US", "account_age_days": None},
        "risk_assessment": {"final_score": 41.5, "risk_level": "Medium Risk", "evidence_strength": "Moderate"},
        "user_risk_preferences": {"ip_reputation": 60, "geographic_risk": 40},
        "categories": [
            {"category": "ip_reputation", "score": 70, "weight": .6, "risk_coefficient": .3, "contribution": 41.5, "evidence": [{"factor": "Fraud score", "score": 70, "providers": ["FFraud"], "values": [70]}]},
            {"category": "geographic_risk", "score": None, "weight": .4, "risk_coefficient": 0, "contribution": None, "evidence": []},
        ],
        "provider_results": [{"provider": "FFraud", "status": "success", "signals": [{"category": "ip_reputation", "risk_score": 70}]}],
    }
    result = build_report_data(context)
    assert result["overall"]["risk_score"] == 41.5
    assert result["customer_weight_analysis"]["available_weight_coverage"] == .6
    assert result["customer_weight_analysis"]["effective_weights"]["ip_reputation"] == 1
    assert result["dimensions"][1]["included_in_final_score"] is False
    assert result["dimensions"][1]["risk_score"] is None


def test_provider_country_conflict_is_not_resolved_arbitrarily():
    context = {"transaction": {}, "risk_assessment": {}, "categories": [], "user_risk_preferences": {},
               "provider_results": [
                   {"provider": "IP-DB", "status": "success", "signals": [], "raw_result": {"countryCode": "US"}},
                   {"provider": "VirusTotal", "status": "success", "signals": [], "raw_result": {"data": {"attributes": {"country": "CA"}}}},
               ]}
    item = next(x for x in build_report_data(context)["data_consistency"] if x["field"] == "IP country")
    assert item["status"] == "INCONSISTENT"
    assert len(item["values"]) == 2
