from types import SimpleNamespace

import pytest

from app.services.risk_engine.preferences import normalize_preferences
from app.schemas.risk import NormalizedSignal
from app.services.risk_engine.scoring import score_signals
from app.services.risk_engine.category_mapping import normalize_provider


def profile(**overrides):
    defaults = {"ip_reputation": 50, "network_anonymity": 50, "malicious_infrastructure": 50, "geographic_risk": 50, "transaction_behavior": 50, "account_characteristics": 50}
    return SimpleNamespace(**(defaults | overrides))


def test_weights_sum_to_one_and_equal_preferences_are_equal():
    weights = normalize_preferences(profile())
    assert sum(weights.values()) == pytest.approx(1)
    assert all(weight == pytest.approx(1 / 6) for weight in weights.values())


def test_larger_preference_has_larger_weight():
    weights = normalize_preferences(profile(ip_reputation=100, network_anonymity=10))
    assert weights["ip_reputation"] > weights["network_anonymity"]


def test_all_zero_preferences_fall_back_to_equal_weights():
    weights = normalize_preferences(profile(**{key: 0 for key in ("ip_reputation", "network_anonymity", "malicious_infrastructure", "geographic_risk", "transaction_behavior", "account_characteristics")}))
    assert sum(weights.values()) == pytest.approx(1)


def test_provider_fields_map_to_unified_categories_and_leave_omissions_unknown():
    signals=normalize_provider("VirusTotal",{"data":{"attributes":{"last_analysis_stats":{"malicious":2,"suspicious":2,"harmless":6}}}})
    assert signals[0].category=="malicious_infrastructure"
    assert signals[0].risk_score==100  # score is capped at 100


def test_ffraud_and_ipdb_provider_fields_normalize_consistently():
    ffraud=normalize_provider("FFraud",{"success":True,"fraud_score":61,"vpn":True,"threat_tags":["bot"]})
    ipdb=normalize_provider("IP-DB",{"ipAddress":"203.0.113.1","abuseConfidenceScore":61,"blacklistSources":["demo"]})
    assert {s.category for s in ffraud}=={"ip_reputation","network_anonymity","malicious_infrastructure"}
    assert next(s for s in ipdb if s.factor=="Abuse confidence").risk_score==61
    absent=normalize_provider("IP-DB",{"ipAddress":"203.0.113.1"})
    assert absent == []


def test_agreement_increases_evidence_strength_without_double_counting_score():
    one=NormalizedSignal(category="ip_reputation",factor="Reputation",risk_score=70,provider="A",confidence=.8)
    two=one.model_copy(update={"provider":"B"})
    single=score_signals([one],profile())["categories"][0]
    together=score_signals([one,two],profile())["categories"][0]
    assert single["score"]==together["score"]==70
    assert together["evidence_strength"]>single["evidence_strength"]
