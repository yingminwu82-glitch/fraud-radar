from types import SimpleNamespace

import pytest

from app.services.risk_engine.preferences import normalize_preferences


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
