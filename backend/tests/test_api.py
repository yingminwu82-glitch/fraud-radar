def test_health(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_profile_create_and_validation(client, profile_payload):
    created = client.post("/api/risk-profiles", json=profile_payload)
    assert created.status_code == 201
    assert created.json()["profile_name"] == "Test Balanced"
    invalid = dict(profile_payload, profile_name="Invalid", ip_reputation=101)
    assert client.post("/api/risk-profiles", json=invalid).status_code == 422


def test_mock_analysis_returns_bounded_explainable_score(client):
    profile = client.post("/api/risk-profiles", json={"profile_name": "Security", "ip_reputation": 80, "network_anonymity": 90, "malicious_infrastructure": 95, "geographic_risk": 50, "transaction_behavior": 40, "account_characteristics": 30}).json()
    payload = {"transaction_id": "TX001", "ip_address": "203.0.113.42", "transaction_amount": 2500, "currency": "USD", "user_country": "US", "transaction_country": "US", "transaction_velocity": 2, "account_age_days": 450, "risk_profile_id": profile["id"]}
    result = client.post("/api/analyze", json=payload)
    assert result.status_code == 200, result.text
    body = result.json()
    assert 0 <= body["risk_score"] <= 100
    assert body["risk_level"] in {"Low Risk", "Medium Risk", "High Risk", "Critical Risk"}
    assert body["factor_scores"]
    assert "IP Reputation" in [factor["factor"] for factor in body["factor_scores"]]


def test_transactions_list(client):
    assert client.get("/api/transactions").status_code == 200


def test_same_transaction_can_be_rescored_with_another_profile(client):
    security = client.post("/api/risk-profiles", json={
        "profile_name": "Security", "ip_reputation": 90, "network_anonymity": 90,
        "malicious_infrastructure": 90, "geographic_risk": 10,
        "transaction_behavior": 10, "account_characteristics": 10,
    }).json()
    behavior = client.post("/api/risk-profiles", json={
        "profile_name": "Behavior", "ip_reputation": 10, "network_anonymity": 10,
        "malicious_infrastructure": 10, "geographic_risk": 10,
        "transaction_behavior": 90, "account_characteristics": 90,
    }).json()
    base = {"transaction_id": "TX-CACHE", "ip_address": "203.0.113.19", "transaction_amount": 3200,
            "currency": "USD", "user_country": "US", "transaction_country": "DE",
            "transaction_velocity": 8, "account_age_days": 3}
    first = client.post("/api/analyze", json={**base, "risk_profile_id": security["id"]}).json()
    second = client.post("/api/analyze", json={**base, "risk_profile_id": behavior["id"]}).json()
    assert first["risk_score"] != second["risk_score"]
    assert first["provider_results"] == second["provider_results"]
