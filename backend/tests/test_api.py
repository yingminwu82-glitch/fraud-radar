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


def test_ai_report_uses_risk_engine_score_and_is_cached(client):
    body={"transaction_id":"TX-AI","ip_address":"203.0.113.25","transaction_amount":1400,"currency":"USD","risk_profile_id":1,"account_age_days":None}
    analysis=client.post("/api/analyze",json=body).json()
    generated=client.post(f"/api/ai/report/{analysis['analysis_id']}",json={})
    assert generated.status_code==200,generated.text
    first=generated.json()
    assert first["report"]["risk_score"]==analysis["risk_score"]
    assert first["report"]["risk_level"]==analysis["risk_level"]
    assert "Insufficient account-level evidence is available." in first["report"]["limitations"]
    assert "Transaction history and historical behavior data are unavailable in this prototype." in first["report"]["limitations"]
    cached=client.post(f"/api/ai/report/{analysis['analysis_id']}",json={}).json()
    assert cached["id"]==first["id"]
    assert client.get(f"/api/ai/report/{analysis['analysis_id']}").json()["report"]==first["report"]


def test_fraud_detective_keeps_session_history_and_can_clear(client):
    analysis=client.post("/api/analyze",json={"transaction_id":"TX-CHAT","ip_address":"203.0.113.21","transaction_amount":1800,"currency":"USD","risk_profile_id":1,"account_age_days":12}).json()
    path=f"/api/ai/chat/{analysis['analysis_id']}"
    first=client.post(path,json={"question":"What is the biggest risk factor?"})
    assert first.status_code==200,first.text
    data=first.json()
    second=client.post(path,json={"question":"Why does that matter?","session_id":data["session_id"]})
    assert second.status_code==200,second.text
    history=client.get(f"{path}/{data['session_id']}").json()
    assert len(history["messages"])==4
    assert client.delete(f"{path}/{data['session_id']}").json()["status"]=="cleared"


def test_provider_evidence_chat_uses_separate_current_analysis_context(client,monkeypatch):
    from app.api.routes import api as api_routes

    class CaptureLLM:
        model_name="capture-llm"
        contexts=[]
        async def generate_report(self,context):
            from app.services.llm.mock import MockLLMProvider
            return await MockLLMProvider().generate_report(context)
        async def answer(self,context,history,question):
            self.contexts.append(context)
            return "Context received."

    llm=CaptureLLM()
    monkeypatch.setattr(api_routes,"get_llm_provider",lambda:llm)
    analysis=client.post("/api/analyze",json={"transaction_id":"TX-PROVIDER-QA","ip_address":"203.0.113.42","transaction_amount":1800,"currency":"USD","risk_profile_id":1}).json()
    analysis_id=analysis["analysis_id"]
    assert client.post(f"/api/ai/report/{analysis_id}",json={}).status_code==200
    provider_response=client.post(f"/api/ai/chat/{analysis_id}",json={"question":"What does the FFraud fraud score mean?","context_type":"provider_evidence"})
    assert provider_response.status_code==200,provider_response.text
    provider_context=llm.contexts[-1]
    assert provider_context["analysis_id"]==analysis_id
    assert provider_context["context_type"]=="provider_evidence"
    assert provider_context["provider_evidence"][0]["provider_reported_fields"]["fraud_score"]==78
    assert provider_context["provider_evidence"][0]["backend_normalized_signals"]
    assert provider_context["dimension_mappings"]
    assert "report" not in provider_context

    report_response=client.post(f"/api/ai/chat/{analysis_id}",json={"question":"Explain the report context.","context_type":"report"})
    assert report_response.status_code==200,report_response.text
    report_context=llm.contexts[-1]
    assert report_context["context_type"]=="report"
    assert "provider_results" in report_context
    assert "provider_evidence" not in report_context
    assert report_context["report"]["executive_summary"]
    assert report_response.json()["session_id"]!=provider_response.json()["session_id"]

    context_mismatch=client.post(f"/api/ai/chat/{analysis_id}",json={"question":"Mix contexts","context_type":"report","session_id":provider_response.json()["session_id"]})
    assert context_mismatch.status_code==404

    next_analysis=client.post("/api/analyze",json={"transaction_id":"TX-PROVIDER-QA-2","ip_address":"198.51.100.9","transaction_amount":900,"currency":"USD","risk_profile_id":1}).json()
    next_chat=client.post(f"/api/ai/chat/{next_analysis['analysis_id']}",json={"question":"Explain these provider fields.","context_type":"provider_evidence"})
    assert next_chat.status_code==200,next_chat.text
    assert llm.contexts[-1]["analysis_id"]==next_analysis["analysis_id"]
    assert llm.contexts[-1]["analysis_id"]!=analysis_id


def test_missing_deepseek_key_gracefully_disables_ai(client,monkeypatch):
    from app.core.config import settings
    monkeypatch.setattr(settings,"use_mock_llm",False)
    monkeypatch.setattr(settings,"deepseek_api_key",None)
    analysis=client.post("/api/analyze",json={"transaction_id":"TX-NO-KEY","ip_address":"203.0.113.22","transaction_amount":1100,"currency":"USD","risk_profile_id":1}).json()
    response=client.post(f"/api/ai/report/{analysis['analysis_id']}",json={})
    assert response.status_code==503
    assert response.json()["detail"]["code"]=="missing_api_key"
