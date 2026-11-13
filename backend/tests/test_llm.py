import httpx
import pytest

from app.schemas.ai import AIReportContent
from app.services.llm.deepseek import DeepSeekProvider, LLMServiceError, SYSTEM_PROMPT
from app.services.llm.mock import MockLLMProvider

@pytest.fixture
def anyio_backend(): return "asyncio"

def sample_context():
    return {"risk_assessment":{"final_score":72.5,"risk_level":"High Risk","evidence_strength":"Moderate"},"categories":[{"category":"ip_reputation","score":80,"weight":.5,"contribution":40,"evidence_strength":.8,"evidence":[{"providers":["FFraud"]}]}],"provider_agreement":[],"provider_results":[],"limitations":["IP-DB data unavailable."],"user_risk_preferences":{"ip_reputation":90}}

@pytest.mark.anyio
async def test_mock_llm_report_and_chat_are_deterministic_and_use_engine_score():
    llm=MockLLMProvider(); context=sample_context()
    report=await llm.generate_report(context)
    answer=await llm.answer(context,[],"What is the largest contributor?")
    assert "72.5/100" in report["executive_summary"]
    assert "IP Reputation" in answer
    assert "IP-DB data unavailable." in report["limitations"]

class FakeResponse:
    def __init__(self,status,payload): self.status_code,self.payload=status,payload
    def json(self): return self.payload

class FakeClient:
    def __init__(self,response=None,error=None,**kwargs): self.response,self.error=response,error; self.kwargs=kwargs
    async def __aenter__(self): return self
    async def __aexit__(self,*args): return None
    async def post(self,*args,**kwargs):
        self.request=kwargs
        if self.error: raise self.error
        return self.response

@pytest.mark.anyio
async def test_deepseek_valid_json_and_prompt_guard(monkeypatch):
    body={"executive_summary":"Explanation","overall_interpretation":"Context only","sections":{k:"Unknown" for k in ("ip_reputation","network_anonymity","malicious_infrastructure","geographic_risk","transaction_behavior","account_characteristics")},"multi_source_analysis":"No agreement","risk_contribution_analysis":"Engine values","user_preference_impact":"Weights from profile","positive_signals":[],"limitations":[],"recommended_actions":[],"key_risk_drivers":[],"confidence_explanation":"Limited"}
    client=FakeClient(FakeResponse(200,{"choices":[{"message":{"content":__import__("json").dumps(body)}}]}))
    monkeypatch.setattr("app.services.llm.deepseek.httpx.AsyncClient",lambda **kwargs:client)
    provider=DeepSeekProvider("secret","model","https://example.test")
    result=await provider.generate_report(sample_context())
    AIReportContent.model_validate(result)
    assert "Do not override" in SYSTEM_PROMPT
    assert client.request["headers"]["Authorization"]=="Bearer secret"

@pytest.mark.anyio
async def test_deepseek_malformed_json_timeout_and_rate_limit(monkeypatch):
    provider=DeepSeekProvider("key","model","https://example.test")
    client=FakeClient(FakeResponse(200,{"choices":[{"message":{"content":"not json"}}]}))
    monkeypatch.setattr("app.services.llm.deepseek.httpx.AsyncClient",lambda **kwargs:client)
    with pytest.raises(LLMServiceError,match="malformed report JSON"):
        await provider.generate_report(sample_context())
    timeout_client=FakeClient(error=httpx.ReadTimeout("timeout"))
    monkeypatch.setattr("app.services.llm.deepseek.httpx.AsyncClient",lambda **kwargs:timeout_client)
    with pytest.raises(LLMServiceError) as timeout: await provider.generate_report(sample_context())
    assert timeout.value.code=="timeout"
    limited=FakeClient(FakeResponse(429,{}))
    monkeypatch.setattr("app.services.llm.deepseek.httpx.AsyncClient",lambda **kwargs:limited)
    with pytest.raises(LLMServiceError) as rate: await provider.generate_report(sample_context())
    assert rate.value.code=="rate_limited"
    failed=FakeClient(FakeResponse(500,{}))
    monkeypatch.setattr("app.services.llm.deepseek.httpx.AsyncClient",lambda **kwargs:failed)
    with pytest.raises(LLMServiceError) as api_error: await provider.generate_report(sample_context())
    assert api_error.value.code=="api_error"

def test_model_cannot_supply_official_score_field():
    context=sample_context()
    llm_report={"executive_summary":"x","overall_interpretation":"x","sections":{k:"x" for k in ("ip_reputation","network_anonymity","malicious_infrastructure","geographic_risk","transaction_behavior","account_characteristics")},"multi_source_analysis":"x","risk_contribution_analysis":"x","user_preference_impact":"x","positive_signals":[],"limitations":[],"recommended_actions":[],"key_risk_drivers":[],"confidence_explanation":"x","risk_score":0,"risk_level":"Low"}
    validated=AIReportContent.model_validate(llm_report)
    assert "risk_score" not in validated.model_dump()
    assert context["risk_assessment"]["final_score"]==72.5
