from app.core.config import settings
from app.services.llm.deepseek import DeepSeekProvider
from app.services.llm.mock import MockLLMProvider


def get_llm_provider():
    if settings.use_mock_llm:
        return MockLLMProvider()
    if not settings.deepseek_api_key or not settings.deepseek_api_key.strip():
        return None
    return DeepSeekProvider(settings.deepseek_api_key.strip(),settings.deepseek_model,settings.deepseek_base_url,settings.deepseek_timeout_seconds)
