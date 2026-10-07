from app.services.llm.base import LLMProvider


class MockLLMProvider(LLMProvider):
    async def explain(self, structured_result: dict) -> str:
        raise NotImplementedError("LLM explanations are reserved for a later stage")
