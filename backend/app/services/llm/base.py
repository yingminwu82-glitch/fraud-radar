from abc import ABC, abstractmethod


class LLMProvider(ABC):
    """Interpret trusted, structured Risk Engine output; never calculate risk."""

    @abstractmethod
    async def generate_report(self, context: dict) -> dict:
        raise NotImplementedError

    @abstractmethod
    async def answer(self, context: dict, history: list[dict], question: str) -> str:
        raise NotImplementedError
