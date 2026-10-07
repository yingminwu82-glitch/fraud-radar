from abc import ABC, abstractmethod


class LLMProvider(ABC):
    """Future language layer: explain structured results; never calculate scores."""

    @abstractmethod
    async def explain(self, structured_result: dict) -> str:
        raise NotImplementedError
