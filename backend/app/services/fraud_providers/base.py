from abc import ABC, abstractmethod

from app.schemas.risk import NormalizedSignal


class FraudDetectionProvider(ABC):
    """Provider boundary: adapters return shared signals, never scoring decisions."""

    provider_name: str

    @abstractmethod
    async def analyze_ip(self, ip_address: str) -> list[NormalizedSignal]:
        raise NotImplementedError

    async def analyze_url(self, url: str) -> list[NormalizedSignal]:
        raise NotImplementedError(f"{self.provider_name} does not support URL analysis")
