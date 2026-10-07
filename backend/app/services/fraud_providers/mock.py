from app.schemas.risk import NormalizedSignal
from app.services.fraud_providers.base import FraudDetectionProvider


class MockFraudProvider(FraudDetectionProvider):
    """Deterministic synthetic signals for demos; this adapter makes no network calls."""

    provider_name = "Mock Network Intel"

    async def analyze_ip(self, ip_address: str) -> list[NormalizedSignal]:
        # Reserved documentation ranges make safe, repeatable demo inputs.
        watch_ip = ip_address.startswith(("203.0.113.", "198.51.100."))
        return [
            NormalizedSignal(category="ip_reputation", factor="IP Reputation", value="watchlist" if watch_ip else "clean", risk_score=82 if watch_ip else 8, confidence=0.82, provider=self.provider_name),
            NormalizedSignal(category="network_anonymity", factor="VPN", value=watch_ip, risk_score=70 if watch_ip else 0, confidence=0.8, provider=self.provider_name),
            NormalizedSignal(category="network_anonymity", factor="Proxy", value=False, risk_score=0, confidence=0.8, provider=self.provider_name),
            NormalizedSignal(category="malicious_infrastructure", factor="Abuse Indicator", value=watch_ip, risk_score=75 if watch_ip else 3, confidence=0.72, provider=self.provider_name),
        ]
