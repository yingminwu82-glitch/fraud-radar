from app.services.fraud_providers.base import FraudDetectionProvider


class VPNDetectionProvider(FraudDetectionProvider):
    provider_name = "VPNDetection (placeholder)"

    async def analyze_ip(self, ip_address: str):
        raise NotImplementedError("Real VPNDetection integration is reserved for a later stage")
