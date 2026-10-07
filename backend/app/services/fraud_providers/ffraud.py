from app.services.fraud_providers.base import FraudDetectionProvider


class FFraudProvider(FraudDetectionProvider):
    provider_name = "FFraud (placeholder)"

    async def analyze_ip(self, ip_address: str):
        raise NotImplementedError("Real FFraud integration is reserved for a later stage")
