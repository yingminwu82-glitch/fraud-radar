from app.services.fraud_providers.base import FraudDetectionProvider


class IPDBProvider(FraudDetectionProvider):
    provider_name = "IP-DB (placeholder)"

    async def analyze_ip(self, ip_address: str):
        raise NotImplementedError("Real IP-DB integration is reserved for a later stage")
