from app.services.fraud_providers.base import FraudDetectionProvider


class VirusTotalProvider(FraudDetectionProvider):
    provider_name = "VirusTotal (placeholder)"

    async def analyze_ip(self, ip_address: str):
        raise NotImplementedError("Real VirusTotal integration is reserved for a later stage")
