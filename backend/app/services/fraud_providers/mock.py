from app.services.fraud_providers.base import FraudDetectionProvider


class MockProvider(FraudDetectionProvider):
    def __init__(self, provider_name): self.provider_name = provider_name
    async def analyze_ip(self, ip_address: str) -> dict:
        watch = ip_address.startswith(("203.0.113.", "198.51.100."))
        if self.provider_name == "FFraud":
            return {"success": True, "ip": ip_address, "fraud_score": 78 if watch else 6, "vpn": watch, "proxy": False, "tor": False, "hosting": False, "is_abuser": watch, "recent_abuse": watch, "confidence": "high", "threat_tags": ["abuse"] if watch else []}
        if self.provider_name == "IP-DB":
            return {"ipAddress": ip_address, "abuseConfidenceScore": 76 if watch else 4, "networkType": "residential", "blacklistSources": ["demo"] if watch else []}
        return {"data": {"attributes": {"reputation": -72 if watch else 2, "last_analysis_stats": {"malicious": 5 if watch else 0, "suspicious": 2 if watch else 0, "harmless": 45, "undetected": 8}}}}
