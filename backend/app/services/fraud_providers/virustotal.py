from app.services.fraud_providers.base import FraudDetectionProvider


class VirusTotalProvider(FraudDetectionProvider):
    provider_name = "VirusTotal"
    def __init__(self, client, api_key=None): self.client, self.api_key = client, api_key
    @property
    def enabled(self): return bool(self.api_key)
    async def analyze_ip(self, ip_address: str) -> dict:
        response = await self.client.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}", headers={"x-apikey": self.api_key})
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict) or not isinstance(data.get("data", {}).get("attributes"), dict):
            raise ValueError("VirusTotal returned an invalid response")
        return data
