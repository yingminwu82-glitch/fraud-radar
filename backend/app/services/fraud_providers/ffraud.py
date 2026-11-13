from app.services.fraud_providers.base import FraudDetectionProvider


class FFraudProvider(FraudDetectionProvider):
    provider_name = "FFraud"
    enabled = True  # Public IP endpoint works without a key.
    def __init__(self, client, api_key=None): self.client, self.api_key = client, api_key
    async def analyze_ip(self, ip_address: str) -> dict:
        headers = {"X-API-Key": self.api_key} if self.api_key else {}
        response = await self.client.get(f"https://api.ffraud.com/public/ip/{ip_address}", headers=headers)
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict) or not data.get("success"):
            raise ValueError("FFraud returned an invalid response")
        return data
