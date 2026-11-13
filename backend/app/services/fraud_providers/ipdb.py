import ipaddress

import httpx

from app.services.fraud_providers.base import FraudDetectionProvider


class ProviderFailure(Exception):
    """Safe provider failure with a UI-friendly status and message."""

    def __init__(self, status: str, message: str):
        self.status = status
        self.message = message
        super().__init__(message)


class IPDBProvider(FraudDetectionProvider):
    provider_name = "IP-DB"
    base_url = "https://ip-db.com/api/v1/check"

    def __init__(self, client: httpx.AsyncClient, api_key: str | None = None):
        self.client = client
        self.api_key = api_key.strip() if api_key else None

    @property
    def enabled(self) -> bool:
        return bool(self.api_key)

    async def analyze_ip(self, ip_address: str) -> dict:
        try:
            ip = str(ipaddress.ip_address(ip_address))
        except ValueError as exc:
            raise ProviderFailure("invalid_input", "A valid IPv4 or IPv6 address is required") from exc
        if not self.api_key:
            raise ProviderFailure("disabled", "IP-DB API key is not configured")

        try:
            response = await self.client.get(
                f"{self.base_url}/{ip}", headers={"Key": self.api_key}
            )
        except httpx.TimeoutException as exc:
            raise ProviderFailure("timeout", "IP-DB request timed out") from exc
        except httpx.RequestError as exc:
            raise ProviderFailure("error", "IP-DB network request failed") from exc

        if response.status_code == 429:
            raise ProviderFailure("rate_limited", "IP-DB rate limit reached")
        if response.status_code in (401, 403):
            raise ProviderFailure("error", "IP-DB rejected the API key")
        if response.status_code >= 500:
            raise ProviderFailure("error", "IP-DB service is unavailable")
        if response.is_error:
            raise ProviderFailure("error", f"IP-DB returned HTTP {response.status_code}")

        try:
            data = response.json()
        except (ValueError, TypeError) as exc:
            raise ProviderFailure("invalid_response", "IP-DB returned invalid JSON") from exc
        if not isinstance(data, dict) or not any(
            key in data for key in ("ipAddress", "abuseConfidenceScore")
        ):
            raise ProviderFailure("invalid_response", "IP-DB response is missing expected fields")
        return data
