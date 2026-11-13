import asyncio

import httpx
import pytest

from app.services.fraud_providers.ipdb import IPDBProvider, ProviderFailure


class StubClient:
    def __init__(self, response=None, error=None):
        self.response, self.error, self.calls = response, error, []

    async def get(self, url, headers):
        self.calls.append((url, headers))
        if self.error:
            raise self.error
        return self.response


def response(status=200, json_data=None, text=None):
    request = httpx.Request("GET", "https://ip-db.com/api/v1/check/8.8.8.8")
    return httpx.Response(status, text=text, request=request) if text is not None else httpx.Response(status, json=json_data, request=request)


def test_success_sends_key_header_and_preserves_raw_fields():
    async def run():
        raw = {"ipAddress": "8.8.8.8", "abuseConfidenceScore": 12, "asnOrg": "Example"}
        client = StubClient(response=response(json_data=raw))
        assert await IPDBProvider(client, "secret").analyze_ip("8.8.8.8") == raw
        assert client.calls == [("https://ip-db.com/api/v1/check/8.8.8.8", {"Key": "secret"})]
    asyncio.run(run())


@pytest.mark.parametrize("ip", ["not-an-ip", "999.1.1.1"])
def test_invalid_ip_fails_before_network(ip):
    async def run():
        client = StubClient()
        with pytest.raises(ProviderFailure, match="valid IPv4"):
            await IPDBProvider(client, "secret").analyze_ip(ip)
        assert client.calls == []
    asyncio.run(run())


def test_missing_key_is_disabled_without_request():
    async def run():
        client = StubClient(); provider = IPDBProvider(client)
        assert not provider.enabled
        with pytest.raises(ProviderFailure) as error:
            await provider.analyze_ip("8.8.8.8")
        assert error.value.status == "disabled" and client.calls == []
    asyncio.run(run())


@pytest.mark.parametrize(("status_code", "expected"), [(401, "error"), (403, "error"), (429, "rate_limited"), (503, "error")])
def test_http_failures_are_classified(status_code, expected):
    async def run():
        provider=IPDBProvider(StubClient(response=response(status=status_code)),"secret")
        with pytest.raises(ProviderFailure) as error: await provider.analyze_ip("8.8.8.8")
        assert error.value.status==expected and "secret" not in str(error.value)
    asyncio.run(run())


def test_timeout_network_and_invalid_json_are_safe():
    async def run():
        timeout=IPDBProvider(StubClient(error=httpx.ReadTimeout("sensitive")),"secret")
        with pytest.raises(ProviderFailure) as error: await timeout.analyze_ip("8.8.8.8")
        assert error.value.status=="timeout"
        network=IPDBProvider(StubClient(error=httpx.ConnectError("sensitive")),"secret")
        with pytest.raises(ProviderFailure) as error: await network.analyze_ip("8.8.8.8")
        assert error.value.status=="error"
        invalid=IPDBProvider(StubClient(response=response(text="not-json")),"secret")
        with pytest.raises(ProviderFailure) as error: await invalid.analyze_ip("8.8.8.8")
        assert error.value.status=="invalid_response" and "secret" not in str(error.value)
    asyncio.run(run())


def test_missing_schema_fields_are_invalid_response():
    async def run():
        provider=IPDBProvider(StubClient(response=response(json_data={"countryCode":"US"})),"secret")
        with pytest.raises(ProviderFailure) as error: await provider.analyze_ip("8.8.8.8")
        assert error.value.status=="invalid_response"
    asyncio.run(run())
