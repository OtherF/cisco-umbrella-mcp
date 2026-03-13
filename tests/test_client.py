"""Tests for the shared Umbrella HTTP client."""

from __future__ import annotations

import httpx
import pytest
import respx

from cisco_umbrella_mcp.auth import TokenManager
from cisco_umbrella_mcp.client import UmbrellaAPIError, UmbrellaClient, format_error


@pytest.fixture
def tm() -> TokenManager:
    tm = TokenManager(api_key="k", api_secret="s")
    tm._access_token = "test-token"
    tm._expires_at = 9999999999.0
    return tm


@pytest.fixture
def client(tm: TokenManager) -> UmbrellaClient:
    return UmbrellaClient(tm)


class TestUmbrellaClient:
    @respx.mock
    async def test_get_request(self, client: UmbrellaClient) -> None:
        route = respx.get("https://api.umbrella.com/investigate/v2/whois/example.com").respond(
            json={"domain": "example.com"}
        )
        result = await client.get("investigate/v2", "whois/example.com")
        assert result == {"domain": "example.com"}
        assert "Bearer test-token" in route.calls[0].request.headers["Authorization"]

    @respx.mock
    async def test_post_with_json_body(self, client: UmbrellaClient) -> None:
        respx.post("https://api.umbrella.com/policies/v2/destinationlists").respond(
            json={"id": 1}
        )
        result = await client.post(
            "policies/v2", "destinationlists", json_data={"name": "test"}
        )
        assert result == {"id": 1}

    @respx.mock
    async def test_api_error_raised(self, client: UmbrellaClient) -> None:
        respx.get("https://api.umbrella.com/admin/v2/users").respond(
            status_code=403, json={"error": "forbidden"}
        )
        with pytest.raises(UmbrellaAPIError) as exc_info:
            await client.get("admin/v2", "users")
        assert exc_info.value.status_code == 403

    @respx.mock
    async def test_204_returns_none(self, client: UmbrellaClient) -> None:
        respx.delete("https://api.umbrella.com/policies/v2/destinationlists/1").respond(
            status_code=204
        )
        result = await client.delete("policies/v2", "destinationlists/1")
        assert result is None


class TestFormatError:
    def test_api_error_with_hint(self) -> None:
        err = UmbrellaAPIError(429, "rate limited")
        msg = format_error(err)
        assert "429" in msg
        assert "Rate limit" in msg

    def test_timeout_error(self) -> None:
        err = httpx.ReadTimeout("timed out")
        msg = format_error(err)
        assert "timed out" in msg.lower()

    def test_generic_error(self) -> None:
        err = ValueError("something wrong")
        msg = format_error(err)
        assert "ValueError" in msg
