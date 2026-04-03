"""Tests for the OAuth token manager."""

from __future__ import annotations

import time

import httpx
import pytest
import respx

from cisco_umbrella_mcp.auth import TokenManager


@pytest.fixture
def tm() -> TokenManager:
    return TokenManager(
        api_key="test-key",
        api_secret="test-secret",
        token_url="https://api.umbrella.com/auth/v2/token",
    )


class TestTokenManager:
    def test_initial_state_is_expired(self, tm: TokenManager) -> None:
        assert tm.is_expired is True
        assert tm._access_token is None

    @respx.mock
    async def test_get_token_fetches_new_token(self, tm: TokenManager) -> None:
        respx.post("https://api.umbrella.com/auth/v2/token").respond(
            json={"access_token": "abc123", "token_type": "bearer", "expires_in": 3600}
        )
        token = await tm.get_token()
        assert token == "abc123"
        assert tm.is_expired is False

    @respx.mock
    async def test_get_token_reuses_valid_token(self, tm: TokenManager) -> None:
        route = respx.post("https://api.umbrella.com/auth/v2/token").respond(
            json={"access_token": "abc123", "token_type": "bearer", "expires_in": 3600}
        )
        await tm.get_token()
        await tm.get_token()
        assert route.call_count == 1

    @respx.mock
    async def test_get_token_refreshes_expired_token(self, tm: TokenManager) -> None:
        respx.post("https://api.umbrella.com/auth/v2/token").respond(
            json={"access_token": "new-token", "token_type": "bearer", "expires_in": 3600}
        )
        # Simulate an expired token
        tm._access_token = "old-token"
        tm._expires_at = time.time() - 100

        token = await tm.get_token()
        assert token == "new-token"

    @respx.mock
    async def test_auth_error_propagates(self, tm: TokenManager) -> None:
        respx.post("https://api.umbrella.com/auth/v2/token").respond(status_code=401)
        with pytest.raises(httpx.HTTPStatusError):
            await tm.get_token()

    @respx.mock
    async def test_org_id_header_sent(self) -> None:
        tm = TokenManager(
            api_key="key",
            api_secret="secret",
            token_url="https://api.umbrella.com/auth/v2/token",
            org_id="child-org-123",
        )
        route = respx.post("https://api.umbrella.com/auth/v2/token").respond(
            json={"access_token": "tok", "token_type": "bearer", "expires_in": 3600}
        )
        await tm.get_token()
        assert route.calls[0].request.headers["X-Umbrella-OrgId"] == "child-org-123"
