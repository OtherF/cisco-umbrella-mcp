"""OAuth 2.0 token management for the Cisco Umbrella API.

Handles client credentials flow with automatic token refresh.
"""

import asyncio
import time
from dataclasses import dataclass, field

import httpx

DEFAULT_TOKEN_URL = "https://api.umbrella.com/auth/v2/token"

# Refresh 60 seconds before actual expiry to avoid race conditions
TOKEN_REFRESH_BUFFER_SECONDS = 60


@dataclass
class TokenManager:
    """Manages OAuth 2.0 access tokens with automatic refresh."""

    api_key: str
    api_secret: str
    token_url: str = DEFAULT_TOKEN_URL
    org_id: str | None = None
    _access_token: str | None = field(default=None, init=False, repr=False)
    _expires_at: float = field(default=0.0, init=False, repr=False)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False, repr=False)

    @property
    def is_expired(self) -> bool:
        return time.time() >= (self._expires_at - TOKEN_REFRESH_BUFFER_SECONDS)

    async def get_token(self) -> str:
        """Return a valid access token, refreshing if needed."""
        if self._access_token is None or self.is_expired:
            async with self._lock:
                # Re-check after acquiring lock — another coroutine may have refreshed already
                if self._access_token is None or self.is_expired:
                    await self._refresh_token()
        if self._access_token is None:
            raise RuntimeError("Token unavailable after refresh — check API_KEY and API_SECRET")
        return self._access_token

    async def _refresh_token(self) -> None:
        """Request a new access token from the Umbrella auth endpoint."""
        headers: dict[str, str] = {
            "Content-Type": "application/x-www-form-urlencoded",
        }
        if self.org_id:
            headers["X-Umbrella-OrgId"] = self.org_id

        async with httpx.AsyncClient() as client:
            response = await client.post(
                self.token_url,
                auth=(self.api_key, self.api_secret),
                headers=headers,
                data={"grant_type": "client_credentials"},
                timeout=30.0,
            )
            response.raise_for_status()
            data = response.json()

        self._access_token = data["access_token"]
        self._expires_at = time.time() + data.get("expires_in", 3600)
