"""Shared async HTTP client for the Cisco Umbrella API.

All tool modules use UmbrellaClient to make authenticated API requests.
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from cisco_umbrella_mcp.auth import TokenManager

API_BASE_URL = "https://api.umbrella.com"
REQUEST_TIMEOUT = 30.0


class UmbrellaAPIError(Exception):
    """Raised when the Umbrella API returns an error response."""

    def __init__(self, status_code: int, detail: str) -> None:
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"Umbrella API error {status_code}: {detail}")


class UmbrellaClient:
    """Async HTTP client for the Cisco Umbrella REST API."""

    def __init__(self, token_manager: TokenManager, http_client: httpx.AsyncClient) -> None:
        self.token_manager = token_manager
        self._http = http_client

    async def _get_headers(self) -> dict[str, str]:
        token = await self.token_manager.get_token()
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

    async def request(
        self,
        method: str,
        scope: str,
        endpoint: str,
        *,
        params: dict[str, Any] | None = None,
        json_data: Any | None = None,
    ) -> Any:
        """Make an authenticated request to the Umbrella API.

        Args:
            method: HTTP method (GET or POST for read-only queries).
            scope: API scope path (e.g. "investigate/v2", "policies/v2").
            endpoint: Path after the scope (e.g. "domains/categorization/example.com").
            params: Optional query parameters.
            json_data: Optional JSON request body (for POST-as-query endpoints).

        Returns:
            Parsed JSON response.
        """
        url = f"{API_BASE_URL}/{scope}/{endpoint}"
        headers = await self._get_headers()

        response = await self._http.request(
            method,
            url,
            headers=headers,
            params=params,
            json=json_data,
            timeout=REQUEST_TIMEOUT,
        )

        if response.status_code >= 400:
            try:
                detail = response.json()
            except Exception:
                detail = response.text
            raise UmbrellaAPIError(response.status_code, str(detail))

        if response.status_code == 204:
            return None

        body = response.content
        if len(body) > 2 * 1024 * 1024:
            raise RuntimeError(f"Response too large ({len(body):,} bytes). Narrow your query or reduce the limit.")
        return response.json()

    async def get(self, scope: str, endpoint: str, **kwargs: Any) -> Any:
        return await self.request("GET", scope, endpoint, **kwargs)


def format_error(e: Exception) -> str:
    """Format an exception into an actionable error message for the LLM."""
    if isinstance(e, UmbrellaAPIError):
        messages: dict[int, str] = {
            400: "Bad request. Check that all parameters are valid.",
            401: "Authentication failed. Verify your API_KEY and API_SECRET are correct and not expired.",
            403: "Permission denied. Your API key may lack the required scope for this operation.",
            404: "Resource not found. Verify the ID or domain you provided exists.",
            429: "Rate limit exceeded. Wait a moment before retrying.",
            500: "Umbrella server error. Try again shortly.",
            503: "Umbrella service temporarily unavailable. Try again shortly.",
        }
        hint = messages.get(e.status_code, "")
        detail = e.detail[:500] + "…" if len(e.detail) > 500 else e.detail
        return f"Error {e.status_code}: {detail}" + (f" — {hint}" if hint else "")
    if isinstance(e, httpx.TimeoutException):
        return "Error: Request timed out. Try again or use a smaller query."
    return f"Error: {type(e).__name__}: {e}"


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------


def _strip_empty(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _strip_empty(v) for k, v in obj.items() if v is not None and v != "" and v != [] and v != {}}
    if isinstance(obj, list):
        return [_strip_empty(item) for item in obj]
    return obj


def compact_json(data: Any) -> str:
    """Serialise data to compact JSON with null/empty fields stripped."""
    return json.dumps(_strip_empty(data), separators=(",", ":"))
