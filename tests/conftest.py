"""Shared test fixtures for cisco-umbrella-mcp tests."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from cisco_umbrella_mcp.auth import TokenManager
from cisco_umbrella_mcp.client import UmbrellaClient


@pytest.fixture
def token_manager() -> TokenManager:
    """Create a TokenManager with test credentials."""
    return TokenManager(
        api_key="test-key",
        api_secret="test-secret",
        token_url="https://api.umbrella.com/auth/v2/token",
    )


@pytest.fixture
def mock_client(token_manager: TokenManager) -> UmbrellaClient:
    """Create an UmbrellaClient with a mocked request method."""
    client = UmbrellaClient(token_manager)
    client.request = AsyncMock()  # type: ignore[method-assign]
    return client
