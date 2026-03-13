"""Tests for investigate tools."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from cisco_umbrella_mcp.tools.investigate import (
    DomainInput,
    DomainsInput,
    PdnsInput,
    SampleInput,
    WhoisInput,
)


@pytest.fixture
def mock_ctx(mock_client):
    """Create a mock MCP Context that returns the mock_client."""
    ctx = AsyncMock()
    ctx.request_context.lifespan_context.client = mock_client
    return ctx


class TestInvestigateInputModels:
    def test_domain_input_strips_and_lowercases(self) -> None:
        inp = DomainInput(domain="  Example.COM.  ")
        assert inp.domain == "example.com"

    def test_domains_input_max_length(self) -> None:
        with pytest.raises(Exception):
            DomainsInput(domains=["a.com"] * 1001)

    def test_pdns_input_defaults(self) -> None:
        inp = PdnsInput(value="example.com")
        assert inp.limit == 20
        assert inp.offset == 0

    def test_sample_input_requires_64_chars(self) -> None:
        with pytest.raises(Exception):
            SampleInput(hash="tooshort")

    def test_whois_input_valid(self) -> None:
        inp = WhoisInput(domain="example.com")
        assert inp.domain == "example.com"
