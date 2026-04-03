"""Tests for policies tools."""

from __future__ import annotations

from cisco_umbrella_mcp.tools.policies import (
    ListPaginationInput,
)


class TestPoliciesInputModels:
    def test_pagination_defaults(self) -> None:
        inp = ListPaginationInput()
        assert inp.page == 1
        assert inp.limit == 25
