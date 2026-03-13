"""Tests for policies tools."""

from __future__ import annotations

import pytest

from cisco_umbrella_mcp.tools.policies import (
    DestinationListCreateInput,
    DestinationsAddInput,
    ListPaginationInput,
)


class TestPoliciesInputModels:
    def test_pagination_defaults(self) -> None:
        inp = ListPaginationInput()
        assert inp.page == 1
        assert inp.limit == 100

    def test_create_destination_list_requires_name(self) -> None:
        with pytest.raises(Exception):
            DestinationListCreateInput(name="", access="allow")

    def test_create_destination_list_valid(self) -> None:
        inp = DestinationListCreateInput(name="My Block List", access="block")
        assert inp.name == "My Block List"
        assert inp.access == "block"
        assert inp.is_global is False

    def test_add_destinations_max_500(self) -> None:
        with pytest.raises(Exception):
            DestinationsAddInput(
                destination_list_id=1,
                destinations=["d.com"] * 501,
            )

    def test_add_destinations_valid(self) -> None:
        inp = DestinationsAddInput(
            destination_list_id=123,
            destinations=["evil.com", "10.0.0.1"],
            comment="Blocked by policy",
        )
        assert len(inp.destinations) == 2
        assert inp.comment == "Blocked by policy"
