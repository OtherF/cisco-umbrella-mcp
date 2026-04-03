"""Policies tools — destination lists and application lists (read-only)."""

from __future__ import annotations

from mcp.server.fastmcp import Context
from pydantic import Field

from cisco_umbrella_mcp.client import compact_json, format_error
from cisco_umbrella_mcp.server import mcp
from cisco_umbrella_mcp.tools import ToolInput, get_client

SCOPE = "policies/v2"


# ---------------------------------------------------------------------------
# Input models
# ---------------------------------------------------------------------------


class ListPaginationInput(ToolInput):
    page: int | None = Field(default=1, description="Page number (starts at 1)", ge=1)
    limit: int | None = Field(default=25, description="Records per page (max 200)", ge=1, le=200)


class DestinationListIdInput(ToolInput):
    destination_list_id: int = Field(..., description="ID of the destination list")


class DestinationsGetInput(ToolInput):
    destination_list_id: int = Field(..., description="ID of the destination list")
    page: int | None = Field(default=1, ge=1)
    limit: int | None = Field(default=25, ge=1, le=200)


# ---------------------------------------------------------------------------
# Destination List tools (read-only)
# ---------------------------------------------------------------------------


@mcp.tool(
    name="umbrella_list_destination_lists",
    annotations={
        "title": "List Destination Lists",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_list_destination_lists(params: ListPaginationInput, ctx: Context) -> str:
    """Get all destination lists in the organization.

    Destination lists are allow/block lists of domains, IPs, and URLs used in policies.
    Returns list metadata including name, access type, and destination counts.
    """
    try:
        data = await get_client(ctx).get(SCOPE, "destinationlists", params={"page": params.page, "limit": params.limit})
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_destination_list",
    annotations={
        "title": "Get Destination List",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_destination_list(params: DestinationListIdInput, ctx: Context) -> str:
    """Get details of a specific destination list by ID."""
    try:
        data = await get_client(ctx).get(SCOPE, f"destinationlists/{params.destination_list_id}")
        return compact_json(data)
    except Exception as e:
        return format_error(e)


# ---------------------------------------------------------------------------
# Destination tools (items within a list — read-only)
# ---------------------------------------------------------------------------


@mcp.tool(
    name="umbrella_list_destinations",
    annotations={
        "title": "List Destinations in a List",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_list_destinations(params: DestinationsGetInput, ctx: Context) -> str:
    """Get all destinations (domains, IPs, URLs) in a specific destination list."""
    try:
        data = await get_client(ctx).get(
            SCOPE,
            f"destinationlists/{params.destination_list_id}/destinations",
            params={"page": params.page, "limit": params.limit},
        )
        return compact_json(data)
    except Exception as e:
        return format_error(e)


# ---------------------------------------------------------------------------
# Application List tools (read-only)
# ---------------------------------------------------------------------------


@mcp.tool(
    name="umbrella_list_application_lists",
    annotations={
        "title": "List Application Lists",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_list_application_lists(ctx: Context) -> str:
    """Get all application lists in the organization.

    Application lists group internet applications for use in Umbrella policies.
    """
    try:
        data = await get_client(ctx).get(SCOPE, "applicationLists")
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_application_usage",
    annotations={
        "title": "Get Application Usage",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_application_usage(ctx: Context) -> str:
    """Get usage statistics for applications across all application lists.

    Shows which applications from the Umbrella catalog are in use within policies.
    """
    try:
        data = await get_client(ctx).get(SCOPE, "applications/usage")
        return compact_json(data)
    except Exception as e:
        return format_error(e)
