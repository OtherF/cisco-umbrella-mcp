"""App Discovery tools — cloud application usage and risk reporting."""

from __future__ import annotations

from mcp.server.fastmcp import Context
from pydantic import Field

from cisco_umbrella_mcp.client import compact_json, format_error
from cisco_umbrella_mcp.server import mcp
from cisco_umbrella_mcp.tools import ToolInput, get_client

SCOPE = "reports/v2"


# ---------------------------------------------------------------------------
# Input models
# ---------------------------------------------------------------------------


class AppDiscoveryInput(ToolInput):
    """Common time-range and pagination parameters for App Discovery queries."""

    from_time: str = Field(
        ..., description="Start time — relative (e.g. '-30days') or ISO 8601 (e.g. '2024-01-01T00:00:00Z')"
    )
    to_time: str = Field(default="now", description="End time — relative (e.g. 'now') or ISO 8601. Defaults to 'now'.")
    limit: int | None = Field(default=25, ge=1, le=500)
    offset: int | None = Field(default=0, ge=0)


class AppIdInput(ToolInput):
    application_id: int = Field(..., description="Umbrella application ID")


class AppIdentitiesInput(ToolInput):
    application_id: int = Field(..., description="Umbrella application ID")
    from_time: str = Field(..., description="Start time — relative (e.g. '-30days') or ISO 8601")
    to_time: str = Field(default="now", description="End time")
    limit: int | None = Field(default=25, ge=1, le=500)
    offset: int | None = Field(default=0, ge=0)


class ProtocolIdInput(ToolInput):
    protocol_id: int = Field(..., description="Protocol ID")


class ProtocolIdentitiesInput(ToolInput):
    protocol_id: int = Field(..., description="Protocol ID")
    from_time: str = Field(..., description="Start time — relative (e.g. '-30days') or ISO 8601")
    to_time: str = Field(default="now", description="End time")
    limit: int | None = Field(default=25, ge=1, le=500)
    offset: int | None = Field(default=0, ge=0)


# ---------------------------------------------------------------------------
# App Discovery tools
# ---------------------------------------------------------------------------


@mcp.tool(
    name="umbrella_get_app_discovery_applications",
    annotations={
        "title": "Get App Discovery — Applications",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_app_discovery_applications(params: AppDiscoveryInput, ctx: Context) -> str:
    """List cloud applications discovered in network traffic during a time range.

    Returns applications with traffic volume, risk score, category, and user counts.
    Sortable by lastDetected, name, or weightedRisk.
    """
    try:
        query = {
            "from": params.from_time,
            "to": params.to_time,
            "limit": params.limit,
            "offset": params.offset,
        }
        data = await get_client(ctx).get(SCOPE, "appDiscovery/applications", params=query)
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_app_discovery_application_info",
    annotations={
        "title": "Get App Discovery — Application Info",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_app_discovery_application_info(params: AppDiscoveryInput, ctx: Context) -> str:
    """Get enriched information for discovered cloud applications in a time range.

    Returns application metadata including vendor details, risk factors, and policy compliance.
    Added March 2025.
    """
    try:
        query = {
            "from": params.from_time,
            "to": params.to_time,
            "limit": params.limit,
            "offset": params.offset,
        }
        data = await get_client(ctx).get(SCOPE, "appDiscovery/applications/info", params=query)
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_app_discovery_application_attributes",
    annotations={
        "title": "Get App Discovery — Application Attributes",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_app_discovery_application_attributes(params: AppIdInput, ctx: Context) -> str:
    """Get detailed security and compliance attributes for a specific application.

    Returns risk factors, data handling policies, certifications, and compliance details.
    Added November 2023.
    """
    try:
        data = await get_client(ctx).get(SCOPE, f"appDiscovery/applications/{params.application_id}/attributes")
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_list_app_categories",
    annotations={
        "title": "List App Discovery — Application Categories",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_list_app_categories(ctx: Context) -> str:
    """List all application categories used in App Discovery classification."""
    try:
        data = await get_client(ctx).get(SCOPE, "appDiscovery/applicationCategories")
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_app_discovery_application",
    annotations={
        "title": "Get App Discovery — Application by ID",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_app_discovery_application(params: AppIdInput, ctx: Context) -> str:
    """Get detailed information about a specific discovered application by ID."""
    try:
        data = await get_client(ctx).get(SCOPE, f"appDiscovery/applications/{params.application_id}")
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_app_discovery_identities",
    annotations={
        "title": "Get App Discovery — Application Identities",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_app_discovery_identities(params: AppIdentitiesInput, ctx: Context) -> str:
    """Get identities (users, devices) accessing a specific discovered application."""
    try:
        query = {
            "from": params.from_time,
            "to": params.to_time,
            "limit": params.limit,
            "offset": params.offset,
        }
        data = await get_client(ctx).get(
            SCOPE, f"appDiscovery/applications/{params.application_id}/identities", params=query
        )
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_app_discovery_risk",
    annotations={
        "title": "Get App Discovery — Application Risk",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_app_discovery_risk(params: AppIdInput, ctx: Context) -> str:
    """Get risk assessment details for a specific discovered application."""
    try:
        data = await get_client(ctx).get(SCOPE, f"appDiscovery/applications/{params.application_id}/risk")
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_list_app_discovery_protocols",
    annotations={
        "title": "List App Discovery — Protocols",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_list_app_discovery_protocols(params: AppDiscoveryInput, ctx: Context) -> str:
    """List network protocols discovered in traffic during a time range."""
    try:
        query = {
            "from": params.from_time,
            "to": params.to_time,
            "limit": params.limit,
            "offset": params.offset,
        }
        data = await get_client(ctx).get(SCOPE, "appDiscovery/protocols", params=query)
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_app_discovery_protocol",
    annotations={
        "title": "Get App Discovery — Protocol by ID",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_app_discovery_protocol(params: ProtocolIdInput, ctx: Context) -> str:
    """Get details of a specific network protocol by ID."""
    try:
        data = await get_client(ctx).get(SCOPE, f"appDiscovery/protocols/{params.protocol_id}")
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_app_discovery_protocol_identities",
    annotations={
        "title": "Get App Discovery — Protocol Identities",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_app_discovery_protocol_identities(params: ProtocolIdentitiesInput, ctx: Context) -> str:
    """Get identities using a specific network protocol."""
    try:
        query = {
            "from": params.from_time,
            "to": params.to_time,
            "limit": params.limit,
            "offset": params.offset,
        }
        data = await get_client(ctx).get(SCOPE, f"appDiscovery/protocols/{params.protocol_id}/identities", params=query)
        return compact_json(data)
    except Exception as e:
        return format_error(e)
