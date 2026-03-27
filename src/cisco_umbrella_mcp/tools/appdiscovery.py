"""App Discovery tools — cloud application usage and risk reporting."""

from __future__ import annotations

from typing import Optional

from mcp.server.fastmcp import Context
from pydantic import BaseModel, ConfigDict, Field

from cisco_umbrella_mcp.client import UmbrellaClient, compact_json, format_error
from cisco_umbrella_mcp.server import AppContext, mcp

SCOPE = "reports/v2"


def _get_client(ctx: Context) -> UmbrellaClient:
    app: AppContext = ctx.request_context.lifespan_context
    return app.client


# ---------------------------------------------------------------------------
# Input models
# ---------------------------------------------------------------------------


class AppDiscoveryInput(BaseModel):
    """Common time-range and pagination parameters for App Discovery queries."""

    model_config = ConfigDict(str_strip_whitespace=True)
    from_time: str = Field(
        ..., description="Start time — relative (e.g. '-30days') or ISO 8601 (e.g. '2024-01-01T00:00:00Z')"
    )
    to_time: str = Field(
        default="now", description="End time — relative (e.g. 'now') or ISO 8601. Defaults to 'now'."
    )
    limit: Optional[int] = Field(default=25, ge=1, le=500)
    offset: Optional[int] = Field(default=0, ge=0)


class AppIdInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    application_id: int = Field(..., description="Umbrella application ID")


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
        data = await _get_client(ctx).get(SCOPE, "appDiscovery/applications", params=query)
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
        data = await _get_client(ctx).get(SCOPE, "appDiscovery/applications/info", params=query)
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
        data = await _get_client(ctx).get(
            SCOPE, f"appDiscovery/applications/{params.application_id}/attributes"
        )
        return compact_json(data)
    except Exception as e:
        return format_error(e)
