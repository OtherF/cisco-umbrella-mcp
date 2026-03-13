"""Reports tools — activity logs, aggregations, summaries, and app discovery."""

from __future__ import annotations

import json
from typing import Optional

from mcp.server.fastmcp import Context
from pydantic import BaseModel, ConfigDict, Field

from cisco_umbrella_mcp.client import UmbrellaClient, format_error
from cisco_umbrella_mcp.server import AppContext, mcp

SCOPE = "reports/v2"


def _get_client(ctx: Context) -> UmbrellaClient:
    app: AppContext = ctx.request_context.lifespan_context
    return app.client


# ---------------------------------------------------------------------------
# Input models
# NOTE: 'from' is a Python reserved keyword — fields are named from_time/to_time
#       and mapped to the API's 'from'/'to' query params in _time_params().
# ---------------------------------------------------------------------------

class ActivityInput(BaseModel):
    """Common parameters for activity/event queries."""

    model_config = ConfigDict(str_strip_whitespace=True)
    from_time: str = Field(
        ..., description="Start time — relative (e.g. '-1days', '-7days') or ISO 8601 (e.g. '2024-01-01T00:00:00Z')"
    )
    to_time: str = Field(
        default="now", description="End time — relative (e.g. 'now') or ISO 8601. Defaults to 'now'."
    )
    limit: Optional[int] = Field(default=100, ge=1, le=500)
    offset: Optional[int] = Field(default=0, ge=0)
    domains: Optional[str] = Field(default=None, description="Comma-separated domains to filter")
    ip: Optional[str] = Field(default=None, description="IP address to filter")
    verdict: Optional[str] = Field(default=None, description="Filter by verdict: 'allowed' or 'blocked'")


class TopReportInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    from_time: str = Field(
        ..., description="Start time — relative (e.g. '-7days') or ISO 8601 (e.g. '2024-01-01T00:00:00Z')"
    )
    to_time: str = Field(
        default="now", description="End time — relative (e.g. 'now') or ISO 8601. Defaults to 'now'."
    )
    limit: Optional[int] = Field(default=10, ge=1, le=100)
    offset: Optional[int] = Field(default=0, ge=0)


class SummaryInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    from_time: str = Field(
        ..., description="Start time — relative (e.g. '-7days') or ISO 8601 (e.g. '2024-01-01T00:00:00Z')"
    )
    to_time: str = Field(
        default="now", description="End time — relative (e.g. 'now') or ISO 8601. Defaults to 'now'."
    )


class IdentitiesInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    limit: Optional[int] = Field(default=100, ge=1, le=500, description="Max identities to return")
    offset: Optional[int] = Field(default=0, ge=0, description="Pagination offset")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _time_params(model: BaseModel) -> dict:
    """Map from_time/to_time field names to the API's 'from'/'to' query params."""
    p: dict = {}
    from_time = getattr(model, "from_time", None)
    to_time = getattr(model, "to_time", None)
    if from_time:
        p["from"] = from_time
    if to_time:
        p["to"] = to_time
    limit = getattr(model, "limit", None)
    offset = getattr(model, "offset", None)
    if limit is not None:
        p["limit"] = limit
    if offset is not None:
        p["offset"] = offset
    return p


def _activity_params(model: ActivityInput) -> dict:
    p = _time_params(model)
    if model.domains:
        p["domains"] = model.domains
    if model.ip:
        p["ip"] = model.ip
    if model.verdict:
        p["verdict"] = model.verdict
    return p


# ---------------------------------------------------------------------------
# Activity tools
# ---------------------------------------------------------------------------

@mcp.tool(
    name="umbrella_get_activity",
    annotations={
        "title": "Get Activity Events (All Types)",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_activity(params: ActivityInput, ctx: Context) -> str:
    """Get all activity events (DNS, proxy, firewall, intrusion) within a time range.

    Provide from_time (required) and to_time (optional, defaults to 'now').
    Filter by domains, IP, or verdict.
    """
    try:
        data = await _get_client(ctx).get(SCOPE, "activity", params=_activity_params(params))
        return json.dumps(data, indent=2)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_activity_dns",
    annotations={
        "title": "Get DNS Activity",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_activity_dns(params: ActivityInput, ctx: Context) -> str:
    """Get DNS activity events within a time range.

    Provide from_time (required) and to_time (optional, defaults to 'now').
    Shows DNS queries with domains, categories, threats, identities, and verdicts.
    """
    try:
        data = await _get_client(ctx).get(SCOPE, "activity/dns", params=_activity_params(params))
        return json.dumps(data, indent=2)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_activity_proxy",
    annotations={
        "title": "Get Proxy Activity",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_activity_proxy(params: ActivityInput, ctx: Context) -> str:
    """Get web proxy (SWG) activity events within a time range.

    Provide from_time (required) and to_time (optional, defaults to 'now').
    Shows HTTP/HTTPS requests with URLs, categories, and file information.
    """
    try:
        data = await _get_client(ctx).get(SCOPE, "activity/proxy", params=_activity_params(params))
        return json.dumps(data, indent=2)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_activity_firewall",
    annotations={
        "title": "Get Firewall Activity",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_activity_firewall(params: ActivityInput, ctx: Context) -> str:
    """Get firewall activity events within a time range.

    Provide from_time (required) and to_time (optional, defaults to 'now').
    """
    try:
        data = await _get_client(ctx).get(
            SCOPE, "activity/firewall", params=_activity_params(params)
        )
        return json.dumps(data, indent=2)
    except Exception as e:
        return format_error(e)


# ---------------------------------------------------------------------------
# Aggregation / Top-N tools
# ---------------------------------------------------------------------------

@mcp.tool(
    name="umbrella_get_top_destinations",
    annotations={
        "title": "Get Top Destinations",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_top_destinations(params: TopReportInput, ctx: Context) -> str:
    """Get the top destinations (domains) by request count in a time range.

    Provide from_time (required) and to_time (optional, defaults to 'now').
    """
    try:
        data = await _get_client(ctx).get(SCOPE, "top-destinations", params=_time_params(params))
        return json.dumps(data, indent=2)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_top_identities",
    annotations={
        "title": "Get Top Identities",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_top_identities(params: TopReportInput, ctx: Context) -> str:
    """Get the top identities (users, networks, devices) by request count.

    Provide from_time (required) and to_time (optional, defaults to 'now').
    """
    try:
        data = await _get_client(ctx).get(SCOPE, "top-identities", params=_time_params(params))
        return json.dumps(data, indent=2)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_top_categories",
    annotations={
        "title": "Get Top Categories",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_top_categories(params: TopReportInput, ctx: Context) -> str:
    """Get the top content/security categories by request count.

    Provide from_time (required) and to_time (optional, defaults to 'now').
    """
    try:
        data = await _get_client(ctx).get(SCOPE, "top-categories", params=_time_params(params))
        return json.dumps(data, indent=2)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_top_threats",
    annotations={
        "title": "Get Top Threats",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_top_threats(params: TopReportInput, ctx: Context) -> str:
    """Get the top threats detected in a time range, ranked by occurrence count.

    Provide from_time (required) and to_time (optional, defaults to 'now').
    """
    try:
        data = await _get_client(ctx).get(SCOPE, "top-threats", params=_time_params(params))
        return json.dumps(data, indent=2)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_top_threat_types",
    annotations={
        "title": "Get Top Threat Types",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_top_threat_types(params: TopReportInput, ctx: Context) -> str:
    """Get the top threat type categories (malware, phishing, C2, etc.) by count.

    Provide from_time (required) and to_time (optional, defaults to 'now').
    """
    try:
        data = await _get_client(ctx).get(SCOPE, "top-threat-types", params=_time_params(params))
        return json.dumps(data, indent=2)
    except Exception as e:
        return format_error(e)


# ---------------------------------------------------------------------------
# Summary tools
# ---------------------------------------------------------------------------

@mcp.tool(
    name="umbrella_get_summary",
    annotations={
        "title": "Get Security Summary",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_summary(params: SummaryInput, ctx: Context) -> str:
    """Get an overall security summary for the organization in a time range.

    Provide from_time (required) and to_time (optional, defaults to 'now').
    Returns total requests, blocked requests, threat counts, and breakdowns.
    """
    try:
        data = await _get_client(ctx).get(SCOPE, "summary", params=_time_params(params))
        return json.dumps(data, indent=2)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_total_requests",
    annotations={
        "title": "Get Total Requests",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_total_requests(params: SummaryInput, ctx: Context) -> str:
    """Get total request counts (allowed/blocked) for the organization in a time range.

    Provide from_time (required) and to_time (optional, defaults to 'now').
    """
    try:
        data = await _get_client(ctx).get(SCOPE, "total-requests", params=_time_params(params))
        return json.dumps(data, indent=2)
    except Exception as e:
        return format_error(e)


# ---------------------------------------------------------------------------
# Utility tools
# ---------------------------------------------------------------------------

@mcp.tool(
    name="umbrella_list_categories",
    annotations={
        "title": "List Security/Content Categories",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_list_categories(ctx: Context) -> str:
    """List all Umbrella security and content categories with their IDs and labels.

    Useful for interpreting category IDs returned by other tools.
    """
    try:
        data = await _get_client(ctx).get(SCOPE, "categories")
        return json.dumps(data, indent=2)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_list_identities",
    annotations={
        "title": "List Identities",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_list_identities(params: IdentitiesInput, ctx: Context) -> str:
    """List all identities (networks, users, devices, sites) in the organization.

    Useful for mapping identity IDs in activity reports to names.
    Requires limit and offset parameters (defaults: limit=100, offset=0).
    """
    try:
        data = await _get_client(ctx).get(
            SCOPE, "identities", params={"limit": params.limit, "offset": params.offset}
        )
        return json.dumps(data, indent=2)
    except Exception as e:
        return format_error(e)
