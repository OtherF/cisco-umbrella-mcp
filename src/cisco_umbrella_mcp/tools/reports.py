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
# ---------------------------------------------------------------------------

class ActivityInput(BaseModel):
    """Common parameters for activity/event queries."""

    model_config = ConfigDict(str_strip_whitespace=True)
    from_ts: str = Field(
        ..., description="Start time — ISO 8601 datetime or epoch ms (e.g. '-1days', '2024-01-01T00:00:00Z')",
        alias="from",
    )
    to_ts: Optional[str] = Field(
        default=None, description="End time (defaults to now)", alias="to"
    )
    limit: Optional[int] = Field(default=100, ge=1, le=500)
    offset: Optional[int] = Field(default=0, ge=0)
    domains: Optional[str] = Field(default=None, description="Comma-separated domains to filter")
    ip: Optional[str] = Field(default=None, description="IP address to filter")
    verdict: Optional[str] = Field(default=None, description="Filter by verdict: 'allowed' or 'blocked'")


class ActivityTypeInput(ActivityInput):
    """Activity query for a specific type (dns, proxy, firewall, intrusion)."""

    activity_type: str = Field(
        ..., description="Activity type: 'dns', 'proxy', 'firewall', or 'intrusion'"
    )


class TimeRangeInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    from_ts: str = Field(..., description="Start time (ISO 8601 or epoch ms)", alias="from")
    to_ts: Optional[str] = Field(default=None, description="End time (defaults to now)", alias="to")
    limit: Optional[int] = Field(default=20, ge=1, le=500)
    offset: Optional[int] = Field(default=0, ge=0)


class TopReportInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    from_ts: str = Field(..., description="Start time (ISO 8601 or epoch ms, e.g. '-7days', '2024-01-01T00:00:00Z')", alias="from")
    to_ts: str = Field(..., description="End time (ISO 8601 or epoch ms, e.g. 'now', '2024-01-07T00:00:00Z')", alias="to")
    limit: Optional[int] = Field(default=10, ge=1, le=100)
    offset: Optional[int] = Field(default=0, ge=0)


class SummaryInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    from_ts: str = Field(..., description="Start time (ISO 8601 or epoch ms, e.g. '-7days', '2024-01-01T00:00:00Z')", alias="from")
    to_ts: str = Field(..., description="End time (ISO 8601 or epoch ms, e.g. 'now', '2024-01-07T00:00:00Z')", alias="to")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _time_params(model: BaseModel) -> dict:
    """Extract common time-range query params from a model."""
    p: dict = {}
    from_ts = getattr(model, "from_ts", None)
    to_ts = getattr(model, "to_ts", None)
    if from_ts:
        p["from"] = from_ts
    if to_ts:
        p["to"] = to_ts
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

    Use 'from' and optionally 'to' to set the time window. Filter by domains, IP, or verdict.
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
    """Get firewall activity events within a time range."""
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
    """Get the top destinations (domains) by request count in a time range."""
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
    """Get the top identities (users, networks, devices) by request count."""
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
    """Get the top content/security categories by request count."""
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
    """Get the top threats detected in a time range, ranked by occurrence count."""
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
    """Get the top threat type categories (malware, phishing, C2, etc.) by count."""
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
    """Get total request counts (allowed/blocked) for the organization in a time range."""
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
async def umbrella_list_identities(ctx: Context) -> str:
    """List all identities (networks, users, devices, sites) in the organization.

    Useful for mapping identity IDs in activity reports to names.
    """
    try:
        data = await _get_client(ctx).get(SCOPE, "identities")
        return json.dumps(data, indent=2)
    except Exception as e:
        return format_error(e)
