"""Reports tools — activity logs, aggregations, summaries, and app discovery."""

from __future__ import annotations

from mcp.server.fastmcp import Context
from pydantic import Field, field_validator

from cisco_umbrella_mcp.client import compact_json, format_error
from cisco_umbrella_mcp.server import mcp
from cisco_umbrella_mcp.tools import ToolInput, get_client

SCOPE = "reports/v2"


# ---------------------------------------------------------------------------
# Input models
# NOTE: 'from' is a Python reserved keyword — fields are named from_time/to_time
#       and mapped to the API's 'from'/'to' query params in _time_params().
# ---------------------------------------------------------------------------


class ActivityInput(ToolInput):
    """Common parameters for activity/event queries."""

    from_time: str = Field(
        ..., description="Start time — relative (e.g. '-1days', '-7days') or ISO 8601 (e.g. '2024-01-01T00:00:00Z')"
    )
    to_time: str = Field(default="now", description="End time — relative (e.g. 'now') or ISO 8601. Defaults to 'now'.")
    limit: int | None = Field(default=25, ge=1, le=500)
    offset: int | None = Field(default=0, ge=0)
    domains: str | None = Field(default=None, description="Comma-separated domains to filter")
    ip: str | None = Field(default=None, description="IP address to filter")
    verdict: str | None = Field(default=None, description="Filter by verdict: 'allowed' or 'blocked'")

    @field_validator("verdict")
    @classmethod
    def validate_verdict(cls, v: str | None) -> str | None:
        if v is not None and v not in ("allowed", "blocked"):
            raise ValueError("verdict must be 'allowed' or 'blocked'")
        return v


class TopReportInput(ToolInput):
    from_time: str = Field(
        ..., description="Start time — relative (e.g. '-7days') or ISO 8601 (e.g. '2024-01-01T00:00:00Z')"
    )
    to_time: str = Field(default="now", description="End time — relative (e.g. 'now') or ISO 8601. Defaults to 'now'.")
    limit: int | None = Field(default=10, ge=1, le=100)
    offset: int | None = Field(default=0, ge=0)


class SummaryInput(ToolInput):
    from_time: str = Field(
        ..., description="Start time — relative (e.g. '-7days') or ISO 8601 (e.g. '2024-01-01T00:00:00Z')"
    )
    to_time: str = Field(default="now", description="End time — relative (e.g. 'now') or ISO 8601. Defaults to 'now'.")


class IdentitiesInput(ToolInput):
    limit: int | None = Field(default=25, ge=1, le=500, description="Max identities to return")
    offset: int | None = Field(default=0, ge=0, description="Pagination offset")


class ApiUsageInput(ToolInput):
    from_time: str = Field(
        ..., description="Start time — relative (e.g. '-7days') or ISO 8601 (e.g. '2024-01-01T00:00:00Z')"
    )
    to_time: str = Field(default="now", description="End time — relative (e.g. 'now') or ISO 8601. Defaults to 'now'.")
    limit: int | None = Field(default=25, ge=1, le=500)
    offset: int | None = Field(default=0, ge=0)


class TypedTopReportInput(ToolInput):
    report_type: str = Field(..., description="Report type: 'dns', 'proxy', 'firewall', or 'ip'")
    from_time: str = Field(..., description="Start time — relative (e.g. '-7days') or ISO 8601")
    to_time: str = Field(default="now", description="End time")
    limit: int | None = Field(default=10, ge=1, le=100)
    offset: int | None = Field(default=0, ge=0)

    @field_validator("report_type")
    @classmethod
    def validate_report_type(cls, v: str) -> str:
        allowed = {"dns", "proxy", "firewall", "ip"}
        if v not in allowed:
            raise ValueError(f"report_type must be one of {allowed}")
        return v


class TypedSummaryInput(ToolInput):
    report_type: str = Field(..., description="Report type: 'dns', 'proxy', 'firewall', or 'ip'")
    from_time: str = Field(..., description="Start time — relative (e.g. '-7days') or ISO 8601")
    to_time: str = Field(default="now", description="End time")

    @field_validator("report_type")
    @classmethod
    def validate_report_type(cls, v: str) -> str:
        allowed = {"dns", "proxy", "firewall", "ip"}
        if v not in allowed:
            raise ValueError(f"report_type must be one of {allowed}")
        return v


class ProviderReportInput(ToolInput):
    from_time: str = Field(..., description="Start time — relative (e.g. '-7days') or ISO 8601")
    to_time: str = Field(default="now", description="End time")
    limit: int | None = Field(default=25, ge=1, le=500)
    offset: int | None = Field(default=0, ge=0)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _time_params(model: ToolInput) -> dict:
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
        data = await get_client(ctx).get(SCOPE, "activity", params=_activity_params(params))
        return compact_json(data)
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
        data = await get_client(ctx).get(SCOPE, "activity/dns", params=_activity_params(params))
        return compact_json(data)
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
        data = await get_client(ctx).get(SCOPE, "activity/proxy", params=_activity_params(params))
        return compact_json(data)
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
        data = await get_client(ctx).get(SCOPE, "activity/firewall", params=_activity_params(params))
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_activity_intrusion",
    annotations={
        "title": "Get Intrusion Activity",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_activity_intrusion(params: ActivityInput, ctx: Context) -> str:
    """Get IPS/intrusion detection activity events within a time range.

    Provide from_time (required) and to_time (optional, defaults to 'now').
    Shows intrusion prevention system (IPS) events with threat details.
    """
    try:
        data = await get_client(ctx).get(SCOPE, "activity/intrusion", params=_activity_params(params))
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_activity_amp",
    annotations={
        "title": "Get AMP Retrospective Activity",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_activity_amp(params: ActivityInput, ctx: Context) -> str:
    """Get AMP (Advanced Malware Protection) retrospective activity events.

    AMP retrospective events occur when a file initially classified as benign is
    later reclassified as malicious. Provide from_time (required).
    """
    try:
        data = await get_client(ctx).get(SCOPE, "activity/amp-retrospective", params=_activity_params(params))
        return compact_json(data)
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
        data = await get_client(ctx).get(SCOPE, "top-destinations", params=_time_params(params))
        return compact_json(data)
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
        data = await get_client(ctx).get(SCOPE, "top-identities", params=_time_params(params))
        return compact_json(data)
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
        data = await get_client(ctx).get(SCOPE, "top-categories", params=_time_params(params))
        return compact_json(data)
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
        data = await get_client(ctx).get(SCOPE, "top-threats", params=_time_params(params))
        return compact_json(data)
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
        data = await get_client(ctx).get(SCOPE, "top-threat-types", params=_time_params(params))
        return compact_json(data)
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
        data = await get_client(ctx).get(SCOPE, "summary", params=_time_params(params))
        return compact_json(data)
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
        data = await get_client(ctx).get(SCOPE, "total-requests", params=_time_params(params))
        return compact_json(data)
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
        data = await get_client(ctx).get(SCOPE, "categories")
        return compact_json(data)
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
        data = await get_client(ctx).get(SCOPE, "identities", params={"limit": params.limit, "offset": params.offset})
        return compact_json(data)
    except Exception as e:
        return format_error(e)


# ---------------------------------------------------------------------------
# API Usage tools
# ---------------------------------------------------------------------------


@mcp.tool(
    name="umbrella_get_api_usage_requests",
    annotations={
        "title": "Get API Usage — Requests",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_api_usage_requests(params: ApiUsageInput, ctx: Context) -> str:
    """Get API request counts by endpoint for the organization in a time range.

    Provides visibility into how the Umbrella API is being used — which endpoints
    are called and how frequently. Added January 2024.
    """
    try:
        data = await get_client(ctx).get(SCOPE, "apiUsage/requests", params=_time_params(params))
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_api_usage_responses",
    annotations={
        "title": "Get API Usage — Responses",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_api_usage_responses(params: ApiUsageInput, ctx: Context) -> str:
    """Get API response code distribution (2xx, 4xx, 5xx) for the organization in a time range.

    Helps identify API errors, rate limiting (429), and auth failures (401/403). Added January 2024.
    """
    try:
        data = await get_client(ctx).get(SCOPE, "apiUsage/responses", params=_time_params(params))
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_api_usage_by_key",
    annotations={
        "title": "Get API Usage — By Key",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_api_usage_by_key(params: ApiUsageInput, ctx: Context) -> str:
    """Get API request counts broken down per API key in a time range.

    Useful for auditing which API keys are active and how heavily used. Added January 2024.
    """
    try:
        data = await get_client(ctx).get(SCOPE, "apiUsage/keys", params=_time_params(params))
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_api_usage_summary",
    annotations={
        "title": "Get API Usage — Summary",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_api_usage_summary(params: ApiUsageInput, ctx: Context) -> str:
    """Get a high-level summary of API usage (total requests, errors, top keys) in a time range.

    Added January 2024.
    """
    try:
        data = await get_client(ctx).get(SCOPE, "apiUsage/summary", params=_time_params(params))
        return compact_json(data)
    except Exception as e:
        return format_error(e)


# ---------------------------------------------------------------------------
# Organization Requests tools (time-series request volume)
# ---------------------------------------------------------------------------


@mcp.tool(
    name="umbrella_get_requests_by_hour",
    annotations={
        "title": "Get Requests by Hour",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_requests_by_hour(params: SummaryInput, ctx: Context) -> str:
    """Get request volume bucketed by hour for the organization in a time range.

    Returns hourly time-series data for allowed and blocked requests.
    """
    try:
        data = await get_client(ctx).get(SCOPE, "organizations/requests/hour", params=_time_params(params))
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_requests_by_timerange",
    annotations={
        "title": "Get Requests by Time Range",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_requests_by_timerange(params: SummaryInput, ctx: Context) -> str:
    """Get aggregate request counts for the organization in a time range.

    Returns a single summary of allowed/blocked request totals for the period.
    """
    try:
        data = await get_client(ctx).get(SCOPE, "organizations/requests/timerange", params=_time_params(params))
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_requests_by_hour_and_category",
    annotations={
        "title": "Get Requests by Hour and Category",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_requests_by_hour_and_category(params: SummaryInput, ctx: Context) -> str:
    """Get hourly request volume broken down by content/security category.

    Returns time-series data showing request counts per category per hour.
    """
    try:
        data = await get_client(ctx).get(SCOPE, "organizations/requests/hour/categories", params=_time_params(params))
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_requests_by_timerange_and_category",
    annotations={
        "title": "Get Requests by Time Range and Category",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_requests_by_timerange_and_category(params: SummaryInput, ctx: Context) -> str:
    """Get aggregate request counts per category for the organization in a time range.

    Returns category-level totals for allowed/blocked requests over the period.
    """
    try:
        data = await get_client(ctx).get(
            SCOPE, "organizations/requests/timerange/categories", params=_time_params(params)
        )
        return compact_json(data)
    except Exception as e:
        return format_error(e)


# ---------------------------------------------------------------------------
# Bandwidth tools
# ---------------------------------------------------------------------------


@mcp.tool(
    name="umbrella_get_bandwidth_by_hour",
    annotations={
        "title": "Get Bandwidth by Hour",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_bandwidth_by_hour(params: SummaryInput, ctx: Context) -> str:
    """Get proxy bandwidth usage bucketed by hour for the organization.

    Returns hourly time-series data for bytes sent/received through the SWG proxy.
    """
    try:
        data = await get_client(ctx).get(SCOPE, "organizations/bandwidth/hour", params=_time_params(params))
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_bandwidth_by_timerange",
    annotations={
        "title": "Get Bandwidth by Time Range",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_bandwidth_by_timerange(params: SummaryInput, ctx: Context) -> str:
    """Get aggregate proxy bandwidth usage (bytes in/out) for the organization in a time range."""
    try:
        data = await get_client(ctx).get(SCOPE, "organizations/bandwidth/timerange", params=_time_params(params))
        return compact_json(data)
    except Exception as e:
        return format_error(e)


# ---------------------------------------------------------------------------
# Activity/IP endpoint
# ---------------------------------------------------------------------------


@mcp.tool(
    name="umbrella_get_activity_ip",
    annotations={
        "title": "Get IP Activity",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_activity_ip(params: ActivityInput, ctx: Context) -> str:
    """Get IP-layer activity events within a time range."""
    try:
        data = await get_client(ctx).get(SCOPE, "activity/ip", params=_activity_params(params))
        return compact_json(data)
    except Exception as e:
        return format_error(e)


# ---------------------------------------------------------------------------
# Typed Top-N endpoints (type path parameter)
# ---------------------------------------------------------------------------


@mcp.tool(
    name="umbrella_get_top_destinations_by_type",
    annotations={
        "title": "Get Top Destinations by Type",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_top_destinations_by_type(params: TypedTopReportInput, ctx: Context) -> str:
    """Get top destinations filtered by traffic type (dns, proxy, firewall, ip)."""
    try:
        data = await get_client(ctx).get(SCOPE, f"top-destinations/{params.report_type}", params=_time_params(params))
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_top_identities_by_type",
    annotations={
        "title": "Get Top Identities by Type",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_top_identities_by_type(params: TypedTopReportInput, ctx: Context) -> str:
    """Get top identities filtered by traffic type."""
    try:
        data = await get_client(ctx).get(SCOPE, f"top-identities/{params.report_type}", params=_time_params(params))
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_top_categories_by_type",
    annotations={
        "title": "Get Top Categories by Type",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_top_categories_by_type(params: TypedTopReportInput, ctx: Context) -> str:
    """Get top categories filtered by traffic type."""
    try:
        data = await get_client(ctx).get(SCOPE, f"top-categories/{params.report_type}", params=_time_params(params))
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_top_threats_by_type",
    annotations={
        "title": "Get Top Threats by Type",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_top_threats_by_type(params: TypedTopReportInput, ctx: Context) -> str:
    """Get top threats filtered by traffic type."""
    try:
        data = await get_client(ctx).get(SCOPE, f"top-threats/{params.report_type}", params=_time_params(params))
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_top_threat_types_by_type",
    annotations={
        "title": "Get Top Threat Types by Type",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_top_threat_types_by_type(params: TypedTopReportInput, ctx: Context) -> str:
    """Get top threat type categories filtered by traffic type."""
    try:
        data = await get_client(ctx).get(SCOPE, f"top-threat-types/{params.report_type}", params=_time_params(params))
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_summary_by_type",
    annotations={
        "title": "Get Security Summary by Type",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_summary_by_type(params: TypedSummaryInput, ctx: Context) -> str:
    """Get security summary filtered by traffic type."""
    try:
        data = await get_client(ctx).get(SCOPE, f"summary/{params.report_type}", params=_time_params(params))
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_total_requests_by_type",
    annotations={
        "title": "Get Total Requests by Type",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_total_requests_by_type(params: TypedSummaryInput, ctx: Context) -> str:
    """Get total request counts filtered by traffic type."""
    try:
        data = await get_client(ctx).get(SCOPE, f"total-requests/{params.report_type}", params=_time_params(params))
        return compact_json(data)
    except Exception as e:
        return format_error(e)


# ---------------------------------------------------------------------------
# Additional Top-N endpoints
# ---------------------------------------------------------------------------


@mcp.tool(
    name="umbrella_get_top_urls",
    annotations={
        "title": "Get Top URLs",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_top_urls(params: TopReportInput, ctx: Context) -> str:
    """Get top URLs by request count in a time range."""
    try:
        data = await get_client(ctx).get(SCOPE, "top-urls", params=_time_params(params))
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_top_ips",
    annotations={
        "title": "Get Top External IPs",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_top_ips(params: TopReportInput, ctx: Context) -> str:
    """Get top external IPs by request count in a time range."""
    try:
        data = await get_client(ctx).get(SCOPE, "top-ips", params=_time_params(params))
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_top_internal_ips",
    annotations={
        "title": "Get Top Internal IPs",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_top_internal_ips(params: TopReportInput, ctx: Context) -> str:
    """Get top internal IPs by request count in a time range."""
    try:
        data = await get_client(ctx).get(SCOPE, "top-ips/internal", params=_time_params(params))
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_top_files",
    annotations={
        "title": "Get Top Files",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_top_files(params: TopReportInput, ctx: Context) -> str:
    """Get top files by transfer count in a time range."""
    try:
        data = await get_client(ctx).get(SCOPE, "top-files", params=_time_params(params))
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_top_event_types",
    annotations={
        "title": "Get Top Event Types",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_top_event_types(params: TopReportInput, ctx: Context) -> str:
    """Get top event types by occurrence count in a time range."""
    try:
        data = await get_client(ctx).get(SCOPE, "top-eventtypes", params=_time_params(params))
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_top_dns_query_types",
    annotations={
        "title": "Get Top DNS Query Types",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_top_dns_query_types(params: TopReportInput, ctx: Context) -> str:
    """Get top DNS query types (A, AAAA, MX, etc.) by count."""
    try:
        data = await get_client(ctx).get(SCOPE, "top-dns-query-types", params=_time_params(params))
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_identity_distribution",
    annotations={
        "title": "Get Identity Distribution",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_identity_distribution(params: SummaryInput, ctx: Context) -> str:
    """Get request distribution across identity types in a time range."""
    try:
        data = await get_client(ctx).get(SCOPE, "identity-distribution", params=_time_params(params))
        return compact_json(data)
    except Exception as e:
        return format_error(e)


# ---------------------------------------------------------------------------
# MSP/Provider endpoints
# ---------------------------------------------------------------------------


@mcp.tool(
    name="umbrella_get_provider_categories",
    annotations={
        "title": "Get Provider Categories",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_provider_categories(params: ProviderReportInput, ctx: Context) -> str:
    """Get category breakdown across managed organizations (MSP/provider)."""
    try:
        data = await get_client(ctx).get(SCOPE, "providers/categories", params=_time_params(params))
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_provider_deployments",
    annotations={
        "title": "Get Provider Deployments",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_provider_deployments(params: ProviderReportInput, ctx: Context) -> str:
    """Get deployment statistics across managed organizations."""
    try:
        data = await get_client(ctx).get(SCOPE, "providers/deployments", params=_time_params(params))
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_provider_requests_by_org",
    annotations={
        "title": "Get Provider Requests by Org",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_provider_requests_by_org(params: ProviderReportInput, ctx: Context) -> str:
    """Get request counts per managed organization."""
    try:
        data = await get_client(ctx).get(SCOPE, "providers/requests-by-org", params=_time_params(params))
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_provider_requests_by_hour",
    annotations={
        "title": "Get Provider Requests by Hour",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_provider_requests_by_hour(params: SummaryInput, ctx: Context) -> str:
    """Get hourly request volume across managed organizations."""
    try:
        data = await get_client(ctx).get(SCOPE, "providers/requests-by-hour", params=_time_params(params))
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_provider_requests_by_timerange",
    annotations={
        "title": "Get Provider Requests by Time Range",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_provider_requests_by_timerange(params: SummaryInput, ctx: Context) -> str:
    """Get aggregate request counts across managed organizations."""
    try:
        data = await get_client(ctx).get(SCOPE, "providers/requests-by-timerange", params=_time_params(params))
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_provider_requests_by_category",
    annotations={
        "title": "Get Provider Requests by Category",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_provider_requests_by_category(params: ProviderReportInput, ctx: Context) -> str:
    """Get request counts by category across managed organizations."""
    try:
        data = await get_client(ctx).get(SCOPE, "providers/requests-by-category", params=_time_params(params))
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_provider_requests_by_destination",
    annotations={
        "title": "Get Provider Requests by Destination",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_provider_requests_by_destination(params: ProviderReportInput, ctx: Context) -> str:
    """Get request counts by destination across managed organizations."""
    try:
        data = await get_client(ctx).get(SCOPE, "providers/requests-by-destination", params=_time_params(params))
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_provider_category_requests_by_org",
    annotations={
        "title": "Get Provider Category Requests by Org",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_provider_category_requests_by_org(params: ProviderReportInput, ctx: Context) -> str:
    """Get per-category request counts per managed organization."""
    try:
        data = await get_client(ctx).get(SCOPE, "providers/category-requests-by-org", params=_time_params(params))
        return compact_json(data)
    except Exception as e:
        return format_error(e)
