"""Reports tools — activity logs, top-N aggregations, summaries, and provider/MSP reports."""

from __future__ import annotations

from urllib.parse import quote

from mcp.server.fastmcp import Context
from pydantic import Field, field_validator, model_validator

from cisco_umbrella_mcp.client import compact_json, format_error
from cisco_umbrella_mcp.server import mcp
from cisco_umbrella_mcp.tools import ToolInput, get_client

SCOPE = "reports/v2"


# ---------------------------------------------------------------------------
# Endpoint maps
# ---------------------------------------------------------------------------

_ACTIVITY_ENDPOINTS: dict[str, str] = {
    "all": "activity",
    "dns": "activity/dns",
    "proxy": "activity/proxy",
    "firewall": "activity/firewall",
    "intrusion": "activity/intrusion",
    "amp": "activity/amp-retrospective",
    "ip": "activity/ip",
}

# Top-N reports that support an optional traffic_type filter
_TOP_TYPED_ENDPOINTS: dict[str, str] = {
    "destinations": "top-destinations",
    "identities": "top-identities",
    "categories": "top-categories",
    "threats": "top-threats",
    "threat_types": "top-threat-types",
}

# Top-N reports that do NOT support traffic_type
_TOP_SIMPLE_ENDPOINTS: dict[str, str] = {
    "urls": "top-urls",
    "ips": "top-ips",
    "internal_ips": "top-ips/internal",
    "files": "top-files",
    "event_types": "top-eventtypes",
    "dns_query_types": "top-dns-query-types",
}

_ALL_TOP_METRICS = {**_TOP_TYPED_ENDPOINTS, **_TOP_SIMPLE_ENDPOINTS}

_SUMMARY_REPORTS: dict[str, str] = {
    "summary": "summary",
    "total_requests": "total-requests",
}

_TRAFFIC_TYPES = {"dns", "proxy", "firewall", "ip"}

_API_USAGE_ENDPOINTS: dict[str, str] = {
    "requests": "apiUsage/requests",
    "responses": "apiUsage/responses",
    "keys": "apiUsage/keys",
    "summary": "apiUsage/summary",
}

_PROVIDER_ENDPOINTS: dict[str, str] = {
    "categories": "providers/categories",
    "deployments": "providers/deployments",
    "requests_by_org": "providers/requests-by-org",
    "requests_by_hour": "providers/requests-by-hour",
    "requests_by_timerange": "providers/requests-by-timerange",
    "requests_by_category": "providers/requests-by-category",
    "requests_by_destination": "providers/requests-by-destination",
    "category_requests_by_org": "providers/category-requests-by-org",
}


# ---------------------------------------------------------------------------
# Input models
# NOTE: 'from' is a Python reserved keyword — fields are named from_time/to_time
#       and mapped to the API's 'from'/'to' query params in _time_params().
# ---------------------------------------------------------------------------


class ActivityInput(ToolInput):
    """Parameters for activity/event queries."""

    activity_type: str = Field(
        default="all",
        description=(
            "Activity type. Valid values: 'all', 'dns', 'proxy', 'firewall', "
            "'intrusion', 'amp', 'ip'."
        ),
    )
    from_time: str = Field(
        ..., description="Start time — relative (e.g. '-1days', '-7days') or ISO 8601 (e.g. '2024-01-01T00:00:00Z')"
    )
    to_time: str = Field(default="now", description="End time — relative (e.g. 'now') or ISO 8601. Defaults to 'now'.")
    limit: int | None = Field(default=25, ge=1, le=500)
    offset: int | None = Field(default=0, ge=0)
    domains: str | None = Field(default=None, description="Comma-separated domains to filter")
    ip: str | None = Field(default=None, description="IP address to filter")
    verdict: str | None = Field(default=None, description="Filter by verdict: 'allowed' or 'blocked'")

    @field_validator("activity_type")
    @classmethod
    def validate_activity_type(cls, v: str) -> str:
        if v not in _ACTIVITY_ENDPOINTS:
            allowed = ", ".join(sorted(_ACTIVITY_ENDPOINTS))
            raise ValueError(f"activity_type must be one of: {allowed}")
        return v

    @field_validator("verdict")
    @classmethod
    def validate_verdict(cls, v: str | None) -> str | None:
        if v is not None and v not in ("allowed", "blocked"):
            raise ValueError("verdict must be 'allowed' or 'blocked'")
        return v


class TopReportInput(ToolInput):
    """Parameters for top-N aggregation reports."""

    metric: str = Field(
        ...,
        description=(
            "Which top-N metric to retrieve. Valid values: "
            "'destinations', 'identities', 'categories', 'threats', 'threat_types', "
            "'urls', 'ips', 'internal_ips', 'files', 'event_types', 'dns_query_types'."
        ),
    )
    traffic_type: str | None = Field(
        default=None,
        description=(
            "Optional traffic type filter. Valid values: 'dns', 'proxy', 'firewall', 'ip'. "
            "Only supported for metrics: destinations, identities, categories, threats, threat_types. "
            "Omit for an overall (all-traffic) result."
        ),
    )
    from_time: str = Field(
        ..., description="Start time — relative (e.g. '-7days') or ISO 8601 (e.g. '2024-01-01T00:00:00Z')"
    )
    to_time: str = Field(default="now", description="End time — relative (e.g. 'now') or ISO 8601. Defaults to 'now'.")
    limit: int | None = Field(default=10, ge=1, le=100)
    offset: int | None = Field(default=0, ge=0)

    @field_validator("metric")
    @classmethod
    def validate_metric(cls, v: str) -> str:
        if v not in _ALL_TOP_METRICS:
            allowed = ", ".join(sorted(_ALL_TOP_METRICS))
            raise ValueError(f"metric must be one of: {allowed}")
        return v

    @field_validator("traffic_type")
    @classmethod
    def validate_traffic_type(cls, v: str | None) -> str | None:
        if v is not None and v not in _TRAFFIC_TYPES:
            allowed = ", ".join(sorted(_TRAFFIC_TYPES))
            raise ValueError(f"traffic_type must be one of: {allowed}")
        return v

    @model_validator(mode="after")
    def validate_traffic_type_combination(self) -> TopReportInput:
        if self.traffic_type is not None and self.metric not in _TOP_TYPED_ENDPOINTS:
            supported = ", ".join(sorted(_TOP_TYPED_ENDPOINTS))
            raise ValueError(
                f"traffic_type is only supported for metrics: {supported}. "
                f"Got metric='{self.metric}' with traffic_type='{self.traffic_type}'."
            )
        return self


class SummaryReportInput(ToolInput):
    """Parameters for summary and total-requests reports."""

    report: str = Field(
        ...,
        description="Report type. Valid values: 'summary', 'total_requests'.",
    )
    traffic_type: str | None = Field(
        default=None,
        description=(
            "Optional traffic type filter. Valid values: 'dns', 'proxy', 'firewall', 'ip'. "
            "Omit for an overall (all-traffic) result."
        ),
    )
    from_time: str = Field(
        ..., description="Start time — relative (e.g. '-7days') or ISO 8601 (e.g. '2024-01-01T00:00:00Z')"
    )
    to_time: str = Field(default="now", description="End time — relative (e.g. 'now') or ISO 8601. Defaults to 'now'.")

    @field_validator("report")
    @classmethod
    def validate_report(cls, v: str) -> str:
        if v not in _SUMMARY_REPORTS:
            allowed = ", ".join(sorted(_SUMMARY_REPORTS))
            raise ValueError(f"report must be one of: {allowed}")
        return v

    @field_validator("traffic_type")
    @classmethod
    def validate_traffic_type(cls, v: str | None) -> str | None:
        if v is not None and v not in _TRAFFIC_TYPES:
            allowed = ", ".join(sorted(_TRAFFIC_TYPES))
            raise ValueError(f"traffic_type must be one of: {allowed}")
        return v


class IdentitiesInput(ToolInput):
    limit: int | None = Field(default=25, ge=1, le=500, description="Max identities to return")
    offset: int | None = Field(default=0, ge=0, description="Pagination offset")


class SummaryInput(ToolInput):
    """Time-range-only input (used by identity distribution)."""

    from_time: str = Field(
        ..., description="Start time — relative (e.g. '-7days') or ISO 8601 (e.g. '2024-01-01T00:00:00Z')"
    )
    to_time: str = Field(default="now", description="End time — relative (e.g. 'now') or ISO 8601. Defaults to 'now'.")


class ApiUsageInput(ToolInput):
    """Parameters for API usage reports."""

    metric: str = Field(
        ...,
        description=(
            "API usage metric. Valid values: 'requests', 'responses', 'keys', 'summary'."
        ),
    )
    from_time: str = Field(
        ..., description="Start time — relative (e.g. '-7days') or ISO 8601 (e.g. '2024-01-01T00:00:00Z')"
    )
    to_time: str = Field(default="now", description="End time — relative (e.g. 'now') or ISO 8601. Defaults to 'now'.")
    limit: int | None = Field(default=25, ge=1, le=500)
    offset: int | None = Field(default=0, ge=0)

    @field_validator("metric")
    @classmethod
    def validate_metric(cls, v: str) -> str:
        if v not in _API_USAGE_ENDPOINTS:
            allowed = ", ".join(sorted(_API_USAGE_ENDPOINTS))
            raise ValueError(f"metric must be one of: {allowed}")
        return v


class RequestVolumeInput(ToolInput):
    """Parameters for organization request volume reports."""

    granularity: str = Field(
        ...,
        description="Time granularity. Valid values: 'hour', 'timerange'.",
    )
    by_category: bool = Field(
        default=False,
        description="If true, break down results by content/security category.",
    )
    from_time: str = Field(
        ..., description="Start time — relative (e.g. '-7days') or ISO 8601 (e.g. '2024-01-01T00:00:00Z')"
    )
    to_time: str = Field(default="now", description="End time — relative (e.g. 'now') or ISO 8601. Defaults to 'now'.")

    @field_validator("granularity")
    @classmethod
    def validate_granularity(cls, v: str) -> str:
        if v not in ("hour", "timerange"):
            raise ValueError("granularity must be 'hour' or 'timerange'")
        return v


class BandwidthInput(ToolInput):
    """Parameters for bandwidth reports."""

    granularity: str = Field(
        ...,
        description="Time granularity. Valid values: 'hour', 'timerange'.",
    )
    from_time: str = Field(
        ..., description="Start time — relative (e.g. '-7days') or ISO 8601 (e.g. '2024-01-01T00:00:00Z')"
    )
    to_time: str = Field(default="now", description="End time — relative (e.g. 'now') or ISO 8601. Defaults to 'now'.")

    @field_validator("granularity")
    @classmethod
    def validate_granularity(cls, v: str) -> str:
        if v not in ("hour", "timerange"):
            raise ValueError("granularity must be 'hour' or 'timerange'")
        return v


class ProviderReportInput(ToolInput):
    """Parameters for MSP/provider reports."""

    report: str = Field(
        ...,
        description=(
            "Provider report type. Valid values: 'categories', 'deployments', "
            "'requests_by_org', 'requests_by_hour', 'requests_by_timerange', "
            "'requests_by_category', 'requests_by_destination', 'category_requests_by_org'."
        ),
    )
    from_time: str = Field(
        ..., description="Start time — relative (e.g. '-7days') or ISO 8601"
    )
    to_time: str = Field(default="now", description="End time")
    limit: int | None = Field(default=25, ge=1, le=500)
    offset: int | None = Field(default=0, ge=0)

    @field_validator("report")
    @classmethod
    def validate_report(cls, v: str) -> str:
        if v not in _PROVIDER_ENDPOINTS:
            allowed = ", ".join(sorted(_PROVIDER_ENDPOINTS))
            raise ValueError(f"report must be one of: {allowed}")
        return v


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
# 1. Activity (7 endpoints → 1 tool)
# ---------------------------------------------------------------------------


@mcp.tool(
    name="umbrella_get_activity",
    annotations={
        "title": "Get Activity Events",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_activity(params: ActivityInput, ctx: Context) -> str:
    """Get activity events within a time range, optionally filtered by type.

    Set activity_type to choose which events to retrieve:
      - 'all'       — all activity events (DNS, proxy, firewall, intrusion)
      - 'dns'       — DNS query events
      - 'proxy'     — web proxy (SWG) events
      - 'firewall'  — firewall events
      - 'intrusion' — IPS/intrusion detection events
      - 'amp'       — AMP retrospective events (files reclassified as malicious)
      - 'ip'        — IP-layer events

    Provide from_time (required). Filter by domains, ip, or verdict.
    """
    try:
        endpoint = _ACTIVITY_ENDPOINTS[params.activity_type]
        data = await get_client(ctx).get(SCOPE, endpoint, params=_activity_params(params))
        return compact_json(data)
    except Exception as e:
        return format_error(e)


# ---------------------------------------------------------------------------
# 2. Top-N (16 endpoints → 1 tool)
# ---------------------------------------------------------------------------


@mcp.tool(
    name="umbrella_get_top",
    annotations={
        "title": "Get Top-N Report",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_top(params: TopReportInput, ctx: Context) -> str:
    """Get top-N aggregation report for a chosen metric in a time range.

    Set metric to one of:
      - 'destinations'    — top domains by request count
      - 'identities'     — top users/networks/devices by request count
      - 'categories'     — top content/security categories
      - 'threats'        — top threats by occurrence
      - 'threat_types'   — top threat type categories (malware, phishing, C2, etc.)
      - 'urls'           — top URLs by request count
      - 'ips'            — top external IPs
      - 'internal_ips'   — top internal IPs
      - 'files'          — top files by transfer count
      - 'event_types'    — top event types by occurrence
      - 'dns_query_types' — top DNS query types (A, AAAA, MX, etc.)

    Optional traffic_type ('dns', 'proxy', 'firewall', 'ip') filters by traffic source.
    Only supported for: destinations, identities, categories, threats, threat_types.
    Omit traffic_type for an overall (all-traffic) result.
    """
    try:
        base_path = _ALL_TOP_METRICS[params.metric]
        if params.traffic_type:
            endpoint = f"{base_path}/{quote(params.traffic_type, safe='')}"
        else:
            endpoint = base_path
        data = await get_client(ctx).get(SCOPE, endpoint, params=_time_params(params))
        return compact_json(data)
    except Exception as e:
        return format_error(e)


# ---------------------------------------------------------------------------
# 3. Summary / Total Requests (4 endpoints → 1 tool)
# ---------------------------------------------------------------------------


@mcp.tool(
    name="umbrella_get_summary",
    annotations={
        "title": "Get Summary or Total Requests",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_summary(params: SummaryReportInput, ctx: Context) -> str:
    """Get a security summary or total request counts for the organization.

    Set report to:
      - 'summary'        — overall security summary (total, blocked, threat counts)
      - 'total_requests' — total allowed/blocked request counts

    Optional traffic_type ('dns', 'proxy', 'firewall', 'ip') filters by traffic source.
    Omit for an overall (all-traffic) result.
    """
    try:
        base_path = _SUMMARY_REPORTS[params.report]
        if params.traffic_type:
            endpoint = f"{base_path}/{quote(params.traffic_type, safe='')}"
        else:
            endpoint = base_path
        data = await get_client(ctx).get(SCOPE, endpoint, params=_time_params(params))
        return compact_json(data)
    except Exception as e:
        return format_error(e)


# ---------------------------------------------------------------------------
# 4. API Usage (4 endpoints → 1 tool)
# ---------------------------------------------------------------------------


@mcp.tool(
    name="umbrella_get_api_usage",
    annotations={
        "title": "Get API Usage Report",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_api_usage(params: ApiUsageInput, ctx: Context) -> str:
    """Get Umbrella API usage statistics in a time range.

    Set metric to:
      - 'requests'  — API request counts by endpoint
      - 'responses' — API response code distribution (2xx, 4xx, 5xx)
      - 'keys'      — API request counts per API key
      - 'summary'   — high-level API usage summary
    """
    try:
        endpoint = _API_USAGE_ENDPOINTS[params.metric]
        data = await get_client(ctx).get(SCOPE, endpoint, params=_time_params(params))
        return compact_json(data)
    except Exception as e:
        return format_error(e)


# ---------------------------------------------------------------------------
# 5. Request Volume (4 endpoints → 1 tool)
# ---------------------------------------------------------------------------


@mcp.tool(
    name="umbrella_get_request_volume",
    annotations={
        "title": "Get Request Volume",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_request_volume(params: RequestVolumeInput, ctx: Context) -> str:
    """Get organization request volume in a time range.

    Set granularity to:
      - 'hour'      — hourly time-series data
      - 'timerange' — single aggregate total for the period

    Set by_category to true to break down results by content/security category.

    Endpoints reached:
      hour            → organizations/requests/hour
      hour+category   → organizations/requests/hour/categories
      timerange       → organizations/requests/timerange
      timerange+cat   → organizations/requests/timerange/categories
    """
    try:
        path = f"organizations/requests/{params.granularity}"
        if params.by_category:
            path = f"{path}/categories"
        data = await get_client(ctx).get(SCOPE, path, params=_time_params(params))
        return compact_json(data)
    except Exception as e:
        return format_error(e)


# ---------------------------------------------------------------------------
# 6. Bandwidth (2 endpoints → 1 tool)
# ---------------------------------------------------------------------------


@mcp.tool(
    name="umbrella_get_bandwidth",
    annotations={
        "title": "Get Bandwidth Report",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_bandwidth(params: BandwidthInput, ctx: Context) -> str:
    """Get proxy bandwidth usage for the organization in a time range.

    Set granularity to:
      - 'hour'      — hourly time-series of bytes sent/received
      - 'timerange' — aggregate bandwidth total for the period
    """
    try:
        endpoint = f"organizations/bandwidth/{params.granularity}"
        data = await get_client(ctx).get(SCOPE, endpoint, params=_time_params(params))
        return compact_json(data)
    except Exception as e:
        return format_error(e)


# ---------------------------------------------------------------------------
# 7. Provider / MSP (8 endpoints → 1 tool)
# ---------------------------------------------------------------------------


@mcp.tool(
    name="umbrella_get_provider_report",
    annotations={
        "title": "Get Provider/MSP Report",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_provider_report(params: ProviderReportInput, ctx: Context) -> str:
    """Get MSP/provider-level reports across managed organizations.

    Set report to:
      - 'categories'              — category breakdown across managed orgs
      - 'deployments'             — deployment statistics across managed orgs
      - 'requests_by_org'         — request counts per managed organization
      - 'requests_by_hour'        — hourly request volume across managed orgs
      - 'requests_by_timerange'   — aggregate request counts across managed orgs
      - 'requests_by_category'    — request counts by category across managed orgs
      - 'requests_by_destination' — request counts by destination across managed orgs
      - 'category_requests_by_org' — per-category request counts per managed org
    """
    try:
        endpoint = _PROVIDER_ENDPOINTS[params.report]
        data = await get_client(ctx).get(SCOPE, endpoint, params=_time_params(params))
        return compact_json(data)
    except Exception as e:
        return format_error(e)


# ---------------------------------------------------------------------------
# 8-10. Standalone tools (kept as-is)
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
    """
    try:
        data = await get_client(ctx).get(SCOPE, "identities", params={"limit": params.limit, "offset": params.offset})
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
