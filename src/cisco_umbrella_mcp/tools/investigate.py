"""Investigate tools — domain/IP/URL threat intelligence, WHOIS, DNS, malware samples."""

from __future__ import annotations

from urllib.parse import quote

from mcp.server.fastmcp import Context
from pydantic import Field, field_validator

from cisco_umbrella_mcp.client import compact_json, format_error
from cisco_umbrella_mcp.server import mcp
from cisco_umbrella_mcp.tools import ToolInput, clean_domain_value, get_client, validate_no_path_separators

SCOPE = "investigate/v2"


# ---------------------------------------------------------------------------
# Input models
# ---------------------------------------------------------------------------


class DomainInput(ToolInput):
    domain: str = Field(..., description="Domain name to look up (e.g. 'example.com')", min_length=1)

    @field_validator("domain")
    @classmethod
    def clean_domain(cls, v: str) -> str:
        return clean_domain_value(v)


class DomainsInput(ToolInput):
    domains: list[str] = Field(
        ..., description="List of domain names to check (max 1000)", min_length=1, max_length=1000
    )
    show_labels: bool = Field(default=False, description="Return human-readable category labels instead of IDs")


class DomainVolumeInput(ToolInput):
    domain: str = Field(..., description="Domain name", min_length=1)

    @field_validator("domain")
    @classmethod
    def clean_domain(cls, v: str) -> str:
        return clean_domain_value(v)

    start: str | None = Field(default=None, description="Start date in epoch ms or relative (-30days)")
    stop: str | None = Field(default=None, description="End date in epoch ms or relative (now)")
    match: str | None = Field(default=None, description="Match type: 'exact', 'component', or 'all'")


class DomainSearchInput(ToolInput):
    expression: str = Field(
        ...,
        description="Search expression — regex pattern to match domain names (e.g. '.*malware.*')",
        min_length=1,
    )
    start: str | None = Field(default=None, description="Start time for the search window (epoch ms)")
    limit: int | None = Field(default=20, description="Maximum results to return", ge=1, le=1000)
    include_category: bool | None = Field(default=None, description="Include domain category info")


class IpInput(ToolInput):
    ip: str = Field(..., description="IP address to look up", min_length=1)

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        return validate_no_path_separators(v)


class WhoisInput(ToolInput):
    domain: str = Field(..., description="Domain name for WHOIS lookup", min_length=1)

    @field_validator("domain")
    @classmethod
    def clean_domain(cls, v: str) -> str:
        return clean_domain_value(v)


class WhoisHistoryInput(ToolInput):
    domain: str = Field(..., description="Domain name for WHOIS history", min_length=1)
    limit: int | None = Field(default=10, description="Max history records", ge=1, le=100)

    @field_validator("domain")
    @classmethod
    def clean_domain(cls, v: str) -> str:
        return clean_domain_value(v)


class WhoisEmailInput(ToolInput):
    email: str = Field(..., description="Email address to search WHOIS records", min_length=1)
    limit: int | None = Field(default=20, ge=1, le=500)
    offset: int | None = Field(default=0, ge=0)

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        return validate_no_path_separators(v)


class WhoisNameserverInput(ToolInput):
    nameserver: str = Field(..., description="Nameserver hostname to search WHOIS records", min_length=1)

    @field_validator("nameserver")
    @classmethod
    def validate_nameserver(cls, v: str) -> str:
        return validate_no_path_separators(v)


class PdnsInput(ToolInput):
    value: str = Field(..., description="Domain name or IP address for passive DNS lookup", min_length=1)
    record_type: str | None = Field(default=None, description="Filter by record type (A, AAAA, CNAME, etc.)")
    limit: int | None = Field(default=20, ge=1, le=500)
    offset: int | None = Field(default=0, ge=0)

    @field_validator("value")
    @classmethod
    def validate_value(cls, v: str) -> str:
        return validate_no_path_separators(v)


class SampleInput(ToolInput):
    hash: str = Field(..., description="SHA-256 hash of the malware sample", min_length=64, max_length=64)

    @field_validator("hash")
    @classmethod
    def validate_hex(cls, v: str) -> str:
        if not all(c in "0123456789abcdefABCDEF" for c in v):
            raise ValueError("hash must be a valid hex string")
        return v.lower()


class SamplesSearchInput(ToolInput):
    destination: str = Field(..., description="Domain, IP, or URL to find related malware samples", min_length=1)
    limit: int | None = Field(default=20, ge=1, le=500)
    offset: int | None = Field(default=0, ge=0)


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@mcp.tool(
    name="umbrella_get_domain_status",
    annotations={
        "title": "Get Domain Status and Categorization",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_domain_status(params: DomainInput, ctx: Context) -> str:
    """Get the security status and category for a single domain.

    Returns status (-1=malicious, 0=undetermined, 1=safe), plus security
    and content category IDs. Use umbrella_check_domains_bulk for multiple domains.
    """
    try:
        data = await get_client(ctx).get(
            SCOPE,
            f"domains/categorization/{quote(params.domain, safe='')}",
            params={"showLabels": True},
        )
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_check_domains_bulk",
    annotations={
        "title": "Bulk Domain Status Check",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_check_domains_bulk(params: DomainsInput, ctx: Context) -> str:
    """Check status and categorization for multiple domains in one request (max 1000).

    Returns per-domain status (-1=malicious, 0=undetermined, 1=safe) and categories.
    """
    try:
        data = await get_client(ctx).request(
            "POST",
            SCOPE,
            "domains/categorization",
            params={"showLabels": params.show_labels},
            json_data=params.domains,
        )
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_domain_volume",
    annotations={
        "title": "Get Domain Query Volume",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_domain_volume(params: DomainVolumeInput, ctx: Context) -> str:
    """Get DNS query volume for a domain over the last 30 days.

    Returns arrays of dates and corresponding query counts.
    """
    try:
        query: dict = {}
        if params.start:
            query["start"] = params.start
        if params.stop:
            query["stop"] = params.stop
        if params.match:
            query["match"] = params.match
        data = await get_client(ctx).get(SCOPE, f"domains/volume/{quote(params.domain, safe='')}", params=query or None)
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_domain_security",
    annotations={
        "title": "Get Domain Security Info",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_domain_security(params: DomainInput, ctx: Context) -> str:
    """Get security reputation scores for a domain.

    Returns threat scores including DGA score, perplexity, entropy, geodiversity,
    and other risk indicators.
    """
    try:
        data = await get_client(ctx).get(SCOPE, f"security/name/{quote(params.domain, safe='')}")
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_domain_risk_score",
    annotations={
        "title": "Get Domain Risk Score",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_domain_risk_score(params: DomainInput, ctx: Context) -> str:
    """Get the overall risk score for a domain (0-100, higher = riskier)."""
    try:
        data = await get_client(ctx).get(SCOPE, f"domains/risk-score/{quote(params.domain, safe='')}")
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_cooccurrences",
    annotations={
        "title": "Get Domain Co-occurrences",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_cooccurrences(params: DomainInput, ctx: Context) -> str:
    """Get domains that co-occur with the given domain.

    Co-occurrences are domains accessed by the same users in a short time window.
    Suspicious co-occurrences can indicate attack infrastructure.
    """
    try:
        data = await get_client(ctx).get(SCOPE, f"recommendations/name/{quote(params.domain, safe='')}.json")
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_related_domains",
    annotations={
        "title": "Get Related Domains",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_related_domains(params: DomainInput, ctx: Context) -> str:
    """Get domains related to the given domain based on shared infrastructure."""
    try:
        data = await get_client(ctx).get(SCOPE, f"links/name/{quote(params.domain, safe='')}")
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_subdomains",
    annotations={
        "title": "Get Subdomains",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_subdomains(params: DomainInput, ctx: Context) -> str:
    """List known subdomains of a domain observed by Umbrella DNS resolvers."""
    try:
        data = await get_client(ctx).get(SCOPE, f"subdomains/{quote(params.domain, safe='')}")
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_domain_timeline",
    annotations={
        "title": "Get Domain Timeline",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_domain_timeline(params: DomainInput, ctx: Context) -> str:
    """Get the tagging timeline for a domain, IP, or URL.

    Shows when security events (malware, phishing, etc.) were associated with the domain.
    """
    try:
        data = await get_client(ctx).get(SCOPE, f"timeline/{quote(params.domain, safe='')}")
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_search_domains",
    annotations={
        "title": "Search Domains by Pattern",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_search_domains(params: DomainSearchInput, ctx: Context) -> str:
    """Search for domains matching a regex pattern in Umbrella's dataset.

    Use '.*' prefix for wildcard searches (slower, 3 req/min limit).
    """
    try:
        query: dict = {}
        if params.start:
            query["start"] = params.start
        if params.limit:
            query["limit"] = params.limit
        if params.include_category is not None:
            query["includeCategory"] = params.include_category
        data = await get_client(ctx).get(SCOPE, f"search/{quote(params.expression, safe='')}", params=query or None)
        return compact_json(data)
    except Exception as e:
        return format_error(e)


# --- Passive DNS ---


@mcp.tool(
    name="umbrella_get_pdns_domain",
    annotations={
        "title": "Get Passive DNS for Domain",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_pdns_domain(params: PdnsInput, ctx: Context) -> str:
    """Get passive DNS records for a domain — shows historical IP resolutions.

    Accepts a domain name in the 'value' field. Returns DNS records (A, AAAA, CNAME, etc.)
    with first/last seen timestamps.
    """
    try:
        query: dict = {"limit": params.limit, "offset": params.offset}
        if params.record_type:
            query["recordType"] = params.record_type
        data = await get_client(ctx).get(SCOPE, f"pdns/name/{quote(params.value, safe='')}", params=query)
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_pdns_ip",
    annotations={
        "title": "Get Passive DNS for IP",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_pdns_ip(params: PdnsInput, ctx: Context) -> str:
    """Get passive DNS records for an IP address — shows domains that resolved to it.

    Accepts an IP address in the 'value' field. Returns domain-to-IP mappings with timestamps.
    """
    try:
        query: dict = {"limit": params.limit, "offset": params.offset}
        if params.record_type:
            query["recordType"] = params.record_type
        data = await get_client(ctx).get(SCOPE, f"pdns/ip/{quote(params.value, safe='')}", params=query)
        return compact_json(data)
    except Exception as e:
        return format_error(e)


# --- WHOIS ---


@mcp.tool(
    name="umbrella_get_whois",
    annotations={
        "title": "Get WHOIS for Domain",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_whois(params: WhoisInput, ctx: Context) -> str:
    """Get current WHOIS registration data for a domain.

    Returns registrant, registrar, nameservers, creation/expiry dates, and contact info.
    """
    try:
        data = await get_client(ctx).get(SCOPE, f"whois/{quote(params.domain, safe='')}")
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_whois_history",
    annotations={
        "title": "Get WHOIS History",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_whois_history(params: WhoisHistoryInput, ctx: Context) -> str:
    """Get historical WHOIS records for a domain.

    Shows how registration details changed over time.
    """
    try:
        data = await get_client(ctx).get(
            SCOPE,
            f"whois/{quote(params.domain, safe='')}/history",
            params={"limit": params.limit},
        )
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_search_whois_by_email",
    annotations={
        "title": "Search WHOIS by Email",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_search_whois_by_email(params: WhoisEmailInput, ctx: Context) -> str:
    """Find domains registered with a given email address via WHOIS records."""
    try:
        data = await get_client(ctx).get(
            SCOPE,
            f"whois/emails/{quote(params.email, safe='')}",
            params={"limit": params.limit, "offset": params.offset},
        )
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_search_whois_by_nameserver",
    annotations={
        "title": "Search WHOIS by Nameserver",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_search_whois_by_nameserver(params: WhoisNameserverInput, ctx: Context) -> str:
    """Find domains using a specific nameserver via WHOIS records."""
    try:
        data = await get_client(ctx).get(SCOPE, f"whois/nameservers/{quote(params.nameserver, safe='')}")
        return compact_json(data)
    except Exception as e:
        return format_error(e)


# --- ASN / BGP ---


@mcp.tool(
    name="umbrella_get_asn_for_ip",
    annotations={
        "title": "Get ASN for IP",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_asn_for_ip(params: IpInput, ctx: Context) -> str:
    """Get the autonomous system number (ASN) and BGP routing info for an IP address."""
    try:
        data = await get_client(ctx).get(SCOPE, f"bgp_routes/ip/{quote(params.ip, safe='')}/as_for_ip.json")
        return compact_json(data)
    except Exception as e:
        return format_error(e)


# --- Malware Samples ---


@mcp.tool(
    name="umbrella_get_samples",
    annotations={
        "title": "Get Malware Samples for Destination",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_samples(params: SamplesSearchInput, ctx: Context) -> str:
    """Find malware samples associated with a domain, IP, or URL.

    Returns sample hashes, threat names, and metadata from Cisco Secure Malware Analytics.
    """
    try:
        data = await get_client(ctx).get(
            SCOPE,
            f"samples/{quote(params.destination, safe='')}",
            params={"limit": params.limit, "offset": params.offset},
        )
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_sample_info",
    annotations={
        "title": "Get Malware Sample Details",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_sample_info(params: SampleInput, ctx: Context) -> str:
    """Get detailed threat intelligence for a malware sample by SHA-256 hash.

    Returns file metadata, threat classification, and analysis results.
    """
    try:
        data = await get_client(ctx).get(SCOPE, f"sample/{params.hash}")
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_sample_connections",
    annotations={
        "title": "Get Malware Sample Connections",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_sample_connections(params: SampleInput, ctx: Context) -> str:
    """Get network connections made by a malware sample (domains and IPs it contacted)."""
    try:
        data = await get_client(ctx).get(SCOPE, f"sample/{params.hash}/connections")
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_sample_behaviors",
    annotations={
        "title": "Get Malware Sample Behaviors",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_sample_behaviors(params: SampleInput, ctx: Context) -> str:
    """Get behavioral analysis of a malware sample (file system, registry, process activity)."""
    try:
        data = await get_client(ctx).get(SCOPE, f"sample/{params.hash}/behaviors")
        return compact_json(data)
    except Exception as e:
        return format_error(e)


# ---------------------------------------------------------------------------
# New input models
# ---------------------------------------------------------------------------


class AsnInput(ToolInput):
    asn: int = Field(..., description="Autonomous System Number")


class WhoisSearchInput(ToolInput):
    field: str = Field(
        ..., description="WHOIS field to search (e.g. 'registrant_name', 'registrant_org')", min_length=1
    )
    regex: str = Field(..., description="Regex pattern to match", min_length=1)


# ---------------------------------------------------------------------------
# New tools
# ---------------------------------------------------------------------------


@mcp.tool(
    name="umbrella_get_asn_prefixes",
    annotations={
        "title": "Get IP Prefixes for ASN",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_asn_prefixes(params: AsnInput, ctx: Context) -> str:
    """Get IP prefixes announced by an autonomous system (ASN)."""
    try:
        data = await get_client(ctx).get(SCOPE, f"bgp_routes/asn/{params.asn}/prefixes_for_asn.json")
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_pdns_raw",
    annotations={
        "title": "Get Raw Passive DNS Records",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_pdns_raw(params: PdnsInput, ctx: Context) -> str:
    """Get raw passive DNS records for a domain or IP, including all record types."""
    try:
        query: dict = {"limit": params.limit, "offset": params.offset}
        if params.record_type:
            query["recordType"] = params.record_type
        data = await get_client(ctx).get(SCOPE, f"pdns/raw/{quote(params.value, safe='')}", params=query)
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_pdns_timeline",
    annotations={
        "title": "Get Passive DNS Timeline",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_pdns_timeline(params: DomainInput, ctx: Context) -> str:
    """Get passive DNS timeline showing when DNS records changed for a domain."""
    try:
        data = await get_client(ctx).get(SCOPE, f"pdns/timeline/{quote(params.domain, safe='')}")
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_sample_artifacts",
    annotations={
        "title": "Get Malware Sample Artifacts",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_sample_artifacts(params: SampleInput, ctx: Context) -> str:
    """Get file artifacts (dropped files, network artifacts) from a malware sample."""
    try:
        data = await get_client(ctx).get(SCOPE, f"sample/{params.hash}/artifacts")
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_search_whois_advanced",
    annotations={
        "title": "Advanced WHOIS Field Search",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_search_whois_advanced(params: WhoisSearchInput, ctx: Context) -> str:
    """Search WHOIS records by field name and regex pattern."""
    try:
        data = await get_client(ctx).get(
            SCOPE,
            f"whois/search/{quote(params.field, safe='')}/{quote(params.regex, safe='')}",
        )
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_list_nameservers_whois",
    annotations={
        "title": "List Nameservers with WHOIS Counts",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_list_nameservers_whois(ctx: Context) -> str:
    """List all nameservers with associated WHOIS domain counts."""
    try:
        data = await get_client(ctx).get(SCOPE, "whois/nameservers")
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_domain_tags",
    annotations={
        "title": "Get Domain Security Tags",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_domain_tags(params: DomainInput, ctx: Context) -> str:
    """Get security tags (malware, phishing, etc.) associated with a domain."""
    try:
        data = await get_client(ctx).get(SCOPE, f"domains/{quote(params.domain, safe='')}/tags")
        return compact_json(data)
    except Exception as e:
        return format_error(e)


# ---------------------------------------------------------------------------
# Popularity list
# ---------------------------------------------------------------------------


class TopDomainsInput(ToolInput):
    limit: int | None = Field(
        default=None,
        ge=1,
        description="Maximum number of domains to return. Omit to retrieve the full list (up to 1 million).",
    )


@mcp.tool(
    name="umbrella_get_top_domains",
    annotations={
        "title": "Get Top Most Seen Domains",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_top_domains(params: TopDomainsInput, ctx: Context) -> str:
    """List the most queried domains across the Umbrella global network.

    Powered by 180B+ daily DNS requests from 165+ countries. Useful as a
    popularity baseline — domains on this list are broadly seen and generally
    legitimate, helping analysts separate noise from genuine threats.

    Requires the Investigate add-on license.
    """
    try:
        query: dict = {}
        if params.limit is not None:
            query["limit"] = params.limit
        data = await get_client(ctx).get(SCOPE, "topmillion", params=query or None)
        return compact_json(data)
    except Exception as e:
        return format_error(e)
