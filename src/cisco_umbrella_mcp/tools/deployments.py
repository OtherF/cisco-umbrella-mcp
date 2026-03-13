"""Deployments tools — networks, sites, tunnels, roaming computers, virtual appliances."""

from __future__ import annotations

import json
from typing import Optional

from mcp.server.fastmcp import Context
from pydantic import BaseModel, ConfigDict, Field

from cisco_umbrella_mcp.client import UmbrellaClient, format_error
from cisco_umbrella_mcp.server import AppContext, mcp

SCOPE = "deployments/v2"


def _get_client(ctx: Context) -> UmbrellaClient:
    app: AppContext = ctx.request_context.lifespan_context
    return app.client


# ---------------------------------------------------------------------------
# Input models
# ---------------------------------------------------------------------------

class PaginationInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    page: Optional[int] = Field(default=1, ge=1)
    limit: Optional[int] = Field(default=100, ge=1, le=1000)


class NetworkIdInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    network_id: int = Field(..., description="Network ID")


class SiteIdInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    site_id: int = Field(..., description="Site ID")


class TunnelIdInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    tunnel_id: int = Field(..., description="Network tunnel ID")


class RoamingComputerIdInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    device_id: int = Field(..., description="Roaming computer device ID")


class InternalDomainIdInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    internal_domain_id: int = Field(..., description="Internal domain ID")


# ---------------------------------------------------------------------------
# Network tools
# ---------------------------------------------------------------------------

@mcp.tool(
    name="umbrella_list_networks",
    annotations={
        "title": "List Networks",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_list_networks(params: PaginationInput, ctx: Context) -> str:
    """List all networks in the organization.

    Networks are IP-based identities protected by Umbrella DNS.
    """
    try:
        data = await _get_client(ctx).get(
            SCOPE, "networks", params={"page": params.page, "limit": params.limit}
        )
        return json.dumps(data, indent=2)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_network",
    annotations={
        "title": "Get Network Details",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_network(params: NetworkIdInput, ctx: Context) -> str:
    """Get details of a specific network by ID."""
    try:
        data = await _get_client(ctx).get(SCOPE, f"networks/{params.network_id}")
        return json.dumps(data, indent=2)
    except Exception as e:
        return format_error(e)


# ---------------------------------------------------------------------------
# Site tools
# ---------------------------------------------------------------------------

@mcp.tool(
    name="umbrella_list_sites",
    annotations={
        "title": "List Sites",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_list_sites(params: PaginationInput, ctx: Context) -> str:
    """List all sites in the organization. Sites represent physical locations."""
    try:
        data = await _get_client(ctx).get(
            SCOPE, "sites", params={"page": params.page, "limit": params.limit}
        )
        return json.dumps(data, indent=2)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_site",
    annotations={
        "title": "Get Site Details",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_site(params: SiteIdInput, ctx: Context) -> str:
    """Get details of a specific site by ID."""
    try:
        data = await _get_client(ctx).get(SCOPE, f"sites/{params.site_id}")
        return json.dumps(data, indent=2)
    except Exception as e:
        return format_error(e)


# ---------------------------------------------------------------------------
# Tunnel tools
# ---------------------------------------------------------------------------

@mcp.tool(
    name="umbrella_list_tunnels",
    annotations={
        "title": "List Network Tunnels",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_list_tunnels(params: PaginationInput, ctx: Context) -> str:
    """List all network tunnels (IPsec/GRE) in the organization."""
    try:
        data = await _get_client(ctx).get(
            SCOPE, "tunnels", params={"page": params.page, "limit": params.limit}
        )
        return json.dumps(data, indent=2)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_tunnel",
    annotations={
        "title": "Get Tunnel Details",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_tunnel(params: TunnelIdInput, ctx: Context) -> str:
    """Get details of a specific network tunnel including configuration."""
    try:
        data = await _get_client(ctx).get(SCOPE, f"tunnels/{params.tunnel_id}")
        return json.dumps(data, indent=2)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_tunnel_state",
    annotations={
        "title": "Get Tunnel State",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_tunnel_state(params: TunnelIdInput, ctx: Context) -> str:
    """Get the current operational state of a network tunnel (up/down)."""
    try:
        data = await _get_client(ctx).get(SCOPE, f"tunnels/{params.tunnel_id}/state")
        return json.dumps(data, indent=2)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_list_tunnels_state",
    annotations={
        "title": "List All Tunnel States",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_list_tunnels_state(ctx: Context) -> str:
    """Get the operational state of all network tunnels in the organization."""
    try:
        data = await _get_client(ctx).get(SCOPE, "tunnelsState")
        return json.dumps(data, indent=2)
    except Exception as e:
        return format_error(e)


# ---------------------------------------------------------------------------
# Roaming computer tools
# ---------------------------------------------------------------------------

@mcp.tool(
    name="umbrella_list_roaming_computers",
    annotations={
        "title": "List Roaming Computers",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_list_roaming_computers(params: PaginationInput, ctx: Context) -> str:
    """List all roaming computers (Umbrella agent-protected devices) in the organization."""
    try:
        data = await _get_client(ctx).get(
            SCOPE, "roamingcomputers", params={"page": params.page, "limit": params.limit}
        )
        return json.dumps(data, indent=2)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_roaming_computer",
    annotations={
        "title": "Get Roaming Computer",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_roaming_computer(params: RoamingComputerIdInput, ctx: Context) -> str:
    """Get details of a specific roaming computer by device ID."""
    try:
        data = await _get_client(ctx).get(SCOPE, f"roamingcomputers/{params.device_id}")
        return json.dumps(data, indent=2)
    except Exception as e:
        return format_error(e)


# ---------------------------------------------------------------------------
# Internal domain tools
# ---------------------------------------------------------------------------

@mcp.tool(
    name="umbrella_list_internal_domains",
    annotations={
        "title": "List Internal Domains",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_list_internal_domains(params: PaginationInput, ctx: Context) -> str:
    """List all internal domains configured in the organization.

    Internal domains are resolved by internal DNS servers rather than Umbrella.
    """
    try:
        data = await _get_client(ctx).get(
            SCOPE, "internaldomains", params={"page": params.page, "limit": params.limit}
        )
        return json.dumps(data, indent=2)
    except Exception as e:
        return format_error(e)


# ---------------------------------------------------------------------------
# Virtual appliance tools
# ---------------------------------------------------------------------------

@mcp.tool(
    name="umbrella_list_virtual_appliances",
    annotations={
        "title": "List Virtual Appliances",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_list_virtual_appliances(ctx: Context) -> str:
    """List all Umbrella virtual appliances (VAs) in the organization."""
    try:
        data = await _get_client(ctx).get(SCOPE, "virtualappliances")
        return json.dumps(data, indent=2)
    except Exception as e:
        return format_error(e)


# ---------------------------------------------------------------------------
# Policy tools
# ---------------------------------------------------------------------------

@mcp.tool(
    name="umbrella_list_policies",
    annotations={
        "title": "List Deployment Policies",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_list_policies(ctx: Context) -> str:
    """List all deployment policies in the organization."""
    try:
        data = await _get_client(ctx).get(SCOPE, "policies")
        return json.dumps(data, indent=2)
    except Exception as e:
        return format_error(e)
