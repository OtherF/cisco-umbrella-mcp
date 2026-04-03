"""Deployments tools — networks, sites, tunnels, roaming computers, virtual appliances (read-only)."""

from __future__ import annotations

from mcp.server.fastmcp import Context
from pydantic import Field

from cisco_umbrella_mcp.client import compact_json, format_error
from cisco_umbrella_mcp.server import mcp
from cisco_umbrella_mcp.tools import ToolInput, get_client

SCOPE = "deployments/v2"


# ---------------------------------------------------------------------------
# Input models
# ---------------------------------------------------------------------------


class PaginationInput(ToolInput):
    page: int | None = Field(default=1, ge=1)
    limit: int | None = Field(default=25, ge=1, le=1000)


class NetworkIdInput(ToolInput):
    network_id: int = Field(..., description="Network ID")


class SiteIdInput(ToolInput):
    site_id: int = Field(..., description="Site ID")


class TunnelIdInput(ToolInput):
    tunnel_id: int = Field(..., description="Network tunnel ID")


class RoamingComputerIdInput(ToolInput):
    device_id: int = Field(..., description="Roaming computer device ID")


class TagIdInput(ToolInput):
    tag_id: int = Field(..., description="Tag ID")


class DeviceIdsInput(ToolInput):
    device_ids: list[int] = Field(..., description="List of roaming computer device IDs", min_length=1)


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
        data = await get_client(ctx).get(SCOPE, "networks", params={"page": params.page, "limit": params.limit})
        return compact_json(data)
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
        data = await get_client(ctx).get(SCOPE, f"networks/{params.network_id}")
        return compact_json(data)
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
        data = await get_client(ctx).get(SCOPE, "sites", params={"page": params.page, "limit": params.limit})
        return compact_json(data)
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
        data = await get_client(ctx).get(SCOPE, f"sites/{params.site_id}")
        return compact_json(data)
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
        data = await get_client(ctx).get(SCOPE, "tunnels", params={"page": params.page, "limit": params.limit})
        return compact_json(data)
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
        data = await get_client(ctx).get(SCOPE, f"tunnels/{params.tunnel_id}")
        return compact_json(data)
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
        data = await get_client(ctx).get(SCOPE, f"tunnels/{params.tunnel_id}/state")
        return compact_json(data)
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
        data = await get_client(ctx).get(SCOPE, "tunnelsState")
        return compact_json(data)
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
        data = await get_client(ctx).get(SCOPE, "roamingcomputers", params={"page": params.page, "limit": params.limit})
        return compact_json(data)
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
        data = await get_client(ctx).get(SCOPE, f"roamingcomputers/{params.device_id}")
        return compact_json(data)
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
        data = await get_client(ctx).get(SCOPE, "internaldomains", params={"page": params.page, "limit": params.limit})
        return compact_json(data)
    except Exception as e:
        return format_error(e)


# ---------------------------------------------------------------------------
# Internal network tools (RFC 1918 subnets)
# ---------------------------------------------------------------------------


class InternalNetworkIdInput(ToolInput):
    internal_network_id: int = Field(..., description="Internal network ID")


@mcp.tool(
    name="umbrella_list_internal_networks",
    annotations={
        "title": "List Internal Networks",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_list_internal_networks(params: PaginationInput, ctx: Context) -> str:
    """List all internal networks (RFC 1918 subnets) in the organization.

    Internal networks define non-routable private subnets associated with a
    site, network, or tunnel. Useful for mapping private address space and
    understanding network topology during incident response.
    """
    try:
        data = await get_client(ctx).get(SCOPE, "internalnetworks", params={"page": params.page, "limit": params.limit})
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_internal_network",
    annotations={
        "title": "Get Internal Network Details",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_internal_network(params: InternalNetworkIdInput, ctx: Context) -> str:
    """Get details of a specific internal network (RFC 1918 subnet) by ID."""
    try:
        data = await get_client(ctx).get(SCOPE, f"internalnetworks/{params.internal_network_id}")
        return compact_json(data)
    except Exception as e:
        return format_error(e)


# ---------------------------------------------------------------------------
# Network device tools (hardware DNS routers)
# ---------------------------------------------------------------------------


class NetworkDeviceIdInput(ToolInput):
    device_id: int = Field(..., description="Network device ID")


@mcp.tool(
    name="umbrella_list_network_devices",
    annotations={
        "title": "List Network Devices",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_list_network_devices(params: PaginationInput, ctx: Context) -> str:
    """List all network devices registered in the organization.

    Network devices are hardware appliances that route DNS traffic to the
    Umbrella resolvers. Useful for device inventory and assessing the impact
    radius of a potentially compromised device.
    """
    try:
        data = await get_client(ctx).get(SCOPE, "networkdevices", params={"page": params.page, "limit": params.limit})
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_network_device",
    annotations={
        "title": "Get Network Device Details",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_network_device(params: NetworkDeviceIdInput, ctx: Context) -> str:
    """Get details of a specific network device by ID."""
    try:
        data = await get_client(ctx).get(SCOPE, f"networkdevices/{params.device_id}")
        return compact_json(data)
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
        data = await get_client(ctx).get(SCOPE, "virtualappliances")
        return compact_json(data)
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
        data = await get_client(ctx).get(SCOPE, "policies")
        return compact_json(data)
    except Exception as e:
        return format_error(e)


# ---------------------------------------------------------------------------
# Roaming computers — OrgInfo
# ---------------------------------------------------------------------------


@mcp.tool(
    name="umbrella_get_roaming_org_info",
    annotations={
        "title": "Get Roaming Computers Org Info",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_roaming_org_info(ctx: Context) -> str:
    """Get organization-level properties for roaming computers.

    Returns org-wide configuration and status for the Umbrella roaming client deployment.
    Added September 2024.
    """
    try:
        data = await get_client(ctx).get(SCOPE, "roamingcomputers/orgInfo")
        return compact_json(data)
    except Exception as e:
        return format_error(e)


# ---------------------------------------------------------------------------
# Tags tools
# ---------------------------------------------------------------------------


@mcp.tool(
    name="umbrella_list_tags",
    annotations={
        "title": "List Roaming Computer Tags",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_list_tags(ctx: Context) -> str:
    """List all tags used to group roaming computers.

    Tags allow applying different policies to subsets of roaming computers.
    Added January 2024.
    """
    try:
        data = await get_client(ctx).get(SCOPE, "tags")
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_list_tag_devices",
    annotations={
        "title": "List Devices with Tag",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_list_tag_devices(params: TagIdInput, ctx: Context) -> str:
    """List all roaming computers associated with a specific tag."""
    try:
        data = await get_client(ctx).get(SCOPE, f"tags/{params.tag_id}/devices")
        return compact_json(data)
    except Exception as e:
        return format_error(e)


# ---------------------------------------------------------------------------
# SWG Device Settings tools (read-only)
# ---------------------------------------------------------------------------


@mcp.tool(
    name="umbrella_list_swg_device_settings",
    annotations={
        "title": "List SWG Device Settings",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_list_swg_device_settings(params: DeviceIdsInput, ctx: Context) -> str:
    """Get the SWG override settings for specific roaming computers.

    Returns per-device SWG enabled/disabled configuration.
    """
    try:
        data = await get_client(ctx).request(
            "POST", SCOPE, "deviceSettings/SWGEnabled/list", json_data={"deviceIds": params.device_ids}
        )
        return compact_json(data)
    except Exception as e:
        return format_error(e)
