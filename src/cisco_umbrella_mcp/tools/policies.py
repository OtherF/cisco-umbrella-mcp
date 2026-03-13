"""Policies tools — destination lists, destinations, and application lists."""

from __future__ import annotations

import json
from typing import Optional

from mcp.server.fastmcp import Context
from pydantic import BaseModel, ConfigDict, Field

from cisco_umbrella_mcp.client import UmbrellaClient, format_error
from cisco_umbrella_mcp.server import AppContext, mcp

SCOPE = "policies/v2"


def _get_client(ctx: Context) -> UmbrellaClient:
    app: AppContext = ctx.request_context.lifespan_context
    return app.client


# ---------------------------------------------------------------------------
# Input models
# ---------------------------------------------------------------------------

class ListPaginationInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    page: Optional[int] = Field(default=1, description="Page number (starts at 1)", ge=1)
    limit: Optional[int] = Field(default=100, description="Records per page (max 200)", ge=1, le=200)


class DestinationListIdInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    destination_list_id: int = Field(..., description="ID of the destination list")


class DestinationListCreateInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    name: str = Field(..., description="Name for the new destination list", min_length=1, max_length=255)
    access: str = Field(..., description="Access type: 'allow' or 'block'")
    is_global: bool = Field(default=False, description="Whether this is a global list")
    destinations: Optional[list[str]] = Field(
        default=None,
        description="Optional initial destinations (domains, IPs, or URLs). Max 500.",
        max_length=500,
    )


class DestinationListUpdateInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    destination_list_id: int = Field(..., description="ID of the destination list to update")
    name: str = Field(..., description="New name for the destination list", min_length=1, max_length=255)


class DestinationsGetInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    destination_list_id: int = Field(..., description="ID of the destination list")
    page: Optional[int] = Field(default=1, ge=1)
    limit: Optional[int] = Field(default=100, ge=1, le=200)


class DestinationsAddInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    destination_list_id: int = Field(..., description="ID of the destination list")
    destinations: list[str] = Field(
        ..., description="Destinations to add (domains, IPs, or URLs). Max 500 per request.",
        min_length=1, max_length=500,
    )
    comment: Optional[str] = Field(default=None, description="Comment for the new destinations")


class DestinationsRemoveInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    destination_list_id: int = Field(..., description="ID of the destination list")
    destination_ids: list[int] = Field(
        ..., description="IDs of the destinations to remove", min_length=1
    )


class ApplicationListsInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)


class ApplicationListCreateInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    name: str = Field(..., description="Name for the new application list", min_length=1, max_length=255)
    application_ids: Optional[list[int]] = Field(
        default=None, description="Optional list of application IDs to include"
    )


class ApplicationListUpdateInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    application_list_id: int = Field(..., description="ID of the application list to update")
    name: Optional[str] = Field(default=None, description="New name", max_length=255)
    application_ids: Optional[list[int]] = Field(default=None, description="Updated application IDs")


class ApplicationListDeleteInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    application_list_id: int = Field(..., description="ID of the application list to delete")


# ---------------------------------------------------------------------------
# Destination List tools
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
        data = await _get_client(ctx).get(
            SCOPE, "destinationlists", params={"page": params.page, "limit": params.limit}
        )
        return json.dumps(data, indent=2)
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
        data = await _get_client(ctx).get(SCOPE, f"destinationlists/{params.destination_list_id}")
        return json.dumps(data, indent=2)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_create_destination_list",
    annotations={
        "title": "Create Destination List",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True,
    },
)
async def umbrella_create_destination_list(params: DestinationListCreateInput, ctx: Context) -> str:
    """Create a new destination list (allow or block).

    Optionally provide initial destinations (domains, IPs, URLs). Max 500 per request.
    """
    try:
        body: dict = {
            "access": params.access,
            "isGlobal": params.is_global,
            "name": params.name,
        }
        if params.destinations:
            body["destinations"] = [{"destination": d} for d in params.destinations]
        data = await _get_client(ctx).post(SCOPE, "destinationlists", json_data=body)
        return json.dumps(data, indent=2)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_update_destination_list",
    annotations={
        "title": "Update Destination List",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_update_destination_list(params: DestinationListUpdateInput, ctx: Context) -> str:
    """Rename a destination list."""
    try:
        data = await _get_client(ctx).patch(
            SCOPE,
            f"destinationlists/{params.destination_list_id}",
            json_data={"name": params.name},
        )
        return json.dumps(data, indent=2)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_delete_destination_list",
    annotations={
        "title": "Delete Destination List",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": True,
    },
)
async def umbrella_delete_destination_list(params: DestinationListIdInput, ctx: Context) -> str:
    """Delete a destination list by ID. This action cannot be undone."""
    try:
        data = await _get_client(ctx).delete(SCOPE, f"destinationlists/{params.destination_list_id}")
        return json.dumps(data, indent=2) if data else "Destination list deleted successfully."
    except Exception as e:
        return format_error(e)


# ---------------------------------------------------------------------------
# Destination tools (items within a list)
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
        data = await _get_client(ctx).get(
            SCOPE,
            f"destinationlists/{params.destination_list_id}/destinations",
            params={"page": params.page, "limit": params.limit},
        )
        return json.dumps(data, indent=2)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_add_destinations",
    annotations={
        "title": "Add Destinations to List",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True,
    },
)
async def umbrella_add_destinations(params: DestinationsAddInput, ctx: Context) -> str:
    """Add domains, IPs, or URLs to an existing destination list. Max 500 per request.

    Note: URLs on high-volume domains may be rejected — add the domain instead.
    """
    try:
        items = [{"destination": d} for d in params.destinations]
        if params.comment:
            items = [{"destination": d, "comment": params.comment} for d in params.destinations]
        data = await _get_client(ctx).post(
            SCOPE,
            f"destinationlists/{params.destination_list_id}/destinations",
            json_data=items,
        )
        return json.dumps(data, indent=2)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_remove_destinations",
    annotations={
        "title": "Remove Destinations from List",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_remove_destinations(params: DestinationsRemoveInput, ctx: Context) -> str:
    """Remove destinations from a destination list by their IDs."""
    try:
        data = await _get_client(ctx).delete(
            SCOPE,
            f"destinationlists/{params.destination_list_id}/destinations/remove",
            json_data=params.destination_ids,
        )
        return json.dumps(data, indent=2) if data else "Destinations removed successfully."
    except Exception as e:
        return format_error(e)


# ---------------------------------------------------------------------------
# Application List tools
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
        data = await _get_client(ctx).get(SCOPE, "applicationLists")
        return json.dumps(data, indent=2)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_create_application_list",
    annotations={
        "title": "Create Application List",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True,
    },
)
async def umbrella_create_application_list(params: ApplicationListCreateInput, ctx: Context) -> str:
    """Create a new application list."""
    try:
        body: dict = {"applicationListName": params.name}
        if params.application_ids:
            body["applicationIds"] = params.application_ids
        data = await _get_client(ctx).post(SCOPE, "applicationLists", json_data=body)
        return json.dumps(data, indent=2)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_update_application_list",
    annotations={
        "title": "Update Application List",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_update_application_list(params: ApplicationListUpdateInput, ctx: Context) -> str:
    """Update an application list's name or applications."""
    try:
        body: dict = {}
        if params.name is not None:
            body["applicationListName"] = params.name
        if params.application_ids is not None:
            body["applicationIds"] = params.application_ids
        data = await _get_client(ctx).put(
            SCOPE, f"applicationLists/{params.application_list_id}", json_data=body
        )
        return json.dumps(data, indent=2)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_delete_application_list",
    annotations={
        "title": "Delete Application List",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": True,
    },
)
async def umbrella_delete_application_list(params: ApplicationListDeleteInput, ctx: Context) -> str:
    """Delete an application list by ID. This action cannot be undone."""
    try:
        data = await _get_client(ctx).delete(SCOPE, f"applicationLists/{params.application_list_id}")
        return json.dumps(data, indent=2) if data else "Application list deleted successfully."
    except Exception as e:
        return format_error(e)
