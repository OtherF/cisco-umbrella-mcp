"""Admin tools — users, roles, and API key management."""

from __future__ import annotations

import json
from typing import Optional

from mcp.server.fastmcp import Context
from pydantic import BaseModel, ConfigDict, Field

from cisco_umbrella_mcp.client import UmbrellaClient, format_error
from cisco_umbrella_mcp.server import AppContext, mcp

SCOPE = "admin/v2"


def _get_client(ctx: Context) -> UmbrellaClient:
    app: AppContext = ctx.request_context.lifespan_context
    return app.client


# ---------------------------------------------------------------------------
# Input models
# ---------------------------------------------------------------------------

class UserIdInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    user_id: int = Field(..., description="Umbrella user ID")


class ApiKeyIdInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    api_key_id: int = Field(..., description="Umbrella API key ID")


class ApiKeyListInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    page: Optional[int] = Field(default=1, ge=1)
    limit: Optional[int] = Field(default=100, ge=1, le=200)


# ---------------------------------------------------------------------------
# User & Role tools
# ---------------------------------------------------------------------------

@mcp.tool(
    name="umbrella_list_users",
    annotations={
        "title": "List Organization Users",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_list_users(ctx: Context) -> str:
    """List all user accounts in the Umbrella organization.

    Returns user details including name, email, role, and status.
    """
    try:
        data = await _get_client(ctx).get(SCOPE, "users")
        return json.dumps(data, indent=2)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_user",
    annotations={
        "title": "Get User Details",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_user(params: UserIdInput, ctx: Context) -> str:
    """Get details of a specific Umbrella user by ID."""
    try:
        data = await _get_client(ctx).get(SCOPE, f"users/{params.user_id}")
        return json.dumps(data, indent=2)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_list_roles",
    annotations={
        "title": "List User Roles",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_list_roles(ctx: Context) -> str:
    """List all available user roles in the Umbrella organization."""
    try:
        data = await _get_client(ctx).get(SCOPE, "roles")
        return json.dumps(data, indent=2)
    except Exception as e:
        return format_error(e)


# ---------------------------------------------------------------------------
# API Key tools
# ---------------------------------------------------------------------------

@mcp.tool(
    name="umbrella_list_api_keys",
    annotations={
        "title": "List API Keys",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_list_api_keys(params: ApiKeyListInput, ctx: Context) -> str:
    """List all API keys in the Umbrella organization.

    Returns key metadata (name, scopes, expiration) — secrets are never returned.
    """
    try:
        data = await _get_client(ctx).get(
            SCOPE, "apiKeys", params={"page": params.page, "limit": params.limit}
        )
        return json.dumps(data, indent=2)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_get_api_key",
    annotations={
        "title": "Get API Key Details",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_get_api_key(params: ApiKeyIdInput, ctx: Context) -> str:
    """Get details of a specific API key by ID. Secrets are never returned."""
    try:
        data = await _get_client(ctx).get(SCOPE, f"apiKeys/{params.api_key_id}")
        return json.dumps(data, indent=2)
    except Exception as e:
        return format_error(e)
