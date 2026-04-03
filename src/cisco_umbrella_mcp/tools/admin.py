"""Admin tools — users, roles, and API key read-only queries."""

from __future__ import annotations

from mcp.server.fastmcp import Context
from pydantic import Field

from cisco_umbrella_mcp.client import compact_json, format_error
from cisco_umbrella_mcp.server import mcp
from cisco_umbrella_mcp.tools import ToolInput, get_client

SCOPE = "admin/v2"


# ---------------------------------------------------------------------------
# Input models
# ---------------------------------------------------------------------------


class UserIdInput(ToolInput):
    user_id: int = Field(..., description="Umbrella user ID")


class ApiKeyIdInput(ToolInput):
    api_key_id: int = Field(..., description="Umbrella API key ID")


class ApiKeyListInput(ToolInput):
    page: int | None = Field(default=1, ge=1)
    limit: int | None = Field(default=25, ge=1, le=200)


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
        data = await get_client(ctx).get(SCOPE, "users")
        return compact_json(data)
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
        data = await get_client(ctx).get(SCOPE, f"users/{params.user_id}")
        return compact_json(data)
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
        data = await get_client(ctx).get(SCOPE, "roles")
        return compact_json(data)
    except Exception as e:
        return format_error(e)


# ---------------------------------------------------------------------------
# API Key tools (read-only)
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
        data = await get_client(ctx).get(SCOPE, "apiKeys", params={"page": params.page, "limit": params.limit})
        return compact_json(data)
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
        data = await get_client(ctx).get(SCOPE, f"apiKeys/{params.api_key_id}")
        return compact_json(data)
    except Exception as e:
        return format_error(e)
