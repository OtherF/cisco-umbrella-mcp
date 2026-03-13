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


class ApiKeyCreateInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    name: str = Field(..., description="Name for the new API key", min_length=1, max_length=255)
    scopes: list[str] = Field(
        ...,
        description="OAuth 2.0 scopes to grant (e.g. ['reports:read', 'policies:write'])",
        min_length=1,
    )
    description: Optional[str] = Field(default=None, description="Optional description")
    allowed_ips: Optional[list[str]] = Field(
        default=None, description="Optional list of IP CIDRs allowed to use this key"
    )
    expire_at: Optional[str] = Field(
        default=None, description="Expiry in ISO 8601 format (e.g. '2025-12-31T00:00:00Z') or null for no expiry"
    )


class ApiKeyUpdateInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    api_key_id: int = Field(..., description="ID of the API key to update")
    name: Optional[str] = Field(default=None, description="New name", max_length=255)
    description: Optional[str] = Field(default=None, description="New description")
    allowed_ips: Optional[list[str]] = Field(default=None, description="Updated list of allowed IP CIDRs")
    expire_at: Optional[str] = Field(default=None, description="New expiry in ISO 8601 format or null")


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


@mcp.tool(
    name="umbrella_create_api_key",
    annotations={
        "title": "Create API Key",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True,
    },
)
async def umbrella_create_api_key(params: ApiKeyCreateInput, ctx: Context) -> str:
    """Create a new Umbrella API key with specified scopes and optional restrictions.

    Returns the new key's clientId and clientSecret — store the secret securely,
    it is only returned once.
    """
    try:
        body: dict = {"name": params.name, "scopes": params.scopes}
        if params.description is not None:
            body["description"] = params.description
        if params.allowed_ips is not None:
            body["allowedIPs"] = params.allowed_ips
        if params.expire_at is not None:
            body["expireAt"] = params.expire_at
        data = await _get_client(ctx).post(SCOPE, "apiKeys", json_data=body)
        return json.dumps(data, indent=2)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_update_api_key",
    annotations={
        "title": "Update API Key",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def umbrella_update_api_key(params: ApiKeyUpdateInput, ctx: Context) -> str:
    """Update an existing API key's name, description, allowed IPs, or expiry."""
    try:
        body: dict = {}
        if params.name is not None:
            body["name"] = params.name
        if params.description is not None:
            body["description"] = params.description
        if params.allowed_ips is not None:
            body["allowedIPs"] = params.allowed_ips
        if params.expire_at is not None:
            body["expireAt"] = params.expire_at
        data = await _get_client(ctx).patch(SCOPE, f"apiKeys/{params.api_key_id}", json_data=body)
        return json.dumps(data, indent=2)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_delete_api_key",
    annotations={
        "title": "Delete API Key",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": True,
    },
)
async def umbrella_delete_api_key(params: ApiKeyIdInput, ctx: Context) -> str:
    """Delete an API key permanently. This immediately revokes all access using this key."""
    try:
        data = await _get_client(ctx).delete(SCOPE, f"apiKeys/{params.api_key_id}")
        return json.dumps(data, indent=2) if data else "API key deleted successfully."
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_refresh_api_key",
    annotations={
        "title": "Refresh API Key Credentials",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": True,
    },
)
async def umbrella_refresh_api_key(params: ApiKeyIdInput, ctx: Context) -> str:
    """Rotate the credentials for an API key, generating a new clientSecret.

    The old secret is immediately invalidated. Store the new secret securely — it
    is only returned once.
    """
    try:
        data = await _get_client(ctx).post(SCOPE, f"apiKeys/{params.api_key_id}/refresh")
        return json.dumps(data, indent=2)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="umbrella_rotate_s3_key",
    annotations={
        "title": "Rotate S3 Bucket Key",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": True,
    },
)
async def umbrella_rotate_s3_key(ctx: Context) -> str:
    """Rotate the managed S3 bucket key used for Umbrella log exports.

    Generates new S3 credentials for the organization's managed S3 bucket.
    Added May 2025.
    """
    try:
        data = await _get_client(ctx).post(SCOPE, "iam/rotateKey")
        return json.dumps(data, indent=2) if data else "S3 key rotated successfully."
    except Exception as e:
        return format_error(e)
