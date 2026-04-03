"""Umbrella MCP tool modules — shared base classes and helpers."""

from __future__ import annotations

from typing import TYPE_CHECKING

from mcp.server.fastmcp import Context
from pydantic import BaseModel, ConfigDict

if TYPE_CHECKING:
    from cisco_umbrella_mcp.client import UmbrellaClient


class ToolInput(BaseModel):
    """Base model for all tool inputs — strips whitespace from strings."""

    model_config = ConfigDict(str_strip_whitespace=True)


def get_client(ctx: Context) -> UmbrellaClient:
    """Retrieve the shared UmbrellaClient from the MCP context."""
    return ctx.request_context.lifespan_context.client  # type: ignore[union-attr]


def validate_no_path_separators(v: str) -> str:
    """Reject values containing path separators (prevents path traversal)."""
    if "/" in v or "\\" in v:
        raise ValueError("must not contain path separators")
    return v


def clean_domain_value(v: str) -> str:
    """Normalise a domain name: strip, lowercase, remove trailing dot, reject path separators."""
    v = v.strip().lower().rstrip(".")
    return validate_no_path_separators(v)
