"""Cisco Umbrella MCP Server.

FastMCP server that exposes Cisco Umbrella API operations as MCP tools.
"""

from __future__ import annotations

import os
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass

from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP

from cisco_umbrella_mcp.auth import TokenManager
from cisco_umbrella_mcp.client import UmbrellaClient

load_dotenv()


@dataclass
class AppContext:
    """Shared application state available to all tools via lifespan."""

    client: UmbrellaClient


@asynccontextmanager
async def app_lifespan(server: FastMCP) -> AsyncIterator[AppContext]:
    """Initialize the Umbrella API client for the server lifetime."""
    api_key = os.environ.get("API_KEY", "")
    api_secret = os.environ.get("API_SECRET", "")

    if not api_key or not api_secret:
        print(
            "Error: API_KEY and API_SECRET environment variables are required.\n"
            "Copy .env.example to .env and fill in your Umbrella API credentials.",
            file=sys.stderr,
        )
        sys.exit(1)

    token_manager = TokenManager(
        api_key=api_key,
        api_secret=api_secret,
        token_url=os.environ.get("TOKEN_URL", "https://api.umbrella.com/auth/v2/token"),
        org_id=os.environ.get("UMBRELLA_ORG_ID"),
    )
    client = UmbrellaClient(token_manager)

    yield AppContext(client=client)


mcp = FastMCP(
    "cisco-umbrella-mcp",
    lifespan=app_lifespan,
)

# Import tool modules to register them with the server
from cisco_umbrella_mcp.tools import (  # noqa: E402, F401
    admin,
    deployments,
    investigate,
    policies,
    reports,
)


def main() -> None:
    """Entry point for the MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()
