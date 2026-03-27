# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Install for development
pip install -e ".[dev]"

# Run tests
pytest                                        # all tests
pytest tests/test_investigate.py              # single module
pytest tests/test_investigate.py::test_name  # single test
pytest -x                                     # stop on first failure

# Lint / format
ruff check src/ tests/
ruff format src/ tests/

# Type checking
mypy src/

# Test with MCP Inspector (interactive tool UI)
npx @modelcontextprotocol/inspector cisco-umbrella-mcp
```

## Architecture

Four layers, each with a single responsibility:

```
auth.py → client.py → server.py → tools/*.py
```

- **`auth.py` — `TokenManager`**: OAuth 2.0 client credentials flow. Uses `asyncio.Lock` with double-checked locking so concurrent tool calls don't race to refresh the token.
- **`client.py` — `UmbrellaClient`**: Thin httpx wrapper. All requests go through one `request()` method that builds `https://api.umbrella.com/{scope}/{endpoint}`. `follow_redirects=True` is required — the Reports API uses 302 redirects. `format_error()` converts HTTP status codes into actionable LLM-friendly strings.
- **`server.py` — FastMCP app**: Creates `TokenManager` + `UmbrellaClient` once in the `app_lifespan` context manager and exposes them as `AppContext` to all tools via `ctx.request_context.lifespan_context`. Validates `TOKEN_URL` env var at startup to prevent SSRF. Imports all tool modules at the bottom to trigger tool registration.
- **`tools/*.py` — one file per API scope**: Each module calls `_get_client(ctx)` to retrieve the shared client and registers tools with `@mcp.tool`. Tool functions return `json.dumps(data, indent=2)` on success or `format_error(e)` on failure.

## Key Conventions

**Pydantic input models**: All tool inputs use `BaseModel` with `ConfigDict(str_strip_whitespace=True)`. Never use Pydantic `alias` on fields — FastMCP passes Python field names, not aliases. If the API parameter name conflicts with a Python keyword (e.g. `from`, `to`), rename the field (`from_time`, `to_time`) and map it manually when building the query dict.

**Path safety**: User-supplied strings embedded in URL path segments must be encoded with `urllib.parse.quote(value, safe='')`. Fields that should be simple identifiers (domains, hashes) should also reject `/` and `\` via a `field_validator`.

**MCP annotations**: Every tool declares `readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`. Mark `destructiveHint: True` for any operation that immediately invalidates existing state (deletes, credential rotation) — not just explicit "delete" endpoints.

**Tests**: `conftest.py` provides `mock_client` (an `UmbrellaClient` with `request` replaced by `AsyncMock`) and `mock_ctx` (a mock MCP context pointing to that client). Tests focus on input model validation and that the correct API path/params are passed to `client.request`.
