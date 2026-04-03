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

- **`auth.py` — `TokenManager`**: OAuth 2.0 client credentials flow. Uses `asyncio.Lock` with double-checked locking so concurrent tool calls don't race to refresh the token. Accepts an optional shared `http_client` from the lifespan context.
- **`client.py` — `UmbrellaClient`**: Read-only httpx wrapper. All requests go through `get()` which calls `request()`, building `https://api.umbrella.com/{scope}/{endpoint}`. Only `get()` and `request()` are exposed — no write methods. `compact_json()` strips empty fields and whitespace for token-efficient responses. `format_error()` converts HTTP status codes into actionable LLM-friendly strings.
- **`server.py` — FastMCP app**: Creates a single `httpx.AsyncClient` in the lifespan (shared by `TokenManager` and `UmbrellaClient`), validates `TOKEN_URL` using `urlparse` at startup (SSRF prevention), and exposes `AppContext` to all tools via `ctx.request_context.lifespan_context`. Imports all tool modules at the bottom to trigger tool registration.
- **`tools/__init__.py` — shared helpers**: `ToolInput` (Pydantic base class), `get_client()`, `validate_no_path_separators()`, `clean_domain_value()`. Every tool module imports from here.
- **`tools/*.py` — one file per API scope**: Each module uses `get_client(ctx)` to retrieve the shared client and registers tools with `@mcp.tool`. Tool functions return `compact_json(data)` on success or `format_error(e)` on failure.

## Key Conventions

**Read-only server**: All write and destructive tools have been removed. `UmbrellaClient` only exposes `get()` and `request()`. Do not add `post()`, `put()`, `patch()`, or `delete()` methods.

**Pydantic input models**: All tool inputs inherit from `ToolInput` (in `tools/__init__.py`), which provides `ConfigDict(str_strip_whitespace=True)`. Use `X | None` instead of `Optional[X]` (Python 3.10+ style). Never use Pydantic `alias` on fields — FastMCP passes Python field names, not aliases. If the API parameter name conflicts with a Python keyword (e.g. `from`, `to`), rename the field (`from_time`, `to_time`) and map it manually when building the query dict.

**Path safety**: User-supplied strings embedded in URL path segments must be encoded with `urllib.parse.quote(value, safe='')`. Use `validate_no_path_separators()` or `clean_domain_value()` from `tools/__init__.py` in `field_validator` for identifier fields.

**Output**: Always return `compact_json(data)` from tool functions, never `json.dumps(data, indent=2)`. `compact_json()` strips null/empty fields and removes whitespace (~30–50% token reduction).

**MCP annotations**: Every tool declares `readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`. Since the server is read-only, all tools should have `readOnlyHint: True` and `destructiveHint: False`.

**Tests**: `conftest.py` provides `mock_client` (an `UmbrellaClient` with `request` replaced by `AsyncMock`) and `mock_ctx` (a mock MCP context pointing to that client). Tests focus on input model validation and that the correct API path/params are passed to `client.request`.
