# Contributing

Thank you for your interest in contributing to cisco-umbrella-mcp.

## Development Setup

```bash
git clone https://github.com/OtherF/cisco-umbrella-mcp.git
cd cisco-umbrella-mcp
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
cp .env.example .env            # add your credentials
```

## Running Tests

```bash
pytest                                       # all tests
pytest tests/test_investigate.py             # single module
pytest tests/test_investigate.py::test_name  # single test
pytest -x                                    # stop on first failure
```

Tests use mocked HTTP — no real Umbrella credentials are needed.

## Lint, Format, Type Check

```bash
ruff check src/ tests/     # lint
ruff format src/ tests/    # format
mypy src/                  # type checking
```

All three must pass cleanly before submitting a PR.

## Code Standards

- **Read-only**: This server exposes only read operations. Do not add tools that create, update, or delete resources.
- **Pydantic models**: All tool inputs inherit from `ToolInput` (`tools/__init__.py`). Use `X | None` (Python 3.10+ union syntax), not `Optional[X]`.
- **Path safety**: User-supplied strings in URL paths must be encoded with `urllib.parse.quote(value, safe='')` and validated with `validate_no_path_separators()`.
- **Output**: Return `compact_json(data)` on success, `format_error(e)` on failure. Never `json.dumps(data, indent=2)`.
- **Limits**: Default `limit` on list/search tools is 25, not 100.
- **Annotations**: Every `@mcp.tool` must declare `readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`.
- **Tool consolidation**: When adding multiple tools that share the same input shape and differ only by API endpoint, use the routing-parameter pattern (see `tools/reports.py`).

## Adding a New Tool

1. Find the right scope module in `src/cisco_umbrella_mcp/tools/` or create a new one.
2. Define a Pydantic input model inheriting from `ToolInput`.
3. Register the tool with `@mcp.tool(name=..., annotations={...})`.
4. Return `compact_json(data)` on success, `format_error(e)` on failure — never raise from a tool function.
5. Add the tool to the table in `README.md`.
6. If creating a new module, import it at the bottom of `server.py`.
7. Write tests in `tests/test_<scope>.py` using the `mock_client` / `mock_ctx` fixtures from `conftest.py`.

## Pull Requests

- One logical change per PR.
- Include tests for any new tool or behaviour change.
- Update `README.md` if the tool table changes.
- Ensure `ruff`, `mypy`, and `pytest` all pass before requesting review.

## Reporting Security Issues

Please do not open public issues for security vulnerabilities. Follow the process in [SECURITY.md](SECURITY.md).
