# cisco-umbrella-mcp

An MCP (Model Context Protocol) server that exposes the [Cisco Umbrella](https://umbrella.cisco.com/) REST API as tools for AI assistants. Built with Python and [FastMCP](https://github.com/modelcontextprotocol/python-sdk).

## Features

- **Investigate** — Domain/IP threat intelligence, risk scores, WHOIS, passive DNS, malware samples
- **Policies** — Manage destination lists (allow/block) and application lists
- **Deployments** — View networks, sites, tunnels, roaming computers, virtual appliances
- **Reports** — Activity logs, top destinations/threats/identities, security summaries
- **Admin** — List users, roles, and API keys

## Prerequisites

- Python 3.10+
- A Cisco Umbrella account with an API key ([create one here](https://dashboard.umbrella.com))
- API key scopes configured for the resources you want to access

## Installation

### From source

```bash
git clone https://github.com/your-org/cisco-umbrella-mcp.git
cd cisco-umbrella-mcp
pip install -e .
```

### For development

```bash
pip install -e ".[dev]"
```

## Configuration

Copy the example environment file and fill in your credentials:

```bash
cp .env.example .env
```

Edit `.env`:

```env
API_KEY=your-umbrella-api-key
API_SECRET=your-umbrella-api-secret

# Optional: for multi-org/MSP child organization access
# UMBRELLA_ORG_ID=child-org-id
```

> **Important:** Never commit your `.env` file. It is already in `.gitignore`.

### Required API Key Scopes

Configure your Umbrella API key with the scopes needed for the tools you plan to use:

| Tool Category | Required Scope |
|---------------|---------------|
| Investigate | `investigate:read` |
| Destination Lists | `policies:read` and/or `policies:write` |
| Application Lists | `policies:read` and/or `policies:write` |
| Deployments | `deployments:read` |
| Reports | `reports:read` |
| Admin | `admin:read` |

## Usage

### Run the MCP server

```bash
# Using the entry point
cisco-umbrella-mcp

# Or as a Python module
python -m cisco_umbrella_mcp
```

The server runs over **stdio** transport by default, which is what MCP clients (like Claude Desktop) expect.

### Claude Desktop integration

Add to your Claude Desktop config (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "cisco-umbrella": {
      "command": "cisco-umbrella-mcp",
      "env": {
        "API_KEY": "your-api-key",
        "API_SECRET": "your-api-secret"
      }
    }
  }
}
```

Or if running from source:

```json
{
  "mcpServers": {
    "cisco-umbrella": {
      "command": "python",
      "args": ["-m", "cisco_umbrella_mcp"],
      "cwd": "/path/to/cisco-umbrella-mcp",
      "env": {
        "API_KEY": "your-api-key",
        "API_SECRET": "your-api-secret"
      }
    }
  }
}
```

### Testing with MCP Inspector

```bash
npx @modelcontextprotocol/inspector cisco-umbrella-mcp
```

## Available Tools

### Investigate (Threat Intelligence)

| Tool | Description |
|------|-------------|
| `umbrella_get_domain_status` | Get security status and categories for a domain |
| `umbrella_check_domains_bulk` | Bulk check up to 1000 domains |
| `umbrella_get_domain_volume` | DNS query volume over 30 days |
| `umbrella_get_domain_security` | Security reputation scores (DGA, entropy, etc.) |
| `umbrella_get_domain_risk_score` | Overall risk score (0–100) |
| `umbrella_get_cooccurrences` | Domains co-accessed with a given domain |
| `umbrella_get_related_domains` | Domains sharing infrastructure |
| `umbrella_get_subdomains` | Known subdomains |
| `umbrella_get_domain_timeline` | Security event timeline |
| `umbrella_search_domains` | Search domains by regex pattern |
| `umbrella_get_pdns_domain` | Passive DNS records for a domain |
| `umbrella_get_pdns_ip` | Passive DNS records for an IP |
| `umbrella_get_whois` | WHOIS registration data |
| `umbrella_get_whois_history` | Historical WHOIS records |
| `umbrella_search_whois_by_email` | Find domains by registrant email |
| `umbrella_search_whois_by_nameserver` | Find domains by nameserver |
| `umbrella_get_asn_for_ip` | ASN/BGP info for an IP |
| `umbrella_get_samples` | Malware samples for a domain/IP/URL |
| `umbrella_get_sample_info` | Malware sample details by hash |
| `umbrella_get_sample_connections` | Network connections from a sample |
| `umbrella_get_sample_behaviors` | Behavioral analysis of a sample |

### Policies

| Tool | Description |
|------|-------------|
| `umbrella_list_destination_lists` | List all destination lists |
| `umbrella_get_destination_list` | Get a destination list by ID |
| `umbrella_create_destination_list` | Create an allow or block list |
| `umbrella_update_destination_list` | Rename a destination list |
| `umbrella_delete_destination_list` | Delete a destination list |
| `umbrella_list_destinations` | List entries in a destination list |
| `umbrella_add_destinations` | Add domains/IPs/URLs to a list |
| `umbrella_remove_destinations` | Remove entries from a list |
| `umbrella_list_application_lists` | List all application lists |
| `umbrella_create_application_list` | Create an application list |
| `umbrella_update_application_list` | Update an application list |
| `umbrella_delete_application_list` | Delete an application list |

### Deployments

| Tool | Description |
|------|-------------|
| `umbrella_list_networks` | List all networks |
| `umbrella_get_network` | Get network details |
| `umbrella_list_sites` | List all sites |
| `umbrella_get_site` | Get site details |
| `umbrella_list_tunnels` | List network tunnels |
| `umbrella_get_tunnel` | Get tunnel details |
| `umbrella_get_tunnel_state` | Get tunnel operational state |
| `umbrella_list_tunnels_state` | Get all tunnel states |
| `umbrella_list_roaming_computers` | List roaming computers |
| `umbrella_get_roaming_computer` | Get roaming computer details |
| `umbrella_list_internal_domains` | List internal domains |
| `umbrella_list_virtual_appliances` | List virtual appliances |
| `umbrella_list_policies` | List deployment policies |

### Reports

| Tool | Description |
|------|-------------|
| `umbrella_get_activity` | All activity events in a time range |
| `umbrella_get_activity_dns` | DNS activity events |
| `umbrella_get_activity_proxy` | Web proxy activity events |
| `umbrella_get_activity_firewall` | Firewall activity events |
| `umbrella_get_top_destinations` | Top destinations by request count |
| `umbrella_get_top_identities` | Top identities by request count |
| `umbrella_get_top_categories` | Top categories by request count |
| `umbrella_get_top_threats` | Top threats detected |
| `umbrella_get_top_threat_types` | Top threat type categories |
| `umbrella_get_summary` | Overall security summary |
| `umbrella_get_total_requests` | Total request counts |
| `umbrella_list_categories` | List all category IDs and labels |
| `umbrella_list_identities` | List all identity IDs and names |

### Admin

| Tool | Description |
|------|-------------|
| `umbrella_list_users` | List organization users |
| `umbrella_get_user` | Get user details |
| `umbrella_list_roles` | List available roles |
| `umbrella_list_api_keys` | List API keys (no secrets) |
| `umbrella_get_api_key` | Get API key details |

## Development

### Run tests

```bash
pytest                                        # all tests
pytest tests/test_investigate.py              # single module
pytest tests/test_investigate.py::test_name   # single test
pytest -x                                     # stop on first failure
```

### Lint and format

```bash
ruff check src/ tests/
ruff format src/ tests/
```

### Type checking

```bash
mypy src/
```

## License

MIT
