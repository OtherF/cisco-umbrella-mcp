# cisco-umbrella-mcp

An MCP (Model Context Protocol) server that exposes the [Cisco Umbrella](https://umbrella.cisco.com/) REST API as tools for AI assistants. Built with Python and [FastMCP](https://github.com/modelcontextprotocol/python-sdk).

## Features

**Read-only MCP tools across 6 API scopes:**

- **Investigate** — Domain/IP/URL threat intelligence, risk scores, WHOIS, passive DNS, malware samples
- **Policies** — Query destination lists, application lists, application usage
- **Deployments** — Networks, sites, tunnels, roaming computers, virtual appliances, tags, SWG device settings
- **Reports** — Activity logs (DNS, proxy, firewall, intrusion, AMP), top destinations/threats/identities, bandwidth, request time-series, app discovery, API usage
- **Admin** — Users, roles, API key metadata
- **App Discovery** — Cloud application discovery, risk assessment, compliance attributes

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

The server requires two environment variables:

| Variable | Required | Description |
|----------|----------|-------------|
| `API_KEY` | Yes | Umbrella API key |
| `API_SECRET` | Yes | Umbrella API secret |
| `UMBRELLA_ORG_ID` | No | Child org ID (for MSP/multi-org) |
| `TOKEN_URL` | No | Override token endpoint (default: `https://api.umbrella.com/auth/v2/token`) |

Credentials are passed from the MCP client configuration — **not** stored on the server. See connection scenarios below.

### Required API Key Scopes

Configure your Umbrella API key with the scopes needed for the tools you plan to use:

| Tool Category | Required Scope |
|---------------|---------------|
| Investigate | `investigate:read` |
| Policies | `policies:read` |
| Deployments | `deployments:read` |
| Reports | `reports:read` |
| App Discovery | `reports:read` |
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

### Scenario 1: Local (same host)

The MCP client and server run on the same machine. Credentials are passed via the `env` block:

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

Or if running from a cloned source directory:

```json
{
  "mcpServers": {
    "cisco-umbrella": {
      "command": "/path/to/cisco-umbrella-mcp/.venv/bin/python",
      "args": ["-m", "cisco_umbrella_mcp"],
      "env": {
        "API_KEY": "your-api-key",
        "API_SECRET": "your-api-secret"
      }
    }
  }
}
```

### Scenario 2: WSL → Windows host

The server is installed in WSL; the MCP client (Claude Desktop, VS Code) runs on Windows. Claude Desktop does **not** forward the `env` block to WSL processes, so credentials must be inlined in the bash command:

```json
{
  "mcpServers": {
    "cisco-umbrella": {
      "command": "wsl.exe",
      "args": [
        "--", "bash", "-c",
        "API_KEY='your-api-key' API_SECRET='your-api-secret' /path/to/cisco-umbrella-mcp/.venv/bin/python -m cisco_umbrella_mcp"
      ]
    }
  }
}
```

> **Notes:**
> - Replace `/path/to/cisco-umbrella-mcp` with the actual WSL path.
> - Use `--distribution Ubuntu` instead of `--` to target a specific WSL distro (`wsl.exe --list` shows distro names).
> - Credentials are passed as inline env vars in the bash command — not stored on disk.
> - `exec` is not needed since Python replaces the shell process.

### Scenario 3: Remote server via SSH

The server is installed on a remote Linux server. The MCP client connects via SSH with key-based auth:

```json
{
  "mcpServers": {
    "cisco-umbrella": {
      "command": "ssh",
      "args": [
        "-o", "StrictHostKeyChecking=accept-new",
        "-i", "/path/to/ssh-key",
        "user@remote-host",
        "API_KEY='your-api-key' API_SECRET='your-api-secret' cisco-umbrella-mcp"
      ]
    }
  }
}
```

> **Notes:**
> - SSH key auth avoids interactive password prompts.
> - `StrictHostKeyChecking=accept-new` auto-accepts on first connect.
> - Credentials are passed as inline env vars — no credentials stored on the remote server.
> - The server must be installed on the remote host (`pip install cisco-umbrella-mcp` or from source).

If running from source on the remote host:

```json
{
  "mcpServers": {
    "cisco-umbrella": {
      "command": "ssh",
      "args": [
        "-o", "StrictHostKeyChecking=accept-new",
        "-i", "/path/to/ssh-key",
        "user@remote-host",
        "API_KEY='your-api-key' API_SECRET='your-api-secret' /path/to/cisco-umbrella-mcp/.venv/bin/python -m cisco_umbrella_mcp"
      ]
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
| `umbrella_get_pdns_raw` | Raw passive DNS records |
| `umbrella_get_pdns_timeline` | Passive DNS timeline |
| `umbrella_get_whois` | WHOIS registration data |
| `umbrella_get_whois_history` | Historical WHOIS records |
| `umbrella_search_whois_by_email` | Find domains by registrant email |
| `umbrella_search_whois_by_nameserver` | Find domains by nameserver |
| `umbrella_search_whois_advanced` | Search WHOIS by field and regex |
| `umbrella_list_nameservers_whois` | List nameservers with domain counts |
| `umbrella_get_asn_for_ip` | ASN/BGP info for an IP |
| `umbrella_get_asn_prefixes` | Get IP prefixes for an ASN |
| `umbrella_get_samples` | Malware samples for a domain/IP/URL |
| `umbrella_get_sample_info` | Malware sample details by hash |
| `umbrella_get_sample_connections` | Network connections from a sample |
| `umbrella_get_sample_behaviors` | Behavioral analysis of a sample |
| `umbrella_get_sample_artifacts` | File artifacts from a malware sample |
| `umbrella_get_domain_tags` | Security tags for a domain |

### Policies

| Tool | Description |
|------|-------------|
| `umbrella_list_destination_lists` | List all destination lists |
| `umbrella_get_destination_list` | Get a destination list by ID |
| `umbrella_list_destinations` | List entries in a destination list |
| `umbrella_list_application_lists` | List all application lists |
| `umbrella_get_application_usage` | Get usage statistics across all application lists |

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
| `umbrella_get_roaming_org_info` | Get org-level roaming computer properties |
| `umbrella_list_internal_domains` | List internal domains |
| `umbrella_list_virtual_appliances` | List virtual appliances |
| `umbrella_list_policies` | List deployment policies |
| `umbrella_list_tags` | List roaming computer tags |
| `umbrella_list_tag_devices` | List devices with a specific tag |
| `umbrella_list_swg_device_settings` | Get per-device SWG override settings |

### Reports

| Tool | Description |
|------|-------------|
| `umbrella_get_activity` | All activity events in a time range |
| `umbrella_get_activity_dns` | DNS activity events |
| `umbrella_get_activity_proxy` | Web proxy activity events |
| `umbrella_get_activity_firewall` | Firewall activity events |
| `umbrella_get_activity_intrusion` | IPS/intrusion detection events |
| `umbrella_get_activity_amp` | AMP retrospective events (files reclassified as malicious) |
| `umbrella_get_activity_ip` | IP-layer activity events |
| `umbrella_get_top_destinations` | Top destinations by request count |
| `umbrella_get_top_destinations_by_type` | Top destinations by traffic type |
| `umbrella_get_top_identities` | Top identities by request count |
| `umbrella_get_top_identities_by_type` | Top identities by traffic type |
| `umbrella_get_top_categories` | Top categories by request count |
| `umbrella_get_top_categories_by_type` | Top categories by traffic type |
| `umbrella_get_top_threats` | Top threats detected |
| `umbrella_get_top_threats_by_type` | Top threats by traffic type |
| `umbrella_get_top_threat_types` | Top threat type categories |
| `umbrella_get_top_threat_types_by_type` | Top threat types by traffic type |
| `umbrella_get_summary` | Overall security summary |
| `umbrella_get_summary_by_type` | Security summary by traffic type |
| `umbrella_get_total_requests` | Total request counts |
| `umbrella_get_total_requests_by_type` | Total requests by traffic type |
| `umbrella_get_requests_by_hour` | Hourly request volume time-series |
| `umbrella_get_requests_by_timerange` | Aggregate request counts for a period |
| `umbrella_get_requests_by_hour_and_category` | Hourly request volume by category |
| `umbrella_get_requests_by_timerange_and_category` | Aggregate request counts per category |
| `umbrella_get_bandwidth_by_hour` | Hourly proxy bandwidth usage |
| `umbrella_get_bandwidth_by_timerange` | Aggregate proxy bandwidth for a period |
| `umbrella_get_top_urls` | Top URLs by request count |
| `umbrella_get_top_ips` | Top external IPs |
| `umbrella_get_top_internal_ips` | Top internal IPs |
| `umbrella_get_top_files` | Top files by transfer count |
| `umbrella_get_top_event_types` | Top event types |
| `umbrella_get_top_dns_query_types` | Top DNS query types |
| `umbrella_get_identity_distribution` | Request distribution by identity type |
| `umbrella_list_categories` | List all category IDs and labels |
| `umbrella_list_identities` | List all identity IDs and names |
| `umbrella_get_api_usage_requests` | API request counts by endpoint |
| `umbrella_get_api_usage_responses` | API response code distribution |
| `umbrella_get_api_usage_by_key` | API request counts per key |
| `umbrella_get_api_usage_summary` | High-level API usage summary |
| `umbrella_get_provider_categories` | MSP: category breakdown by org |
| `umbrella_get_provider_deployments` | MSP: deployment statistics |
| `umbrella_get_provider_requests_by_org` | MSP: requests per org |
| `umbrella_get_provider_requests_by_hour` | MSP: hourly request volume |
| `umbrella_get_provider_requests_by_timerange` | MSP: aggregate requests |
| `umbrella_get_provider_requests_by_category` | MSP: requests by category |
| `umbrella_get_provider_requests_by_destination` | MSP: requests by destination |
| `umbrella_get_provider_category_requests_by_org` | MSP: category requests by org |

### App Discovery

| Tool | Description |
|------|-------------|
| `umbrella_get_app_discovery_applications` | List discovered cloud applications with risk scores |
| `umbrella_get_app_discovery_application_info` | Enriched info for discovered applications |
| `umbrella_get_app_discovery_application_attributes` | Security/compliance attributes for a specific app |
| `umbrella_list_app_categories` | List application categories |
| `umbrella_get_app_discovery_application` | Get app details by ID |
| `umbrella_get_app_discovery_identities` | Identities using an app |
| `umbrella_get_app_discovery_risk` | Risk assessment for an app |
| `umbrella_list_app_discovery_protocols` | List discovered protocols |
| `umbrella_get_app_discovery_protocol` | Protocol details |
| `umbrella_get_app_discovery_protocol_identities` | Identities using a protocol |

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
