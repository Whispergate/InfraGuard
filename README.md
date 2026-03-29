# InfraGuard

![InfraGuard Logo](/images/infraguard_logo.svg)

Red team infrastructure tracker and C2 redirector -- a modern alternative to [RedWarden](https://github.com/mgeeky/RedWarden).

InfraGuard sits between the internet and your C2 teamserver, validating every inbound request against your malleable C2 profile and blocking anything that doesn't conform. Scanners, bots, and blue team probes get redirected to a decoy site while legitimate beacon traffic passes through to your teamserver.

## Features

- **Multi-domain proxying** -- proxy multiple domains simultaneously, each with independent C2 profiles, upstreams, and rules
- **C2 profile validation** -- parse and enforce Cobalt Strike malleable profiles and Mythic HTTPX profiles as redirector rules
- **Scoring-based filter pipeline** -- 7 filters (IP, bot, header, DNS, geo, profile, replay) each contribute a 0.0-1.0 score; configurable threshold determines block/allow
- **Anti-bot / anti-crawling** -- 40+ known scanner/bot User-Agent patterns, header anomaly detection
- **IP intelligence** -- built-in CIDR blocklists for 19 security vendor ranges (Shodan, Censys, Rapid7, etc.), GeoIP filtering, reverse DNS keyword matching
- **Dynamic IP blocking** -- block IPs outside whitelisted ranges; auto-whitelist IPs after N valid C2 requests
- **Drop actions** -- redirect, TCP reset, proxy to decoy site, or tarpit (slow-drip response to waste scanner time)
- **Web dashboard** -- real-time SPA with live request feed, domain stats, top blocked IPs, WebSocket event streaming
- **Terminal UI** -- Textual-based TUI for monitoring directly over SSH
- **Backend config generation** -- generate Nginx, Caddy, or Apache configs from your C2 profiles
- **Plugin system** -- extend the filter pipeline with custom plugins
- **Structured logging** -- JSON-formatted structured logs via structlog
- **Tracking & persistence** -- SQLite with WAL mode for request logging, statistics, and node registry

## Requirements

- Python 3.12+

## Installation

### With pipx (recommended)

[pipx](https://pipx.pypa.io/) installs InfraGuard into its own isolated environment and makes the `infraguard` command available globally.

```bash
# Install from the repository
pipx install git+https://github.com/Whispergate/InfraGuard.git

# With all optional dependencies (dashboard, TUI, GeoIP, async DNS)
pipx install "infraguard[all] @ git+https://github.com/Whispergate/InfraGuard.git"
```

To add optional dependencies to an existing pipx install:

```bash
pipx inject infraguard textual          # Terminal UI
pipx inject infraguard fastapi jinja2   # Web dashboard extras
pipx inject infraguard maxminddb        # GeoIP lookups
pipx inject infraguard aiodns           # Async DNS resolution
```

### With uv

```bash
git clone https://github.com/Whispergate/InfraGuard.git
cd InfraGuard
uv sync
```

### With pip

```bash
git clone https://github.com/Whispergate/InfraGuard.git
cd InfraGuard
pip install .

# Or with optional dependencies
pip install ".[all]"
```

### Optional dependency groups

| Group | Packages | Purpose |
|---|---|---|
| `web` | fastapi, jinja2 | Extended web dashboard features |
| `tui` | textual | Terminal UI |
| `geoip` | maxminddb | GeoIP lookups via MaxMind databases |
| `dns` | aiodns | Async DNS resolution |
| `all` | All of the above | Everything |

### Verify installation

```bash
infraguard --version
```

## Quick Start

### 1. Generate a starter configuration

```bash
infraguard init -o config.yaml
```

This creates a `config.yaml` with annotated defaults. Edit it to match your deployment.

### 2. Parse and inspect your C2 profile

```bash
# Cobalt Strike malleable profile
infraguard profile parse profiles/jquery-c2.3.14.profile

# Mythic HTTPX profile (JSON)
infraguard profile parse profiles/mythic-http.json

# Output as JSON
infraguard profile parse profiles/jquery-c2.3.14.profile --format json

# Convert CS profile to InfraGuard JSON format
infraguard profile convert profiles/jquery-c2.3.14.profile -o profiles/jquery.json
```

### 3. Start the redirector proxy

```bash
infraguard run -c config.yaml
```

InfraGuard will:
- Load each domain's C2 profile
- Build the filter pipeline (IP, bot, header, DNS, profile conformance, replay detection)
- Start the ASGI reverse proxy on the configured listener

### 4. Start the web dashboard (optional)

```bash
infraguard dashboard -c config.yaml
```

Open `http://127.0.0.1:8080` in your browser. Pass `?token=YOUR_TOKEN` if auth is configured.

### 5. Launch the terminal UI (optional)

```bash
infraguard tui -c config.yaml
```

### 6. Generate web server configs (optional)

If you prefer to front InfraGuard with Nginx, Caddy, or Apache:

```bash
infraguard generate nginx -c config.yaml -o nginx.conf
infraguard generate caddy -c config.yaml -o Caddyfile
infraguard generate apache -c config.yaml -o .htaccess
```

These configs replicate URI matching, User-Agent validation, and header checks using native server directives. Note: transform chain validation and scoring require the InfraGuard proxy itself.

## Configuration

InfraGuard uses YAML configuration with environment variable support (`${ENV_VAR}` syntax).

### Minimal example

```yaml
listeners:
  - bind: "0.0.0.0"
    port: 443
    tls:
      cert: "/etc/letsencrypt/live/cdn.example.com/fullchain.pem"
      key: "/etc/letsencrypt/live/cdn.example.com/privkey.pem"
    domains:
      - "cdn.example.com"

domains:
  cdn.example.com:
    upstream: "https://10.0.0.5:8443"
    profile_path: "profiles/jquery-c2.3.14.profile"
    profile_type: "cobalt_strike"
    whitelist_cidrs:
      - "192.168.1.0/24"
    drop_action:
      type: "redirect"
      target: "https://jquery.com"
```

### Full configuration reference

```yaml
# ── Listeners ─────────────────────────────────────────────────────────
listeners:
  - bind: "0.0.0.0"
    port: 443
    tls:
      cert: "/path/to/fullchain.pem"
      key: "/path/to/privkey.pem"
    domains:
      - "cdn.example.com"
      - "static.example.com"
  - bind: "0.0.0.0"
    port: 80
    domains:
      - "cdn.example.com"

# ── Domains ───────────────────────────────────────────────────────────
# Each domain has its own C2 profile, upstream, and filtering rules.
domains:
  cdn.example.com:
    upstream: "https://10.0.0.5:8443"          # C2 teamserver address
    profile_path: "profiles/jquery-c2.profile"  # Path to C2 profile
    profile_type: "cobalt_strike"               # cobalt_strike | mythic
    whitelist_cidrs:                             # Only these IPs allowed (if set)
      - "192.168.1.0/24"
      - "10.0.0.0/8"
    decoy_dir: "decoys/jquery/"                 # Static files served to blocked requests
    drop_action:
      type: "redirect"                          # redirect | reset | proxy | tarpit
      target: "https://jquery.com"              # Redirect URL or proxy target
    rules: []                                   # Additional rule references

  static.example.com:
    upstream: "https://10.0.0.5:8443"
    profile_path: "profiles/mythic-http.json"
    profile_type: "mythic"
    drop_action:
      type: "proxy"
      target: "https://example.com"

# ── IP Intelligence ───────────────────────────────────────────────────
intel:
  geoip_db: "/usr/share/GeoIP/GeoLite2-City.mmdb"  # MaxMind DB path
  blocked_countries: ["CN", "RU", "KP"]
  blocked_asns: [14061, 16276]                       # e.g. DigitalOcean, OVH
  auto_block_scanners: true                          # Block known security vendor IPs
  dynamic_whitelist_threshold: 3                     # Auto-whitelist after N valid requests
  banned_ip_file: "data/banned_ips.txt"              # Additional CIDR blocklist file
  banned_words_file: "data/banned_words.txt"         # Header keyword blocklist file

# ── Filter Pipeline ───────────────────────────────────────────────────
pipeline:
  block_score_threshold: 0.7    # Cumulative score above this = blocked
  enable_ip_filter: true        # IP whitelist/blacklist checks
  enable_bot_filter: true       # User-Agent bot/scanner detection
  enable_header_filter: true    # Banned keywords in HTTP headers
  enable_geo_filter: true       # GeoIP-based filtering
  enable_dns_filter: true       # Reverse DNS hostname checks
  enable_replay_filter: true    # Anti-replay (duplicate request rejection)
  enable_profile_filter: true   # C2 profile conformance validation

# ── Tracking ──────────────────────────────────────────────────────────
tracking:
  db_path: "infraguard.db"      # SQLite database path
  retention_days: 30            # How long to keep request logs

# ── Dashboard API ─────────────────────────────────────────────────────
api:
  bind: "127.0.0.1"
  port: 8080
  auth_token: "${INFRAGUARD_API_TOKEN}"   # Bearer token (env var recommended)

# ── Logging ───────────────────────────────────────────────────────────
logging:
  level: "INFO"                 # DEBUG | INFO | WARNING | ERROR
  format: "json"                # json | console

# ── Plugins ───────────────────────────────────────────────────────────
plugins:
  - "infraguard.plugins.builtin.example"
```

### Drop actions

| Action | Behavior |
|---|---|
| `redirect` | HTTP 302 redirect to the target URL |
| `reset` | Immediately close the TCP connection (HTTP 444) |
| `proxy` | Fetch and serve content from the target URL (look like a real site) |
| `tarpit` | Slow-drip response to waste scanner/bot time |

### Profile types

| Type | File format | Description |
|---|---|---|
| `cobalt_strike` | `.profile` | Cobalt Strike malleable C2 profile DSL |
| `mythic` | `.json` | Mythic HTTPX profile JSON |

Profile type is auto-detected from the file extension. Use `--type` to override.

## Filter Pipeline

Requests flow through the filter chain in order. Each filter returns a score (0.0 = legitimate, 1.0 = malicious). Scores accumulate, and if the total exceeds `block_score_threshold`, the request is blocked.

```
Request
  |
  v
[IP Filter]       Block known bad IPs, enforce whitelists
  |
  v
[Bot Filter]      Detect scanner/bot User-Agents, header anomalies
  |
  v
[Header Filter]   Check for banned keywords in header names/values
  |
  v
[DNS Filter]      Reverse DNS lookup, check for security vendor hostnames
  |
  v
[Profile Filter]  Validate URI, HTTP verb, headers, metadata, transforms
  |
  v
[Replay Filter]   Reject duplicate requests within time window
  |
  v
ALLOW or BLOCK (based on cumulative score)
```

Hard blocks (score = 1.0) short-circuit immediately. Soft signals (score < threshold) accumulate.

## CLI Reference

```
infraguard --version                          Show version
infraguard --help                             Show help

infraguard run -c config.yaml                 Start the reverse proxy
infraguard run -c config.yaml --port 8443     Override listen port
infraguard run -c config.yaml --host 0.0.0.0  Override bind address

infraguard dashboard -c config.yaml           Start the web dashboard
infraguard tui -c config.yaml                 Launch terminal UI

infraguard profile parse <file>               Parse and display a C2 profile
infraguard profile parse <file> --format json  Output as JSON
infraguard profile parse <file> --type mythic  Force profile type
infraguard profile convert <file> -o out.json  Convert profile to JSON

infraguard generate nginx -c config.yaml       Generate Nginx config
infraguard generate caddy -c config.yaml       Generate Caddyfile
infraguard generate apache -c config.yaml      Generate Apache .htaccess

infraguard init -o config.yaml                 Generate starter config
infraguard validate -c config.yaml             Validate config file
```

## Dashboard API

When running with `infraguard dashboard`, the following REST API is available:

| Endpoint | Method | Description |
|---|---|---|
| `/api/stats` | GET | Overview statistics (last 24h by default, `?hours=N`) |
| `/api/requests` | GET | Recent request log (`?limit=50&domain=...`) |
| `/api/nodes` | GET | List registered redirector nodes |
| `/api/nodes/register` | POST | Register a new node |
| `/api/nodes/{id}/heartbeat` | POST | Update node heartbeat |
| `/api/intel/classify` | POST | Classify an IP address (`{"ip": "1.2.3.4"}`) |
| `/api/intel/blocklist` | POST | Add CIDRs to blocklist (`{"cidrs": ["1.2.3.0/24"]}`) |
| `/api/config` | GET | Current configuration (sanitized) |
| `/api/config/domains` | GET | List configured domains |
| `/api/decoys` | GET | List decoy files per domain |
| `/api/decoys/{domain}/{file}` | GET | Read a decoy file |
| `/api/decoys/{domain}/{file}` | PUT | Update a decoy file (`{"content": "..."}`) |
| `/ws/events` | WS | Real-time event stream (WebSocket) |

All API endpoints require a `Authorization: Bearer <token>` header when `auth_token` is configured.

## Architecture

```
infraguard/
    __init__.py              Package init
    __main__.py              python -m infraguard entry
    main.py                  Click CLI
    config/                  YAML config loading + Pydantic validation
    core/                    ASGI proxy engine (app, proxy, router, TLS, drop actions)
    profiles/                C2 profile parsers (Cobalt Strike + Mythic)
    pipeline/                Request validation filters (IP, bot, header, DNS, geo, profile, replay)
    intel/                   IP intelligence (blocklists, GeoIP, reverse DNS, known ranges)
    tracking/                SQLite persistence (request logging, stats, node registry)
    plugins/                 Plugin system (protocol, loader, builtins)
    ui/
        api/                 REST API + WebSocket (Starlette)
        web/                 SPA dashboard (HTML/JS/CSS)
        tui/                 Terminal UI (Textual)
    backends/                Config generators (Nginx, Caddy, Apache)
    models/                  Shared types and event models
```

## Comparison with RedWarden

| Feature | RedWarden | InfraGuard |
|---|---|---|
| Architecture | Single ~99KB file | Modular package (71 files) |
| Profile parsing | Regex state machine | Structured parser with full block/transform support |
| C2 support | Cobalt Strike only | Cobalt Strike + Mythic |
| Filter model | Binary pass/fail | Scoring-based (0.0-1.0 threshold) |
| Operator UI | None | Web dashboard + Terminal UI |
| Config generation | None | Nginx, Caddy, Apache |
| Plugin system | Basic 4-method interface | Protocol-based with lifecycle hooks |
| Anti-replay | SQLite hash | In-memory with configurable window |
| Drop actions | redirect, reset, proxy | redirect, reset, proxy, tarpit |
| Logging | Custom colored output | Structured JSON (structlog) |
| Async | Tornado callbacks | Native async/await (ASGI + uvicorn) |

## Writing Plugins

Create a Python module with a `Plugin` class:

```python
# my_plugin.py
from infraguard.models.common import FilterResult
from infraguard.pipeline.base import RequestContext
from starlette.responses import Response


class Plugin:
    name = "my-plugin"
    version = "1.0.0"

    async def on_request(self, ctx: RequestContext) -> FilterResult | None:
        # Return FilterResult.block(...) to block, or None to pass through
        if "suspicious" in ctx.request.headers.get("x-custom", ""):
            return FilterResult.block(reason="Custom check failed", score=0.8)
        return None

    async def on_response(self, ctx: RequestContext, response: Response) -> Response | None:
        return None

    async def on_startup(self) -> None:
        pass

    async def on_shutdown(self) -> None:
        pass
```

Add it to your config:

```yaml
plugins:
  - "my_plugin"
```

## License

BSD 2-Clause License. See [LICENSE](LICENSE) for details.

Copyright (c) 2026, Whispergate
