![InfraGuard Logo](/images/infraguard_logo.svg)

Red team infrastructure tracker and C2 redirector -- a modern alternative to [RedWarden](https://github.com/mgeeky/RedWarden).

InfraGuard sits between the internet and your C2 teamserver, validating every inbound request against your malleable C2 profile and blocking anything that doesn't conform. Scanners, bots, and blue team probes get redirected to a decoy site while legitimate beacon traffic passes through to your teamserver.

## Features

- **Multi-domain proxying** -- proxy multiple domains simultaneously, each with independent C2 profiles, upstreams, and rules
- **C2 profile validation** -- parse and enforce Cobalt Strike malleable profiles and Mythic HTTPX profiles as redirector rules
- **Scoring-based filter pipeline** -- 7 filters (IP, bot, header, DNS, geo, profile, replay) each contribute a 0.0-1.0 score; configurable threshold determines block/allow
- **Anti-bot / anti-crawling** -- 40+ known scanner/bot User-Agent patterns, header anomaly detection
- **IP intelligence** -- built-in CIDR blocklists for 19 security vendor ranges (Shodan, Censys, Rapid7, etc.), GeoIP filtering, reverse DNS keyword matching
- **Threat intel feeds** -- auto-update blocklists from public sources (abuse.ch, Emerging Threats, Spamhaus DROP, Binary Defense) with configurable refresh interval and disk caching
- **Rule ingestion** -- import IP blocklists and User-Agent patterns from existing `.htaccess` and `robots.txt` files
- **Dynamic IP blocking** -- block IPs outside whitelisted ranges; auto-whitelist IPs after N valid C2 requests
- **Content delivery routes** -- serve payloads, decoys, and static files at specific paths via PwnDrop, local filesystem, or HTTP proxy backends, with optional conditional delivery (real content to targets, decoys to scanners)
- **Drop actions** -- redirect, TCP reset, proxy to decoy site, or tarpit (slow-drip response to waste scanner time)
- **Web dashboard** -- real-time SPA with login page, live request feed, domain stats, top blocked IPs, authenticated WebSocket event streaming
- **Terminal UI** -- Textual-based TUI with login screen, live API polling, color-coded request log
- **SIEM integration** -- built-in plugins for Elasticsearch, Wazuh, and Syslog (CEF/JSON) with batched forwarding
- **Webhook alerts** -- built-in plugins for Discord (embeds), Slack (Block Kit), and generic webhook (Rocket.Chat, Mattermost, Teams)
- **Plugin system** -- event-driven architecture with `on_event` hooks, per-plugin config, event filtering (only_blocked, min_score, domain include/exclude)
- **Backend config generation** -- generate Nginx, Caddy, or Apache configs with full operator customization (TLS, IP filtering, header checks, aliases, custom headers)
- **Docker deployment** -- Dockerfile + docker-compose with optional Let's Encrypt, GeoIP downloader, and PwnDrop payload server
- **GeoIP support** -- all three GeoLite2 databases (City, ASN, Country) with Docker auto-download
- **Self-signed TLS fallback** -- auto-generates certificates when configured paths don't exist
- **Environment variable support** -- `.env` file auto-loaded; `${VAR}` syntax works in all config values and keys
- **Configurable health endpoint** -- change the health check path to avoid fingerprinting
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

### With Docker

```bash
git clone https://github.com/Whispergate/InfraGuard.git
cd InfraGuard
cp .env.example .env        # Edit with your values
docker compose up -d
```

See [Docker Deployment](#docker-deployment) for full details.

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

### 1. Set up environment

```bash
cp .env.example .env
```

Edit `.env` with your domain, teamserver address, and API token:

```bash
INFRAGUARD_DOMAIN=cdn.example.com
INFRAGUARD_DOMAIN_EMAIL=operator@example.com
INFRAGUARD_CS_UPSTREAM=https://10.0.0.5:8443
INFRAGUARD_API_TOKEN=your-secret-token
```

### 2. Generate a starter configuration

```bash
infraguard init -o config.yaml
```

This creates a `config.yaml` with annotated defaults. Environment variables like `${INFRAGUARD_API_TOKEN}` are resolved from your `.env` file automatically.

### 3. Parse and inspect your C2 profile

```bash
# Cobalt Strike malleable profile
infraguard profile parse examples/jquery-c2.3.14.profile

# Mythic HTTPX profile (JSON)
infraguard profile parse examples/mythic-httpx.json

# Output as JSON
infraguard profile parse examples/jquery-c2.3.14.profile --format json

# Convert CS profile to InfraGuard JSON format
infraguard profile convert examples/jquery-c2.3.14.profile -o profiles/jquery.json
```

### 4. Start the redirector proxy

```bash
infraguard run -c config.yaml
```

InfraGuard will:
- Load each domain's C2 profile
- Build the filter pipeline (IP, bot, header, DNS, profile conformance, replay detection)
- Connect to the tracking database and start recording events
- Auto-generate a self-signed TLS certificate if the configured cert paths don't exist
- Start the ASGI reverse proxy on the configured listener

### 5. Start the web dashboard (optional)

```bash
infraguard dashboard -c config.yaml
```

Open `http://127.0.0.1:8080` in your browser. Pass `?token=YOUR_TOKEN` if auth is configured. The dashboard shows live stats, request logs, domain breakdowns, and top blocked IPs.

### 6. Launch the terminal UI (optional)

```bash
# With login screen
infraguard tui

# Auto-connect to a dashboard
infraguard tui --url http://127.0.0.1:8080 --token your-secret-token

# Read connection details from config
infraguard tui -c config.yaml
```

The TUI shows a login screen where you enter the dashboard URL and API token. If `--url` and `--token` are provided (or read from config), it skips login and connects directly.

### 7. Import existing server rules (optional)

```bash
# Ingest .htaccess IP blocks and User-Agent rules
infraguard ingest .htaccess --format blocklist -o banned_ips.txt

# Ingest robots.txt bot names
infraguard ingest robots.txt

# Ingest multiple files
infraguard ingest .htaccess robots.txt --format json
```

### 8. Generate web server configs (optional)

```bash
# Basic generation from config
infraguard generate nginx -c config.yaml -o nginx.conf

# With operator overrides
infraguard generate nginx -c config.yaml \
  --listen-port 8443 \
  --redirect-url "https://decoy.example.com" \
  --alias "cdn.example.com:static.example.com" \
  --header "X-Frame-Options:DENY" \
  --header "X-Content-Type-Options:nosniff"

# Other backends
infraguard generate caddy -c config.yaml -o Caddyfile
infraguard generate apache -c config.yaml -o vhost.conf
```

Generated configs include TLS paths, IP allow/deny blocks from whitelists, User-Agent validation, header checks, and proxy rules -- all derived from your C2 profile and InfraGuard config.

## Environment Variables

InfraGuard auto-loads a `.env` file from the config file's directory or the current working directory. Copy `.env.example` to `.env` and fill in your values.

The `${VAR}` syntax works everywhere in `config.yaml` -- including dictionary keys, list values, and nested strings. Real environment variables take precedence over `.env` file values.

| Variable | Purpose | Example |
|---|---|---|
| `INFRAGUARD_DOMAIN` | Primary redirector domain | `cdn.example.com` |
| `INFRAGUARD_DOMAIN_EMAIL` | Email for Let's Encrypt registration | `operator@example.com` |
| `INFRAGUARD_LETSENCRYPT` | Enable auto-cert via certbot | `true` / `false` |
| `INFRAGUARD_TLS_CERT` | Path to TLS certificate | `/app/certs/live/.../fullchain.pem` |
| `INFRAGUARD_TLS_KEY` | Path to TLS private key | `/app/certs/live/.../privkey.pem` |
| `INFRAGUARD_API_TOKEN` | Dashboard API bearer token | `your-secret-token` |
| `INFRAGUARD_CS_UPSTREAM` | Cobalt Strike teamserver address | `https://10.0.0.5:8443` |
| `INFRAGUARD_MYTHIC_UPSTREAM` | Mythic teamserver address | `https://10.0.0.6:443` |
| `INFRAGUARD_GEOIP_DB` | Path to MaxMind GeoLite2 database | `/usr/share/GeoIP/GeoLite2-City.mmdb` |
| `INFRAGUARD_HEALTH_PATH` | Custom health endpoint path (OPSEC) | `status`, `api/ping`, `.well-known/health` |
| `INFRAGUARD_LOG_LEVEL` | Log level | `DEBUG` / `INFO` / `WARNING` |

## Configuration

InfraGuard uses YAML configuration with environment variable support (`${ENV_VAR}` syntax).

### Minimal example

```yaml
listeners:
  - bind: "0.0.0.0"
    port: 443
    tls:
      cert: "${INFRAGUARD_TLS_CERT}"
      key: "${INFRAGUARD_TLS_KEY}"
    domains:
      - "cdn.example.com"

domains:
  cdn.example.com:
    upstream: "https://10.0.0.5:8443"
    profile_path: "examples/jquery-c2.3.14.profile"
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
  feeds:
    enabled: true                                    # Auto-update from threat intel feeds
    refresh_interval_hours: 6                        # How often to refresh
    cache_dir: ".infraguard/feeds"                   # Disk cache for fetched feeds
    urls: []                                         # Empty = use built-in defaults

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
  auth_token: "${INFRAGUARD_API_TOKEN}"              # Bearer token (env var recommended)
  health_path: "/health"                             # Customize to avoid fingerprinting

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

### TLS Certificate Resolution

InfraGuard resolves TLS certificates in this order:

1. **Configured paths** -- if `tls.cert` and `tls.key` exist on disk, use them
2. **Let's Encrypt** -- if running via Docker with `INFRAGUARD_LETSENCRYPT=true`, certbot places certs at the configured paths
3. **Self-signed fallback** -- if neither exists, a self-signed certificate is auto-generated for the domain and saved to `.infraguard/tls/`

Self-signed certs include SANs for the domain, its wildcard, `localhost`, and `127.0.0.1`.

### Threat Intel Feeds

When `intel.feeds.enabled` is `true`, InfraGuard periodically fetches IP blocklists from public threat intelligence sources and merges them into the blocklist. Fetched data is cached to disk so it survives restarts.

Built-in feed sources (used when `urls` is empty):
- Feodo Tracker (Dridex, Emotet, TrickBot C2s)
- Emerging Threats compromised IPs
- CI Army bad IPs
- Spamhaus DROP (Don't Route Or Peer)
- Binary Defense IP banlist

Add custom feeds by providing URLs that serve plain-text IP/CIDR lists (one per line):

```yaml
intel:
  feeds:
    urls:
      - "https://example.com/custom-blocklist.txt"
      - "https://example.com/another-feed.txt"
```

### Configurable Health Endpoint

By default, the proxy exposes a health check at `/health`. Change this to avoid fingerprinting:

```yaml
api:
  health_path: "/${INFRAGUARD_HEALTH_PATH}"
```

```bash
# .env
INFRAGUARD_HEALTH_PATH=api/v1/status
```

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

## Content Delivery Routes

Content routes let you serve payloads, decoys, and static files at specific URI paths through the same redirector that handles C2 traffic. They are evaluated **before** the C2 profile filter, so paths like `/downloads/payload.exe` go to your payload server instead of being blocked as "URI not in profile".

```
Request → resolve domain → match content route?
                             ├─ YES → [optional fingerprint check] → serve from backend
                             └─ NO  → run full C2 filter pipeline → proxy/drop
```

### Backend types

| Type | Description | Target format |
|---|---|---|
| `pwndrop` | Proxy to a PwnDrop instance | `http://pwndrop:80` or `https://pwndrop.example.com` |
| `filesystem` | Serve local files from a directory | `/app/decoys` or `./decoys/cdn.example.com` |
| `http_proxy` | Generic reverse proxy to any URL | `https://redfile.internal:9090` |

### Configuration

```yaml
domains:
  cdn.example.com:
    upstream: "https://10.0.0.5:8443"
    profile_path: "examples/jquery-c2.3.14.profile"
    profile_type: "cobalt_strike"

    content_routes:
      # PwnDrop payload delivery with conditional filtering
      - path: "/downloads/*"
        backend:
          type: "pwndrop"
          target: "http://pwndrop:80"
          auth_token: "${PWNDROP_TOKEN}"
        conditional:
          score_threshold: 0.5
          scanner_backend:
            type: "http_proxy"
            target: "https://jquery.com/downloads/"
        track: true

      # Static files from local directory
      - path: "/assets/*"
        backend:
          type: "filesystem"
          target: "./decoys/cdn.example.com"

      # RedFile conditional delivery
      - path: "/share/*"
        backend:
          type: "http_proxy"
          target: "https://redfile.internal:9090"
        conditional:
          score_threshold: 0.4
```

### URI patterns

| Pattern | Type | Example match |
|---|---|---|
| `/file.exe` | Exact | Only `/file.exe` |
| `/downloads/*` | Prefix glob | `/downloads/payload.exe`, `/downloads/doc.pdf` |
| `~^/d/[a-f0-9]+` | Regex (prefix `~`) | `/d/abc123`, `/d/ff00` |

First match wins. Routes are evaluated in config order.

### Conditional delivery

When `conditional` is configured, InfraGuard runs a **fingerprint pipeline** (IP, bot, header, geo filters -- but NOT the C2 profile filter) to classify the visitor:

- **Score below threshold** -- legitimate target, serve the real payload from the primary backend
- **Score above threshold** -- scanner/bot detected, serve from `scanner_backend` or return 404

This lets you deliver payloads to real targets while showing decoy content to blue team scanners -- all through the same URL.

### Download tracking

Content delivery events are recorded in the same tracking database with `filter_result` values:
- `content_served` -- real content delivered
- `content_blocked` -- scanner detected, decoy served

These appear in the dashboard alongside C2 traffic stats. The `/api/stats/content` endpoint provides aggregated content delivery statistics.

## Rule Ingestion

Import IP blocklists and User-Agent patterns from existing server configuration files:

```bash
# Parse .htaccess deny rules, RewriteCond UA patterns, Require directives
infraguard ingest .htaccess

# Parse robots.txt bot names and disallowed paths
infraguard ingest robots.txt

# Combine multiple files
infraguard ingest .htaccess robots.txt

# Output as a blocklist file (usable as intel.banned_ip_file)
infraguard ingest .htaccess --format blocklist -o banned_ips.txt

# Output as JSON for programmatic use
infraguard ingest .htaccess robots.txt --format json
```

Supported `.htaccess` directives:
- `Deny from` / `Allow from` -- IP/CIDR extraction
- `Require ip` / `Require not ip` -- IP whitelist/blacklist
- `RewriteCond %{HTTP_USER_AGENT}` -- User-Agent pattern extraction (splits alternation groups)
- `SetEnvIfNoCase User-Agent` -- User-Agent pattern extraction

Supported `robots.txt` directives:
- `User-agent:` (non-wildcard) -- bot name extraction
- `Disallow:` -- blocked path extraction

## CLI Reference

```
infraguard --version                                Show version
infraguard --help                                   Show help

infraguard run -c config.yaml                       Start the reverse proxy
infraguard run -c config.yaml --port 8443           Override listen port
infraguard run -c config.yaml --host 0.0.0.0        Override bind address

infraguard dashboard -c config.yaml                 Start the web dashboard
infraguard dashboard -c config.yaml --port 9090     Override dashboard port

infraguard tui                                      Launch TUI with login screen
infraguard tui --url http://host:8080 --token TOK   Auto-connect to dashboard
infraguard tui -c config.yaml                       Read URL/token from config

infraguard profile parse <file>                     Parse and display a C2 profile
infraguard profile parse <file> --format json        Output as JSON
infraguard profile parse <file> --type mythic        Force profile type
infraguard profile convert <file> -o out.json        Convert profile to JSON

infraguard ingest <files...>                         Ingest .htaccess/robots.txt rules
infraguard ingest <files...> --format blocklist      Output as IP blocklist
infraguard ingest <files...> --format json           Output as JSON
infraguard ingest <files...> -o banned_ips.txt       Write blocklist to file

infraguard generate nginx -c config.yaml             Generate Nginx config
infraguard generate caddy -c config.yaml             Generate Caddyfile
infraguard generate apache -c config.yaml            Generate Apache VirtualHost

infraguard init -o config.yaml                       Generate starter config
infraguard validate -c config.yaml                   Validate config file
```

### Generator options

The `generate` command accepts additional flags for operator customization:

| Flag | Description |
|---|---|
| `--listen-port PORT` | Override listen port (default: from config) |
| `--ssl-cert PATH` | Override SSL certificate path |
| `--ssl-key PATH` | Override SSL key path |
| `--redirect-url URL` | Override redirect URL for blocked requests |
| `--default-action redirect\|404` | Action for non-matching requests |
| `--no-ip-filter` | Omit IP allow/deny blocks |
| `--no-header-check` | Omit header validation rules |
| `--alias DOMAIN:ALIAS` | Add server name alias (repeatable) |
| `--header NAME:VALUE` | Add custom response header (repeatable) |

## Dashboard API

When running with `infraguard dashboard`, the following REST API is available:

| Endpoint | Method | Description |
|---|---|---|
| `/api/stats` | GET | Overview statistics (last 24h by default, `?hours=N`) |
| `/api/requests` | GET | Recent request log (`?limit=50&domain=...`) |
| `/api/stats/content` | GET | Content delivery statistics (`?hours=24`) |
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

All API endpoints require an `Authorization: Bearer <token>` header when `auth_token` is configured.

## Docker Deployment

### Quick start

```bash
cp .env.example .env
# Edit .env with your domain, teamserver, and token
docker compose up -d
```

This starts two services:
- **proxy** -- the redirector on ports 443 and 80
- **dashboard** -- the web UI on port 8080

### With Let's Encrypt

```bash
# Set in .env:
#   INFRAGUARD_LETSENCRYPT=true
#   INFRAGUARD_DOMAIN=cdn.example.com
#   INFRAGUARD_DOMAIN_EMAIL=operator@example.com

# Obtain the initial certificate
docker compose --profile letsencrypt up certbot

# Start the proxy (will use the LE cert)
docker compose up -d proxy dashboard

# Start auto-renewal (checks every 12 hours)
docker compose --profile letsencrypt up -d certbot-renew
```

Requirements for Let's Encrypt:
- Port 80 must be reachable from the internet
- `INFRAGUARD_DOMAIN` must resolve to this host's public IP
- `INFRAGUARD_DOMAIN_EMAIL` must be a valid email address

### With GeoIP databases

```bash
# Download all three GeoLite2 databases (City, ASN, Country)
docker compose --profile geoip up geoip-update

# Then start normally — databases are mounted at /app/geoip/
docker compose up -d proxy dashboard
```

### With PwnDrop (payload delivery)

```bash
# Start PwnDrop alongside the proxy
docker compose --profile pwndrop up -d pwndrop

# Access PwnDrop admin UI at https://localhost:8443
# InfraGuard reaches it internally at http://pwndrop:80
```

Then configure content routes in your config to proxy payload paths to PwnDrop:

```yaml
domains:
  cdn.example.com:
    content_routes:
      - path: "/downloads/*"
        backend:
          type: "pwndrop"
          target: "http://pwndrop:80"
          auth_token: "${PWNDROP_TOKEN}"
```

### Scaling

```bash
# Run multiple redirector nodes
docker compose up -d --scale proxy-node=3
```

Uncomment the `proxy-node` service in `docker-compose.yml` to enable.

### Volumes

| Volume | Purpose |
|---|---|
| `./config` | Configuration files (mounted read-only) |
| `./examples` | C2 profiles (mounted read-only) |
| `./data` | SQLite database (persisted) |
| `certs` | TLS certificates (shared between proxy and certbot) |
| `geoip` | GeoLite2 databases (populated by `geoip-update` service) |
| `pwndrop-data` | PwnDrop uploaded files and database |

## Architecture

```
infraguard/
    __init__.py              Package init
    __main__.py              python -m infraguard entry
    main.py                  Click CLI
    config/                  YAML config loading, .env support, Pydantic validation
    core/                    ASGI proxy engine (app, proxy, router, TLS, drop actions, content delivery)
    profiles/                C2 profile parsers (Cobalt Strike + Mythic)
    pipeline/                Request validation filters (IP, bot, header, DNS, geo, profile, replay)
    intel/                   IP intelligence (blocklists, GeoIP, rDNS, feeds, rule ingestion)
    tracking/                SQLite persistence (request logging, stats, node registry)
    plugins/                 Plugin system (protocol, loader, builtins)
    ui/
        api/                 REST API + WebSocket (Starlette)
        web/                 SPA dashboard (HTML/JS/CSS)
        tui/                 Terminal UI (Textual) with login screen
    backends/                Config generators (Nginx, Caddy, Apache)
    models/                  Shared types and event models
```

## Comparison with RedWarden

| Feature | RedWarden | InfraGuard |
|---|---|---|
| Architecture | Single ~99KB file | Modular package |
| Profile parsing | Regex state machine | Structured parser with full block/transform support |
| C2 support | Cobalt Strike only | Cobalt Strike + Mythic |
| Filter model | Binary pass/fail | Scoring-based (0.0-1.0 threshold) |
| Operator UI | None | Web dashboard + Terminal UI |
| Config generation | None | Nginx, Caddy, Apache with full customization |
| Rule ingestion | None | .htaccess + robots.txt parser |
| Content delivery | None | PwnDrop, filesystem, HTTP proxy with conditional delivery |
| Threat intel feeds | None | Auto-update from 5 public sources |
| Plugin system | Basic 4-method interface | Event-driven with on_event hooks + per-plugin config |
| SIEM integration | None | Elasticsearch, Wazuh, Syslog (CEF/JSON) |
| Webhook alerts | None | Discord, Slack, generic webhook |
| Anti-replay | SQLite hash | In-memory with configurable window |
| Drop actions | redirect, reset, proxy | redirect, reset, proxy, tarpit |
| TLS management | Manual only | Auto self-signed + Let's Encrypt integration |
| Deployment | Manual | Docker Compose with health checks |
| Logging | Custom colored output | Structured JSON (structlog) |
| Async | Tornado callbacks | Native async/await (ASGI + uvicorn) |

## Built-in Plugins

### SIEM Integrations

All SIEM plugins batch events for high throughput and support configurable event filtering.

#### Elasticsearch

```yaml
plugins:
  - infraguard.plugins.builtin.elasticsearch

plugin_settings:
  elasticsearch:
    event_filter:
      min_score: 0.0                # forward all events
    options:
      url: "https://es.example.com:9200"
      index: "infraguard-events"
      api_key: "${ELASTICSEARCH_API_KEY}"
      # Or use basic auth:
      # username: "elastic"
      # password: "${ELASTICSEARCH_PASSWORD}"
      batch_size: 50
      flush_interval: 10
```

#### Wazuh

```yaml
plugins:
  - infraguard.plugins.builtin.wazuh

plugin_settings:
  wazuh:
    options:
      url: "https://wazuh.example.com:55000"          # Wazuh API (for JWT auth)
      indexer_url: "https://wazuh.example.com:9200"    # Wazuh-Indexer (OpenSearch)
      username: "wazuh-wui"
      password: "${WAZUH_PASSWORD}"
      index: "infraguard-events"
      batch_size: 50
      flush_interval: 10
```

#### Syslog (Splunk, QRadar, ArcSight)

```yaml
plugins:
  - infraguard.plugins.builtin.syslog

plugin_settings:
  syslog:
    event_filter:
      only_blocked: true
    options:
      host: "syslog.example.com"
      port: 514                  # 514=UDP, 6514=TLS
      protocol: "udp"            # udp | tcp | tcp+tls
      format: "cef"              # cef | json
      facility: 1                # syslog facility (1=user)
      batch_size: 100
      flush_interval: 5
```

CEF output example:
```
CEF:0|InfraGuard|InfraGuard|1.0.0|request|Request Blocked|7|src=1.2.3.4 dst=cdn.example.com requestMethod=GET request=/callback cs1=bot_detected cs1Label=filterReason cn1=0.85 cn1Label=filterScore
```

### Webhook Integrations

Webhook plugins send alerts immediately per-event (not batched) for real-time operator notifications.

#### Discord

```yaml
plugins:
  - infraguard.plugins.builtin.discord

plugin_settings:
  discord:
    event_filter:
      only_blocked: true
    options:
      webhook_url: "${DISCORD_WEBHOOK_URL}"
      username: "InfraGuard"
      # avatar_url: "https://example.com/logo.png"
      # mention_role: "123456789"    # Role ID to @mention on blocks
```

#### Slack

```yaml
plugins:
  - infraguard.plugins.builtin.slack

plugin_settings:
  slack:
    event_filter:
      only_blocked: true
    options:
      webhook_url: "${SLACK_WEBHOOK_URL}"
      # channel: "#infraguard-alerts"
      username: "InfraGuard"
      icon_emoji: ":shield:"
```

#### Generic Webhook (Rocket.Chat, Mattermost, Teams)

```yaml
plugins:
  - infraguard.plugins.builtin.generic_webhook

plugin_settings:
  generic_webhook:
    event_filter:
      only_blocked: true
    options:
      url: "${WEBHOOK_URL}"
      method: "POST"
      content_type: "application/json"
      headers:
        Authorization: "Bearer ${WEBHOOK_TOKEN}"
      # body_template: '{"text": "Blocked {client_ip} on {domain}: {uri}"}'
```

### Event Filtering

All plugins support the same `event_filter` options to control which events are forwarded:

| Option | Type | Description |
|---|---|---|
| `only_blocked` | bool | Only forward blocked requests |
| `only_allowed` | bool | Only forward allowed requests |
| `min_score` | float | Only forward events with score >= this value |
| `include_domains` | list | Only forward events for these domains |
| `exclude_domains` | list | Skip events for these domains |

### Plugin Summary

| Plugin | Type | Transport | Use case |
|---|---|---|---|
| `elasticsearch` | SIEM | HTTP `_bulk` API | Elasticsearch / OpenSearch |
| `wazuh` | SIEM | HTTP `_bulk` + JWT | Wazuh SIEM |
| `syslog` | SIEM | UDP/TCP/TLS | Splunk, QRadar, ArcSight |
| `discord` | Webhook | HTTP POST | Discord channel alerts |
| `slack` | Webhook | HTTP POST | Slack channel alerts |
| `generic_webhook` | Webhook | HTTP POST | Rocket.Chat, Mattermost, Teams, custom |

## Writing Custom Plugins

Create a Python module with a `Plugin` class. Inherit from `BasePlugin` for convenience:

```python
# my_plugin.py
from infraguard.models.common import FilterResult
from infraguard.models.events import RequestEvent
from infraguard.pipeline.base import RequestContext
from infraguard.plugins.base import BasePlugin
from starlette.responses import Response


class Plugin(BasePlugin):
    name = "my-plugin"
    version = "1.0.0"

    async def on_request(self, ctx: RequestContext) -> FilterResult | None:
        # Return FilterResult.block(...) to block, or None to pass through
        if "suspicious" in ctx.request.headers.get("x-custom", ""):
            return FilterResult.block(reason="Custom check failed", score=0.8)
        return None

    async def on_response(self, ctx: RequestContext, response: Response) -> Response | None:
        return None

    async def on_event(self, event: RequestEvent) -> None:
        # Called after every request (allow or block)
        # Use self._opt("key") to read from plugin_settings.options
        pass

    async def on_startup(self) -> None:
        pass

    async def on_shutdown(self) -> None:
        pass
```

For forwarding plugins, inherit from `ForwardingPlugin` or `BatchForwardingPlugin`:

```python
from infraguard.plugins.builtin._base import ForwardingPlugin
from infraguard.models.events import RequestEvent


class Plugin(ForwardingPlugin):
    name = "my-forwarder"
    version = "1.0.0"

    async def on_event(self, event: RequestEvent) -> None:
        if not self._should_forward(event):  # applies event_filter config
            return
        data = self._event_to_dict(event)    # serialize to dict
        url = self._opt("url")               # read from plugin_settings.options
        await self._client.post(url, json=data)
```

Add it to your config:

```yaml
plugins:
  - "my_plugin"

plugin_settings:
  my-plugin:
    enabled: true
    event_filter:
      only_blocked: true
    options:
      url: "https://my-endpoint.com/events"
```

## License

BSD 2-Clause License. See [LICENSE](LICENSE) for details.

Copyright (c) 2026, Whispergate
