![InfraGuard Logo](/images/infraguard_logo.svg)

Red team infrastructure tracker and C2 redirector -- a modern alternative to [RedWarden](https://github.com/mgeeky/RedWarden).

InfraGuard sits between the internet and your C2 teamserver, validating every inbound request against your malleable C2 profile and blocking anything that doesn't conform. Scanners, bots, and blue team probes get redirected to a decoy site while legitimate beacon traffic passes through to your teamserver.

![Mythic Callbacks Xenon](/images/xenon_callback.png)
![InfraGuard Dashboard](/images/infraguard_dashboard.png)
![alt text](image.png)

## Architecture

![Architecture Diagram](/images/InfraGuard%20Infrastructure%20Diagram.drawio.png)

## Features

- **Multi-domain proxying** -- proxy multiple domains simultaneously, each with independent C2 profiles, upstreams, and rules
- **C2 profile validation** -- parse and enforce Cobalt Strike malleable profiles and Mythic HTTPX profiles as redirector rules
- **Multi-protocol listeners** -- HTTP/HTTPS, DNS, MQTT, and WebSocket listeners running simultaneously with shared IP intelligence and event tracking
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
- **Edge proxies** -- lightweight Cloudflare Worker and AWS Lambda for domain fronting through CDN infrastructure, edge country blocking, and host rewriting
- **Docker deployment** -- Dockerfile + docker-compose with optional Let's Encrypt, GeoIP downloader, and PwnDrop payload server
- **GeoIP support** -- all three GeoLite2 databases (City, ASN, Country) with Docker auto-download
- **Self-signed TLS fallback** -- auto-generates certificates when configured paths don't exist
- **Environment variable support** -- `.env` file auto-loaded; `${VAR}` syntax works in all config values and keys
- **Configurable health endpoint** -- change the health check path to avoid fingerprinting
- **Structured logging** -- JSON-formatted structured logs via structlog
- **Tracking & persistence** -- SQLite with WAL mode for request logging, statistics, and node registry

## Installation Guide

Check out the [Wiki Page](https://github.com/Whispergate/InfraGuard/wiki/3.-Installation#installation) for installation

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

# Then start normally - databases are mounted at /app/geoip/
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
| `./rules` | Ingested blocklists and rule source files (mounted read-only) |
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
    listeners/               Protocol listeners (HTTP, DNS, MQTT, WebSocket)
    backends/                Config generators (Nginx, Caddy, Apache)
    models/                  Shared types and event models
```

## Comparison with RedWarden

| Feature | RedWarden | InfraGuard |
|---|---|---|
| Architecture | Single ~99KB file | Modular package |
| Profile parsing | Regex state machine | Structured parser with full block/transform support |
| C2 support | Cobalt Strike only | Cobalt Strike + Mythic |
| Protocols | HTTP only | HTTP, DNS, MQTT, WebSocket |
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
| Edge deployment | None | Cloudflare Worker + AWS Lambda edge proxies with domain fronting |
| Deployment | Manual | Docker Compose with health checks |
| Logging | Custom colored output | Structured JSON (structlog) |
| Async | Tornado callbacks | Native async/await (ASGI + uvicorn) |

## Contributions

- Mgeeky - Original Idea ([RedWarden](https://github.com/mgeeky/RedWarden))
- curi0usJack - [.htaccess rules](https://gist.github.com/curi0usJack/971385e8334e189d93a6cb4671238b10)
- Profiles
  - threatexpress - [jquery-c2.3.14.profile](https://github.com/threatexpress/malleable-c2/blob/master/jquery-c2.3.14.profile)

## License

BSD 2-Clause License. See [LICENSE](LICENSE) for details.

Copyright (c) 2026, Whispergate
