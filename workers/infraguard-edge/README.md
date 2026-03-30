# InfraGuard Edge Worker

Lightweight Cloudflare Worker that sits at Cloudflare's edge and forwards traffic to your InfraGuard server. Provides domain fronting through Cloudflare's CDN -- traffic appears to go to Cloudflare, not your infrastructure.

## Architecture

```
Internet → [Cloudflare Edge] → [This Worker] → [InfraGuard Server] → [C2 Teamserver]
```

## What it does

- **Domain fronting** -- beacon traffic routes through Cloudflare's CDN
- **Edge country blocking** -- drop requests from banned countries before they reach your server
- **Host validation** -- only forward requests for allowed domains
- **Client IP injection** -- adds `X-Real-IP` and `X-Forwarded-For` headers with the real client IP
- **Host rewriting** -- map Cloudflare domain names to the Host header your C2 profile expects

## Prerequisites

- [Node.js](https://nodejs.org/) 18+
- [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/install-and-update/)
- Cloudflare account with Workers enabled
- A domain configured in Cloudflare DNS

## Setup

### 1. Install Wrangler

```bash
npm install -g wrangler
wrangler login
```

### 2. Configure

Edit `wrangler.toml`:

```toml
[vars]
# Your InfraGuard server
INFRAGUARD_BACKEND = "https://your-vps-ip:443"

# Domains the Worker should accept
ALLOWED_HOSTS = "cdn.example.com,static.example.net"

# Optional: block these countries at the edge
BLOCKED_COUNTRIES = "CN,RU,KP"

# Optional: rewrite Host header (Cloudflare domain → C2 profile Host)
HOST_MAP = "cdn.example.com:code.jquery.com"
```

Uncomment and configure the `routes` section to attach the Worker to your domain(s):

```toml
routes = [
  { pattern = "cdn.example.com/*", zone_name = "example.com" },
]
```

### 3. Deploy

```bash
npx wrangler deploy
```

### 4. Verify

```bash
# Should return InfraGuard's response (redirected if not matching C2 profile)
curl -v https://cdn.example.com/test

# Check that real IP is forwarded
# (InfraGuard dashboard should show your real IP, not Cloudflare's)
```

## Configuration Reference

| Variable | Required | Description |
|---|---|---|
| `INFRAGUARD_BACKEND` | Yes | InfraGuard server URL (e.g., `https://10.0.0.5:443`) |
| `ALLOWED_HOSTS` | No | Comma-separated allowed Host headers. If empty, all hosts are forwarded. |
| `BLOCKED_COUNTRIES` | No | Comma-separated ISO country codes to block at edge (e.g., `CN,RU,KP`) |
| `HOST_MAP` | No | Host rewriting rules (e.g., `cf-domain:expected-host`). Useful when your Cloudflare domain differs from the Host header in your C2 profile. |

## How domain fronting works

1. Your C2 beacon connects to `cdn.example.com` (a domain behind Cloudflare)
2. Cloudflare terminates TLS and routes the request to this Worker
3. The Worker forwards the request to your InfraGuard server (which may be on a completely different IP/domain)
4. InfraGuard validates the request against the C2 profile and proxies to the teamserver

From a network observer's perspective, all traffic goes to Cloudflare's IPs -- your actual server IP is never exposed.

## Host rewriting

If your C2 profile specifies `Host: code.jquery.com` but your Cloudflare domain is `cdn.example.com`, use `HOST_MAP` to rewrite:

```toml
HOST_MAP = "cdn.example.com:code.jquery.com"
```

The Worker will change the `Host` header to `code.jquery.com` before forwarding to InfraGuard, so the profile filter matches correctly.

## OPSEC notes

- The Worker strips `CF-*` headers before forwarding to InfraGuard, so your backend doesn't leak Cloudflare metadata
- The `Server` header is stripped from responses to avoid fingerprinting
- Use `wrangler secret put` for sensitive values instead of putting them in `wrangler.toml`
- Consider using a Cloudflare Tunnel instead of exposing InfraGuard's port publicly
