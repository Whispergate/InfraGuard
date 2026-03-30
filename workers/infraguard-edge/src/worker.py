"""InfraGuard Edge Worker - Cloudflare Worker reverse proxy.

Sits at Cloudflare's edge and forwards traffic to your InfraGuard server.
Provides domain fronting, edge-level country blocking, and real client IP
injection via X-Real-IP / X-Forwarded-For headers.

Configure via environment variables in wrangler.toml:
  INFRAGUARD_BACKEND  - InfraGuard server URL (e.g. https://infraguard.example.com:443)
  ALLOWED_HOSTS       - Comma-separated allowed Host headers (e.g. cdn.example.com,static.example.net)
  BLOCKED_COUNTRIES   - Comma-separated ISO country codes to block at edge (e.g. CN,RU,KP)
  HOST_MAP            - Optional host rewriting (e.g. cdn.workers.dev:code.jquery.com)
"""

from js import Response, fetch, Headers


async def on_fetch(request, env):
    url = request.url
    method = request.method
    host = request.headers.get("Host") or ""
    client_ip = request.headers.get("CF-Connecting-IP") or ""
    client_country = request.headers.get("CF-IPCountry") or ""

    # ── Edge filtering: blocked countries ──────────────────────────
    blocked_countries = getattr(env, "BLOCKED_COUNTRIES", "")
    if blocked_countries and client_country:
        blocked = [c.strip().upper() for c in blocked_countries.split(",") if c.strip()]
        if client_country.upper() in blocked:
            return Response.new(
                "Access Denied",
                status=403,
                headers=Headers.new({"Content-Type": "text/plain"}.items()),
            )

    # ── Host allowlist validation ─────────────────────────────────
    allowed_hosts = getattr(env, "ALLOWED_HOSTS", "")
    if allowed_hosts:
        allowed = [h.strip().lower() for h in allowed_hosts.split(",") if h.strip()]
        hostname = host.split(":")[0].lower()
        if hostname not in allowed:
            return Response.new(
                "Not Found",
                status=404,
                headers=Headers.new({"Content-Type": "text/plain"}.items()),
            )

    # ── Build upstream URL ────────────────────────────────────────
    backend = getattr(env, "INFRAGUARD_BACKEND", "")
    if not backend:
        return Response.new("Misconfigured: INFRAGUARD_BACKEND not set", status=502)

    # Parse the path from the original URL
    # request.url is the full URL; extract path + query
    from js import URL
    parsed = URL.new(url)
    upstream_url = backend.rstrip("/") + parsed.pathname
    if parsed.search:
        upstream_url += parsed.search

    # ── Forward headers with real client IP ───────────────────────
    forward_headers = Headers.new()
    for pair in request.headers:
        key = pair[0]
        value = pair[1]
        # Skip Cloudflare internal headers
        if key.lower().startswith("cf-"):
            continue
        forward_headers.set(key, value)

    # Inject real client IP
    forward_headers.set("X-Real-IP", client_ip)
    forward_headers.set("X-Forwarded-For", client_ip)
    forward_headers.set("X-Forwarded-Proto", "https")

    # Optional host rewriting (e.g. cdn.workers.dev → code.jquery.com)
    host_map_str = getattr(env, "HOST_MAP", "")
    if host_map_str:
        for mapping in host_map_str.split(","):
            if ":" in mapping:
                src, dst = mapping.strip().split(":", 1)
                if host.split(":")[0].lower() == src.strip().lower():
                    forward_headers.set("Host", dst.strip())
                    break

    # ── Proxy to InfraGuard ───────────────────────────────────────
    upstream_response = await fetch(
        upstream_url,
        method=method,
        headers=forward_headers,
        body=request.body if method not in ("GET", "HEAD") else None,
        redirect="manual",
    )

    # ── Return response ───────────────────────────────────────────
    response_headers = Headers.new()
    for pair in upstream_response.headers:
        key = pair[0]
        value = pair[1]
        # Strip hop-by-hop and server identification headers
        if key.lower() in ("transfer-encoding", "connection", "server"):
            continue
        response_headers.set(key, value)

    return Response.new(
        upstream_response.body,
        status=upstream_response.status,
        headers=response_headers,
    )
