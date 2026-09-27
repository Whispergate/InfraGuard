"""Additional health + plugin endpoints for the redesigned dashboard.

New endpoints:
  GET /api/health/circuit-breakers  - live per-upstream circuit state
  GET /api/health/watchdog          - rotation watchdog thresholds + status
  GET /api/health/deadman           - dead-man's switch status
  GET /api/health/rotations         - recent rotation events from the audit log

Also exposes ``PLUGIN_CATEGORIES`` and helpers used by
``routes/plugins.py`` to enrich the ``/api/plugins`` response with
category / hook introspection / invocation counts.
"""

from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import structlog
from starlette.requests import Request
from starlette.responses import JSONResponse

from infraguard.plugins.base import BasePlugin

log = structlog.get_logger()


# ── Plugin categories ────────────────────────────────────────────────────────
# Mapping used by the Plugins tab card grid. Not on the plugin class itself
# so third-party plugins can still opt in via `category = "..."` without
# a codebase change.

PLUGIN_CATEGORIES: dict[str, str] = {
    # alerters and SIEMs
    "discord": "alerting",
    "elasticsearch": "siem",
    "generic_webhook": "alerting",
    "pagerduty": "alerting",
    "slack": "alerting",
    "syslog": "siem",
    "telegram_bot": "alerting",
    "wazuh": "siem",
    # detection / classification
    "greynoise": "detection",
    "ml_bot_classifier": "detection",
    "response_canary": "detection",
    "yara_scan": "detection",
    # fingerprint enrichers
    "geoip_enricher": "session",
    "ja4_enricher": "session",
    "p0f_fingerprint": "session",
    "beacon_labeler": "session",
    # request-side mutators / gates
    "js_challenge": "response",
    "html_rewriter": "response",
    "sig_strip": "response",
    "cache_mimicry": "response",
    "http_smuggling": "detection",
    "shadow_block": "testing",
    "slow_tarpit": "response",
    "stager_rate_limit": "payload",
    "payload_shred": "payload",
    "payload_watermark": "payload",
    # observability / recording
    "prom_custom": "testing",
    "request_recorder": "testing",
    "timing_profiler": "session",
}


_HOOK_NAMES = ("on_request", "on_response", "on_event", "on_startup", "on_shutdown")


def plugin_hooks(plugin: object) -> dict[str, bool]:
    """Return {hook_name: True} for every hook the plugin actually overrides.

    Compares the bound method against ``BasePlugin``'s default to detect
    override. Works whether the plugin subclasses ``BasePlugin`` or just
    duck-types the ``InfraGuardPlugin`` protocol.
    """
    out: dict[str, bool] = {}
    for hook in _HOOK_NAMES:
        plugin_fn = getattr(plugin, hook, None)
        base_fn = getattr(BasePlugin, hook, None)
        if plugin_fn is None or base_fn is None:
            out[hook] = False
            continue
        # An unwrapped method's __func__ compares equal only for the base;
        # duck-typed plugins whose class has its own definition will differ.
        pf = getattr(plugin_fn, "__func__", plugin_fn)
        bf = base_fn
        out[hook] = pf is not bf
    return out


# ── Invocation counter ───────────────────────────────────────────────────────
# Simple in-process counter so the dashboard can show "which plugins are
# actually doing work". Wraps a plugin's hook methods with a thin async
# proxy that increments a counter keyed by plugin name.

class PluginInvocationCounter:
    """Track invocation counts + last-called + rolling error rate per plugin.

    Attach to ``app.state.plugin_invocations``. ``wrap_plugin(p)`` replaces
    the plugin's hook methods with counting proxies (idempotent). Read the
    numbers with ``stats_for(name)``.
    """

    def __init__(self) -> None:
        self._counts: dict[str, dict[str, int]] = {}
        self._errors: dict[str, int] = {}
        self._last_called: dict[str, float] = {}
        self._wrapped: set[int] = set()

    def _touch(self, name: str, hook: str) -> None:
        cell = self._counts.setdefault(name, {})
        cell[hook] = cell.get(hook, 0) + 1
        self._last_called[name] = time.time()

    def _err(self, name: str) -> None:
        self._errors[name] = self._errors.get(name, 0) + 1

    def wrap_plugin(self, plugin: object) -> None:
        """Idempotently wrap the plugin's hooks with counting proxies."""
        pid = id(plugin)
        if pid in self._wrapped:
            return
        name = getattr(plugin, "name", "unknown")
        for hook in _HOOK_NAMES:
            original = getattr(plugin, hook, None)
            if original is None:
                continue

            def _make(bound, hname):
                async def _proxy(*args, **kwargs):
                    try:
                        result = await bound(*args, **kwargs)
                    except Exception:
                        self._err(name)
                        raise
                    else:
                        self._touch(name, hname)
                        return result
                _proxy.__name__ = f"counted_{hname}"
                _proxy.__ig_original__ = bound  # allow rediscovery in tests
                return _proxy

            setattr(plugin, hook, _make(original, hook))
        self._wrapped.add(pid)

    def stats_for(self, name: str) -> dict[str, object]:
        counts = self._counts.get(name, {})
        total = sum(counts.values())
        last = self._last_called.get(name)
        return {
            "invocations": total,
            "by_hook": dict(counts),
            "errors": self._errors.get(name, 0),
            "last_called_at": (
                datetime.fromtimestamp(last, tz=UTC).isoformat() if last else None
            ),
        }


def get_or_create_counter(request: Request) -> PluginInvocationCounter:
    counter = getattr(request.app.state, "plugin_invocations", None)
    if counter is None:
        counter = PluginInvocationCounter()
        request.app.state.plugin_invocations = counter
    return counter


# ── forward helper for the standalone dashboard ──────────────────────────────

async def _forward_health(request: Request, path: str) -> JSONResponse | None:
    """Forward a health read to the proxy when this process is the
    standalone dashboard (no live router/watchdog/deadman state)."""
    proxy_url = getattr(request.app.state, "proxy_api_url", None)
    if not proxy_url:
        return None
    import httpx
    url = proxy_url.rstrip("/") + path
    fwd_headers = {"Content-Type": "application/json"}
    if "authorization" in request.headers:
        fwd_headers["Authorization"] = request.headers["authorization"]
    else:
        cfg = getattr(getattr(request.app.state, "config", None), "api", None)
        tok = getattr(cfg, "auth_token", None) if cfg is not None else None
        if tok:
            fwd_headers["Authorization"] = f"Bearer {tok}"
    try:
        async with httpx.AsyncClient(verify=False, timeout=5) as client:
            resp = await client.get(
                url, headers=fwd_headers,
                cookies=dict(request.cookies),
                params=dict(request.query_params),
            )
            return JSONResponse(resp.json(), status_code=resp.status_code)
    except Exception as exc:
        log.debug("health_forward_failed", url=url, error=str(exc))
        return None


# ── /api/health/circuit-breakers ─────────────────────────────────────────────

async def get_circuit_breakers(request: Request) -> JSONResponse:
    """Return per-upstream circuit-breaker state.

    Reads from ``request.app.state.router._breakers`` so the numbers are
    the same ones the proxy hot path sees, not a snapshot.
    """
    router = getattr(request.app.state, "router", None)
    if router is None:
        forwarded = await _forward_health(request, "/api/health/circuit-breakers")
        if forwarded is not None:
            return forwarded
    breakers = getattr(router, "_breakers", None)
    if not breakers:
        return JSONResponse({"breakers": [], "message": "no upstreams registered"})

    out = []
    now = time.time()
    for upstream, breaker in breakers.items():
        opened_at = getattr(breaker, "_opened_at", None)
        entry = {
            "upstream": upstream,
            "state": breaker.state,
            "failures": breaker.failure_count,
            "threshold": getattr(breaker, "_threshold", None),
            "recovery_timeout": getattr(breaker, "_recovery_timeout", None),
            "opened_at": (
                datetime.fromtimestamp(opened_at, tz=UTC).isoformat()
                if opened_at else None
            ),
            "seconds_since_opened": (
                round(now - opened_at, 1) if opened_at else None
            ),
        }
        out.append(entry)

    open_count = sum(1 for b in out if b["state"] == "OPEN")
    half_open_count = sum(1 for b in out if b["state"] == "HALF_OPEN")
    return JSONResponse({
        "breakers": out,
        "open": open_count,
        "half_open": half_open_count,
        "closed": len(out) - open_count - half_open_count,
    })


# ── /api/health/watchdog ─────────────────────────────────────────────────────

async def get_watchdog(request: Request) -> JSONResponse:
    """Return rotation-watchdog thresholds and last-seen burn signals."""
    wd = getattr(request.app.state, "watchdog", None)
    if wd is None:
        # Fall back to the proxy for the standalone dashboard container.
        if getattr(request.app.state, "router", None) is None:
            forwarded = await _forward_health(request, "/api/health/watchdog")
            if forwarded is not None:
                return forwarded
        return JSONResponse({"enabled": False, "message": "watchdog not configured"})

    cfg = getattr(wd, "_cfg", None)
    last_seen = getattr(wd, "_last_burn_seen", {})
    now = time.time()

    domains = []
    for domain, (score, when_first) in last_seen.items():
        domains.append({
            "domain": domain,
            "score": round(score, 3),
            "first_crossed_at": datetime.fromtimestamp(when_first, tz=UTC).isoformat(),
            "seconds_above_threshold": round(now - when_first, 1),
        })

    return JSONResponse({
        "enabled": bool(getattr(cfg, "enabled", False)) if cfg else False,
        "running": getattr(wd, "_task", None) is not None,
        "auto_rotate": bool(getattr(cfg, "auto_rotate", False)) if cfg else False,
        "thresholds": {
            "burn_threshold": getattr(cfg, "burn_threshold", None) if cfg else None,
            "burn_window_seconds": getattr(cfg, "burn_window", None) if cfg else None,
            "cert_days_before": getattr(cfg, "cert_days_before", None) if cfg else None,
            "cost_cap_usd": getattr(cfg, "cost_cap_usd", None) if cfg else None,
            "poll_interval": getattr(cfg, "poll_interval", None) if cfg else None,
        },
        "elevated_domains": domains,
    })


# ── /api/health/deadman ──────────────────────────────────────────────────────

async def get_deadman(request: Request) -> JSONResponse:
    """Return dead-man's switch status (TTL, remaining, last heartbeat)."""
    dm = getattr(request.app.state, "deadman", None)
    if dm is None:
        if getattr(request.app.state, "router", None) is None:
            forwarded = await _forward_health(request, "/api/health/deadman")
            if forwarded is not None:
                return forwarded
        return JSONResponse({"enabled": False, "message": "dead-man's switch not configured"})

    status = dm.get_status()
    # Convert monotonic 'last_heartbeat' -> ISO wall-clock estimate.
    remaining = status.get("time_remaining_seconds", 0)
    ttl = status.get("ttl_seconds", 0)
    elapsed = max(0, ttl - remaining)
    last_wall = datetime.now(UTC) - timedelta(seconds=elapsed)
    status["last_heartbeat_iso"] = last_wall.isoformat()
    status["ttl_used_pct"] = round(elapsed / ttl * 100, 1) if ttl else 0
    return JSONResponse(status)


# ── /api/health/rotations ────────────────────────────────────────────────────

async def get_rotations(request: Request) -> JSONResponse:
    """Return recent rotation events from the audit log."""
    from infraguard.tracking.scheduler import _ROTATION_AUDIT_ACTIONS

    db = getattr(request.app.state, "db", None)
    if db is None:
        return JSONResponse({"rotations": []})

    try:
        limit = int(request.query_params.get("limit", "50"))
    except (TypeError, ValueError):
        limit = 50
    limit = max(1, min(limit, 500))

    audit = await db.get_audit_log(limit=limit * 4)
    rotations = [
        {
            "timestamp": e.get("timestamp"),
            "action": e.get("action"),
            "operator": e.get("operator"),
            "details": e.get("details"),
        }
        for e in audit
        if e.get("action", "") in _ROTATION_AUDIT_ACTIONS
    ][:limit]

    return JSONResponse({
        "rotations": rotations,
        "count": len(rotations),
    })


# ── Operator actions ─────────────────────────────────────────────────────────
# The dashboard is the primary control surface, so buttons that show up
# there must actually do things. Rotate + BURN NOW + Heartbeat are the
# three most important operator actions that were previously CLI-only.

async def post_rotate_preflight(request: Request) -> JSONResponse:
    """POST /api/rotate/preflight - run non-destructive rotation checks.

    Body: ``{"domain": "cdn.example.com"}`` (optional; defaults to every
    configured domain when omitted).

    Returns per-domain DNS / TLS / upstream health results. Does NOT
    touch cloud infrastructure, so this is safe to expose to any
    operator with dashboard access.
    """
    try:
        body = await request.json()
    except Exception:
        body = {}
    requested = body.get("domain") if isinstance(body, dict) else None

    config = getattr(request.app.state, "config", None)
    if config is None or not getattr(config, "domains", None):
        return JSONResponse({"error": "no domains configured"}, status_code=400)

    # Resolve list of domains to check.
    if requested:
        if requested not in config.domains:
            return JSONResponse(
                {"error": f"domain '{requested}' not in config"}, status_code=404,
            )
        targets = {requested: config.domains[requested]}
    else:
        targets = dict(config.domains)

    results: list[dict] = []
    for domain_name, dcfg in targets.items():
        entry = {
            "domain": domain_name,
            "upstream": getattr(dcfg, "upstream", None),
            "dns_ok": None,
            "resolved_ips": [],
            "cert_ok": None,
            "cert_expiry_days": None,
            "upstream_ok": None,
            "error": None,
        }
        try:
            from infraguard.deploy.rotation import RotationManager  # heavy

            mgr = RotationManager(
                provider_name="__preflight__",
                blue_work_dir=Path("/tmp"),
                green_work_dir=None,
                ssh_key=Path("/tmp/dummy"),
                operator_ip="",
            )
            result = await asyncio.get_event_loop().run_in_executor(
                None, mgr.preflight, domain_name, entry["upstream"], None,
            )
            entry["dns_ok"] = result.dns_ok
            entry["resolved_ips"] = list(result.resolved_ips)
            entry["cert_ok"] = result.cert_ok
            entry["cert_expiry_days"] = result.cert_expiry_days
            entry["upstream_ok"] = result.upstream_ok
        except Exception as exc:
            entry["error"] = str(exc)
        results.append(entry)

    ok = all(r["error"] is None for r in results)
    return JSONResponse({"results": results, "all_passed": ok})


async def post_burn(request: Request) -> JSONResponse:
    """POST /api/burn/trigger - stop C2 forwarding for a domain immediately.

    Body: ``{"domain": "cdn.example.com"}`` (optional; defaults to all
    configured domains).

    Effect on the running proxy:
    - Sets ``domain.enabled = False`` on the router so every subsequent
      request to that domain hits the drop_action (decoy/redirect/reset).
    - Fires a ``burn`` audit-log entry so the rotation timeline picks
      it up.
    - Notifies the rotation scheduler (when present) so any
      ON_BURN_DETECTED policy triggers.

    Reversible via ``POST /api/burn/clear``. This does NOT rotate cloud
    infrastructure - use ``infraguard rotate`` for the destructive
    blue-green cycle.
    """
    try:
        body = await request.json()
    except Exception:
        body = {}
    requested = body.get("domain") if isinstance(body, dict) else None

    config = getattr(request.app.state, "config", None)
    router = getattr(request.app.state, "router", None)
    db = getattr(request.app.state, "db", None)

    if config is None or not getattr(config, "domains", None):
        return JSONResponse({"error": "no domains configured"}, status_code=400)

    if requested:
        if requested not in config.domains:
            return JSONResponse(
                {"error": f"domain '{requested}' not in config"}, status_code=404,
            )
        domains = [requested]
    else:
        domains = list(config.domains.keys())

    actor = getattr(request.state, "user", None) or "dashboard"
    burned: list[str] = []
    for dname in domains:
        # Flip the runtime-enabled flag on the router route so hot-path
        # requests immediately fall through to the domain's drop_action.
        if router is not None:
            route = getattr(router, "routes", {}).get(dname)
            if route is not None:
                route.burned = True
                route.enabled = False
        # Audit log entry so the rotation-history timeline updates.
        if db is not None:
            try:
                await db.record_audit(
                    action="burn",
                    actor=str(actor),
                    details=f"dashboard-triggered burn on {dname}",
                )
            except Exception:
                pass
        # Nudge the scheduler if one is registered so ON_BURN_DETECTED
        # rotation policies fire on their next tick.
        sched = getattr(request.app.state, "rotation_scheduler", None)
        if sched is not None and hasattr(sched, "notify_burn_detected"):
            try:
                sched.notify_burn_detected(dname)
            except Exception:
                pass
        burned.append(dname)

    log.warning("burn_triggered", domains=burned, actor=str(actor))
    return JSONResponse({
        "burned": burned,
        "message": (
            f"Stopped C2 forwarding for {len(burned)} domain(s). "
            "Traffic now falls through to each domain's drop_action. "
            "Use POST /api/burn/clear to restore forwarding, or "
            "'infraguard rotate' to cycle infrastructure."
        ),
    })


async def post_burn_clear(request: Request) -> JSONResponse:
    """POST /api/burn/clear - restore C2 forwarding after a burn.

    Body: ``{"domain": "..."}`` (optional; defaults to every burned
    domain).
    """
    try:
        body = await request.json()
    except Exception:
        body = {}
    requested = body.get("domain") if isinstance(body, dict) else None

    router = getattr(request.app.state, "router", None)
    if router is None:
        return JSONResponse({"error": "router not exposed"}, status_code=501)

    cleared: list[str] = []
    for dname, route in getattr(router, "routes", {}).items():
        if requested and dname != requested:
            continue
        if getattr(route, "burned", False):
            route.burned = False
            route.enabled = True
            cleared.append(dname)

    actor = getattr(request.state, "user", None) or "dashboard"
    db = getattr(request.app.state, "db", None)
    if db is not None and cleared:
        try:
            await db.record_audit(
                action="burn_cleared",
                actor=str(actor),
                details=f"dashboard cleared burn on {', '.join(cleared)}",
            )
        except Exception:
            pass
    return JSONResponse({"cleared": cleared})


async def post_heartbeat(request: Request) -> JSONResponse:
    """POST /api/heartbeat - reset the dead-man's switch TTL.

    Any operator activity on the dashboard should count as a heartbeat;
    the front-end pings this on every refresh so an active session
    keeps the switch armed.
    """
    dm = getattr(request.app.state, "deadman", None)
    if dm is None:
        return JSONResponse({
            "ok": False,
            "message": "dead-man's switch not configured",
        }, status_code=501)
    try:
        dm.heartbeat()
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)
    return JSONResponse({
        "ok": True,
        "ttl_seconds": dm.ttl_seconds,
        "time_remaining_seconds": max(0, dm.time_remaining),
    })
