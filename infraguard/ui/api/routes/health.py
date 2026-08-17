"""Infrastructure health monitoring API routes."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path

from starlette.requests import Request
from starlette.responses import JSONResponse

from infraguard.config.schema import InfraGuardConfig
from infraguard.intel.feeds import get_feed_status
from infraguard.tracking.database import Database
from infraguard.tracking.stats import StatsQuery

# Module-level start time for uptime calculation
_start_time = time.monotonic()

# Alert thresholds
CERT_EXPIRY_WARN_DAYS = 7
UPSTREAM_DOWN_WARN_SECONDS = 300  # 5 minutes
FEED_STALE_WARN_HOURS = 24


async def get_health(request: Request) -> JSONResponse:
    """GET /api/health - infrastructure health metrics and active alerts."""
    config: InfraGuardConfig = request.app.state.config
    db: Database = request.app.state.db
    stats_query: StatsQuery = request.app.state.stats_query

    alerts: list[dict] = []

    # ── Uptime ────────────────────────────────────────────────────────────
    uptime_seconds = int(time.monotonic() - _start_time)
    uptime_human = _format_duration(uptime_seconds)

    # ── Request / block rates (last 24h) ──────────────────────────────────
    stats = await stats_query.overview(hours=24)
    total = stats.total_requests or 0
    blocked = stats.blocked_requests or 0
    block_rate = round(blocked / max(total, 1), 3)
    request_rate_per_min = round(total / (24 * 60), 2)

    # ── Upstream latency (avg from DB, last hour) ─────────────────────────
    latency_row = await db.fetchone(
        """SELECT AVG(duration_ms) as avg_ms, COUNT(*) as n
           FROM requests
           WHERE timestamp > datetime('now', '-1 hour')"""
    )
    avg_latency_ms = round(latency_row["avg_ms"], 1) if latency_row and latency_row["avg_ms"] else None

    # ── Per-domain upstream latency (last hour) ───────────────────────────
    latency_rows = await db.fetchall(
        """SELECT domain, AVG(duration_ms) as avg_ms, COUNT(*) as n
           FROM requests
           WHERE timestamp > datetime('now', '-1 hour')
           GROUP BY domain
           ORDER BY avg_ms DESC"""
    )
    domain_latency = [
        {
            "domain": r["domain"],
            "avg_ms": round(r["avg_ms"], 1) if r["avg_ms"] else None,
            "requests": r["n"],
        }
        for r in latency_rows
    ]

    # ── Certificate expiry ────────────────────────────────────────────────
    cert_info: list[dict] = []
    now = datetime.now(timezone.utc)
    for listener in config.listeners:
        if listener.tls and listener.tls.cert:
            cert_path = Path(listener.tls.cert)
            entry: dict = {
                "listener": f"{listener.bind}:{listener.port}",
                "protocol": listener.protocol,
                "cert_path": str(cert_path),
                "exists": cert_path.exists(),
                "days_until_expiry": None,
                "expires_at": None,
                "status": "unknown",
            }
            if cert_path.exists():
                try:
                    expires_at = _read_cert_expiry(cert_path)
                    if expires_at:
                        days_left = (expires_at - now).days
                        entry["days_until_expiry"] = days_left
                        entry["expires_at"] = expires_at.isoformat()
                        if days_left < 0:
                            entry["status"] = "expired"
                            alerts.append({
                                "severity": "critical",
                                "type": "cert_expired",
                                "message": f"Certificate for {listener.bind}:{listener.port} has expired",
                                "detail": str(cert_path),
                            })
                        elif days_left < CERT_EXPIRY_WARN_DAYS:
                            entry["status"] = "warning"
                            alerts.append({
                                "severity": "warning",
                                "type": "cert_expiring",
                                "message": f"Certificate for {listener.bind}:{listener.port} expires in {days_left} day(s)",
                                "detail": str(cert_path),
                            })
                        else:
                            entry["status"] = "ok"
                except Exception as exc:
                    entry["status"] = "error"
                    entry["error"] = str(exc)
            else:
                entry["status"] = "missing"
                alerts.append({
                    "severity": "critical",
                    "type": "cert_missing",
                    "message": f"Certificate file not found for {listener.bind}:{listener.port}",
                    "detail": str(cert_path),
                })
            cert_info.append(entry)

    # ── Feed freshness ────────────────────────────────────────────────────
    feed_status = get_feed_status()
    feeds: list[dict] = []
    for url, iso_ts in feed_status.items():
        feed_entry: dict = {"url": url, "last_refresh": iso_ts, "hours_since": None, "status": "unknown"}
        if iso_ts:
            try:
                last = datetime.fromisoformat(iso_ts)
                if last.tzinfo is None:
                    last = last.replace(tzinfo=timezone.utc)
                hours_since = round((now - last).total_seconds() / 3600, 1)
                feed_entry["hours_since"] = hours_since
                if hours_since > FEED_STALE_WARN_HOURS:
                    feed_entry["status"] = "stale"
                    alerts.append({
                        "severity": "warning",
                        "type": "feed_stale",
                        "message": f"Threat feed stale for {hours_since}h",
                        "detail": url,
                    })
                else:
                    feed_entry["status"] = "ok"
            except Exception:
                feed_entry["status"] = "error"
        else:
            feed_entry["status"] = "never_refreshed"
            alerts.append({
                "severity": "warning",
                "type": "feed_never_refreshed",
                "message": "Threat feed has never successfully refreshed",
                "detail": url,
            })
        feeds.append(feed_entry)

    # ── Node / upstream health ────────────────────────────────────────────
    nodes = await db.fetchall("SELECT * FROM nodes ORDER BY name")
    upstream_health: list[dict] = []
    for node in nodes:
        node_entry: dict = {
            "id": node.get("id"),
            "name": node.get("name"),
            "address": node.get("address"),
            "domains": node.get("domains"),
            "last_heartbeat": node.get("last_heartbeat"),
            "status": "unknown",
            "seconds_since_heartbeat": None,
        }
        hb = node.get("last_heartbeat")
        if hb:
            try:
                hb_dt = datetime.fromisoformat(hb)
                if hb_dt.tzinfo is None:
                    hb_dt = hb_dt.replace(tzinfo=timezone.utc)
                secs = int((now - hb_dt).total_seconds())
                node_entry["seconds_since_heartbeat"] = secs
                if secs > UPSTREAM_DOWN_WARN_SECONDS:
                    node_entry["status"] = "down"
                    alerts.append({
                        "severity": "critical",
                        "type": "upstream_down",
                        "message": f"Node '{node.get('name')}' down for {_format_duration(secs)}",
                        "detail": node.get("address", ""),
                    })
                elif secs > 60:
                    node_entry["status"] = "warning"
                else:
                    node_entry["status"] = "ok"
            except Exception:
                node_entry["status"] = "error"
        else:
            node_entry["status"] = "never_seen"
        upstream_health.append(node_entry)

    # ── Overall status ────────────────────────────────────────────────────
    overall = "ok"
    if any(a["severity"] == "critical" for a in alerts):
        overall = "critical"
    elif alerts:
        overall = "warning"

    return JSONResponse({
        "status": overall,
        "timestamp": now.isoformat(),
        "uptime": {
            "seconds": uptime_seconds,
            "human": uptime_human,
        },
        "traffic": {
            "total_requests_24h": total,
            "blocked_requests_24h": blocked,
            "block_rate_24h": block_rate,
            "request_rate_per_minute": request_rate_per_min,
        },
        "upstream_latency": {
            "avg_ms_1h": avg_latency_ms,
            "by_domain": domain_latency,
        },
        "certificates": cert_info,
        "feeds": feeds,
        "nodes": upstream_health,
        "alerts": alerts,
        "alert_count": len(alerts),
    })


async def get_health_summary(request: Request) -> JSONResponse:
    """GET /api/health/summary - lightweight health status (no DB queries)."""
    uptime_seconds = int(time.monotonic() - _start_time)
    return JSONResponse({
        "status": "ok",
        "uptime_seconds": uptime_seconds,
        "uptime_human": _format_duration(uptime_seconds),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


# ── Helpers ───────────────────────────────────────────────────────────────────

def _format_duration(seconds: int) -> str:
    """Format a duration in seconds to a human-readable string."""
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m {seconds % 60}s"
    if seconds < 86400:
        return f"{seconds // 3600}h {(seconds % 3600) // 60}m"
    days = seconds // 86400
    hours = (seconds % 86400) // 3600
    return f"{days}d {hours}h"


def _read_cert_expiry(cert_path: Path) -> datetime | None:
    """Read certificate expiry date from a local PEM file. Returns None on failure.

    Only reads the local certificate file — no network connection is made.
    """
    try:
        import ssl

        # Preferred: use cryptography library for reliable PEM parsing
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            pem_data = cert_path.read_bytes()
            cert = x509.load_pem_x509_certificate(pem_data, default_backend())
            return cert.not_valid_after_utc
        except ImportError:
            pass

        # Fallback: ssl._ssl._test_decode_cert parses PEM files without a connection
        info = ssl._ssl._test_decode_cert(str(cert_path))
        not_after = info.get("notAfter")
        if not_after:
            # Format: 'Jan  1 00:00:00 2025 GMT'
            return datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except Exception:
        pass
    return None
