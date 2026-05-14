"""Report export endpoints.

Allows operators to download a full InfraGuard engagement report in
HTML, JSON, or CSV format from the dashboard.
"""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone

import structlog
from starlette.requests import Request
from starlette.responses import Response

from infraguard.tracking.database import Database
from infraguard.tracking.nodes import NodeRegistry
from infraguard.tracking.report import _render_html, collect_report_data
from infraguard.tracking.stats import StatsQuery

log = structlog.get_logger()

_VALID_FORMATS = {"html", "json", "csv"}


def _fold_domain_stats(rows: list[dict]) -> list[dict]:
    """Collapse (domain, filter_result) rows into one row per domain."""
    by_domain: dict[str, dict] = {}
    for row in rows:
        d = row["domain"]
        entry = by_domain.setdefault(
            d, {"domain": d, "allowed": 0, "blocked": 0, "total": 0, "block_rate": 0.0}
        )
        if row["filter_result"] == "allow":
            entry["allowed"] += row["count"]
        elif row["filter_result"] == "block":
            entry["blocked"] += row["count"]
        entry["total"] += row["count"]
    for entry in by_domain.values():
        entry["block_rate"] = (
            entry["blocked"] / entry["total"] if entry["total"] else 0.0
        )
    return sorted(by_domain.values(), key=lambda r: r["domain"])


def _build_json_report(data: dict, nodes: list[dict], stats_24h: dict) -> bytes:
    payload = {
        "metadata": {
            "generated_at": data["generated_at"],
            "first_request": data["first_request"],
            "last_request": data["last_request"],
            "report_version": 1,
        },
        "summary_all_time": {
            "total_requests": data["total"],
            "allowed_requests": data["allowed"],
            "blocked_requests": data["blocked"],
            "unique_ips": data["unique_ips"],
            "block_rate": (
                data["blocked"] / data["total"] if data["total"] else 0.0
            ),
        },
        "summary_24h": stats_24h,
        "domains": _fold_domain_stats(data["domain_stats"]),
        "top_blocked_ips": [
            {"ip": r["client_ip"], "count": r["count"]}
            for r in data["top_blocked_ips"]
        ],
        "top_blocked_user_agents": [
            {"user_agent": r["user_agent"], "count": r["count"]}
            for r in data["top_blocked_uas"]
        ],
        "filter_reasons": [
            {"reason": r["filter_reason"], "count": r["count"]}
            for r in data["filter_reasons"]
        ],
        "hourly_volume": [
            {"hour": r["hour"], "filter_result": r["filter_result"], "count": r["count"]}
            for r in data["hourly_volume"]
        ],
        "nodes": nodes,
        "audit_log": data["audit_entries"],
    }
    return json.dumps(payload, indent=2, default=str).encode("utf-8")


def _build_csv_report(data: dict, nodes: list[dict], stats_24h: dict) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf)

    w.writerow(["# InfraGuard Report"])
    w.writerow(["generated_at", data["generated_at"]])
    w.writerow(["first_request", data["first_request"]])
    w.writerow(["last_request", data["last_request"]])
    w.writerow([])

    w.writerow(["# Summary (All Time)"])
    w.writerow(["metric", "value"])
    w.writerow(["total_requests", data["total"]])
    w.writerow(["allowed_requests", data["allowed"]])
    w.writerow(["blocked_requests", data["blocked"]])
    w.writerow(["unique_ips", data["unique_ips"]])
    w.writerow([])

    w.writerow(["# Summary (Last 24h)"])
    w.writerow(["metric", "value"])
    for k, v in stats_24h.items():
        w.writerow([k, v])
    w.writerow([])

    w.writerow(["# Per-Domain Statistics"])
    w.writerow(["domain", "total", "allowed", "blocked", "block_rate"])
    for row in _fold_domain_stats(data["domain_stats"]):
        w.writerow(
            [row["domain"], row["total"], row["allowed"], row["blocked"], f"{row['block_rate']:.4f}"]
        )
    w.writerow([])

    w.writerow(["# Top Blocked IPs"])
    w.writerow(["client_ip", "count"])
    for row in data["top_blocked_ips"]:
        w.writerow([row["client_ip"], row["count"]])
    w.writerow([])

    w.writerow(["# Top Blocked User-Agents"])
    w.writerow(["user_agent", "count"])
    for row in data["top_blocked_uas"]:
        w.writerow([row["user_agent"], row["count"]])
    w.writerow([])

    w.writerow(["# Filter Reasons"])
    w.writerow(["reason", "count"])
    for row in data["filter_reasons"]:
        w.writerow([row["filter_reason"], row["count"]])
    w.writerow([])

    w.writerow(["# Hourly Volume (Last 7 Days)"])
    w.writerow(["hour", "filter_result", "count"])
    for row in data["hourly_volume"]:
        w.writerow([row["hour"], row["filter_result"], row["count"]])
    w.writerow([])

    w.writerow(["# Registered Nodes"])
    w.writerow(["id", "name", "address", "domains", "last_heartbeat", "status"])
    for n in nodes:
        w.writerow(
            [
                n.get("id", ""),
                n.get("name", ""),
                n.get("address", ""),
                n.get("domains", ""),
                n.get("last_heartbeat", ""),
                n.get("status", ""),
            ]
        )
    w.writerow([])

    w.writerow(["# Operator Audit Log"])
    w.writerow(["timestamp", "action", "operator", "client_ip", "resource", "details"])
    for e in data["audit_entries"]:
        w.writerow(
            [
                e.get("timestamp", ""),
                e.get("action", ""),
                e.get("operator", ""),
                e.get("client_ip", ""),
                e.get("resource", ""),
                e.get("details", ""),
            ]
        )

    return buf.getvalue().encode("utf-8")


async def export_report(request: Request) -> Response:
    """GET /api/reports/export?format=html|json|csv -- download a full report."""
    fmt = request.query_params.get("format", "html").lower()
    if fmt not in _VALID_FORMATS:
        return Response(
            json.dumps({"error": f"invalid format; must be one of {sorted(_VALID_FORMATS)}"}),
            status_code=400,
            media_type="application/json",
        )

    db: Database = request.app.state.db
    stats_query: StatsQuery = request.app.state.stats_query
    node_registry: NodeRegistry = request.app.state.node_registry

    data = await collect_report_data(db, audit_limit=200)
    nodes = await node_registry.list_nodes()

    overview_24h = await stats_query.overview(hours=24)
    stats_24h = {
        "total_requests": overview_24h.total_requests,
        "allowed_requests": overview_24h.allowed_requests,
        "blocked_requests": overview_24h.blocked_requests,
        "unique_ips": overview_24h.unique_ips,
        "block_rate": (
            overview_24h.blocked_requests / overview_24h.total_requests
            if overview_24h.total_requests
            else 0.0
        ),
    }

    client_ip = request.client.host if request.client else ""
    try:
        await db.audit(
            action="report_export",
            client_ip=client_ip,
            details=f"format={fmt}",
            resource="reports",
        )
    except Exception:
        log.warning("report_audit_failed", client_ip=client_ip, format=fmt)

    date_stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    filename = f"infraguard-report-{date_stamp}.{fmt}"
    disposition = f'attachment; filename="{filename}"'

    if fmt == "html":
        body = _render_html(
            title="InfraGuard Engagement Report",
            generated_at=data["generated_at"],
            total=data["total"],
            allowed=data["allowed"],
            blocked=data["blocked"],
            first_request=data["first_request"],
            last_request=data["last_request"],
            top_blocked_ips=data["top_blocked_ips"],
            domain_stats=data["domain_stats"],
            filter_reasons=data["filter_reasons"],
            top_blocked_uas=data["top_blocked_uas"],
            audit_entries=data["audit_entries"],
        ).encode("utf-8")
        media = "text/html; charset=utf-8"
    elif fmt == "json":
        body = _build_json_report(data, nodes, stats_24h)
        media = "application/json"
    else:  # csv
        body = _build_csv_report(data, nodes, stats_24h)
        media = "text/csv; charset=utf-8"

    log.info("report_exported", format=fmt, client_ip=client_ip, size=len(body))
    return Response(
        content=body,
        media_type=media,
        headers={"Content-Disposition": disposition},
    )
