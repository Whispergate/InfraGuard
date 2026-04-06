"""Engagement report generation from the tracking database.

Generates HTML reports summarizing redirector activity for post-engagement
deliverables. The report includes:

  - Request volume over time (allowed vs blocked)
  - Top blocked IPs with classification
  - Per-domain statistics
  - Filter effectiveness breakdown
  - Geographic distribution (if GeoIP data available)
  - Operator audit trail
"""

from __future__ import annotations

import html
from datetime import datetime, timezone
from pathlib import Path

import aiosqlite
import structlog

from infraguard.tracking.database import Database

log = structlog.get_logger()


async def generate_report(
    db: Database,
    output_path: Path,
    title: str = "InfraGuard Engagement Report",
) -> Path:
    """Generate an HTML engagement report from the tracking database.

    Args:
        db: Connected Database instance.
        output_path: File path to write the HTML report.
        title: Report title.

    Returns:
        Path to the generated report file.
    """
    now = datetime.now(timezone.utc)

    # Gather statistics
    total = await db.fetchone("SELECT COUNT(*) as count FROM requests")
    total_count = total["count"] if total else 0

    allowed = await db.fetchone(
        "SELECT COUNT(*) as count FROM requests WHERE filter_result = 'allow'"
    )
    allowed_count = allowed["count"] if allowed else 0

    blocked = await db.fetchone(
        "SELECT COUNT(*) as count FROM requests WHERE filter_result = 'block'"
    )
    blocked_count = blocked["count"] if blocked else 0

    # Top blocked IPs
    top_blocked_ips = await db.fetchall(
        "SELECT client_ip, COUNT(*) as count FROM requests "
        "WHERE filter_result = 'block' "
        "GROUP BY client_ip ORDER BY count DESC LIMIT 20"
    )

    # Per-domain stats
    domain_stats = await db.fetchall(
        "SELECT domain, filter_result, COUNT(*) as count FROM requests "
        "GROUP BY domain, filter_result ORDER BY domain"
    )

    # Filter reason breakdown
    filter_reasons = await db.fetchall(
        "SELECT filter_reason, COUNT(*) as count FROM requests "
        "WHERE filter_reason IS NOT NULL AND filter_reason != '' "
        "GROUP BY filter_reason ORDER BY count DESC LIMIT 15"
    )

    # Hourly volume (last 7 days)
    hourly_volume = await db.fetchall(
        "SELECT strftime('%Y-%m-%d %H:00', timestamp) as hour, "
        "filter_result, COUNT(*) as count FROM requests "
        "WHERE timestamp > datetime('now', '-7 days') "
        "GROUP BY hour, filter_result ORDER BY hour"
    )

    # Top User-Agents (blocked)
    top_blocked_uas = await db.fetchall(
        "SELECT user_agent, COUNT(*) as count FROM requests "
        "WHERE filter_result = 'block' AND user_agent != '' "
        "GROUP BY user_agent ORDER BY count DESC LIMIT 10"
    )

    # Audit log summary
    audit_entries = await db.get_audit_log(limit=50)

    # Time range
    first_req = await db.fetchone(
        "SELECT MIN(timestamp) as first_ts FROM requests"
    )
    last_req = await db.fetchone(
        "SELECT MAX(timestamp) as last_ts FROM requests"
    )
    first_ts = (first_req["first_ts"] if first_req and first_req["first_ts"] else "N/A")
    last_ts = (last_req["last_ts"] if last_req and last_req["last_ts"] else "N/A")

    # Build HTML
    report_html = _render_html(
        title=title,
        generated_at=now.isoformat(),
        total=total_count,
        allowed=allowed_count,
        blocked=blocked_count,
        first_request=first_ts,
        last_request=last_ts,
        top_blocked_ips=top_blocked_ips,
        domain_stats=domain_stats,
        filter_reasons=filter_reasons,
        top_blocked_uas=top_blocked_uas,
        audit_entries=audit_entries,
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(report_html, encoding="utf-8")
    log.info("report_generated", path=str(output_path), total_requests=total_count)
    return output_path


def _render_html(
    title: str,
    generated_at: str,
    total: int,
    allowed: int,
    blocked: int,
    first_request: str,
    last_request: str,
    top_blocked_ips: list[dict],
    domain_stats: list[dict],
    filter_reasons: list[dict],
    top_blocked_uas: list[dict],
    audit_entries: list[dict],
) -> str:
    """Render the report as a self-contained HTML document."""
    block_rate = (blocked / total * 100) if total > 0 else 0

    # Domain stats table
    domain_rows = ""
    domains: dict[str, dict[str, int]] = {}
    for row in domain_stats:
        d = row["domain"]
        if d not in domains:
            domains[d] = {"allow": 0, "block": 0}
        domains[d][row["filter_result"]] = row["count"]

    for d, counts in sorted(domains.items()):
        d_total = counts.get("allow", 0) + counts.get("block", 0)
        d_block_rate = (counts.get("block", 0) / d_total * 100) if d_total > 0 else 0
        domain_rows += (
            f"<tr><td>{html.escape(d)}</td>"
            f"<td>{d_total}</td>"
            f"<td>{counts.get('allow', 0)}</td>"
            f"<td>{counts.get('block', 0)}</td>"
            f"<td>{d_block_rate:.1f}%</td></tr>\n"
        )

    # Blocked IPs table
    ip_rows = ""
    for row in top_blocked_ips:
        ip_rows += f"<tr><td>{html.escape(row['client_ip'])}</td><td>{row['count']}</td></tr>\n"

    # Filter reasons table
    reason_rows = ""
    for row in filter_reasons:
        reason_rows += (
            f"<tr><td>{html.escape(row['filter_reason'] or '')}</td>"
            f"<td>{row['count']}</td></tr>\n"
        )

    # Blocked UAs table
    ua_rows = ""
    for row in top_blocked_uas:
        ua_rows += (
            f"<tr><td>{html.escape(row['user_agent'][:80])}</td>"
            f"<td>{row['count']}</td></tr>\n"
        )

    # Audit log table
    audit_rows = ""
    for entry in audit_entries:
        audit_rows += (
            f"<tr><td>{html.escape(entry.get('timestamp', ''))}</td>"
            f"<td>{html.escape(entry.get('action', ''))}</td>"
            f"<td>{html.escape(entry.get('operator', ''))}</td>"
            f"<td>{html.escape(entry.get('details', ''))}</td></tr>\n"
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{html.escape(title)}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace;
         max-width: 1000px; margin: 40px auto; padding: 0 20px; color: #1a1a1a;
         background: #f8f9fa; }}
  h1 {{ border-bottom: 3px solid #dc3545; padding-bottom: 10px; }}
  h2 {{ color: #495057; margin-top: 40px; }}
  .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px; margin: 20px 0; }}
  .stat {{ background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
  .stat .value {{ font-size: 2em; font-weight: bold; }}
  .stat .label {{ color: #6c757d; font-size: 0.9em; }}
  .stat.allowed .value {{ color: #28a745; }}
  .stat.blocked .value {{ color: #dc3545; }}
  table {{ width: 100%; border-collapse: collapse; margin: 16px 0; background: #fff;
           border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
  th, td {{ padding: 10px 14px; text-align: left; border-bottom: 1px solid #dee2e6; }}
  th {{ background: #343a40; color: #fff; font-weight: 600; }}
  tr:hover {{ background: #f1f3f5; }}
  .meta {{ color: #6c757d; font-size: 0.85em; margin: 10px 0; }}
</style>
</head>
<body>
<h1>{html.escape(title)}</h1>
<p class="meta">Generated: {html.escape(generated_at)} | Period: {html.escape(first_request)} to {html.escape(last_request)}</p>

<div class="stats">
  <div class="stat"><div class="value">{total:,}</div><div class="label">Total Requests</div></div>
  <div class="stat allowed"><div class="value">{allowed:,}</div><div class="label">Allowed (C2)</div></div>
  <div class="stat blocked"><div class="value">{blocked:,}</div><div class="label">Blocked</div></div>
  <div class="stat blocked"><div class="value">{block_rate:.1f}%</div><div class="label">Block Rate</div></div>
</div>

<h2>Per-Domain Statistics</h2>
<table>
<tr><th>Domain</th><th>Total</th><th>Allowed</th><th>Blocked</th><th>Block Rate</th></tr>
{domain_rows}
</table>

<h2>Top Blocked IPs</h2>
<table>
<tr><th>Client IP</th><th>Blocked Requests</th></tr>
{ip_rows}
</table>

<h2>Filter Effectiveness</h2>
<table>
<tr><th>Block Reason</th><th>Count</th></tr>
{reason_rows}
</table>

<h2>Top Blocked User-Agents</h2>
<table>
<tr><th>User-Agent</th><th>Count</th></tr>
{ua_rows}
</table>

<h2>Operator Audit Trail</h2>
<table>
<tr><th>Timestamp</th><th>Action</th><th>Operator</th><th>Details</th></tr>
{audit_rows}
</table>

</body>
</html>"""
