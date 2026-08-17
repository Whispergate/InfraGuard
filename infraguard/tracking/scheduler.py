"""Scheduled engagement report generation and delivery.

Periodically generates InfraGuard engagement reports (traffic statistics,
blocked requests, burn events, rotation history, and observed IOCs) and
delivers them to operators via email (SMTP) and/or webhooks.

Supported formats: HTML, PDF (best-effort via optional backends), JSON, CSV.

Typical usage from the application lifespan::

    scheduler = ReportScheduler(config.reporting, db=db, node_registry=nodes)
    await scheduler.start()
    ...
    await scheduler.stop()

The scheduler may also be driven externally (cron, CI) via::

    await scheduler.run_once()
"""

from __future__ import annotations

import asyncio
import csv
import io
import json
import smtplib
import ssl
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import TYPE_CHECKING, Any

import httpx
import structlog

from infraguard.config.schema import ReportScheduleConfig
from infraguard.tracking.database import Database
from infraguard.tracking.report import _render_html, collect_report_data

if TYPE_CHECKING:
    from infraguard.tracking.nodes import NodeRegistry

log = structlog.get_logger()

_FORMATS = {"html", "pdf", "json", "csv"}

# Actions recorded in the audit log that constitute infrastructure events.
_BURN_AUDIT_ACTIONS = ("burn_detected", "burn_alert", "burn")
_ROTATION_AUDIT_ACTIONS = (
    "rotation",
    "rotation_started",
    "rotation_complete",
    "rotation_failed",
    "deploy_rotate",
)


class ReportScheduler:
    """Generates and delivers engagement reports on a schedule.

    The scheduler runs a background asyncio task that ticks every
    ``check_interval_seconds``; when the configured ``interval_hours`` has
    elapsed since the last run, a report is generated in each configured
    format, written to ``output_dir``, and delivered via the configured
    email / webhook channels.
    """

    def __init__(
        self,
        config: ReportScheduleConfig,
        db: Database,
        node_registry: "NodeRegistry | None" = None,
    ):
        self.config = config
        self.db = db
        self._nodes = node_registry
        self._task: asyncio.Task | None = None
        self._stop_event = asyncio.Event()
        self._last_run: float | None = None
        self._http: httpx.AsyncClient | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    async def start(self) -> None:
        """Start the background scheduler loop."""
        if not self.config.enabled:
            log.info("report_scheduler_disabled")
            return
        self._http = httpx.AsyncClient(timeout=httpx.Timeout(30.0))
        self._task = asyncio.create_task(self._loop(), name="report-scheduler")
        log.info(
            "report_scheduler_started",
            interval_hours=self.config.interval_hours,
            formats=self.config.formats,
        )

    async def stop(self) -> None:
        """Signal the loop to exit and wait for the task to finish."""
        self._stop_event.set()
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
            self._task = None
        if self._http is not None:
            await self._http.aclose()
            self._http = None
        log.info("report_scheduler_stopped")

    async def _loop(self) -> None:
        """Tick loop: sleep, check whether a report is due, generate if so."""
        interval_s = self.config.interval_hours * 3600.0
        while not self._stop_event.is_set():
            try:
                await asyncio.wait_for(
                    self._stop_event.wait(),
                    timeout=self.config.check_interval_seconds,
                )
                break  # stop event set
            except asyncio.TimeoutError:
                pass

            now = asyncio.get_event_loop().time()
            if self._last_run is None or (now - self._last_run) >= interval_s:
                try:
                    await self.run_once()
                    self._last_run = now
                except Exception:
                    log.exception("report_generation_failed")

    # ------------------------------------------------------------------
    # One-shot generation
    # ------------------------------------------------------------------
    async def run_once(self) -> list[Path]:
        """Generate a report in every configured format and deliver it.

        Returns the list of written file paths (empty for delivery modes
        that don't produce files, though all current formats do).
        """
        data = await self._collect()
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        out_dir = Path(self.config.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        written: list[Path] = []
        rendered: dict[str, bytes] = {}
        for fmt in self.config.formats:
            fmt = fmt.lower()
            if fmt not in _FORMATS:
                log.warning("report_unknown_format", format=fmt)
                continue
            try:
                body = await self._render(fmt, data)
            except Exception:
                log.exception("report_render_failed", format=fmt)
                continue
            rendered[fmt] = body
            path = out_dir / f"infraguard-report-{stamp}.{fmt}"
            path.write_bytes(body)
            written.append(path)
            log.info("report_written", path=str(path), format=fmt, size=len(body))

        if rendered:
            await self._deliver(rendered, stamp, data)

        return written

    # ------------------------------------------------------------------
    # Data collection
    # ------------------------------------------------------------------
    async def _collect(self) -> dict[str, Any]:
        """Collect base report data plus burn events, rotation history, IOCs."""
        data = await collect_report_data(self.db, audit_limit=self.config.audit_limit)

        # Burn events: audit log entries + requests flagged as burn_alert
        burn_audit = await self.db.get_audit_log(limit=200)
        data["burn_events"] = [
            e for e in burn_audit
            if e.get("action", "") in _BURN_AUDIT_ACTIONS
        ]
        burn_requests = await self.db.fetchall(
            "SELECT timestamp, domain, client_ip, filter_reason FROM requests "
            "WHERE filter_result = 'burn_alert' ORDER BY timestamp DESC LIMIT 100"
        )
        data["burn_alerts"] = burn_requests

        # Rotation history from the audit trail
        data["rotation_history"] = [
            e for e in burn_audit
            if e.get("action", "") in _ROTATION_AUDIT_ACTIONS
        ]

        # IOCs observed in traffic: top blocked IPs / UAs / paths act as
        # indicators of blue-team or scanner interest in the infrastructure.
        ioc_paths = await self.db.fetchall(
            "SELECT uri, domain, COUNT(*) as count FROM requests "
            "WHERE filter_result = 'block' "
            "GROUP BY uri, domain ORDER BY count DESC LIMIT 25"
        )
        data["ioc_paths"] = ioc_paths

        # Registered nodes (redirector fleet) when a registry is available
        if self._nodes is not None:
            try:
                data["nodes"] = await self._nodes.list_nodes()
            except Exception:
                log.exception("report_node_list_failed")
                data["nodes"] = []
        else:
            data["nodes"] = []

        return data

    # ------------------------------------------------------------------
    # Rendering
    # ------------------------------------------------------------------
    async def _render(self, fmt: str, data: dict[str, Any]) -> bytes:
        if fmt == "html":
            return self._render_html(data).encode("utf-8")
        if fmt == "json":
            return self._render_json(data)
        if fmt == "csv":
            return self._render_csv(data)
        if fmt == "pdf":
            return await self._render_pdf(data)
        raise ValueError(f"unsupported format: {fmt}")

    def _render_html(self, data: dict[str, Any]) -> str:
        """Render the full engagement report HTML, with scheduler sections."""
        base = _render_html(
            title=self.config.title,
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
        )

        import html as _h

        burn_rows = "".join(
            f"<tr><td>{_h.escape(e.get('timestamp', ''))}</td>"
            f"<td>{_h.escape(e.get('action', ''))}</td>"
            f"<td>{_h.escape(e.get('details', ''))}</td>"
            f"<td>{_h.escape(e.get('resource', ''))}</td></tr>\n"
            for e in data.get("burn_events", [])
        ) or "<tr><td colspan='4'><em>No burn events recorded.</em></td></tr>"

        alert_rows = "".join(
            f"<tr><td>{_h.escape(r.get('timestamp', ''))}</td>"
            f"<td>{_h.escape(r.get('domain', ''))}</td>"
            f"<td>{_h.escape(r.get('client_ip', ''))}</td>"
            f"<td>{_h.escape(r.get('filter_reason') or '')}</td></tr>\n"
            for r in data.get("burn_alerts", [])
        ) or "<tr><td colspan='4'><em>No burn alerts in traffic.</em></td></tr>"

        rot_rows = "".join(
            f"<tr><td>{_h.escape(e.get('timestamp', ''))}</td>"
            f"<td>{_h.escape(e.get('action', ''))}</td>"
            f"<td>{_h.escape(e.get('operator', ''))}</td>"
            f"<td>{_h.escape(e.get('details', ''))}</td></tr>\n"
            for e in data.get("rotation_history", [])
        ) or "<tr><td colspan='4'><em>No rotations recorded.</em></td></tr>"

        ioc_rows = "".join(
            f"<tr><td>{_h.escape(r.get('domain', ''))}</td>"
            f"<td>{_h.escape(r.get('uri', ''))}</td>"
            f"<td>{r.get('count', 0)}</td></tr>\n"
            for r in data.get("ioc_paths", [])
        )

        extra = f"""
<h2>Burn Events</h2>
<table>
<tr><th>Timestamp</th><th>Action</th><th>Details</th><th>Resource</th></tr>
{burn_rows}
</table>

<h2>Burn Alerts (Traffic)</h2>
<table>
<tr><th>Timestamp</th><th>Domain</th><th>Client IP</th><th>Reason</th></tr>
{alert_rows}
</table>

<h2>Rotation History</h2>
<table>
<tr><th>Timestamp</th><th>Action</th><th>Operator</th><th>Details</th></tr>
{rot_rows}
</table>

<h2>Observed IOCs - Top Blocked Paths</h2>
<table>
<tr><th>Domain</th><th>URI</th><th>Blocked Count</th></tr>
{ioc_rows}
</table>
"""
        # Inject the extra sections before the closing </body> tag.
        return base.replace("</body>", extra + "\n</body>")

    def _render_json(self, data: dict[str, Any]) -> bytes:
        payload = {
            "metadata": {
                "title": self.config.title,
                "generated_at": data["generated_at"],
                "first_request": data["first_request"],
                "last_request": data["last_request"],
                "report_version": 1,
            },
            "summary": {
                "total_requests": data["total"],
                "allowed_requests": data["allowed"],
                "blocked_requests": data["blocked"],
                "unique_ips": data["unique_ips"],
                "block_rate": (
                    data["blocked"] / data["total"] if data["total"] else 0.0
                ),
            },
            "domains": data["domain_stats"],
            "top_blocked_ips": data["top_blocked_ips"],
            "top_blocked_user_agents": data["top_blocked_uas"],
            "filter_reasons": data["filter_reasons"],
            "hourly_volume": data["hourly_volume"],
            "burn_events": data.get("burn_events", []),
            "burn_alerts": data.get("burn_alerts", []),
            "rotation_history": data.get("rotation_history", []),
            "iocs": {
                "blocked_ips": [
                    {"ip": r["client_ip"], "count": r["count"]}
                    for r in data["top_blocked_ips"]
                ],
                "blocked_paths": data.get("ioc_paths", []),
                "blocked_user_agents": [
                    {"user_agent": r["user_agent"], "count": r["count"]}
                    for r in data["top_blocked_uas"]
                ],
            },
            "nodes": data.get("nodes", []),
            "audit_log": data["audit_entries"],
        }
        return json.dumps(payload, indent=2, default=str).encode("utf-8")

    def _render_csv(self, data: dict[str, Any]) -> bytes:
        buf = io.StringIO()
        w = csv.writer(buf)

        w.writerow(["# InfraGuard Scheduled Report"])
        w.writerow(["title", self.config.title])
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

        w.writerow(["# Top Blocked IPs (IOCs)"])
        w.writerow(["client_ip", "count"])
        for row in data["top_blocked_ips"]:
            w.writerow([row["client_ip"], row["count"]])
        w.writerow([])

        w.writerow(["# Blocked Paths (IOCs)"])
        w.writerow(["domain", "uri", "count"])
        for row in data.get("ioc_paths", []):
            w.writerow([row.get("domain", ""), row.get("uri", ""), row.get("count", 0)])
        w.writerow([])

        w.writerow(["# Filter Reasons"])
        w.writerow(["reason", "count"])
        for row in data["filter_reasons"]:
            w.writerow([row["filter_reason"], row["count"]])
        w.writerow([])

        w.writerow(["# Burn Events"])
        w.writerow(["timestamp", "action", "details", "resource"])
        for e in data.get("burn_events", []):
            w.writerow([
                e.get("timestamp", ""), e.get("action", ""),
                e.get("details", ""), e.get("resource", ""),
            ])
        w.writerow([])

        w.writerow(["# Burn Alerts (Traffic)"])
        w.writerow(["timestamp", "domain", "client_ip", "reason"])
        for r in data.get("burn_alerts", []):
            w.writerow([
                r.get("timestamp", ""), r.get("domain", ""),
                r.get("client_ip", ""), r.get("filter_reason") or "",
            ])
        w.writerow([])

        w.writerow(["# Rotation History"])
        w.writerow(["timestamp", "action", "operator", "details"])
        for e in data.get("rotation_history", []):
            w.writerow([
                e.get("timestamp", ""), e.get("action", ""),
                e.get("operator", ""), e.get("details", ""),
            ])
        w.writerow([])

        w.writerow(["# Operator Audit Log"])
        w.writerow(["timestamp", "action", "operator", "client_ip", "resource", "details"])
        for e in data["audit_entries"]:
            w.writerow([
                e.get("timestamp", ""), e.get("action", ""), e.get("operator", ""),
                e.get("client_ip", ""), e.get("resource", ""), e.get("details", ""),
            ])

        return buf.getvalue().encode("utf-8")

    async def _render_pdf(self, data: dict[str, Any]) -> bytes:
        """Render the report as PDF.

        PDF generation is best-effort: it tries optional backends in order
        (``weasyprint``, then ``fpdf``). If neither is installed, a
        RuntimeError is raised and the format is skipped by the caller.
        """
        html_body = self._render_html(data)

        try:
            import weasyprint  # type: ignore

            return await asyncio.to_thread(
                weasyprint.HTML(string=html_body).write_pdf
            )
        except ImportError:
            pass

        try:
            from fpdf import FPDF  # type: ignore

            def _build() -> bytes:
                pdf = FPDF()
                pdf.set_auto_page_break(auto=True, margin=15)
                pdf.add_page()
                pdf.set_font("Helvetica", "B", 16)
                pdf.cell(0, 10, self.config.title, new_x="LMARGIN", new_y="NEXT")
                pdf.set_font("Helvetica", "", 10)
                pdf.cell(0, 8, f"Generated: {data['generated_at']}",
                         new_x="LMARGIN", new_y="NEXT")
                pdf.ln(4)
                pdf.set_font("Helvetica", "B", 12)
                pdf.cell(0, 8, "Summary", new_x="LMARGIN", new_y="NEXT")
                pdf.set_font("Helvetica", "", 10)
                for label, value in (
                    ("Total requests", data["total"]),
                    ("Allowed (C2)", data["allowed"]),
                    ("Blocked", data["blocked"]),
                    ("Unique IPs", data["unique_ips"]),
                ):
                    pdf.cell(0, 6, f"{label}: {value}",
                             new_x="LMARGIN", new_y="NEXT")
                pdf.ln(4)
                pdf.set_font("Helvetica", "B", 12)
                pdf.cell(0, 8, "Top Blocked IPs", new_x="LMARGIN", new_y="NEXT")
                pdf.set_font("Helvetica", "", 9)
                for row in data["top_blocked_ips"][:20]:
                    pdf.cell(0, 5, f"{row['client_ip']}  -  {row['count']}",
                             new_x="LMARGIN", new_y="NEXT")
                return bytes(pdf.output())

            return await asyncio.to_thread(_build)
        except ImportError:
            pass

        raise RuntimeError(
            "PDF rendering requires the optional 'weasyprint' or 'fpdf' package"
        )

    # ------------------------------------------------------------------
    # Delivery
    # ------------------------------------------------------------------
    async def _deliver(
        self,
        rendered: dict[str, bytes],
        stamp: str,
        data: dict[str, Any],
    ) -> None:
        """Dispatch rendered reports to configured delivery channels."""
        delivery = self.config.delivery

        if delivery.webhook_urls and self._http is not None:
            await self._deliver_webhooks(rendered, stamp, data, delivery.webhook_urls)

        if delivery.email.enabled:
            await self._deliver_email(rendered, stamp, data)

    async def _deliver_webhooks(
        self,
        rendered: dict[str, bytes],
        stamp: str,
        data: dict[str, Any],
        urls: list[str],
    ) -> None:
        """POST a summary payload to each configured webhook URL.

        The JSON report (when generated) is embedded inline; other formats
        are referenced by filename only, since generic webhooks expect
        JSON bodies (mirrors the generic_webhook plugin pattern).
        """
        summary = {
            "title": self.config.title,
            "generated_at": data["generated_at"],
            "stamp": stamp,
            "summary": {
                "total_requests": data["total"],
                "allowed_requests": data["allowed"],
                "blocked_requests": data["blocked"],
                "unique_ips": data["unique_ips"],
            },
            "burn_event_count": len(data.get("burn_events", [])),
            "rotation_count": len(data.get("rotation_history", [])),
            "formats": sorted(rendered.keys()),
        }
        if "json" in rendered and self.config.delivery.webhook_include_full_json:
            try:
                summary["report"] = json.loads(rendered["json"].decode("utf-8"))
            except Exception:
                log.warning("report_webhook_json_embed_failed")

        body = json.dumps(summary, default=str)
        for url in urls:
            try:
                resp = await self._http.post(
                    url, content=body,
                    headers={"Content-Type": "application/json"},
                )
                if resp.status_code >= 400:
                    log.warning(
                        "report_webhook_error", url=url, status=resp.status_code
                    )
                else:
                    log.info("report_webhook_sent", url=url)
            except Exception:
                log.exception("report_webhook_send_error", url=url)

    async def _deliver_email(
        self,
        rendered: dict[str, bytes],
        stamp: str,
        data: dict[str, Any],
    ) -> None:
        """Send the report via SMTP with rendered formats as attachments."""
        email_cfg = self.config.delivery.email

        msg = EmailMessage()
        msg["Subject"] = f"{self.config.title} - {stamp}"
        msg["From"] = email_cfg.from_addr
        msg["To"] = ", ".join(email_cfg.to_addrs)

        text = (
            f"{self.config.title}\n"
            f"Generated: {data['generated_at']}\n\n"
            f"Total requests:  {data['total']}\n"
            f"Allowed (C2):    {data['allowed']}\n"
            f"Blocked:         {data['blocked']}\n"
            f"Unique IPs:      {data['unique_ips']}\n"
            f"Burn events:     {len(data.get('burn_events', []))}\n"
            f"Rotations:       {len(data.get('rotation_history', []))}\n"
        )
        msg.set_content(text)

        # Attach HTML inline-viewable, everything else as attachments.
        _mime = {
            "html": ("text", "html"),
            "json": ("application", "json"),
            "csv": ("text", "csv"),
            "pdf": ("application", "pdf"),
        }
        for fmt, body in rendered.items():
            maintype, subtype = _mime.get(fmt, ("application", "octet-stream"))
            msg.add_attachment(
                body,
                maintype=maintype,
                subtype=subtype,
                filename=f"infraguard-report-{stamp}.{fmt}",
            )

        def _send() -> None:
            context = ssl.create_default_context()
            cls = smtplib.SMTP_SSL if email_cfg.use_tls else smtplib.SMTP
            with cls(email_cfg.smtp_host, email_cfg.smtp_port,
                     timeout=30, context=context if email_cfg.use_tls else None) as server:
                if email_cfg.use_starttls and not email_cfg.use_tls:
                    server.starttls(context=context)
                if email_cfg.username:
                    server.login(email_cfg.username, email_cfg.password or "")
                server.send_message(msg)

        try:
            await asyncio.to_thread(_send)
            log.info(
                "report_email_sent",
                to=email_cfg.to_addrs,
                formats=sorted(rendered.keys()),
            )
        except Exception:
            log.exception("report_email_failed", to=email_cfg.to_addrs)


# Convenience re-export so callers can validate config without importing
# the schema module directly.
__all__ = ["ReportScheduler"]
