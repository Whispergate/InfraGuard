"""Syslog plugin - forwards events as CEF or JSON syslog messages.

Supports UDP, TCP, and TCP+TLS transports. Covers Splunk, QRadar,
ArcSight, and any syslog-compatible SIEM.
"""

from __future__ import annotations

import asyncio
import json
import socket
import ssl as _ssl
from datetime import datetime, timezone

import structlog

from infraguard.models.events import RequestEvent
from infraguard.plugins.builtin._batch import BatchForwardingPlugin

log = structlog.get_logger()


def _cef_escape(s: str) -> str:
    """Escape special characters for CEF format."""
    return s.replace("\\", "\\\\").replace("|", "\\|").replace("=", "\\=")


class Plugin(BatchForwardingPlugin):
    name = "syslog"
    version = "1.0.0"

    def __init__(self):
        super().__init__()
        self._transport: asyncio.DatagramTransport | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._sock: socket.socket | None = None

    async def on_startup(self) -> None:
        # Don't call super - syslog doesn't use httpx
        protocol = self._opt("protocol", "udp")
        host = self._opt("host", "127.0.0.1")
        port = int(self._opt("port", 514))

        try:
            if protocol == "udp":
                loop = asyncio.get_event_loop()
                transport, _ = await loop.create_datagram_endpoint(
                    asyncio.DatagramProtocol,
                    remote_addr=(host, port),
                )
                self._transport = transport
            elif protocol in ("tcp", "tcp+tls"):
                ssl_ctx = None
                if protocol == "tcp+tls":
                    ssl_ctx = _ssl.create_default_context()
                    ca_path = self._opt("ca_cert")
                    if ca_path:
                        ssl_ctx.load_verify_locations(ca_path)
                    else:
                        ssl_ctx.check_hostname = False
                        ssl_ctx.verify_mode = _ssl.CERT_NONE
                _, self._writer = await asyncio.open_connection(host, port, ssl=ssl_ctx)

            log.info("syslog_connected", host=host, port=port, protocol=protocol)
        except Exception:
            log.exception("syslog_connect_error", host=host, port=port)

        # Start flush loop
        self._flush_task = asyncio.create_task(self._flush_loop())

    async def on_shutdown(self) -> None:
        if self._flush_task:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass
        await self._flush_batch()
        if self._transport:
            self._transport.close()
        if self._writer:
            self._writer.close()

    async def _send_batch(self, events: list[RequestEvent]) -> None:
        fmt = self._opt("format", "cef")
        facility = int(self._opt("facility", 1))

        for event in events:
            severity = 4 if event.filter_result == "block" else 6
            pri = facility * 8 + severity

            if fmt == "cef":
                msg = self._format_cef(event, pri)
            else:
                msg = self._format_json(event, pri)

            encoded = msg.encode("utf-8")
            try:
                if self._transport:
                    self._transport.sendto(encoded)
                elif self._writer:
                    self._writer.write(encoded + b"\n")
                    await self._writer.drain()
            except Exception:
                log.exception("syslog_send_error")
                break

    def _format_cef(self, event: RequestEvent, pri: int) -> str:
        ts = event.timestamp.strftime("%b %d %H:%M:%S")
        severity = 7 if event.filter_result == "block" else 3
        reason = _cef_escape(event.filter_reason or "")
        return (
            f"<{pri}>{ts} infraguard "
            f"CEF:0|InfraGuard|InfraGuard|1.0.0|request|"
            f"Request {event.filter_result.title()}|{severity}|"
            f"src={event.client_ip} "
            f"dst={event.domain} "
            f"requestMethod={event.method} "
            f"request={_cef_escape(event.uri)} "
            f"cs1={reason} cs1Label=filterReason "
            f"cn1={event.filter_score:.2f} cn1Label=filterScore "
            f"outcome={event.filter_result}"
        )

    def _format_json(self, event: RequestEvent, pri: int) -> str:
        ts = event.timestamp.strftime("%b %d %H:%M:%S")
        payload = json.dumps(self._event_to_dict(event))
        return f"<{pri}>{ts} infraguard {payload}"
