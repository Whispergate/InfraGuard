"""Passive TCP/IP fingerprint enrichment (p0f-style).

Extracts what the SYN packet's TTL, window size, TCP options, and
DF-flag tell us about the source OS. Real p0f runs at L2 and needs
the raw pcap here we approximate from what Starlette makes available
(client host, request headers, ASGI scope) plus optional integration
with an on-host p0f daemon over its unix socket.

Adds:

    ctx.metadata["os_guess"] = "Linux 5.x" | "Windows 10/11" | "macOS ..."

for use by the profile filter (e.g. "this campaign is Windows-only;
drop guesses of Linux even if the beacon shape matches").

If the p0f socket is not reachable, we fall back to a very small
User-Agent heuristic. Both are enrichers never block.
"""

from __future__ import annotations

import asyncio
from typing import Any

import structlog

from infraguard.pipeline.base import RequestContext
from infraguard.plugins.base import BasePlugin

log = structlog.get_logger()


class Plugin(BasePlugin):
    name = "p0f_fingerprint"
    version = "0.1.0"

    def __init__(self) -> None:
        self._settings: Any = None
        self._sock_path: str | None = None

    def configure(self, settings: Any) -> None:
        self._settings = settings

    def _opt(self, key: str, default: Any = None) -> Any:
        if self._settings and hasattr(self._settings, "options"):
            return self._settings.options.get(key, default)
        return default

    async def on_startup(self) -> None:
        self._sock_path = self._opt("p0f_socket", "/var/run/p0f.sock")

    async def on_request(self, ctx: RequestContext) -> None:
        # Try the real p0f API first.
        guess = await self._p0f_query(str(ctx.client_ip))
        if guess:
            ctx.metadata["os_guess"] = guess
            return None
        # Fallback: cheap UA parse.
        ua = ctx.request.headers.get("user-agent", "")
        guess = _ua_os_guess(ua)
        if guess:
            ctx.metadata["os_guess"] = guess
        return None

    async def _p0f_query(self, ip: str) -> str | None:
        """Query the p0f v3 API socket for an OS guess on ``ip``.

        Wire format from p0f-3.x api.h:
            request:  uint32 magic=0x50304601 + uint8 addr_type +
                      uint8[16] addr (v4 in first 4 bytes)
            response: uint32 magic=0x50304602 + uint32 status + ... +
                      uint8[32] os_name + uint8[32] os_flavor + ...

        Missing / unreachable socket returns None so the UA fallback
        can run.
        """
        import ipaddress
        import struct

        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return None

        if isinstance(ip_obj, ipaddress.IPv4Address):
            addr_type = 4
            addr_bytes = ip_obj.packed + b"\x00" * 12
        else:
            addr_type = 6
            addr_bytes = ip_obj.packed

        req = struct.pack("<I B 16s", 0x50304601, addr_type, addr_bytes)

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_unix_connection(self._sock_path), timeout=0.3
            )
        except (TimeoutError, FileNotFoundError, ConnectionRefusedError, PermissionError, OSError):
            return None

        os_name = os_flavor = ""
        try:
            writer.write(req)
            await writer.drain()
            resp = await asyncio.wait_for(reader.read(112), timeout=0.3)
            if len(resp) >= 112 and resp[:4] == b"\x02\x46\x30\x50":
                status = struct.unpack_from("<I", resp, 4)[0]
                if status == 0x10:  # RESP_OK
                    os_name = resp[48:80].split(b"\x00", 1)[0].decode("ascii", "replace")
                    os_flavor = resp[80:112].split(b"\x00", 1)[0].decode("ascii", "replace")
        except (TimeoutError, OSError):
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except OSError:
                pass

        if not os_name:
            return None
        return f"{os_name} {os_flavor}".strip()


def _ua_os_guess(ua: str) -> str | None:
    lo = ua.lower()
    if "windows nt 10" in lo:
        return "Windows 10/11"
    if "windows nt 6" in lo:
        return "Windows 7/8"
    if "mac os x" in lo or "macintosh" in lo:
        return "macOS"
    if "linux" in lo:
        return "Linux"
    if "android" in lo:
        return "Android"
    if "iphone" in lo or "ipad" in lo:
        return "iOS"
    return None
