"""DNS listener - intercepts DNS queries, filters, and forwards to upstream.

Uses dnspython for async DNS server and resolution. Queries are filtered
through the IP intelligence pipeline (no C2 profile validation) and
recorded as events with ``protocol="dns"``.

Install: ``pip install infraguard[dns-listener]`` (requires dnspython)
"""

from __future__ import annotations

import asyncio
import time
from ipaddress import ip_address

import structlog

from infraguard.config.schema import ListenerConfig
from infraguard.intel.ip_lists import CIDRList
from infraguard.intel.manager import IntelManager
from infraguard.models.events import RequestEvent
from infraguard.tracking.recorder import EventRecorder

log = structlog.get_logger()


class DNSListener:
    """Async DNS server that filters and proxies queries."""

    protocol = "dns"

    def __init__(
        self,
        config: ListenerConfig,
        intel: IntelManager,
        recorder: EventRecorder | None = None,
    ):
        self._config = config
        self._intel = intel
        self._recorder = recorder
        self._upstream = config.options.get("upstream", "8.8.8.8:53")
        self._allowed_types = [
            t.upper() for t in config.options.get("allowed_types", [])
        ]
        self._transport: asyncio.DatagramTransport | None = None

    async def start(self) -> None:
        try:
            import dns.message
            import dns.rdatatype
        except ImportError:
            log.error(
                "dns_listener_unavailable",
                reason="dnspython not installed. Install with: pip install infraguard[dns-listener]",
            )
            return

        host = self._config.bind
        port = self._config.port

        loop = asyncio.get_event_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _DNSProtocol(self),
            local_addr=(host, port),
        )
        self._transport = transport
        log.info("dns_listener_started", bind=host, port=port, upstream=self._upstream)

    async def stop(self) -> None:
        if self._transport:
            self._transport.close()

    async def handle_query(self, data: bytes, addr: tuple[str, int]) -> bytes | None:
        """Process a DNS query, filter, and forward or deny."""
        import dns.message
        import dns.rdatatype

        start = time.perf_counter()
        client_ip_str = addr[0]

        try:
            query = dns.message.from_wire(data)
        except Exception:
            return None

        # Extract query info
        if not query.question:
            return None
        q = query.question[0]
        qname = str(q.name).rstrip(".")
        qtype = dns.rdatatype.to_text(q.rdtype)
        domain = qname

        # Filter: allowed query types
        if self._allowed_types and qtype not in self._allowed_types:
            self._record_event(
                domain, client_ip_str, qtype, qname, "block",
                f"DNS type {qtype} not allowed", start,
            )
            return self._make_refused(query)

        # Filter: IP intelligence
        try:
            client_ip = ip_address(client_ip_str)
            classification = await self._intel.classify(client_ip)
            if classification.is_blocked:
                self._record_event(
                    domain, client_ip_str, qtype, qname, "block",
                    classification.reason, start,
                )
                return self._make_refused(query)
        except Exception:
            pass

        # Forward to upstream
        response_data = await self._forward_query(data)
        if response_data is None:
            self._record_event(
                domain, client_ip_str, qtype, qname, "block",
                "upstream_timeout", start,
            )
            return self._make_servfail(query)

        self._record_event(
            domain, client_ip_str, qtype, qname, "allow", None, start,
        )
        return response_data

    async def _forward_query(self, data: bytes) -> bytes | None:
        """Forward a DNS query to the upstream resolver via UDP."""
        host, _, port_str = self._upstream.rpartition(":")
        if not host:
            host = self._upstream
            port_str = "53"
        port = int(port_str)

        try:
            loop = asyncio.get_event_loop()
            transport, protocol = await loop.create_datagram_endpoint(
                asyncio.DatagramProtocol,
                remote_addr=(host, port),
            )
            future: asyncio.Future[bytes] = asyncio.get_event_loop().create_future()

            class _Receiver(asyncio.DatagramProtocol):
                def datagram_received(self, data: bytes, addr: tuple) -> None:
                    if not future.done():
                        future.set_result(data)

            transport, _ = await loop.create_datagram_endpoint(
                _Receiver, remote_addr=(host, port),
            )
            transport.sendto(data)

            try:
                response = await asyncio.wait_for(future, timeout=5.0)
                return response
            except asyncio.TimeoutError:
                return None
            finally:
                transport.close()
        except Exception:
            log.exception("dns_forward_error", upstream=self._upstream)
            return None

    def _record_event(
        self,
        domain: str,
        client_ip: str,
        method: str,
        uri: str,
        result: str,
        reason: str | None,
        start: float,
    ) -> None:
        if not self._recorder:
            return
        duration_ms = (time.perf_counter() - start) * 1000
        self._recorder.record(
            RequestEvent.now(
                domain=domain,
                client_ip=client_ip,
                method=method,
                uri=uri,
                user_agent="",
                filter_result=result,
                filter_reason=reason,
                filter_score=1.0 if result == "block" else 0.0,
                response_status=0,
                duration_ms=round(duration_ms, 1),
                protocol="dns",
            )
        )

    @staticmethod
    def _make_refused(query) -> bytes:
        import dns.message
        import dns.rcode
        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.REFUSED)
        return response.to_wire()

    @staticmethod
    def _make_servfail(query) -> bytes:
        import dns.message
        import dns.rcode
        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.SERVFAIL)
        return response.to_wire()


class _DNSProtocol(asyncio.DatagramProtocol):
    """asyncio UDP protocol that dispatches to DNSListener."""

    def __init__(self, listener: DNSListener):
        self._listener = listener
        self._transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self._transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        asyncio.create_task(self._handle(data, addr))

    async def _handle(self, data: bytes, addr: tuple[str, int]) -> None:
        response = await self._listener.handle_query(data, addr)
        if response and self._transport:
            self._transport.sendto(response, addr)
