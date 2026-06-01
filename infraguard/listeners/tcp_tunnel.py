"""TCP tunnel listener - raw byte-stream passthrough for pivot tooling.

Designed for tools whose traffic is not HTTP and therefore cannot be
fronted by the Starlette ASGI app:

  * **Ligolo-ng / Ligolo-mp** - single long-lived TLS connection between
    the agent and the proxy/teamserver.  Multiplexed YAMUX streams ride
    on top.  The proxy port (default 11601) speaks raw TLS, not HTTP.

  * **Generic TLS-over-TCP C2 channels** - any tooling that wants an
    opaque TCP tunnel through the redirector.

The listener accepts TCP on a dedicated port (do NOT colocate with the
HTTP listener on 443 unless you add SNI multiplexing in front), applies
the IP-intel filter at accept time, and bidirectionally pipes bytes to
the configured upstream.  Optionally terminates TLS toward the client
(`tls.terminate = true`) if you want the redirector to present its own
certificate to clients; otherwise traffic passes through opaque and TLS
is negotiated end-to-end between the agent and the teamserver.

Config example::

    listeners:
      - protocol: "tcp_tunnel"
        bind: "0.0.0.0"
        port: 11601
        options:
          upstream_host: "10.3.40.1"
          upstream_port: 11601
          tls_passthrough: true        # forward TLS bytes unmodified
          idle_timeout_seconds: 300    # close after N seconds of no traffic
          profile: "ligolo_mp"         # tag for tracking events
"""

from __future__ import annotations

import asyncio
import hashlib
import ssl
import time
from ipaddress import ip_address

import structlog

from infraguard.config.schema import ListenerConfig
from infraguard.intel.manager import IntelManager
from infraguard.models.events import RequestEvent
from infraguard.tracking.recorder import EventRecorder

log = structlog.get_logger()


class TCPTunnelListener:
    """Raw TCP passthrough listener with IP-intel gating."""

    protocol = "tcp_tunnel"

    def __init__(
        self,
        config: ListenerConfig,
        intel: IntelManager,
        recorder: EventRecorder | None = None,
    ):
        self._config = config
        self._intel = intel
        self._recorder = recorder
        opts = config.options or {}
        self._upstream_host: str = opts.get("upstream_host", "")
        self._upstream_port: int = int(opts.get("upstream_port", 0))
        self._idle_timeout: float = float(opts.get("idle_timeout_seconds", 300))
        self._profile_tag: str = opts.get("profile", "tunnel")

        # ── Client certificate pinning (mTLS) ─────────────────────────
        # Allowlist of SHA-256 fingerprints (lowercase hex, no colons) of
        # client certificates. When non-empty, the listener terminates
        # TLS, requests a client certificate, and drops any connection
        # whose cert fingerprint is not on the list. Pair with the
        # listener's tls.cert/key so the redirector can present its own
        # certificate to clients.
        raw_pins = opts.get("allowed_client_cert_sha256", []) or []
        if isinstance(raw_pins, str):
            raw_pins = [raw_pins]
        # Support comma-separated env-injected values: "abc,def,..."
        flat: list[str] = []
        for entry in raw_pins:
            flat.extend(p.strip() for p in str(entry).split(","))
        self._allowed_fps: set[str] = {
            p.replace(":", "").lower() for p in flat if p
        }
        self._require_client_cert: bool = bool(
            opts.get("require_client_cert", bool(self._allowed_fps))
        )

        # TLS termination (client-facing). If a cert/key is configured on the
        # listener, terminate TLS; otherwise pass raw bytes through.
        self._ssl_ctx: ssl.SSLContext | None = None
        if config.tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(str(config.tls.cert), str(config.tls.key))
            if self._require_client_cert:
                # CERT_OPTIONAL accepts the client certificate into the peer
                # chain without enforcing a CA-signed trust chain - exactly
                # what we want for self-signed Ligolo agent certs that we
                # pin by fingerprint rather than by issuer.
                ctx.verify_mode = ssl.CERT_OPTIONAL
                ctx.check_hostname = False
            self._ssl_ctx = ctx
        elif self._allowed_fps:
            log.warning(
                "tcp_tunnel_pinning_without_tls",
                reason=(
                    "allowed_client_cert_sha256 set but listener has no "
                    "tls cert/key - fingerprint pinning is inactive"
                ),
            )

        self._server: asyncio.base_events.Server | None = None

    async def start(self) -> None:
        if not self._upstream_host or not self._upstream_port:
            log.error(
                "tcp_tunnel_misconfigured",
                reason="upstream_host and upstream_port required",
            )
            return
        self._server = await asyncio.start_server(
            self._handle,
            host=self._config.bind,
            port=self._config.port,
            ssl=self._ssl_ctx,
        )
        log.info(
            "tcp_tunnel_listening",
            bind=self._config.bind,
            port=self._config.port,
            upstream=f"{self._upstream_host}:{self._upstream_port}",
            tls_terminated=self._ssl_ctx is not None,
            profile=self._profile_tag,
        )

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def _handle(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        start = time.perf_counter()
        peer = writer.get_extra_info("peername")
        client_ip_str = peer[0] if peer else "0.0.0.0"

        # IP intel filter
        try:
            client_ip = ip_address(client_ip_str)
            classification = await self._intel.classify(client_ip)
            if classification.is_blocked:
                self._record(
                    client_ip_str, "block", classification.reason, start, 0, 0,
                )
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                return
        except Exception:
            # Don't fail-open silently - let the connection through but log it.
            log.warning("tcp_tunnel_ip_classify_failed", client=client_ip_str)

        # Client-certificate fingerprint pinning (mTLS). Skipped when no
        # allowlist is configured or TLS is not terminated here.
        if self._allowed_fps and self._ssl_ctx is not None:
            ssl_obj = writer.get_extra_info("ssl_object")
            peer_der = ssl_obj.getpeercert(binary_form=True) if ssl_obj else None
            if not peer_der:
                self._record(
                    client_ip_str, "block",
                    "no_client_certificate", start, 0, 0,
                )
                log.warning(
                    "tcp_tunnel_no_client_cert", client=client_ip_str,
                )
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                return
            fp = hashlib.sha256(peer_der).hexdigest()
            if fp not in self._allowed_fps:
                self._record(
                    client_ip_str, "block",
                    f"cert_fp_unknown:{fp}", start, 0, 0,
                )
                log.warning(
                    "tcp_tunnel_cert_fp_rejected",
                    client=client_ip_str,
                    fp=fp,
                )
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                return
            log.info(
                "tcp_tunnel_cert_pinned",
                client=client_ip_str,
                fp=fp,
            )

        # Dial upstream
        try:
            up_reader, up_writer = await asyncio.open_connection(
                self._upstream_host,
                self._upstream_port,
            )
        except (OSError, asyncio.TimeoutError) as e:
            log.warning(
                "tcp_tunnel_upstream_unreachable",
                upstream=f"{self._upstream_host}:{self._upstream_port}",
                error=str(e),
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            self._record(client_ip_str, "error", "upstream_unreachable", start, 0, 0)
            return

        log.info(
            "tcp_tunnel_connected",
            client=client_ip_str,
            upstream=f"{self._upstream_host}:{self._upstream_port}",
            profile=self._profile_tag,
        )

        bytes_c2u = 0  # client → upstream
        bytes_u2c = 0  # upstream → client

        async def _pipe(
            src: asyncio.StreamReader,
            dst: asyncio.StreamWriter,
            counter_attr: str,
        ) -> None:
            nonlocal bytes_c2u, bytes_u2c
            try:
                while True:
                    try:
                        data = await asyncio.wait_for(
                            src.read(65536),
                            timeout=self._idle_timeout,
                        )
                    except asyncio.TimeoutError:
                        return
                    if not data:
                        return
                    if counter_attr == "c2u":
                        bytes_c2u += len(data)
                    else:
                        bytes_u2c += len(data)
                    dst.write(data)
                    await dst.drain()
            except (ConnectionResetError, BrokenPipeError):
                return
            except Exception:
                log.exception("tcp_tunnel_pipe_error", direction=counter_attr)

        try:
            await asyncio.gather(
                _pipe(reader, up_writer, "c2u"),
                _pipe(up_reader, writer, "u2c"),
            )
        finally:
            for w in (writer, up_writer):
                try:
                    w.close()
                except Exception:
                    pass
                try:
                    await w.wait_closed()
                except Exception:
                    pass

        self._record(
            client_ip_str, "allow", None, start, bytes_c2u, bytes_u2c,
        )

    def _record(
        self,
        client_ip: str,
        result: str,
        reason: str | None,
        start: float,
        bytes_c2u: int,
        bytes_u2c: int,
    ) -> None:
        if not self._recorder:
            return
        duration_ms = (time.perf_counter() - start) * 1000
        # No dedicated byte-count fields on RequestEvent yet - fold the
        # transfer summary into filter_reason for forensics.
        summary = reason or f"c2u={bytes_c2u}B u2c={bytes_u2c}B"
        self._recorder.record(
            RequestEvent.now(
                domain=f"tunnel:{self._profile_tag}",
                client_ip=client_ip,
                method="TUNNEL",
                uri=f"tcp://{self._upstream_host}:{self._upstream_port}",
                user_agent="",
                filter_result=result,
                filter_reason=summary,
                filter_score=1.0 if result == "block" else 0.0,
                response_status=0,
                duration_ms=round(duration_ms, 1),
                protocol="tcp_tunnel",
            )
        )
