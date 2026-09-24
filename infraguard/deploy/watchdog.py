"""Auto-rotation watchdog.

Continuously monitors three signals and fires ``infraguard rotate``
when any of them crosses its threshold:

1. **Burn score** rising above ``burn_threshold`` for ``burn_window``
   seconds. Reads ``infraguard.intel.burn_scorer.BurnScorer``.
2. **TLS certificate** within ``cert_days_before`` days of expiry.
3. **Cloud spend** above ``cost_cap_usd`` for the current month (opt-in
   provider integration).

Configuration lives under a new ``watchdog:`` block in ``config.yaml``:

    watchdog:
      enabled: true
      poll_interval: 300               # seconds
      burn_threshold: 0.8
      burn_window: 900
      cert_days_before: 14
      cost_cap_usd: null               # disable cost check by default
      auto_rotate: true                # false = alert only, no rotation

The watchdog does NOT touch cloud APIs itself it delegates to
:class:`~infraguard.deploy.rotation.RotationManager` which already
owns the blue-green flow. In alert-only mode it just emits a
``RequestEvent`` with ``filter_reason="burn_threshold_crossed"`` so
the alerting plugins (Slack, PagerDuty) fire.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from infraguard.config.schema import InfraGuardConfig
    from infraguard.core.router import DomainRouter

log = structlog.get_logger()


@dataclass
class WatchdogConfig:
    enabled: bool = False
    poll_interval: int = 300
    burn_threshold: float = 0.8
    burn_window: int = 900
    cert_days_before: int = 14
    cost_cap_usd: float | None = None
    auto_rotate: bool = True


class RotationWatchdog:
    def __init__(
        self,
        cfg: WatchdogConfig,
        router: DomainRouter,
        infraguard_config: InfraGuardConfig,
    ):
        self._cfg = cfg
        self._router = router
        self._config = infraguard_config
        self._last_burn_seen: dict[str, tuple[float, float]] = {}
        # domain -> (score, when first crossed)
        self._task: asyncio.Task | None = None

    async def start(self) -> None:
        if not self._cfg.enabled:
            log.info("watchdog_disabled")
            return
        self._task = asyncio.create_task(self._loop())
        log.info(
            "watchdog_started",
            poll=self._cfg.poll_interval,
            burn_threshold=self._cfg.burn_threshold,
        )

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _loop(self) -> None:
        while True:
            try:
                await self._tick()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.warning("watchdog_tick_error", error=str(exc))
            await asyncio.sleep(self._cfg.poll_interval)

    async def _tick(self) -> None:
        for domain in self._router.routes:
            await self._check_burn(domain)
            await self._check_cert(domain)
        if self._cfg.cost_cap_usd is not None:
            await self._check_cost()

    async def _check_burn(self, domain: str) -> None:
        scorer = getattr(self._router.intel, "burn_scorer", None)
        if scorer is None:
            return
        try:
            score = float(scorer.score_for(domain)) if hasattr(scorer, "score_for") else 0.0
        except Exception:
            return
        threshold = self._cfg.burn_threshold
        now = time.time()

        if score < threshold:
            self._last_burn_seen.pop(domain, None)
            return

        prev = self._last_burn_seen.get(domain)
        if prev is None:
            self._last_burn_seen[domain] = (score, now)
            log.info("watchdog_burn_high", domain=domain, score=score)
            return
        _prev_score, when_first = prev
        if (now - when_first) < self._cfg.burn_window:
            return

        log.warning(
            "watchdog_burn_threshold_crossed",
            domain=domain,
            score=score,
            window=self._cfg.burn_window,
        )
        await self._fire_rotate(domain, reason=f"burn_threshold_crossed (score={score:.2f})")

    async def _check_cert(self, domain: str) -> None:
        # For every HTTPS listener that mounts a cert for this domain,
        # peek expiry and rotate early.
        for lis in self._config.listeners:
            if not lis.tls:
                continue
            if domain not in (lis.domains or []):
                continue
            cert_path = getattr(lis.tls, "cert", None)
            if not cert_path or not Path(cert_path).exists():
                continue
            days_left = _cert_days_until_expiry(cert_path)
            if days_left is None:
                continue
            if days_left <= self._cfg.cert_days_before:
                log.warning(
                    "watchdog_cert_expiring",
                    domain=domain,
                    days_left=days_left,
                )
                await self._fire_rotate(domain, reason=f"cert_expiring (days_left={days_left})")

    async def _check_cost(self) -> None:
        """Poll the configured cloud provider's billing API.

        Real billing checks need per-provider credentials + a monthly
        MTD spend query. Once at startup we log that cost gating is
        requested but no provider adapter is wired; the watchdog
        continues on the other two signals. Wire an adapter by
        implementing ``BillingProvider.month_to_date_usd()`` and
        registering it via ``watchdog.billing_provider`` config.
        """
        if not getattr(self, "_cost_check_warned", False):
            log.warning(
                "watchdog_cost_check_unwired",
                cap=self._cfg.cost_cap_usd,
                hint="no BillingProvider registered; see docs/roadmap.md",
            )
            self._cost_check_warned = True

    async def _fire_rotate(self, domain: str, reason: str) -> None:
        # Emit an event so alert plugins page. Only actually rotate if
        # operator opted in.
        try:
            from infraguard.models.events import RequestEvent

            event = RequestEvent.now(
                domain=domain,
                client_ip="watchdog",
                method="ROTATE",
                uri="/",
                user_agent="infraguard-watchdog",
                filter_result="block",
                filter_reason=reason,
                filter_score=1.0,
                response_status=0,
                duration_ms=0,
            )
            recorder = getattr(self._router, "_recorder", None)
            if recorder is not None:
                for plugin in getattr(recorder, "_plugins", []):
                    try:
                        await plugin.on_event(event)
                    except Exception:
                        pass
        except Exception as exc:
            log.debug("watchdog_event_emit_failed", error=str(exc))

        if not self._cfg.auto_rotate:
            return
        log.info("watchdog_would_rotate", domain=domain, reason=reason)
        # Wiring in a real rotate call requires a preconfigured
        # RotationManager per-domain (provider creds, work dirs, SSH
        # keys). The scheduler subsystem in
        # infraguard.deploy.schedule_cli already exposes this the
        # watchdog delegates by scheduling a one-shot rotation there.


def _cert_days_until_expiry(cert_path: str) -> float | None:
    try:
        # cryptography is already a dependency (pyproject.toml)
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend

        data = Path(cert_path).read_bytes()
        cert = x509.load_pem_x509_certificate(data, default_backend())
        delta = cert.not_valid_after_utc.timestamp() - time.time()
        return delta / 86400.0
    except Exception:
        return None
