"""Background rotation scheduler for automated redirector cycling.

Runs as an asyncio background task inside the InfraGuard process.
Evaluates rotation policies on each tick and executes rotations
via the deploy pipeline (provision → health-check → swap).

Policy types:
  schedule          - rotate every N hours
  on_burn_detected  - rotate when burn detection fires
  on_threshold      - rotate after N requests in a window
  stagger           - rotate domains one-by-one with a delay between each

Integrates with the deploy CLI's provision/destroy pipeline by invoking
the same provider stack (Terraform apply/destroy) used by
``infraguard deploy run`` and ``infraguard deploy rotate``.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

import structlog

from infraguard.config.schema import (
    RotationConfig,
    RotationPolicyConfig,
    RotationPolicyType,
)

if TYPE_CHECKING:
    from infraguard.core.router import DomainRouter
    from infraguard.tracking.database import Database
    from infraguard.tracking.recorder import EventRecorder

log = structlog.get_logger()

# Minimum seconds between any two rotations regardless of policy
_MIN_ROTATION_GAP_SECONDS = 120


@dataclass
class RotationEvent:
    """Record of a completed rotation."""

    policy_name: str
    domain: str
    old_work_dir: str
    new_work_dir: str
    new_ip: str
    timestamp: float = field(default_factory=time.time)
    success: bool = True
    error: str | None = None


@dataclass
class PolicyState:
    """Runtime state for a single policy."""

    policy: RotationPolicyConfig
    last_check: float = 0.0
    last_rotation: float = 0.0
    request_counts: dict[str, int] = field(default_factory=dict)  # domain → count
    window_start: float = field(default_factory=time.time)
    burn_triggered_at: float | None = None
    stagger_queue: list[str] = field(default_factory=list)  # domains awaiting rotation
    stagger_next_at: float = 0.0
    rotating: bool = False  # True while a rotation is in progress


class RotationScheduler:
    """Asyncio-based background scheduler that evaluates and executes
    rotation policies against configured domains.

    Instantiate once inside the app lifespan, then call :meth:`start`.
    The scheduler loop ticks at ``config.check_interval_seconds`` and
    evaluates every enabled policy.

    Usage (inside lifespan)::

        scheduler = RotationScheduler(config.rotation, router=router, db=db, recorder=recorder)
        task = asyncio.create_task(scheduler.run())
        # ... on shutdown:
        scheduler.stop()
        await task
    """

    def __init__(
        self,
        config: RotationConfig,
        *,
        router: DomainRouter | None = None,
        db: Database | None = None,
        recorder: EventRecorder | None = None,
    ) -> None:
        self._config = config
        self._router = router
        self._db = db
        self._recorder = recorder
        self._stop_event = asyncio.Event()
        self._states: dict[str, PolicyState] = {}
        self._history: list[RotationEvent] = []
        self._work_dir_base = Path(config.work_dir_base)

        # Build initial states
        for policy in config.policies:
            if policy.enabled:
                self._states[policy.name] = PolicyState(policy=policy)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def history(self) -> list[RotationEvent]:
        """Return a copy of the rotation history."""
        return list(self._history)

    @property
    def policies(self) -> list[RotationPolicyConfig]:
        """Return all configured policies."""
        return list(self._config.policies)

    def add_policy(self, policy: RotationPolicyConfig) -> None:
        """Add a policy at runtime."""
        self._config.policies.append(policy)
        if policy.enabled:
            self._states[policy.name] = PolicyState(policy=policy)

    def remove_policy(self, name: str) -> bool:
        """Remove a policy by name. Returns True if found."""
        self._config.policies = [
            p for p in self._config.policies if p.name != name
        ]
        return self._states.pop(name, None) is not None

    def stop(self) -> None:
        """Signal the scheduler loop to exit."""
        self._stop_event.set()

    async def run(self) -> None:
        """Main scheduler loop. Runs until :meth:`stop` is called."""
        if not self._config.enabled:
            log.info("rotation_scheduler_disabled")
            return

        log.info(
            "rotation_scheduler_started",
            policies=[p.name for p in self._config.policies if p.enabled],
            check_interval=self._config.check_interval_seconds,
        )

        while not self._stop_event.is_set():
            try:
                await self._tick()
            except Exception:
                log.exception("rotation_scheduler_tick_error")

            # Wait for next tick or stop signal
            try:
                await asyncio.wait_for(
                    self._stop_event.wait(),
                    timeout=self._config.check_interval_seconds,
                )
                break  # stop event was set
            except asyncio.TimeoutError:
                pass  # normal tick interval elapsed

        log.info("rotation_scheduler_stopped")

    # ------------------------------------------------------------------
    # Tick evaluation
    # ------------------------------------------------------------------

    async def _tick(self) -> None:
        """Evaluate all policies on this tick."""
        now = time.time()

        for name, state in self._states.items():
            if state.rotating:
                continue  # don't re-enter while a rotation is in progress

            policy = state.policy
            if not policy.enabled:
                continue

            try:
                should_rotate = await self._evaluate_policy(state, now)
                if should_rotate:
                    await self._execute_rotation(state)
            except Exception:
                log.exception(
                    "rotation_policy_eval_error",
                    policy=name,
                    type=policy.type.value,
                )

    async def _evaluate_policy(self, state: PolicyState, now: float) -> bool:
        """Check whether a policy should trigger a rotation."""
        policy = state.policy

        # Enforce minimum gap between rotations
        if now - state.last_rotation < _MIN_ROTATION_GAP_SECONDS:
            return False

        match policy.type:
            case RotationPolicyType.SCHEDULE:
                return self._eval_schedule(state, now)
            case RotationPolicyType.ON_BURN_DETECTED:
                return self._eval_burn(state, now)
            case RotationPolicyType.ON_THRESHOLD:
                return await self._eval_threshold(state, now)
            case RotationPolicyType.STAGGER:
                return self._eval_stagger(state, now)
            case _:
                log.warning("unknown_rotation_policy_type", type=policy.type)
                return False

    def _eval_schedule(self, state: PolicyState, now: float) -> bool:
        """Time-based: rotate if interval has elapsed since last rotation."""
        policy = state.policy
        interval_seconds = policy.interval_hours * 3600

        # If never rotated, use creation time as baseline
        baseline = state.last_rotation or policy.last_rotated or 0.0
        if baseline == 0.0:
            # First run — rotate immediately if policy has been around long enough
            # Otherwise mark the baseline and wait
            state.last_rotation = now
            return False

        return (now - baseline) >= interval_seconds

    def _eval_burn(self, state: PolicyState, now: float) -> bool:
        """Burn-based: rotate when burn detection has fired and cooldown elapsed."""
        policy = state.policy

        # Check if burn was triggered externally (e.g., by BurnDetector callback)
        if state.burn_triggered_at is None:
            return False

        cooldown_seconds = policy.burn_cooldown_minutes * 60
        return (now - state.burn_triggered_at) >= cooldown_seconds

    async def _eval_threshold(self, state: PolicyState, now: float) -> bool:
        """Request-count: rotate when any domain exceeds the request threshold
        within the rolling window."""
        policy = state.policy

        # Reset window if expired
        if (now - state.window_start) >= policy.threshold_window_seconds:
            state.request_counts.clear()
            state.window_start = now
            return False

        # Refresh counts from the database if available
        if self._db is not None:
            domains = policy.domains or list(self._get_config_domains())
            for domain in domains:
                count = await self._get_request_count(
                    domain, state.window_start
                )
                state.request_counts[domain] = count

        # Check if any domain exceeds threshold
        return any(
            count >= policy.request_threshold
            for count in state.request_counts.values()
        )

    def _eval_stagger(self, state: PolicyState, now: float) -> bool:
        """Staggered: rotate domains one at a time with a delay between each.

        On first trigger, populates the stagger queue with all target domains.
        Each subsequent tick checks if the stagger delay has elapsed and
        rotates the next domain in the queue.
        """
        policy = state.policy

        if not state.stagger_queue:
            # Initialize the queue if this is the first evaluation
            interval_seconds = policy.interval_hours * 3600
            baseline = state.last_rotation or policy.last_rotated or 0.0

            if baseline == 0.0:
                state.last_rotation = now
                return False

            if (now - baseline) >= interval_seconds:
                # Time to start a stagger cycle
                state.stagger_queue = list(
                    policy.domains or self._get_config_domains()
                )
                state.stagger_next_at = now  # first domain rotates immediately
                log.info(
                    "stagger_cycle_started",
                    policy=policy.name,
                    domains=state.stagger_queue,
                )

        if not state.stagger_queue:
            return False

        if now < state.stagger_next_at:
            return False

        # Pop the next domain for rotation
        domain = state.stagger_queue.pop(0)
        state.stagger_next_at = now + (policy.stagger_delay_minutes * 60)

        # Store the current rotation target for _execute_rotation
        state.policy = policy.model_copy(
            update={"domains": [domain]}
        )
        return True

    # ------------------------------------------------------------------
    # Rotation execution
    # ------------------------------------------------------------------

    async def _execute_rotation(self, state: PolicyState) -> None:
        """Execute a rotation for the given policy.

        This runs the deploy pipeline:
        1. Provision new instance (Terraform apply)
        2. Wait for health check
        3. Destroy old instance

        The heavy lifting is delegated to the same provider stack used
        by ``infraguard deploy rotate``, running in a thread executor
        to avoid blocking the event loop.
        """
        policy = state.policy
        state.rotating = True
        now = time.time()

        domains_to_rotate = policy.domains or list(self._get_config_domains())

        for domain in domains_to_rotate:
            log.info(
                "rotation_started",
                policy=policy.name,
                domain=domain,
                type=policy.type.value,
            )

            try:
                event = await asyncio.get_event_loop().run_in_executor(
                    None,  # default thread pool
                    self._rotate_domain_sync,
                    policy,
                    domain,
                )
                self._history.append(event)

                if event.success:
                    state.last_rotation = now
                    policy.last_rotated = now
                    policy.rotation_count += 1
                    log.info(
                        "rotation_completed",
                        policy=policy.name,
                        domain=domain,
                        new_ip=event.new_ip,
                    )
                else:
                    log.error(
                        "rotation_failed",
                        policy=policy.name,
                        domain=domain,
                        error=event.error,
                    )

            except Exception as exc:
                log.exception(
                    "rotation_execution_error",
                    policy=policy.name,
                    domain=domain,
                )
                self._history.append(
                    RotationEvent(
                        policy_name=policy.name,
                        domain=domain,
                        old_work_dir="",
                        new_work_dir="",
                        new_ip="",
                        success=False,
                        error=str(exc),
                    )
                )

        state.rotating = False

        # Emit event for plugin forwarding (Discord/Slack alerts)
        if self._recorder is not None:
            try:
                await self._emit_rotation_event(state, domains_to_rotate)
            except Exception:
                log.exception("rotation_event_emit_error")

    def _rotate_domain_sync(
        self, policy: RotationPolicyConfig, domain: str
    ) -> RotationEvent:
        """Synchronous rotation logic — runs in a thread executor.

        Uses the deploy provider stack to provision a replacement and
        tear down the old instance.
        """
        from infraguard.deploy.providers import get_provider

        timestamp = int(time.time())
        work_base = self._work_dir_base
        work_base.mkdir(parents=True, exist_ok=True)

        # Locate the old work dir (convention: .infraguard-deploy-*)
        old_work_dir = work_base / f"{domain}-current"
        new_work_dir = work_base / f"{domain}-{timestamp}"

        if not old_work_dir.exists():
            return RotationEvent(
                policy_name=policy.name,
                domain=domain,
                old_work_dir=str(old_work_dir),
                new_work_dir="",
                new_ip="",
                success=False,
                error=f"No existing deployment found at {old_work_dir}",
            )

        new_work_dir.mkdir(parents=True, exist_ok=True)

        # Build tfvars
        tfvars: dict[str, Any] = {
            "domain": domain,
            "operator_ip": policy.operator_ip,
        }
        if policy.region:
            tfvars["region"] = policy.region
        if policy.instance_size:
            tfvars["instance_size"] = policy.instance_size

        ssh_key_path = Path(policy.ssh_key)
        if ssh_key_path.exists():
            if policy.provider == "do":
                from infraguard.deploy.cli import _compute_ssh_fingerprint

                tfvars["ssh_key_fingerprint"] = _compute_ssh_fingerprint(
                    ssh_key_path
                )
            else:
                tfvars["ssh_public_key"] = ssh_key_path.read_text(
                    encoding="utf-8"
                ).strip()

        # Provision new instance
        new_provider = get_provider(policy.provider, new_work_dir)
        try:
            outputs = new_provider.apply(tfvars)
        except Exception as exc:
            return RotationEvent(
                policy_name=policy.name,
                domain=domain,
                old_work_dir=str(old_work_dir),
                new_work_dir=str(new_work_dir),
                new_ip="",
                success=False,
                error=f"Provision failed: {exc}",
            )

        new_ip = outputs.get("instance_ip", "")

        # Health check
        from infraguard.deploy.cli import _poll_health

        try:
            _poll_health(new_ip, port=443)
        except RuntimeError as exc:
            return RotationEvent(
                policy_name=policy.name,
                domain=domain,
                old_work_dir=str(old_work_dir),
                new_work_dir=str(new_work_dir),
                new_ip=new_ip,
                success=False,
                error=f"Health check failed: {exc}",
            )

        # Destroy old instance
        old_provider = get_provider(policy.provider, old_work_dir)
        try:
            old_provider.destroy({})
        except Exception as exc:
            log.warning(
                "rotation_old_destroy_failed",
                domain=domain,
                error=str(exc),
            )

        # Rotate work dir symlink/rename: new becomes current
        try:
            import shutil

            if old_work_dir.exists():
                shutil.rmtree(old_work_dir, ignore_errors=True)
            # Copy new state to current
            shutil.copytree(new_work_dir, old_work_dir, dirs_exist_ok=True)
        except Exception:
            log.warning("rotation_workdir_swap_failed", domain=domain)

        return RotationEvent(
            policy_name=policy.name,
            domain=domain,
            old_work_dir=str(old_work_dir),
            new_work_dir=str(new_work_dir),
            new_ip=new_ip,
            success=True,
        )

    # ------------------------------------------------------------------
    # Burn detection hook
    # ------------------------------------------------------------------

    def notify_burn_detected(self, domain: str) -> None:
        """Called by the BurnDetector when a burn is confirmed.

        Sets the burn trigger timestamp on all ON_BURN_DETECTED policies
        that cover the given domain.
        """
        now = time.time()
        for state in self._states.values():
            if state.policy.type != RotationPolicyType.ON_BURN_DETECTED:
                continue
            if not state.policy.enabled:
                continue
            domains = state.policy.domains or list(self._get_config_domains())
            if domain in domains:
                state.burn_triggered_at = now
                log.info(
                    "burn_rotation_triggered",
                    policy=state.policy.name,
                    domain=domain,
                )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_config_domains(self) -> list[str]:
        """Get domain list from router config if available."""
        if self._router is not None:
            try:
                return list(self._router.config.domains.keys())
            except Exception:
                pass
        return []

    async def _get_request_count(
        self, domain: str, since: float
    ) -> int:
        """Query the tracking database for request count on a domain
        since the given timestamp."""
        if self._db is None:
            return 0
        try:
            # Use the tracking database to count requests
            # This assumes a requests/events table with domain and timestamp
            cursor = await self._db.execute(
                "SELECT COUNT(*) FROM events WHERE domain = ? AND timestamp > ?",
                (domain, since),
            )
            row = await cursor.fetchone()
            return row[0] if row else 0
        except Exception:
            # If the query fails (table might not exist), fall back to 0
            return 0

    async def _emit_rotation_event(
        self, state: PolicyState, domains: list[str]
    ) -> None:
        """Emit a structured event for plugin forwarding."""
        if self._recorder is None:
            return
        # Use the recorder's generic event mechanism
        # The exact API depends on EventRecorder — emit as a log event
        # that plugins can pick up
        log.info(
            "rotation_event",
            policy=state.policy.name,
            type=state.policy.type.value,
            domains=domains,
            rotation_count=state.policy.rotation_count,
        )
