"""Shared-state backends.

InfraGuard's replay cache, circuit-breaker state, dynamic whitelist, and
login rate-limiter historically lived in per-process Python objects. That
made ``docker compose --scale proxy-node=N`` unsafe: an attacker whose
first attempt hit node A could replay against node B, and a breaker that
tripped on one node stayed closed on the others.

This package exposes a minimal :class:`StateBackend` Protocol covering
the operations those subsystems actually need - key/value with TTL,
atomic ``check_and_set`` for the replay-hash use case, and shared
counters for the breaker's failure count - plus two implementations:

* :class:`InMemoryBackend` - the default. Behaviourally identical to the
  old per-process dicts. Safe for single-node deploys.
* :class:`RedisBackend` - opt-in, requires the ``redis`` package. Enable
  by setting ``state.backend: redis`` in ``config.yaml`` and running the
  ``redis`` service from ``docker-compose.yml``.

Configure via ``StateConfig``; call :func:`build_state_backend` at boot.
"""

from infraguard.state.backend import (
    StateBackend,
    StateConfig,
    build_state_backend,
)
from infraguard.state.memory import InMemoryBackend
from infraguard.state.redis_backend import RedisBackend

__all__ = [
    "StateBackend",
    "StateConfig",
    "build_state_backend",
    "InMemoryBackend",
    "RedisBackend",
]
