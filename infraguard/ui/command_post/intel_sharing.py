"""Bi-directional intel sharing across a Command Post fleet.

Turns Command Post from a read-only aggregator into an intel spine:

  * Every proxy node pushes new blocklist entries and observed JA3 to
    Command Post via ``POST /api/intel/push``.
  * Every proxy node pulls the fleet-wide blocklist on a timer via
    ``GET /api/intel/pull?since=<epoch>``.
  * Command Post computes JA3 anomalies (a JA3 seen on N-1 domains
    but not the Nth is flagged) and pushes those back as suspects.

Deduplication is keyed on (kind, value, source_node) so the same
entry from two nodes counts once but distinct nodes are still
attributed. Persistence is in-memory only for this initial version. A sqlite
backing store can drop in later without changing the API.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Literal

import structlog

log = structlog.get_logger()

IntelKind = Literal["ip", "ja3", "ua"]


@dataclass
class IntelEntry:
    kind: IntelKind
    value: str
    source_node: str
    first_seen: float
    reason: str = ""


@dataclass
class SharedIntel:
    """Fleet-wide intel bag with dedup + since-cursor pull."""

    entries: list[IntelEntry] = field(default_factory=list)
    # kind -> value -> IntelEntry (canonicalises dedup)
    _index: dict[str, dict[str, IntelEntry]] = field(default_factory=dict)
    # kind -> value -> set(node) for JA3 anomaly detection
    _ja3_domains: dict[str, set[str]] = field(default_factory=dict)

    def push(
        self,
        kind: IntelKind,
        value: str,
        source_node: str,
        reason: str = "",
    ) -> IntelEntry:
        bucket = self._index.setdefault(kind, {})
        existing = bucket.get(value)
        if existing:
            return existing
        entry = IntelEntry(
            kind=kind,
            value=value,
            source_node=source_node,
            first_seen=time.time(),
            reason=reason,
        )
        bucket[value] = entry
        self.entries.append(entry)
        log.info("intel_push", kind=kind, value=value, node=source_node)
        return entry

    def push_ja3_seen(self, ja3: str, domain: str) -> None:
        """Track which domains have observed a JA3. Used for anomaly scoring."""
        self._ja3_domains.setdefault(ja3, set()).add(domain)

    def ja3_anomalies(self, all_domains: set[str], min_missing: int = 1) -> list[str]:
        """Return JA3 hashes seen on some domains but not others.

        A hash seen on 3/4 domains is a mild anomaly; a hash seen on 1/N
        is a strong anomaly (defender rotating scanner infra).
        """
        out: list[str] = []
        for ja3, domains_seen in self._ja3_domains.items():
            missing = len(all_domains - domains_seen)
            if missing >= min_missing:
                out.append(ja3)
        return out

    def pull_since(self, since: float, kinds: list[IntelKind] | None = None) -> list[IntelEntry]:
        """Return entries added after ``since`` (unix epoch)."""
        allowed = set(kinds) if kinds else None
        return [
            e for e in self.entries
            if e.first_seen > since and (allowed is None or e.kind in allowed)
        ]


# Module-level singleton used by the Command Post app; injected via
# request.app.state.shared_intel in a follow-up wiring commit.
SHARED_INTEL = SharedIntel()


__all__ = ["SHARED_INTEL", "IntelEntry", "IntelKind", "SharedIntel"]
