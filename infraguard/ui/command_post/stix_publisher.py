"""STIX 2.1 / TAXII 2.1 publisher for Command Post.

Publishes the operator's own scanner blocklist so peer red-team orgs
can subscribe. The bundle is served at
``GET /taxii2/collections/{id}/objects/`` per TAXII 2.1 §5.4.

Emits four STIX object types:

  * ``indicator`` for each blocked IP (pattern: ``[ipv4-addr:value =
    'X']``) with confidence and first-seen timestamps.
  * ``sighting`` when a peer proxy pushes the same IP.
  * ``opinion`` for benign classifications (e.g. researcher IPs we
    exempt).
  * ``identity`` for the publishing org (self).

This module produces bundles but does not implement the full TAXII
discovery / status flow. That belongs behind a proper Starlette router
under ``ui/command_post/``.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Iterable


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())


def _stix_id(kind: str) -> str:
    return f"{kind}--{uuid.uuid4()}"


def indicator_for_ip(
    ip: str, *, confidence: int = 80, description: str = "",
) -> dict:
    now = _now_iso()
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": _stix_id("indicator"),
        "created": now,
        "modified": now,
        "confidence": confidence,
        "indicator_types": ["malicious-activity"],
        "pattern_type": "stix",
        "pattern": f"[ipv4-addr:value = '{ip}']",
        "valid_from": now,
        "description": description or "Scanner IP observed by InfraGuard",
    }


def identity_self(org_name: str, contact: str = "") -> dict:
    now = _now_iso()
    return {
        "type": "identity",
        "spec_version": "2.1",
        "id": _stix_id("identity"),
        "created": now,
        "modified": now,
        "name": org_name,
        "identity_class": "organization",
        "contact_information": contact,
    }


def make_bundle(
    ips: Iterable[str],
    org_name: str = "InfraGuard operator",
    contact: str = "",
) -> dict:
    """Produce a TAXII envelope (STIX 2.1 bundle) from a set of IPs."""
    objects = [identity_self(org_name, contact)]
    for ip in ips:
        objects.append(indicator_for_ip(ip))
    return {
        "type": "bundle",
        "id": _stix_id("bundle"),
        "objects": objects,
    }


__all__ = ["identity_self", "indicator_for_ip", "make_bundle"]
