"""Content-route guards and event recording.

Extracted from :class:`DomainRouter` so their gate logic can be unit
tested without a live router.
"""

from __future__ import annotations

import re
import time
from ipaddress import IPv4Address, IPv6Address
from typing import TYPE_CHECKING

from infraguard.models.events import RequestEvent

if TYPE_CHECKING:
    from starlette.requests import Request
    from starlette.responses import Response

    from infraguard.config.schema import ContentRouteGuardConfig
    from infraguard.intel.manager import IntelManager
    from infraguard.tracking.recorder import EventRecorder


def check_content_guard(
    intel: "IntelManager",
    request: "Request",
    guard: "ContentRouteGuardConfig",
    client_ip: IPv4Address | IPv6Address,
) -> str | None:
    """Return ``None`` if all guard checks pass, or a reason string if blocked."""
    if guard.require_beacon_ip:
        if not intel.dynamic_whitelist.is_whitelisted(str(client_ip)):
            return "not a whitelisted beacon IP"

    if guard.allowed_user_agents:
        ua = request.headers.get("user-agent", "")
        if not any(re.search(pat, ua, re.IGNORECASE) for pat in guard.allowed_user_agents):
            return f"UA not in allowlist ({ua[:80]!r})"

    for header_name, expected_value in guard.required_headers.items():
        actual = request.headers.get(header_name, "")
        if actual != expected_value:
            return f"required header mismatch: {header_name}"

    for header_name in guard.forbidden_headers:
        if header_name.lower() in request.headers:
            return f"forbidden header present: {header_name}"

    return None


def record_content_event(
    recorder: "EventRecorder | None",
    domain: str,
    client_ip: IPv4Address | IPv6Address,
    request: "Request",
    response: "Response",
    filter_result: str,
    filter_score: float,
    start: float,
    track: bool,
    request_hash: str = "",
) -> None:
    """Record a content-delivery event to the tracking database."""
    if not track or recorder is None:
        return
    duration_ms = (time.perf_counter() - start) * 1000
    recorder.record(
        RequestEvent.now(
            domain=domain,
            client_ip=str(client_ip),
            method=request.method,
            uri=request.url.path,
            user_agent=request.headers.get("user-agent", ""),
            filter_result=filter_result,
            filter_reason=None,
            filter_score=filter_score,
            response_status=response.status_code,
            duration_ms=round(duration_ms, 1),
            request_hash=request_hash,
        )
    )
