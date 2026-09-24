"""Multi-region GeoDNS resolver scaffold.

Client-side helper for ops who deploy the same domain to N regions
and want beacons to hit the nearest healthy proxy. Reads a small YAML
config of ``region -> [proxy_ip, ...]``, sorts by great-circle
distance to the beacon's source region (from GeoIP), and returns an
answer.

Not a DNS server: the intent is that ops plug this into an existing
authoritative NS (Route 53, Cloudflare, PowerDNS) as a data source.
The module here provides the pure computation.

TODOs:

  1. Hook into the rotation manager so a fresh green in region A gets
     added to the region's pool on rotate completion.
  2. Health check the pools so a downed proxy is elided.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

import structlog

log = structlog.get_logger()

# Simplified region centroids (lat, lon). Only for ranking not
# geographically precise. Extend as the fleet grows.
_REGION_COORDS: dict[str, tuple[float, float]] = {
    "us-east":    (39.0,  -77.0),
    "us-west":    (37.4, -122.0),
    "eu-west":    (53.4,   -6.3),
    "eu-central": (50.1,    8.7),
    "ap-south":   ( 1.4,  103.8),
    "ap-northeast": (35.7, 139.7),
}


@dataclass
class GeoDNSPool:
    region: str
    ips: list[str]


class GeoDNSResolver:
    def __init__(self, pools: list[GeoDNSPool]):
        self._pools = {p.region: p for p in pools}

    def resolve(self, client_country_hint: str | None = None) -> list[str]:
        """Return proxy IPs, closest region first."""
        # For a first cut, treat country codes and region names alike;
        # the CIDR/GeoIP database already knows country codes and can
        # be mapped to regions in a follow-up.
        target = _REGION_COORDS.get(client_country_hint or "", (0.0, 0.0))
        ranked = sorted(
            self._pools.values(),
            key=lambda p: _distance(_REGION_COORDS.get(p.region, (0, 0)), target),
        )
        flat: list[str] = []
        for pool in ranked:
            flat.extend(pool.ips)
        return flat


def _distance(a: tuple[float, float], b: tuple[float, float]) -> float:
    # Great-circle in km via the spherical law of cosines. Good enough
    # for ranking we do not need Vincenty precision.
    lat1, lon1 = map(math.radians, a)
    lat2, lon2 = map(math.radians, b)
    return math.acos(
        min(1.0, max(-1.0,
            math.sin(lat1) * math.sin(lat2)
            + math.cos(lat1) * math.cos(lat2) * math.cos(lon1 - lon2)
        ))
    ) * 6371.0


__all__ = ["GeoDNSPool", "GeoDNSResolver"]
