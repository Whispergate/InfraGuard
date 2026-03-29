"""CIDR-based IP whitelist and blacklist management."""

from __future__ import annotations

from ipaddress import (
    IPv4Address,
    IPv4Network,
    IPv6Address,
    IPv6Network,
    ip_address,
    ip_network,
)
from pathlib import Path

import structlog

log = structlog.get_logger()


class CIDRList:
    """Efficient CIDR membership tester."""

    def __init__(self, name: str = ""):
        self.name = name
        self._networks_v4: list[IPv4Network] = []
        self._networks_v6: list[IPv6Network] = []

    def add(self, cidr: str) -> None:
        try:
            net = ip_network(cidr, strict=False)
            if isinstance(net, IPv4Network):
                self._networks_v4.append(net)
            else:
                self._networks_v6.append(net)
        except ValueError:
            log.warning("invalid_cidr", cidr=cidr, list=self.name)

    def add_many(self, cidrs: list[str]) -> None:
        for cidr in cidrs:
            self.add(cidr)

    def contains(self, ip: IPv4Address | IPv6Address) -> bool:
        if isinstance(ip, IPv4Address):
            return any(ip in net for net in self._networks_v4)
        return any(ip in net for net in self._networks_v6)

    def load_file(self, path: str | Path) -> int:
        """Load CIDRs from a file (one per line, # comments allowed)."""
        count = 0
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    self.add(line)
                    count += 1
        log.info("cidr_list_loaded", name=self.name, count=count, path=str(path))
        return count

    @property
    def size(self) -> int:
        return len(self._networks_v4) + len(self._networks_v6)

    def remove(self, cidr: str) -> bool:
        try:
            net = ip_network(cidr, strict=False)
        except ValueError:
            return False
        if isinstance(net, IPv4Network):
            try:
                self._networks_v4.remove(net)
                return True
            except ValueError:
                return False
        else:
            try:
                self._networks_v6.remove(net)
                return True
            except ValueError:
                return False


class DynamicWhitelist:
    """Auto-whitelist IPs after N consecutive valid C2 requests."""

    def __init__(self, threshold: int = 3):
        self.threshold = threshold
        self._counts: dict[str, int] = {}
        self._whitelisted: set[str] = set()

    def record_valid_request(self, ip: str) -> bool:
        """Record a valid request from an IP. Returns True if newly whitelisted."""
        if ip in self._whitelisted:
            return False
        self._counts[ip] = self._counts.get(ip, 0) + 1
        if self._counts[ip] >= self.threshold:
            self._whitelisted.add(ip)
            del self._counts[ip]
            log.info("dynamic_whitelist_add", ip=ip, threshold=self.threshold)
            return True
        return False

    def is_whitelisted(self, ip: str) -> bool:
        return ip in self._whitelisted

    def reset(self, ip: str) -> None:
        self._whitelisted.discard(ip)
        self._counts.pop(ip, None)
