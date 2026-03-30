"""IP intelligence orchestrator - combines all intel sources."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address

import structlog

from infraguard.config.schema import IntelConfig
from infraguard.intel.dns import reverse_dns
from infraguard.intel.feeds import feed_refresh_loop, load_feed_cache, update_feeds
from infraguard.intel.geoip import GeoIPLookup, GeoInfo
from infraguard.intel.ip_lists import CIDRList, DynamicWhitelist
from infraguard.intel.known_ranges import SECURITY_VENDOR_CIDRS

log = structlog.get_logger()


@dataclass
class IPClassification:
    ip: str
    is_blocked: bool = False
    is_whitelisted: bool = False
    reason: str | None = None
    geo: GeoInfo | None = None
    rdns: str | None = None


class IntelManager:
    """Central IP intelligence service combining all sources."""

    def __init__(self, config: IntelConfig):
        self.config = config

        # Blocklist
        self.blocklist = CIDRList(name="blocklist")
        if config.auto_block_scanners:
            self.blocklist.add_many(SECURITY_VENDOR_CIDRS)
        if config.banned_ip_file:
            from pathlib import Path
            if Path(config.banned_ip_file).exists():
                self.blocklist.load_file(config.banned_ip_file)
            else:
                log.info("banned_ip_file_not_found", path=config.banned_ip_file, hint="Run: infraguard ingest rules/.htaccess --format blocklist -o rules/banned_ips.txt")

        # Whitelist (operator-defined, per-domain whitelists are separate)
        self.whitelist = CIDRList(name="whitelist")

        # Dynamic whitelist
        self.dynamic_whitelist = DynamicWhitelist(
            threshold=config.dynamic_whitelist_threshold
        )

        # Load cached threat intel feeds
        if config.feeds.enabled:
            cached = load_feed_cache(config.feeds.cache_dir)
            if cached:
                self.blocklist.add_many(cached)

        # GeoIP
        self.geoip = GeoIPLookup(
            city_db=config.geoip_db,
            asn_db=config.geoip_asn_db,
            country_db=config.geoip_country_db,
        )

        self._feed_task: asyncio.Task | None = None

        log.info(
            "intel_manager_ready",
            blocklist_size=self.blocklist.size,
            blocked_countries=len(config.blocked_countries),
        )

    def start_feed_refresh(self) -> None:
        """Start the background feed refresh task."""
        if self.config.feeds.enabled:
            feed_urls = self.config.feeds.urls or None  # None = use defaults
            self._feed_task = asyncio.create_task(
                feed_refresh_loop(
                    self.blocklist,
                    urls=feed_urls,
                    cache_dir=self.config.feeds.cache_dir,
                    interval_hours=self.config.feeds.refresh_interval_hours,
                )
            )
            log.info("feed_refresh_started", interval_hours=self.config.feeds.refresh_interval_hours)

    async def stop_feed_refresh(self) -> None:
        """Stop the background feed refresh task."""
        if self._feed_task:
            self._feed_task.cancel()
            try:
                await self._feed_task
            except asyncio.CancelledError:
                pass

    async def classify(self, ip: IPv4Address | IPv6Address) -> IPClassification:
        ip_str = str(ip)
        result = IPClassification(ip=ip_str)

        # Check dynamic whitelist first
        if self.dynamic_whitelist.is_whitelisted(ip_str):
            result.is_whitelisted = True
            return result

        # Check static whitelist
        if self.whitelist.contains(ip):
            result.is_whitelisted = True
            return result

        # Check blocklist
        if self.blocklist.contains(ip):
            result.is_blocked = True
            result.reason = "IP in blocklist"
            return result

        # GeoIP check
        geo = self.geoip.lookup(ip_str)
        result.geo = geo

        if geo.country_code and geo.country_code in self.config.blocked_countries:
            result.is_blocked = True
            result.reason = f"Blocked country: {geo.country_code}"
            return result

        if geo.asn and geo.asn in self.config.blocked_asns:
            result.is_blocked = True
            result.reason = f"Blocked ASN: {geo.asn}"
            return result

        # Reverse DNS (only if not already classified)
        result.rdns = await reverse_dns(ip_str)

        return result

    def record_valid_request(self, ip: str) -> None:
        """Record a valid C2 request for dynamic whitelisting."""
        self.dynamic_whitelist.record_valid_request(ip)
