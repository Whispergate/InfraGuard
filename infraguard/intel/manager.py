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
        if config.banned_ip_file and not config.banned_ip_file.startswith("${"):
            from pathlib import Path
            if Path(config.banned_ip_file).exists():
                self.blocklist.load_file(config.banned_ip_file)
            else:
                log.info("banned_ip_file_not_found", path=config.banned_ip_file)

        # Auto-ingest .htaccess and robots.txt from rules directory
        self._auto_ingest_rules(config)

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

        # Enrich whitelists with GeoIP/ASN data
        self._enrich_whitelists()

        log.info(
            "intel_manager_ready",
            blocklist_size=self.blocklist.size,
            blocked_countries=len(config.blocked_countries),
        )

    def _auto_ingest_rules(self, config: IntelConfig) -> None:
        """Scan the rules directory for .htaccess and robots.txt files and ingest them."""
        from pathlib import Path

        rules_dir = config.rules_dir
        if not rules_dir or rules_dir.startswith("${"):
            return

        rules_path = Path(rules_dir)
        if not rules_path.is_dir():
            return

        # Find all ingestable files
        rule_files: list[Path] = []
        for pattern in ("*.htaccess", ".htaccess", "htaccess", "robots.txt", "*.txt"):
            rule_files.extend(rules_path.glob(pattern))
        # Deduplicate
        rule_files = list(set(rule_files))

        if not rule_files:
            return

        from infraguard.intel.rule_ingest import ingest_files

        result = ingest_files([str(f) for f in rule_files])
        if result.blocked_ips:
            self.blocklist.add_many(result.blocked_ips)
            log.info(
                "rules_auto_ingested",
                files=len(rule_files),
                blocked_ips=len(result.blocked_ips),
                blocked_user_agents=len(result.blocked_user_agents),
                source_files=[f.name for f in rule_files],
            )

    def _enrich_whitelists(self) -> None:
        """Enrich all whitelisted CIDRs with GeoIP/ASN metadata on startup."""
        enriched = self.whitelist.enrich(self.geoip)
        for cidr, info in self.whitelist.metadata.items():
            if info.get("asn") or info.get("country_code"):
                log.info(
                    "whitelist_enriched",
                    cidr=cidr,
                    asn=info.get("asn"),
                    org=info.get("org"),
                    country=info.get("country_code"),
                )

    def enrich_cidr_list(self, cidr_list: CIDRList) -> None:
        """Enrich an external CIDRList (e.g., domain whitelists) with GeoIP data."""
        enriched = cidr_list.enrich(self.geoip)
        for cidr, info in cidr_list.metadata.items():
            if info.get("asn") or info.get("country_code"):
                log.info(
                    "whitelist_enriched",
                    list=cidr_list.name,
                    cidr=cidr,
                    asn=info.get("asn"),
                    org=info.get("org"),
                    country=info.get("country_code"),
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
            result.geo = self.geoip.lookup(ip_str)
            return result

        # Check static whitelist
        if self.whitelist.contains(ip):
            result.is_whitelisted = True
            # Use pre-enriched metadata if available
            meta = self.whitelist.get_metadata_for_ip(ip)
            if meta:
                result.geo = GeoInfo(**{k: v for k, v in meta.items() if k in GeoInfo.__dataclass_fields__})
            else:
                result.geo = self.geoip.lookup(ip_str)
            return result

        # Check blocklist
        if self.blocklist.contains(ip):
            result.is_blocked = True
            result.reason = "IP in blocklist"
            return result

        # GeoIP check
        geo = self.geoip.lookup(ip_str)
        result.geo = geo

        # Country checks: allowed_countries is a whitelist (only these pass);
        # blocked_countries is a blocklist (these are denied).
        # If both are set, allowed takes precedence.
        if self.config.allowed_countries and geo.country_code:
            if geo.country_code not in self.config.allowed_countries:
                result.is_blocked = True
                result.reason = f"Country {geo.country_code} not in allowed list"
                return result
        elif geo.country_code and geo.country_code in self.config.blocked_countries:
            result.is_blocked = True
            result.reason = f"Blocked country: {geo.country_code}"
            return result

        # ASN checks: same logic - allowed_asns whitelist, blocked_asns blocklist
        if self.config.allowed_asns and geo.asn:
            if geo.asn not in self.config.allowed_asns:
                result.is_blocked = True
                result.reason = f"ASN {geo.asn} not in allowed list"
                return result
        elif geo.asn and geo.asn in self.config.blocked_asns:
            result.is_blocked = True
            result.reason = f"Blocked ASN: {geo.asn}"
            return result

        # Reverse DNS (only if not already classified)
        result.rdns = await reverse_dns(ip_str)

        return result

    def is_blocked(self, ip: IPv4Address | IPv6Address) -> bool:
        """Fast synchronous blocklist check (ip_only mode).

        Returns True if the IP is in the blocklist AND not in the whitelist
        or dynamic whitelist. Does NOT perform GeoIP/ASN/DNS lookups.
        """
        ip_str = str(ip)
        # Whitelisted IPs are never blocked
        if self.dynamic_whitelist.is_whitelisted(ip_str):
            return False
        if self.whitelist.contains(ip):
            return False
        return self.blocklist.contains(ip)

    def record_valid_request(self, ip: str) -> None:
        """Record a valid C2 request for dynamic whitelisting."""
        self.dynamic_whitelist.record_valid_request(ip)
