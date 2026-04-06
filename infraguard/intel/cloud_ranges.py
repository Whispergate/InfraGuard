"""Dynamic cloud provider IP range fetching.

AWS, Azure, and GCP publish their IP ranges as machine-readable JSON.
This module fetches them on startup and periodically refreshes them,
providing accurate cloud IP blocking for sandbox/analysis detection.

These ranges supplement the static approximations in known_ranges.py
with authoritative, up-to-date data direct from the providers.
"""

from __future__ import annotations

import asyncio
import json

import httpx
import structlog

from infraguard.intel.ip_lists import CIDRList

log = structlog.get_logger()

# Authoritative cloud provider IP range endpoints
CLOUD_RANGE_SOURCES = {
    "aws": "https://ip-ranges.amazonaws.com/ip-ranges.json",
    "azure": "https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/ServiceTags_Public_20240101.json",
    "gcp": "https://www.gstatic.com/ipranges/cloud.json",
}


def _parse_aws_ranges(data: dict) -> list[str]:
    """Extract IPv4 and IPv6 prefixes from AWS ip-ranges.json."""
    cidrs: list[str] = []
    for prefix in data.get("prefixes", []):
        cidr = prefix.get("ip_prefix")
        if cidr:
            cidrs.append(cidr)
    for prefix in data.get("ipv6_prefixes", []):
        cidr = prefix.get("ipv6_prefix")
        if cidr:
            cidrs.append(cidr)
    return cidrs


def _parse_azure_ranges(data: dict) -> list[str]:
    """Extract prefixes from Azure ServiceTags JSON."""
    cidrs: list[str] = []
    for value in data.get("values", []):
        props = value.get("properties", {})
        for prefix in props.get("addressPrefixes", []):
            cidrs.append(prefix)
    return cidrs


def _parse_gcp_ranges(data: dict) -> list[str]:
    """Extract prefixes from GCP cloud.json."""
    cidrs: list[str] = []
    for prefix in data.get("prefixes", []):
        if "ipv4Prefix" in prefix:
            cidrs.append(prefix["ipv4Prefix"])
        if "ipv6Prefix" in prefix:
            cidrs.append(prefix["ipv6Prefix"])
    return cidrs


_PARSERS = {
    "aws": _parse_aws_ranges,
    "azure": _parse_azure_ranges,
    "gcp": _parse_gcp_ranges,
}


async def fetch_cloud_ranges(
    providers: list[str] | None = None,
    timeout: float = 30.0,
) -> dict[str, list[str]]:
    """Fetch IP ranges from specified cloud providers.

    Args:
        providers: List of provider keys ("aws", "azure", "gcp").
                   Defaults to all providers.
        timeout: HTTP request timeout per provider.

    Returns:
        Dict mapping provider name to list of CIDR strings.
    """
    providers = providers or list(CLOUD_RANGE_SOURCES.keys())
    results: dict[str, list[str]] = {}

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        for provider in providers:
            url = CLOUD_RANGE_SOURCES.get(provider)
            if not url:
                log.warning("cloud_range_unknown_provider", provider=provider)
                continue

            try:
                resp = await client.get(url)
                resp.raise_for_status()
                data = resp.json()

                parser = _PARSERS.get(provider)
                if parser:
                    cidrs = parser(data)
                    results[provider] = cidrs
                    log.info(
                        "cloud_ranges_fetched",
                        provider=provider,
                        ranges=len(cidrs),
                    )
            except (httpx.RequestError, httpx.TimeoutException, json.JSONDecodeError) as e:
                log.warning(
                    "cloud_range_fetch_error",
                    provider=provider,
                    error=str(e),
                )

    return results


async def update_cloud_ranges(
    blocklist: CIDRList,
    providers: list[str] | None = None,
) -> int:
    """Fetch cloud ranges and merge into the blocklist.

    Returns the number of new entries added.
    """
    ranges = await fetch_cloud_ranges(providers)
    before = blocklist.size
    for provider, cidrs in ranges.items():
        blocklist.add_many(cidrs)
    added = blocklist.size - before
    log.info("cloud_ranges_updated", total_new=added)
    return added


async def cloud_range_refresh_loop(
    blocklist: CIDRList,
    providers: list[str] | None = None,
    interval_hours: int = 24,
) -> None:
    """Background task that periodically refreshes cloud provider IP ranges."""
    interval_seconds = interval_hours * 3600
    while True:
        try:
            await update_cloud_ranges(blocklist, providers)
        except Exception as e:
            log.exception("cloud_range_refresh_error", error_type=type(e).__name__)
        await asyncio.sleep(interval_seconds)
