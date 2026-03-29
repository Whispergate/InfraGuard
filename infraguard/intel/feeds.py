"""Threat intelligence feed auto-update.

Fetches IP blocklists from public threat intel sources, caches them to
disk, and merges them into the IntelManager's blocklist. Supports periodic
refresh via an asyncio background task.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path

import httpx
import structlog

from infraguard.intel.ip_lists import CIDRList

log = structlog.get_logger()

# Built-in feed URLs (plain-text, one IP/CIDR per line)
DEFAULT_FEED_URLS: list[str] = [
    # Feodo Tracker (Dridex, Emotet, TrickBot C2s)
    "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
    # Emerging Threats compromised IPs
    "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    # CI Army bad IPs
    "https://cinsscore.com/list/ci-badguys.txt",
    # Spamhaus DROP (Don't Route Or Peer)
    "https://www.spamhaus.org/drop/drop.txt",
    # Binary Defense IP banlist
    "https://www.binarydefense.com/banlist.txt",
]


def _parse_feed_lines(text: str) -> list[str]:
    """Extract IPs/CIDRs from feed text, skipping comments and blanks."""
    entries: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        # Some feeds have "IP ; comment" format (e.g., Spamhaus DROP)
        if ";" in line:
            line = line.split(";")[0].strip()
        if line:
            entries.append(line)
    return entries


async def fetch_feed(url: str, timeout: float = 30.0) -> list[str]:
    """Fetch a single feed URL and return parsed IPs/CIDRs."""
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            entries = _parse_feed_lines(resp.text)
            log.info("feed_fetched", url=url, entries=len(entries))
            return entries
    except Exception:
        log.warning("feed_fetch_failed", url=url)
        return []


async def fetch_all_feeds(urls: list[str]) -> list[str]:
    """Fetch all feed URLs concurrently and return merged entries."""
    tasks = [fetch_feed(url) for url in urls]
    results = await asyncio.gather(*tasks)
    all_entries: list[str] = []
    for entries in results:
        all_entries.extend(entries)
    # Deduplicate
    return list(set(all_entries))


def save_feed_cache(entries: list[str], cache_dir: str) -> Path:
    """Write fetched entries to a cache file on disk."""
    cache_path = Path(cache_dir)
    cache_path.mkdir(parents=True, exist_ok=True)
    cache_file = cache_path / "feed_blocklist.txt"
    now = datetime.now(timezone.utc).isoformat()
    lines = [f"# InfraGuard feed cache - updated {now}\n"]
    lines.extend(f"{entry}\n" for entry in sorted(entries))
    cache_file.write_text("".join(lines), encoding="utf-8")
    log.info("feed_cache_saved", path=str(cache_file), entries=len(entries))
    return cache_file


def load_feed_cache(cache_dir: str) -> list[str]:
    """Load previously cached feed entries from disk."""
    cache_file = Path(cache_dir) / "feed_blocklist.txt"
    if not cache_file.exists():
        return []
    entries = _parse_feed_lines(cache_file.read_text(encoding="utf-8"))
    log.info("feed_cache_loaded", path=str(cache_file), entries=len(entries))
    return entries


async def update_feeds(
    blocklist: CIDRList,
    urls: list[str] | None = None,
    cache_dir: str = ".infraguard/feeds",
) -> int:
    """Fetch all feeds, cache to disk, and merge into the blocklist.

    Returns the number of new entries added.
    """
    feed_urls = urls if urls else DEFAULT_FEED_URLS
    entries = await fetch_all_feeds(feed_urls)

    if entries:
        save_feed_cache(entries, cache_dir)
        before = blocklist.size
        blocklist.add_many(entries)
        added = blocklist.size - before
        log.info("feeds_updated", total_entries=len(entries), new_added=added)
        return added
    else:
        log.warning("feeds_empty", reason="No entries fetched from any feed")
        return 0


async def feed_refresh_loop(
    blocklist: CIDRList,
    urls: list[str] | None = None,
    cache_dir: str = ".infraguard/feeds",
    interval_hours: int = 6,
) -> None:
    """Background task that periodically refreshes threat intel feeds."""
    interval_seconds = interval_hours * 3600
    while True:
        try:
            await update_feeds(blocklist, urls, cache_dir)
        except Exception:
            log.exception("feed_refresh_error")
        await asyncio.sleep(interval_seconds)
