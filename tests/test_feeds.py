"""Tests for feed retry backoff and staleness tracking (RESL-02)."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

import infraguard.intel.feeds as feeds_module
from infraguard.intel.feeds import (
    _STALENESS_THRESHOLD_HOURS,
    fetch_feed,
    feed_refresh_loop,
    get_feed_status,
    update_feeds,
)
from infraguard.intel.ip_lists import CIDRList


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_response(text: str, status: int = 200) -> MagicMock:
    """Build a mock httpx.Response."""
    resp = MagicMock()
    resp.status_code = status
    resp.text = text
    resp.raise_for_status = MagicMock()
    if status >= 400:
        resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            message=f"HTTP {status}", request=MagicMock(), response=resp
        )
    return resp


def _make_blocklist() -> CIDRList:
    return CIDRList(name="test_blocklist")


def _patch_fast_retry():
    """Patch wait_exponential in feeds module to use no-wait for test speed."""
    from tenacity import wait_none
    return patch("infraguard.intel.feeds.wait_exponential", return_value=wait_none())


# ---------------------------------------------------------------------------
# Test 1: fetch_feed retries on httpx.RequestError (up to 3 attempts)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_fetch_feed_retries_on_request_error():
    """fetch_feed should retry up to 3 attempts on httpx.RequestError."""
    call_count = 0

    async def flaky_get(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count < 3:
            raise httpx.RequestError("connection refused")
        return _make_response("1.2.3.4\n5.6.7.8\n")

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = flaky_get

    with _patch_fast_retry():
        with patch("infraguard.intel.feeds.httpx.AsyncClient", return_value=mock_client):
            result = await fetch_feed("http://test.example/feed.txt")

    assert call_count == 3
    assert "1.2.3.4" in result
    assert "5.6.7.8" in result


# ---------------------------------------------------------------------------
# Test 2: fetch_feed returns empty list after all retries exhausted
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_fetch_feed_returns_empty_after_all_retries_exhausted():
    """fetch_feed returns [] after all 3 retries fail - does not raise."""
    async def always_fail(*args, **kwargs):
        raise httpx.RequestError("network unreachable")

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = always_fail

    with _patch_fast_retry():
        with patch("infraguard.intel.feeds.httpx.AsyncClient", return_value=mock_client):
            result = await fetch_feed("http://unreachable.example/feed.txt")

    assert result == []


# ---------------------------------------------------------------------------
# Test 3: Successful fetch updates last_success_at timestamp for that URL
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_fetch_feed_updates_feed_status_on_success():
    """A successful fetch should update _feed_status[url] with a UTC timestamp."""
    url = "http://success.example/feed.txt"

    # Clear any pre-existing status for this URL
    feeds_module._feed_status.pop(url, None)

    async def succeed(*args, **kwargs):
        return _make_response("10.0.0.1\n")

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = succeed

    before = datetime.now(timezone.utc)
    with _patch_fast_retry():
        with patch("infraguard.intel.feeds.httpx.AsyncClient", return_value=mock_client):
            result = await fetch_feed(url)

    assert url in feeds_module._feed_status
    ts = feeds_module._feed_status[url]
    assert ts is not None
    assert ts >= before
    assert ts.tzinfo is not None  # timezone-aware

    # Also verify get_feed_status() exposes it as an ISO string
    status = get_feed_status()
    assert url in status
    assert status[url] is not None


# ---------------------------------------------------------------------------
# Test 4: feed_refresh_loop logs warning when any feed is stale
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_feed_refresh_loop_logs_stale_warning():
    """feed_refresh_loop should log feed_stale warning for feeds stale > 24h."""
    url = "http://stale.example/feed.txt"
    stale_time = datetime.now(timezone.utc) - timedelta(hours=_STALENESS_THRESHOLD_HOURS + 2)

    blocklist = _make_blocklist()

    async def mock_update_feeds(*args, **kwargs):
        pass  # Don't actually fetch

    with patch("infraguard.intel.feeds.update_feeds", side_effect=mock_update_feeds):
        # Pre-set a stale timestamp
        feeds_module._feed_status[url] = stale_time

        with patch.object(feeds_module.log, "warning") as mock_warn:
            # Run one iteration by patching asyncio.sleep to raise CancelledError
            with patch("infraguard.intel.feeds.asyncio.sleep", side_effect=asyncio.CancelledError):
                with pytest.raises(asyncio.CancelledError):
                    await feed_refresh_loop(blocklist, urls=[url], interval_hours=6)

            # Collect all warning calls
            warnings_logged = [call[0][0] for call in mock_warn.call_args_list if call[0]]

    assert any("feed_stale" in str(w) for w in warnings_logged), (
        f"Expected 'feed_stale' warning, got: {warnings_logged}"
    )


# ---------------------------------------------------------------------------
# Test 5a: require_feeds=True raises when all feeds return empty
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_update_feeds_require_true_raises_when_empty():
    """update_feeds with require=True should raise RuntimeError when all feeds empty."""
    blocklist = _make_blocklist()

    with patch("infraguard.intel.feeds.fetch_all_feeds", new=AsyncMock(return_value=[])):
        with pytest.raises(RuntimeError, match="require_feeds"):
            await update_feeds(blocklist, urls=["http://empty.example/"], require=True)


# ---------------------------------------------------------------------------
# Test 5b: require_feeds=False logs warning and returns 0 when all feeds empty
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_update_feeds_require_false_logs_warning_when_empty():
    """update_feeds with require=False should log warning and return 0 when all feeds empty."""
    blocklist = _make_blocklist()

    with patch("infraguard.intel.feeds.fetch_all_feeds", new=AsyncMock(return_value=[])):
        with patch.object(feeds_module.log, "warning") as mock_warn:
            result = await update_feeds(blocklist, urls=["http://empty.example/"], require=False)

    assert result == 0
    warn_events = [call[0][0] for call in mock_warn.call_args_list if call[0]]
    assert any("feeds_empty" in str(e) for e in warn_events)
