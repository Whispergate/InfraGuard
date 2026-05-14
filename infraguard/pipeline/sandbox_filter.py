"""Sandbox and headless browser detection filter.

Detects automated analysis platforms (Cuckoo, ANY.RUN, VirusTotal URL scanner,
Microsoft Safe Links, Playwright, Puppeteer) before they can inspect phishing
pages or payload delivery routes. Uses a score-accumulation model across
multiple header signals - no single signal is definitive.
"""

from __future__ import annotations

import re

import structlog

from infraguard.models.common import FilterResult
from infraguard.pipeline.base import RequestContext

log = structlog.get_logger()

# User-Agent patterns that indicate headless automation
_HEADLESS_UA_PATTERNS = [
    re.compile(r"HeadlessChrome", re.IGNORECASE),
    re.compile(r"Playwright", re.IGNORECASE),
    re.compile(r"PhantomJS", re.IGNORECASE),
    re.compile(r"SlimerJS", re.IGNORECASE),
    re.compile(r"Selenium", re.IGNORECASE),
    re.compile(r"WebDriver", re.IGNORECASE),
    re.compile(r"puppeteer", re.IGNORECASE),
]

# Safe Links / email gateway pre-fetch scanners
_SCANNER_UA_PATTERNS = [
    re.compile(r"SafeLinks", re.IGNORECASE),
    re.compile(r"msnbot-media", re.IGNORECASE),
    re.compile(r"AhrefsBot", re.IGNORECASE),
    re.compile(r"DuckDuckBot", re.IGNORECASE),
    re.compile(r"facebookexternalhit", re.IGNORECASE),
    re.compile(r"LinkedInBot", re.IGNORECASE),
    re.compile(r"Twitterbot", re.IGNORECASE),
    re.compile(r"Slackbot", re.IGNORECASE),
    re.compile(r"vk\.com", re.IGNORECASE),
    re.compile(r"Microsoft Office", re.IGNORECASE),  # Office document link preview
]

_BLOCK_SCORE = 0.7
_SUSPECT_SCORE = 0.2


class SandboxFilter:
    name = "sandbox"

    async def check(self, ctx: RequestContext) -> FilterResult:
        headers = ctx.request.headers
        ua = headers.get("user-agent", "")
        score = 0.0
        signals: list[str] = []

        # Signal: headless browser UA string (very high confidence)
        for pat in _HEADLESS_UA_PATTERNS:
            if pat.search(ua):
                score += 0.75
                signals.append("headless_ua")
                break

        # Signal: known scanner / link-preview bot UA
        if not signals:  # don't double-count with headless_ua
            for pat in _SCANNER_UA_PATTERNS:
                if pat.search(ua):
                    score += 0.65
                    signals.append("scanner_ua")
                    break

        # Signal: missing Accept-Language (present in every real browser)
        if not headers.get("accept-language"):
            score += 0.25
            signals.append("no_accept_language")

        # Signal: Chrome UA without sec-ch-ua (headless Chromium / old automation)
        if "Chrome" in ua and not headers.get("sec-ch-ua"):
            score += 0.20
            signals.append("chrome_no_ch_ua")

        # Signal: Chrome UA without sec-ch-ua-mobile
        if "Chrome" in ua and "sec-ch-ua-mobile" not in headers:
            score += 0.10
            signals.append("chrome_no_ch_ua_mobile")

        # Signal: missing Referer on a non-root path
        # Real phishing victims follow a link and carry a Referer (or come from
        # the email client which omits it but also hits "/" first).
        path = ctx.request.url.path
        if path not in ("/", "") and not headers.get("referer"):
            score += 0.15
            signals.append("no_referer_direct_nav")

        # Signal: Accept header missing or non-browser ordering
        accept = headers.get("accept", "")
        if accept and not accept.startswith("text/html"):
            score += 0.10
            signals.append("non_browser_accept")

        if not signals:
            return FilterResult.allow(filter_name=self.name)

        reason = f"Sandbox/scanner indicators: {', '.join(signals)}"

        if score >= _BLOCK_SCORE:
            log.info("sandbox_blocked", ip=str(ctx.client_ip), signals=signals, score=round(score, 2))
            return FilterResult.block(reason=reason, filter_name=self.name, score=score)

        if score > _SUSPECT_SCORE:
            return FilterResult.suspect(reason=reason, filter_name=self.name, score=score)

        return FilterResult.allow(filter_name=self.name)
