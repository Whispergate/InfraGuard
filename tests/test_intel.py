"""Tests for IP intelligence and rule ingestion."""

import pytest
from ipaddress import ip_address

from infraguard.intel.ip_lists import CIDRList, DynamicWhitelist
from infraguard.intel.known_ranges import (
    BOT_USER_AGENT_PATTERNS,
    SECURITY_VENDOR_CIDRS,
    BANNED_RDNS_KEYWORDS,
)
from infraguard.intel.rule_ingest import (
    IngestResult,
    parse_htaccess,
    parse_robots_txt,
    ingest_files,
)


# ── CIDRList ──────────────────────────────────────────────────────────

class TestCIDRList:
    def test_add_and_contains(self):
        cl = CIDRList(name="test")
        cl.add("192.168.1.0/24")
        assert cl.contains(ip_address("192.168.1.100"))
        assert not cl.contains(ip_address("10.0.0.1"))

    def test_add_many(self):
        cl = CIDRList(name="test")
        cl.add_many(["10.0.0.0/8", "172.16.0.0/12"])
        assert cl.contains(ip_address("10.1.2.3"))
        assert cl.contains(ip_address("172.16.5.1"))
        assert not cl.contains(ip_address("8.8.8.8"))

    def test_size(self):
        cl = CIDRList(name="test")
        assert cl.size == 0
        cl.add("10.0.0.0/8")
        assert cl.size == 1

    def test_remove(self):
        cl = CIDRList(name="test")
        cl.add("10.0.0.0/8")
        assert cl.remove("10.0.0.0/8")
        assert cl.size == 0

    def test_invalid_cidr(self):
        cl = CIDRList(name="test")
        cl.add("not-a-cidr")  # should not raise
        assert cl.size == 0


# ── DynamicWhitelist ──────────────────────────────────────────────────

class TestDynamicWhitelist:
    def test_threshold_whitelisting(self):
        dw = DynamicWhitelist(threshold=3)
        assert not dw.is_whitelisted("1.2.3.4")
        dw.record_valid_request("1.2.3.4")
        dw.record_valid_request("1.2.3.4")
        assert not dw.is_whitelisted("1.2.3.4")
        result = dw.record_valid_request("1.2.3.4")
        assert result is True  # newly whitelisted
        assert dw.is_whitelisted("1.2.3.4")

    def test_already_whitelisted(self):
        dw = DynamicWhitelist(threshold=1)
        dw.record_valid_request("1.2.3.4")
        result = dw.record_valid_request("1.2.3.4")
        assert result is False  # already whitelisted

    def test_reset(self):
        dw = DynamicWhitelist(threshold=1)
        dw.record_valid_request("1.2.3.4")
        assert dw.is_whitelisted("1.2.3.4")
        dw.reset("1.2.3.4")
        assert not dw.is_whitelisted("1.2.3.4")


# ── Known ranges ──────────────────────────────────────────────────────

class TestKnownRanges:
    def test_security_vendor_cidrs_not_empty(self):
        assert len(SECURITY_VENDOR_CIDRS) > 0

    def test_bot_patterns_not_empty(self):
        assert len(BOT_USER_AGENT_PATTERNS) > 0
        assert "Shodan" in BOT_USER_AGENT_PATTERNS
        assert "Nmap" in BOT_USER_AGENT_PATTERNS

    def test_rdns_keywords_not_empty(self):
        assert len(BANNED_RDNS_KEYWORDS) > 0
        assert "shodan" in BANNED_RDNS_KEYWORDS


# ── Rule ingestion ────────────────────────────────────────────────────

class TestHtaccessParser:
    def test_deny_from(self):
        result = parse_htaccess("Deny from 1.2.3.4\nDeny from 10.0.0.0/8")
        assert "1.2.3.4" in result.blocked_ips
        assert "10.0.0.0/8" in result.blocked_ips

    def test_allow_from(self):
        result = parse_htaccess("Allow from 192.168.1.0/24")
        assert "192.168.1.0/24" in result.allowed_ips

    def test_require_not_ip(self):
        result = parse_htaccess("Require not ip 5.6.7.8")
        assert "5.6.7.8" in result.blocked_ips

    def test_require_ip(self):
        result = parse_htaccess("Require ip 10.0.0.0/8")
        assert "10.0.0.0/8" in result.allowed_ips

    def test_rewrite_ua_alternation(self):
        result = parse_htaccess(
            'RewriteCond %{HTTP_USER_AGENT} ^.*(Nmap|Nikto|sqlmap).*$ [NC]'
        )
        assert "Nmap" in result.blocked_user_agents
        assert "Nikto" in result.blocked_user_agents
        assert "sqlmap" in result.blocked_user_agents

    def test_setenvifnocase(self):
        result = parse_htaccess('SetEnvIfNoCase User-Agent "Googlebot" bad_bot')
        assert "Googlebot" in result.blocked_user_agents

    def test_comments_skipped(self):
        result = parse_htaccess("# Deny from 1.2.3.4")
        assert len(result.blocked_ips) == 0


class TestRobotsTxtParser:
    def test_user_agents(self):
        result = parse_robots_txt(
            "User-agent: Googlebot\nDisallow: /admin\n"
            "User-agent: AhrefsBot\nDisallow: /\n"
        )
        assert "Googlebot" in result.blocked_user_agents
        assert "AhrefsBot" in result.blocked_user_agents

    def test_wildcard_skipped(self):
        result = parse_robots_txt("User-agent: *\nDisallow: /private")
        assert len(result.blocked_user_agents) == 0

    def test_disallow_paths(self):
        result = parse_robots_txt(
            "User-agent: bot\nDisallow: /admin\nDisallow: /api"
        )
        assert "/admin" in result.blocked_paths
        assert "/api" in result.blocked_paths


class TestIngestResult:
    def test_merge(self):
        r1 = IngestResult(blocked_ips=["1.1.1.1"])
        r2 = IngestResult(blocked_ips=["2.2.2.2"])
        r1.merge(r2)
        assert "1.1.1.1" in r1.blocked_ips
        assert "2.2.2.2" in r1.blocked_ips

    def test_deduplicate(self):
        r = IngestResult(blocked_ips=["1.1.1.1", "1.1.1.1", "2.2.2.2"])
        r.deduplicate()
        assert len(r.blocked_ips) == 2
