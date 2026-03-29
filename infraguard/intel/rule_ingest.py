"""Ingest .htaccess and robots.txt rules into InfraGuard blocklists.

Parses common server rule formats and extracts:
- IP addresses / CIDR ranges (from .htaccess Deny/Require directives)
- User-Agent patterns (from .htaccess RewriteCond and robots.txt)
- Disallowed paths (from robots.txt)

The extracted data can be merged into InfraGuard's CIDRList (IP blocking)
and BotFilter (User-Agent blocking).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import structlog

log = structlog.get_logger()


@dataclass
class IngestResult:
    """Aggregated rules extracted from one or more files."""

    blocked_ips: list[str] = field(default_factory=list)
    blocked_user_agents: list[str] = field(default_factory=list)
    blocked_paths: list[str] = field(default_factory=list)
    allowed_ips: list[str] = field(default_factory=list)
    source_files: list[str] = field(default_factory=list)

    def merge(self, other: IngestResult) -> None:
        self.blocked_ips.extend(other.blocked_ips)
        self.blocked_user_agents.extend(other.blocked_user_agents)
        self.blocked_paths.extend(other.blocked_paths)
        self.allowed_ips.extend(other.allowed_ips)
        self.source_files.extend(other.source_files)

    def deduplicate(self) -> None:
        self.blocked_ips = list(dict.fromkeys(self.blocked_ips))
        self.blocked_user_agents = list(dict.fromkeys(self.blocked_user_agents))
        self.blocked_paths = list(dict.fromkeys(self.blocked_paths))
        self.allowed_ips = list(dict.fromkeys(self.allowed_ips))

    @property
    def summary(self) -> str:
        return (
            f"IPs: {len(self.blocked_ips)} blocked, {len(self.allowed_ips)} allowed | "
            f"User-Agents: {len(self.blocked_user_agents)} | "
            f"Paths: {len(self.blocked_paths)}"
        )


# ── .htaccess parser ──────────────────────────────────────────────────

# Matches: Deny from 1.2.3.4, Deny from 10.0.0.0/8
_DENY_FROM = re.compile(r"^\s*Deny\s+from\s+(.+)", re.IGNORECASE)
# Matches: Allow from 192.168.1.0/24
_ALLOW_FROM = re.compile(r"^\s*Allow\s+from\s+(.+)", re.IGNORECASE)
# Matches: Require not ip 1.2.3.4 10.0.0.0/8
_REQUIRE_NOT_IP = re.compile(r"^\s*Require\s+not\s+ip\s+(.+)", re.IGNORECASE)
# Matches: Require ip 192.168.1.0/24
_REQUIRE_IP = re.compile(r"^\s*Require\s+ip\s+(.+)", re.IGNORECASE)
# Matches: RewriteCond %{HTTP_USER_AGENT} pattern [NC,OR]
_REWRITE_UA = re.compile(
    r"^\s*RewriteCond\s+%\{HTTP_USER_AGENT\}\s+(.+?)(?:\s+\[.*\])?\s*$",
    re.IGNORECASE,
)
# Matches: SetEnvIfNoCase User-Agent "pattern" bad_bot
_SETENVIF_UA = re.compile(
    r"^\s*SetEnvIfNoCase\s+User-Agent\s+[\"']?(.+?)[\"']?\s+\w+",
    re.IGNORECASE,
)


def _clean_ip_token(token: str) -> str | None:
    """Validate and normalize an IP/CIDR token."""
    token = token.strip().strip('"').strip("'")
    if not token or token in ("all", "env=bad_bot"):
        return None
    # Basic validation: must contain digits and dots or colons
    if re.match(r"^[\d./]+$", token) or re.match(r"^[\da-fA-F:./]+$", token):
        return token
    return None


def _clean_ua_pattern(pattern: str) -> str:
    """Convert an Apache regex UA pattern to plain substrings for matching."""
    pattern = pattern.strip().strip('"').strip("'")
    # Remove regex anchors and common metacharacters
    pattern = re.sub(r"^\^|\$$", "", pattern)
    # Remove apache-style wildcards
    pattern = pattern.replace(".*", "").replace(".+", "")
    # Remove escape backslashes
    pattern = pattern.replace("\\", "")
    # Strip grouping parens
    pattern = pattern.strip("()")
    # If what's left is a reasonable bot name, keep it
    pattern = pattern.strip("|").strip()
    return pattern


def parse_htaccess(content: str) -> IngestResult:
    """Extract IP blocklists and User-Agent patterns from .htaccess content."""
    result = IngestResult()

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # Deny from
        m = _DENY_FROM.match(line)
        if m:
            for token in m.group(1).split():
                ip = _clean_ip_token(token)
                if ip:
                    result.blocked_ips.append(ip)
            continue

        # Allow from
        m = _ALLOW_FROM.match(line)
        if m:
            for token in m.group(1).split():
                ip = _clean_ip_token(token)
                if ip:
                    result.allowed_ips.append(ip)
            continue

        # Require not ip
        m = _REQUIRE_NOT_IP.match(line)
        if m:
            for token in m.group(1).split():
                ip = _clean_ip_token(token)
                if ip:
                    result.blocked_ips.append(ip)
            continue

        # Require ip (whitelist)
        m = _REQUIRE_IP.match(line)
        if m:
            for token in m.group(1).split():
                ip = _clean_ip_token(token)
                if ip:
                    result.allowed_ips.append(ip)
            continue

        # RewriteCond User-Agent
        m = _REWRITE_UA.match(line)
        if m:
            raw = m.group(1)
            # Strip outer regex wrapper like ^.*(pattern).*$
            raw = re.sub(r"^\^?\.\*\(?(.*?)\)?\.\*\$?$", r"\1", raw)
            raw = raw.strip("()")
            # Split on | for multi-pattern alternation groups
            for part in raw.split("|"):
                cleaned = _clean_ua_pattern(part)
                if cleaned and len(cleaned) >= 3:
                    result.blocked_user_agents.append(cleaned)
            continue

        # SetEnvIfNoCase User-Agent
        m = _SETENVIF_UA.match(line)
        if m:
            cleaned = _clean_ua_pattern(m.group(1))
            if cleaned and len(cleaned) >= 3:
                result.blocked_user_agents.append(cleaned)

    return result


# ── robots.txt parser ─────────────────────────────────────────────────

def parse_robots_txt(content: str) -> IngestResult:
    """Extract bot User-Agent names and disallowed paths from robots.txt."""
    result = IngestResult()
    current_agents: list[str] = []

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # User-agent directive
        if line.lower().startswith("user-agent:"):
            agent = line.split(":", 1)[1].strip()
            if agent and agent != "*":
                current_agents.append(agent)
                result.blocked_user_agents.append(agent)
            else:
                current_agents = []
            continue

        # Disallow directive
        if line.lower().startswith("disallow:"):
            path = line.split(":", 1)[1].strip()
            if path and path != "/":
                result.blocked_paths.append(path)
            continue

    return result


# ── Unified ingester ──────────────────────────────────────────────────

def ingest_file(path: str | Path) -> IngestResult:
    """Auto-detect file type and parse rules from it."""
    path = Path(path)
    if not path.exists():
        log.warning("ingest_file_not_found", path=str(path))
        return IngestResult()

    content = path.read_text(encoding="utf-8", errors="replace")
    name = path.name.lower()

    if name == "robots.txt":
        result = parse_robots_txt(content)
    elif name in (".htaccess", "htaccess"):
        result = parse_htaccess(content)
    else:
        # Try to auto-detect: if it has "User-agent:" lines it's robots.txt
        if re.search(r"^User-agent:", content, re.MULTILINE | re.IGNORECASE):
            result = parse_robots_txt(content)
        else:
            result = parse_htaccess(content)

    result.source_files.append(str(path))
    result.deduplicate()
    return result


def ingest_files(paths: list[str | Path]) -> IngestResult:
    """Parse rules from multiple files and merge results."""
    combined = IngestResult()
    for p in paths:
        combined.merge(ingest_file(p))
    combined.deduplicate()
    return combined
