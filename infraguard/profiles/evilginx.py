"""Evilginx phishlet parser.

Parses Evilginx phishlet YAML files to extract proxy_hosts and login
paths. These are converted into allowed path patterns for the phishing
filter so InfraGuard knows which subdomains and paths to proxy.

Phishlet structure (relevant fields):
    proxy_hosts:
        - phish_sub: ''          # subdomain on phishing domain
          orig_sub: ''           # subdomain on original domain
          domain: 'target.com'
          session: true
          is_landing: true
    login:
        domain: 'login.target.com'
        path: '/wp-login.php'
    auth_urls:
        - '*/wp-admin/*'
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml
import structlog

log = structlog.get_logger()


@dataclass
class PhishletInfo:
    """Parsed information from an Evilginx phishlet file."""

    name: str = ""
    proxy_hosts: list[dict[str, str]] = field(default_factory=list)
    login_path: str = "/"
    auth_url_patterns: list[str] = field(default_factory=list)
    credential_paths: list[str] = field(default_factory=list)

    def to_path_patterns(self) -> list[re.Pattern[str]]:
        """Convert phishlet info into regex path patterns for filtering."""
        patterns: list[re.Pattern[str]] = []

        # Login path
        if self.login_path:
            escaped = re.escape(self.login_path)
            patterns.append(re.compile(f"^{escaped}$"))

        # Auth URL patterns (Evilginx uses glob-style: */wp-admin/*)
        for auth_url in self.auth_url_patterns:
            # Convert Evilginx glob to regex
            regex = auth_url.replace("*", ".*")
            # Strip leading domain part if present (keep path only)
            if "/" in regex:
                path_part = "/" + regex.split("/", 1)[1] if not regex.startswith("/") else regex
            else:
                path_part = f".*{regex}.*"
            try:
                patterns.append(re.compile(f"^{path_part}"))
            except re.error:
                log.warning("invalid_auth_url_pattern", pattern=auth_url)

        # Evilginx proxies everything on matched domains, so add catch-all
        # unless we have specific paths defined
        if not patterns:
            patterns.append(re.compile(r"^/"))

        return patterns


def parse_phishlet(path: Path) -> PhishletInfo:
    """Parse an Evilginx phishlet YAML file.

    Args:
        path: Path to the .yaml phishlet file.

    Returns:
        PhishletInfo with extracted proxy hosts, login path, and auth patterns.
    """
    content = path.read_text(encoding="utf-8")
    data = yaml.safe_load(content)

    if not isinstance(data, dict):
        log.warning("invalid_phishlet", path=str(path), reason="not a dict")
        return PhishletInfo()

    info = PhishletInfo(name=data.get("name", path.stem))

    # Extract proxy_hosts
    for host in data.get("proxy_hosts", []):
        if isinstance(host, dict):
            info.proxy_hosts.append({
                "phish_sub": host.get("phish_sub", ""),
                "orig_sub": host.get("orig_sub", ""),
                "domain": host.get("domain", ""),
                "is_landing": str(host.get("is_landing", False)).lower() == "true",
            })

    # Extract login path
    login = data.get("login", {})
    if isinstance(login, dict):
        info.login_path = login.get("path", "/")

    # Extract auth_urls patterns
    auth_urls = data.get("auth_urls", [])
    if isinstance(auth_urls, list):
        info.auth_url_patterns = [str(u) for u in auth_urls]

    # Extract credential POST paths
    creds = data.get("credentials", {})
    if isinstance(creds, dict):
        for field_info in creds.values():
            if isinstance(field_info, dict) and field_info.get("type") == "post":
                # Credentials are submitted via POST — login path handles this
                pass

    log.info(
        "phishlet_parsed",
        name=info.name,
        proxy_hosts=len(info.proxy_hosts),
        login_path=info.login_path,
        auth_patterns=len(info.auth_url_patterns),
    )

    return info
