"""Phishing framework profile definitions.

Unlike C2 profiles which define strict URI/header contracts, phishing
profiles define allowed URL path patterns for each framework. Requests
matching these patterns are proxied to the upstream phishing server;
non-matching requests are dropped.

Passthrough mode skips path filtering entirely - all requests that pass
the IP/bot/geo filters are proxied.

Path sources (merged in order):
1. Framework defaults (built-in patterns for GoPhish, Evilginx, etc.)
2. Phishlet file paths (parsed from Evilginx .yaml phishlets)
3. Operator-defined paths (allowed_paths in config.yaml)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from infraguard.models.common import ProfileType


@dataclass
class PhishingProfile:
    """Defines allowed path patterns for a phishing framework."""

    name: str
    framework: ProfileType
    allowed_patterns: list[re.Pattern[str]] = field(default_factory=list)
    passthrough: bool = False

    def matches(self, path: str) -> bool:
        """Return True if the request path is allowed by this profile."""
        if self.passthrough:
            return True
        return any(p.match(path) for p in self.allowed_patterns)


# GoPhish: tracking pixels, report endpoints, landing pages
_GOPHISH_PATTERNS = [
    re.compile(r"^/track/"),       # tracking pixel callbacks
    re.compile(r"^/report$"),      # phishing report endpoint
    re.compile(r"^/robots\.txt$"), # GoPhish serves a robots.txt
    re.compile(r"^/static/"),      # static assets for landing pages
    re.compile(r"^/"),             # landing pages are served at root paths
]

# Evilginx: default is passthrough (proxies everything on lure domain)
_EVILGINX_PATTERNS = [
    re.compile(r"^/"),  # Evilginx proxies everything on the lure domain
]

# CuddlePhish: OAuth flow paths, callback URLs, device code flow
_CUDDLEPHISH_PATTERNS = [
    re.compile(r"^/"),  # CuddlePhish proxies full OAuth flows
]


def _compile_operator_patterns(paths: list[str]) -> list[re.Pattern[str]]:
    """Compile operator-defined path patterns into regex.

    Supports:
    - Exact: /login.php
    - Prefix glob: /admin/*
    - Regex: ~^/api/v[0-9]+/
    """
    patterns: list[re.Pattern[str]] = []
    for path in paths:
        if path.startswith("~"):
            # Regex pattern
            try:
                patterns.append(re.compile(path[1:]))
            except re.error:
                pass
        elif path.endswith("/*"):
            # Prefix glob
            prefix = re.escape(path[:-1])
            patterns.append(re.compile(f"^{prefix}"))
        elif "*" in path:
            # Simple glob
            prefix = re.escape(path.split("*")[0])
            patterns.append(re.compile(f"^{prefix}"))
        else:
            # Exact match
            patterns.append(re.compile(f"^{re.escape(path)}$"))
    return patterns


def build_phishing_profile(
    framework: ProfileType,
    *,
    operator_paths: list[str] | None = None,
    phishlet_path: str | None = None,
) -> PhishingProfile:
    """Build a PhishingProfile for the given framework type.

    Args:
        framework: The phishing framework type.
        operator_paths: Optional list of path patterns from config.yaml allowed_paths.
        phishlet_path: Optional path to an Evilginx phishlet .yaml file.

    Path sources are merged: framework defaults + phishlet paths + operator paths.
    If operator_paths are provided, they REPLACE framework defaults (operator
    knows best). Phishlet paths are always additive.
    """
    # Start with framework defaults
    if framework == ProfileType.GOPHISH:
        name = "GoPhish"
        default_patterns = list(_GOPHISH_PATTERNS)
    elif framework == ProfileType.EVILGINX:
        name = "Evilginx"
        default_patterns = list(_EVILGINX_PATTERNS)
    elif framework == ProfileType.CUDDLEPHISH:
        name = "CuddlePhish"
        default_patterns = list(_CUDDLEPHISH_PATTERNS)
    elif framework == ProfileType.PASSTHROUGH:
        # If operator defines paths, use those instead of passthrough
        if operator_paths:
            return PhishingProfile(
                name="Passthrough",
                framework=framework,
                allowed_patterns=_compile_operator_patterns(operator_paths),
            )
        return PhishingProfile(
            name="Passthrough",
            framework=framework,
            passthrough=True,
        )
    else:
        return PhishingProfile(
            name="Passthrough",
            framework=framework,
            passthrough=True,
        )

    # If operator defined paths, they replace defaults
    if operator_paths:
        patterns = _compile_operator_patterns(operator_paths)
    else:
        patterns = default_patterns

    # Parse phishlet and merge paths (additive)
    if phishlet_path:
        phishlet_file = Path(phishlet_path)
        if phishlet_file.exists():
            from infraguard.profiles.evilginx import parse_phishlet
            phishlet_info = parse_phishlet(phishlet_file)
            phishlet_patterns = phishlet_info.to_path_patterns()
            # Prepend phishlet patterns (higher priority)
            patterns = phishlet_patterns + patterns
            name = f"Evilginx ({phishlet_info.name})"

    return PhishingProfile(
        name=name,
        framework=framework,
        allowed_patterns=patterns,
    )
