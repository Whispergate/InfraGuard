"""Havoc C2 (Kaine) TOML profile parser.

Parses Havoc/Kaine HTTP C2 profile TOML files into the normalized
C2Profile model. Havoc profiles use TOML format with:
  - ``agent.task-request`` - how the agent polls for tasks (GET)
  - ``agent.task-output`` - how the agent sends output (POST)
  - URI patterns with ``[a|b|c]`` alternation syntax
  - Transform chains (base64, xor, prepend, append, header/parameter placement)

The parser expands URI alternation patterns into all valid combinations
so the profile filter can match incoming beacon requests.
"""

from __future__ import annotations

import itertools
import re
from pathlib import Path
from typing import Any

try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ImportError:
        tomllib = None  # type: ignore[assignment]

from infraguard.profiles.models import (
    C2Profile,
    ClientConfig,
    HttpTransaction,
    MessageConfig,
    ServerConfig,
    Transform,
)


def _expand_alternations(pattern: str) -> list[str]:
    """Expand ``[a|b|c]`` alternation patterns into all combinations.

    Example: ``/[a|b]/get.js`` → ``["/a/get.js", "/b/get.js"]``
    """
    # Find all [x|y|z] groups
    groups = re.findall(r"\[([^\]]+)\]", pattern)
    if not groups:
        return [pattern]

    # Build list of option lists for each group
    options: list[list[str]] = []
    for group in groups:
        options.append(group.split("|"))

    # Generate all combinations
    results: list[str] = []
    for combo in itertools.product(*options):
        result = pattern
        for group, choice in zip(groups, combo):
            result = result.replace(f"[{group}]", choice, 1)
        results.append(result)

    return results


def _parse_headers(header_list: list[dict[str, str]] | None) -> dict[str, str]:
    """Parse Havoc header list format into a flat dict."""
    if not header_list:
        return {}
    headers: dict[str, str] = {}
    for entry in header_list:
        for k, v in entry.items():
            # Expand alternation in header names/values to first option
            k_expanded = re.sub(r"\[([^|]+)\|[^\]]*\]", r"\1", k)
            v_expanded = re.sub(r"\[([^|]+)\|[^\]]*\]", r"\1", v)
            headers[k_expanded] = v_expanded
    return headers


def _parse_transforms(transform_list: list[dict[str, Any]] | None) -> tuple[list[Transform], MessageConfig]:
    """Parse Havoc transform chain into Transform objects and message location."""
    transforms: list[Transform] = []
    message = MessageConfig(location="body", name="")

    if not transform_list:
        return transforms, message

    for entry in transform_list:
        if "encode" in entry:
            enc = entry["encode"]
            if enc == "base64":
                if entry.get("url-safe"):
                    transforms.append(Transform(action="base64url"))
                else:
                    transforms.append(Transform(action="base64"))
            elif enc == "xor":
                transforms.append(Transform(action="mask"))
            elif enc == "netbios":
                transforms.append(Transform(action="netbios"))
        elif "prepend" in entry:
            transforms.append(Transform(action="prepend", value=entry["prepend"]))
        elif "append" in entry:
            transforms.append(Transform(action="append", value=entry["append"]))
        elif "header" in entry:
            message = MessageConfig(location="header", name=entry["header"])
        elif "parameter" in entry:
            message = MessageConfig(location="parameter", name=entry["parameter"])

    return transforms, message


class HavocParser:
    """Parse Havoc/Kaine C2 TOML profiles into a normalized C2Profile."""

    def parse(self, content: str) -> C2Profile:
        if tomllib is None:
            raise ImportError(
                "TOML parsing requires Python 3.11+ (tomllib) or the 'tomli' package"
            )
        data = tomllib.loads(content)
        return self._parse_dict(data)

    def parse_file(self, path: str | Path) -> C2Profile:
        if tomllib is None:
            raise ImportError(
                "TOML parsing requires Python 3.11+ (tomllib) or the 'tomli' package"
            )
        with open(path, "rb") as f:
            data = tomllib.load(f)
        return self._parse_dict(data)

    def _parse_dict(self, data: dict[str, Any]) -> C2Profile:
        # Navigate to the profile - Havoc uses [[kaine.http.profile]]
        profiles = (
            data.get("kaine", {}).get("http", {}).get("profile", [])
        )
        if not profiles:
            return C2Profile(name="Havoc Profile")

        profile = profiles[0]  # Use the first profile
        name = profile.get("name", "Havoc Profile")
        useragent = profile.get("user-agent")

        # Parse task-request (GET - agent polls for tasks)
        http_get = self._parse_transaction(profile, "task-request", "GET")

        # Parse task-output (POST - agent sends results)
        http_post = self._parse_transaction(profile, "task-output", "POST")

        return C2Profile(
            name=name,
            http_get=http_get,
            http_post=http_post,
            useragent=useragent,
        )

    def _parse_transaction(
        self, profile: dict[str, Any], section: str, default_verb: str,
    ) -> HttpTransaction | None:
        # TOML dotted keys are nested: agent.task-request.uri → profile["agent"]["task-request"]["uri"]
        agent_section = profile.get("agent", {}).get(section, {})
        server_section = profile.get("server", {}).get(section, {})

        # URIs - expand alternation patterns
        uri_entries = agent_section.get("uri", [])
        uris: list[str] = []
        verb = default_verb
        for entry in uri_entries:
            for method, pattern in entry.items():
                verb = method.upper()
                expanded = _expand_alternations(pattern)
                uris.extend(expanded)
        uris = list(set(uris))  # deduplicate

        if not uris:
            return None

        # Client headers
        client_headers = _parse_headers(agent_section.get("headers"))

        # Client transforms + message location
        client_transforms, message = _parse_transforms(
            agent_section.get("transform")
        )

        client = ClientConfig(
            headers=client_headers,
            message=message,
            transforms=client_transforms,
        )

        # Server headers
        server_headers = _parse_headers(server_section.get("headers"))

        # Server transforms
        server_transforms, _ = _parse_transforms(
            server_section.get("transform")
        )

        server = ServerConfig(
            headers=server_headers,
            transforms=server_transforms,
        )

        return HttpTransaction(
            verb=verb,
            uris=uris[:100],  # cap to prevent explosion from deep alternation
            client=client,
            server=server,
        )


# ── Convenience functions ─────────────────────────────────────────────


def parse_havoc_profile(
    content: str, name: str | None = None,
) -> C2Profile:
    """Parse a Havoc/Kaine TOML profile string into a C2Profile."""
    parser = HavocParser()
    profile = parser.parse(content)
    if name:
        profile.name = name
    return profile


def parse_havoc_file(
    path: str | Path, name: str | None = None,
) -> C2Profile:
    """Parse a Havoc/Kaine TOML profile file into a C2Profile."""
    parser = HavocParser()
    profile = parser.parse_file(path)
    if name:
        profile.name = name
    return profile
