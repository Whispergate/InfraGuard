"""Mythic C2 HTTPX profile parser.

Parses Mythic HTTP C2 profile JSON files into the normalized C2Profile
model used by InfraGuard. Supports both the Tyche HTTPX profile format
and raw Mythic agent config JSON.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from infraguard.profiles.models import (
    C2Profile,
    ClientConfig,
    HttpTransaction,
    MessageConfig,
    ServerConfig,
    Transform,
)


class MythicHTTPParser:
    """Parse Mythic C2 HTTPX profile JSON into a normalized C2Profile."""

    def parse(self, content: str) -> C2Profile:
        data = json.loads(content)
        return self._parse_dict(data)

    def parse_file(self, path: str | Path) -> C2Profile:
        with open(path, encoding="utf-8") as f:
            return self.parse(f.read())

    def _parse_dict(self, data: dict[str, Any]) -> C2Profile:
        name = data.get("name", "Mythic Profile")

        http_get = self._parse_endpoint(data.get("get")) if "get" in data else None
        http_post = self._parse_endpoint(data.get("post")) if "post" in data else None

        return C2Profile(
            name=name,
            http_get=http_get,
            http_post=http_post,
            useragent=self._extract_useragent(data),
        )

    def _parse_endpoint(self, ep: dict[str, Any]) -> HttpTransaction:
        verb = ep.get("verb", "GET")
        uris = ep.get("uris", ["/"])

        client_data = ep.get("client", {})
        server_data = ep.get("server", {})

        client = self._parse_client(client_data)
        server = self._parse_server(server_data)

        return HttpTransaction(verb=verb, uris=uris, client=client, server=server)

    def _parse_client(self, data: dict[str, Any]) -> ClientConfig:
        headers = data.get("headers", {})
        parameters = data.get("parameters")

        message = None
        msg_data = data.get("message")
        if msg_data:
            message = MessageConfig(
                location=msg_data.get("location", "cookie"),
                name=msg_data.get("name", ""),
            )

        transforms = self._parse_transforms(data.get("transforms"))

        return ClientConfig(
            headers=headers,
            parameters=parameters,
            message=message,
            transforms=transforms,
        )

    def _parse_server(self, data: dict[str, Any]) -> ServerConfig:
        headers = data.get("headers", {})
        transforms = self._parse_transforms(data.get("transforms"))
        return ServerConfig(headers=headers, transforms=transforms)

    @staticmethod
    def _parse_transforms(raw: list[dict[str, str]] | None) -> list[Transform]:
        if not raw:
            return []
        return [
            Transform(action=t.get("action", ""), value=t.get("value", ""))
            for t in raw
        ]

    @staticmethod
    def _extract_useragent(data: dict[str, Any]) -> str | None:
        for section in ("get", "post"):
            ep = data.get(section, {})
            ua = ep.get("client", {}).get("headers", {}).get("User-Agent")
            if ua:
                return ua
        return None


# ── Convenience functions ─────────────────────────────────────────────


def parse_mythic_profile(content: str, name: str | None = None) -> C2Profile:
    """Parse a Mythic HTTPX profile JSON string into a C2Profile."""
    parser = MythicHTTPParser()
    profile = parser.parse(content)
    if name:
        profile.name = name
    return profile


def parse_mythic_file(path: str | Path, name: str | None = None) -> C2Profile:
    """Parse a Mythic HTTPX profile JSON file into a C2Profile."""
    content = Path(path).read_text(encoding="utf-8")
    return parse_mythic_profile(content, name)
