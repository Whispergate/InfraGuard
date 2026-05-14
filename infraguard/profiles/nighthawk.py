"""Nighthawk C2 profile parser (MDSec).

Parses Nighthawk JSON configuration into the normalized C2Profile model.
Nighthawk config structure:
  listener.http.routes[]  -> [{method, uri, headers}]
  implant.metadata        -> {location, name}
  implant.user_agent      -> str
"""

from __future__ import annotations

import json
from pathlib import Path

from infraguard.profiles.models import (
    C2Profile,
    ClientConfig,
    HttpTransaction,
    MessageConfig,
    ServerConfig,
)


class NighthawkParser:
    """Parse Nighthawk JSON config into a normalized C2Profile."""

    def parse(self, content: str) -> C2Profile:
        data = json.loads(content)
        return self._parse_dict(data)

    def parse_file(self, path: str | Path) -> C2Profile:
        content = Path(path).read_text(encoding="utf-8")
        return self.parse(content)

    def _parse_dict(self, data: dict) -> C2Profile:
        listener = data.get("listener", {})
        http_cfg = listener.get("http", {})
        routes = http_cfg.get("routes", [])

        get_uris: list[str] = []
        post_uris: list[str] = []
        client_headers: dict[str, str] = {}

        for route in routes:
            method = route.get("method", "GET").upper()
            uri = route.get("uri", "/")
            hdrs = route.get("headers", {})
            if isinstance(hdrs, dict):
                client_headers.update(hdrs)
            if method == "GET":
                get_uris.append(uri)
            else:
                post_uris.append(uri)

        # Fall back to a sensible default so the profile is never empty
        if not get_uris:
            get_uris = ["/"]

        implant = data.get("implant", {})
        meta = implant.get("metadata", {})
        message = MessageConfig(
            location=meta.get("location", "header"),
            name=meta.get("name", "X-Session-ID"),
        )
        useragent = implant.get("user_agent") or implant.get("userAgent")

        client = ClientConfig(headers=client_headers, message=message)
        server = ServerConfig()

        http_get = HttpTransaction(
            verb="GET", uris=get_uris, client=client, server=server,
        )
        http_post = HttpTransaction(
            verb="POST",
            uris=post_uris or get_uris,
            client=ClientConfig(headers=client_headers, message=message),
            server=ServerConfig(),
        )

        return C2Profile(
            name="Nighthawk",
            http_get=http_get,
            http_post=http_post,
            useragent=useragent,
        )


def parse_nighthawk_file(path: str | Path) -> C2Profile:
    return NighthawkParser().parse_file(path)
