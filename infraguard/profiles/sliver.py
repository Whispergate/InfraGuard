"""Sliver C2 HTTPS profile parser.

Parses Sliver HTTP C2 profile JSON files into the normalized C2Profile
model. Sliver profiles define URI generation rules rather than fixed URIs:
implants construct random URIs from path/file/extension combinations.

The parser generates all valid URI patterns so the profile filter can
match incoming beacon requests. Sliver uses different URI patterns for
different stages:
  - poll (long poll):      /{poll_paths}/{poll_files}{poll_file_ext}
  - session (data xfer):   /{session_paths}/{session_files}{session_file_ext}
  - start_session:         /{session_paths}/{session_files}{start_session_file_ext}
  - close:                 /{close_paths}/{close_files}{close_file_ext}
  - stager:                /{poll_paths}/{poll_files}{stager_file_ext}

Docs: https://sliver.sh/docs?name=HTTPS+C2
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


class SliverParser:
    """Parse Sliver HTTP C2 profile JSON into a normalized C2Profile."""

    def parse(self, content: str) -> C2Profile:
        data = json.loads(content)
        return self._parse_dict(data)

    def parse_file(self, path: str | Path) -> C2Profile:
        with open(path, encoding="utf-8") as f:
            return self.parse(f.read())

    def _parse_dict(self, data: dict[str, Any]) -> C2Profile:
        implant = data.get("implant_config", {})
        server = data.get("server_config", {})

        # Generate all valid URI combinations
        poll_uris = self._generate_uris(
            implant.get("poll_paths", []),
            implant.get("poll_files", []),
            implant.get("poll_file_ext", ".js"),
        )
        session_uris = self._generate_uris(
            implant.get("session_paths", []),
            implant.get("session_files", []),
            implant.get("session_file_ext", ".php"),
        )
        start_session_uris = self._generate_uris(
            implant.get("session_paths", []),
            implant.get("session_files", []),
            implant.get("start_session_file_ext", ".html"),
        )
        close_uris = self._generate_uris(
            implant.get("close_paths", []),
            implant.get("close_files", []),
            implant.get("close_file_ext", ".png"),
        )
        stager_uris = self._generate_uris(
            implant.get("poll_paths", []),
            implant.get("poll_files", []),
            implant.get("stager_file_ext", ".woff"),
        )

        # GET transaction: poll + close + stager URIs
        get_uris = list(set(poll_uris + close_uris + stager_uris))

        # POST transaction: session + start_session URIs
        post_uris = list(set(session_uris + start_session_uris))

        # Server response headers
        resp_headers: dict[str, str] = {}
        for h in server.get("headers", []):
            if h.get("probability", 100) >= 50:
                resp_headers[h["name"]] = h["value"]

        # Server cookies (used in response Set-Cookie headers)
        cookies = server.get("cookies", [])

        # User-Agent (Sliver can be empty = random)
        useragent = implant.get("user_agent") or None

        # Client request headers
        req_headers: dict[str, str] = {}
        for h in (implant.get("headers") or []):
            if isinstance(h, dict) and "name" in h:
                req_headers[h["name"]] = h.get("value", "")

        client = ClientConfig(
            headers=req_headers,
            message=MessageConfig(location="cookie", name=cookies[0] if cookies else "PHPSESSID"),
            transforms=[],
        )

        server_config = ServerConfig(
            headers=resp_headers,
            transforms=[],
        )

        http_get = HttpTransaction(
            verb="GET",
            uris=get_uris[:100],  # cap to prevent explosion
            client=client,
            server=server_config,
        )

        http_post = HttpTransaction(
            verb="POST",
            uris=post_uris[:100],
            client=ClientConfig(
                headers=req_headers,
                message=MessageConfig(location="body", name=""),
                transforms=[],
            ),
            server=server_config,
        )

        return C2Profile(
            name="Sliver HTTPS Profile",
            http_get=http_get,
            http_post=http_post,
            useragent=useragent,
            global_options={
                "stager_ext": implant.get("stager_file_ext", ".woff"),
                "poll_ext": implant.get("poll_file_ext", ".js"),
                "session_ext": implant.get("session_file_ext", ".php"),
                "cookies": ",".join(cookies),
            },
        )

    @staticmethod
    def _generate_uris(
        paths: list[str], files: list[str], ext: str,
    ) -> list[str]:
        """Generate all valid /{path}/{file}{ext} combinations."""
        uris: list[str] = []
        for p in paths:
            for f in files:
                uri = f"/{p}/{f}{ext}"
                uris.append(uri)
        return uris


# ── Convenience functions ─────────────────────────────────────────────


def parse_sliver_profile(
    content: str, name: str | None = None,
) -> C2Profile:
    """Parse a Sliver profile JSON string into a C2Profile."""
    parser = SliverParser()
    profile = parser.parse(content)
    if name:
        profile.name = name
    return profile


def parse_sliver_file(
    path: str | Path, name: str | None = None,
) -> C2Profile:
    """Parse a Sliver profile JSON file into a C2Profile."""
    content = Path(path).read_text(encoding="utf-8")
    return parse_sliver_profile(content, name)
