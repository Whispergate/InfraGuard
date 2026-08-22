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

        # Fallback: generic paths/files/extensions for profiles that
        # don't use stage-specific keys (common in operator-generated
        # Sliver configs).
        generic_paths = implant.get("paths", [])
        generic_files = implant.get("files", [])
        generic_exts = implant.get("extensions", [])

        def _get_paths(stage_key: str) -> list[str]:
            return implant.get(stage_key) or generic_paths

        def _get_files(stage_key: str) -> list[str]:
            return implant.get(stage_key) or generic_files

        def _get_ext(stage_key: str, default: str) -> str | list[str]:
            val = implant.get(stage_key)
            if val:
                return val
            return generic_exts if generic_exts else default

        # Generate all valid URI combinations
        poll_uris = self._generate_uris(
            _get_paths("poll_paths"),
            _get_files("poll_files"),
            _get_ext("poll_file_ext", ".js"),
        )
        session_uris = self._generate_uris(
            _get_paths("session_paths"),
            _get_files("session_files"),
            _get_ext("session_file_ext", ".php"),
        )
        start_session_uris = self._generate_uris(
            _get_paths("session_paths"),
            _get_files("session_files"),
            _get_ext("start_session_file_ext", ".html"),
        )
        close_uris = self._generate_uris(
            _get_paths("close_paths"),
            _get_files("close_files"),
            _get_ext("close_file_ext", ".png"),
        )
        stager_uris = self._generate_uris(
            implant.get("stager_paths") or _get_paths("poll_paths"),
            implant.get("stager_files") or _get_files("poll_files"),
            _get_ext("stager_file_ext", ".woff"),
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
        ) if get_uris else None

        http_post = HttpTransaction(
            verb="POST",
            uris=post_uris[:100],
            client=ClientConfig(
                headers=req_headers,
                message=MessageConfig(location="body", name=""),
                transforms=[],
            ),
            server=server_config,
        ) if post_uris else None

        def _ext_str(val: str | list[str]) -> str:
            if isinstance(val, list):
                return ",".join(val)
            return val

        return C2Profile(
            name="Sliver HTTPS Profile",
            http_get=http_get,
            http_post=http_post,
            useragent=useragent,
            global_options={
                "stager_ext": _ext_str(_get_ext("stager_file_ext", ".woff")),
                "poll_ext": _ext_str(_get_ext("poll_file_ext", ".js")),
                "session_ext": _ext_str(_get_ext("session_file_ext", ".php")),
                "cookies": ",".join(cookies),
            },
        )

    @staticmethod
    def _generate_uris(
        paths: list[str], files: list[str], ext: str | list[str],
    ) -> list[str]:
        """Generate all valid /{path}/{file}{ext} combinations.

        ``ext`` may be a single extension string (stage-specific key) or
        a list of extensions (generic ``extensions`` array).  Extension
        values without a leading dot get one prepended unless they are
        empty (empty string = no extension).
        """
        if isinstance(ext, str):
            exts = [ext]
        else:
            exts = list(ext)

        normalised: list[str] = []
        for e in exts:
            if e and not e.startswith("."):
                e = "." + e
            normalised.append(e)

        uris: list[str] = []
        for p in paths:
            for f in files:
                for e in normalised:
                    uri = f"/{p}/{f}{e}"
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
