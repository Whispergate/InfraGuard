"""Brute Ratel C4 (BRC4) profile parser.

Parses BRC4 server configuration JSON files into the normalized C2Profile
model. BRC4 profiles define listeners with HTTP URIs, headers, prepend/append
transforms, and User-Agent strings.

BRC4 profile structure (relevant fields):
  listeners.<name>.c2_uri         -- list of URI paths
  listeners.<name>.request_headers -- client request headers
  listeners.<name>.response_headers -- server response headers
  listeners.<name>.useragent      -- User-Agent string
  listeners.<name>.prepend        -- prepend string for request body
  listeners.<name>.append         -- append string for request body
  listeners.<name>.prepend_response -- prepend for response body
  listeners.<name>.append_response -- append for response body
  listeners.<name>.data_encoding  -- encoding type (e.g. "Base64")
  listeners.<name>.host           -- expected host
  listeners.<name>.port           -- listen port
  listeners.<name>.ssl            -- TLS enabled
  listeners.<name>.sleep          -- sleep interval
  listeners.<name>.jitter         -- jitter percentage
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


class BruteRatelParser:
    """Parse Brute Ratel C4 profile JSON into a normalized C2Profile."""

    def parse(self, content: str) -> C2Profile:
        data = json.loads(content)
        return self._parse_dict(data)

    def parse_file(self, path: str | Path) -> C2Profile:
        with open(path, encoding="utf-8") as f:
            return self.parse(f.read())

    def _parse_dict(self, data: dict[str, Any]) -> C2Profile:
        listeners = data.get("listeners", {})

        if not listeners:
            return C2Profile(name="Brute Ratel Profile")

        # Use the first listener as the primary C2 channel
        primary_name = next(iter(listeners))
        primary = listeners[primary_name]

        # Build the GET transaction from the primary listener
        http_get = self._parse_listener(primary, "GET")

        # If there's a fallback listener, use it as POST
        http_post = None
        fallback_name = primary.get("fallback")
        if fallback_name and fallback_name in listeners:
            http_post = self._parse_listener(listeners[fallback_name], "POST")

        # If no fallback, use the same listener for POST (BRC4 uses same URIs)
        if http_post is None:
            http_post = self._parse_listener(primary, "POST")

        useragent = primary.get("useragent")
        sleeptime = None
        jitter = None
        if "sleep" in primary:
            try:
                sleeptime = int(primary["sleep"]) * 1000  # BRC4 uses seconds
            except (ValueError, TypeError):
                pass
        if "jitter" in primary:
            try:
                jitter = int(primary["jitter"])
            except (ValueError, TypeError):
                pass

        return C2Profile(
            name=f"Brute Ratel - {primary_name}",
            http_get=http_get,
            http_post=http_post,
            useragent=useragent,
            sleeptime=sleeptime,
            jitter=jitter,
            global_options={
                "host": primary.get("host", ""),
                "port": str(primary.get("port", "")),
                "ssl": str(primary.get("ssl", False)),
                "data_encoding": primary.get("data_encoding", ""),
            },
        )

    def _parse_listener(
        self, listener: dict[str, Any], verb: str
    ) -> HttpTransaction:
        """Convert a BRC4 listener config to an HttpTransaction."""
        # URIs
        uris = listener.get("c2_uri", [])
        if isinstance(uris, str):
            uris = [uris]
        # Normalize: ensure leading /
        uris = [u if u.startswith("/") else f"/{u}" for u in uris]

        # Client headers
        req_headers = listener.get("request_headers", {})
        # Add Host header if present
        if listener.get("host"):
            req_headers["Host"] = listener["host"]

        # Client transforms
        client_transforms: list[Transform] = []
        encoding = listener.get("data_encoding", "").lower()
        if encoding == "base64":
            client_transforms.append(Transform(action="base64"))
        elif encoding == "base64url":
            client_transforms.append(Transform(action="base64url"))

        prepend = listener.get("prepend", "")
        if prepend:
            client_transforms.append(Transform(action="prepend", value=prepend))
        append = listener.get("append", "")
        if append:
            client_transforms.append(Transform(action="append", value=append))

        # Message location: BRC4 sends data in the body with prepend/append wrapping
        message = MessageConfig(location="body", name="")

        client = ClientConfig(
            headers=req_headers,
            message=message,
            transforms=client_transforms,
        )

        # Server headers + transforms
        resp_headers = listener.get("response_headers", {})
        server_transforms: list[Transform] = []

        if encoding == "base64":
            server_transforms.append(Transform(action="base64"))
        elif encoding == "base64url":
            server_transforms.append(Transform(action="base64url"))

        prepend_resp = listener.get("prepend_response", "")
        if prepend_resp:
            server_transforms.append(Transform(action="prepend", value=prepend_resp))
        append_resp = listener.get("append_response", "")
        if append_resp:
            server_transforms.append(Transform(action="append", value=append_resp))

        server = ServerConfig(
            headers=resp_headers,
            transforms=server_transforms,
        )

        return HttpTransaction(
            verb=verb,
            uris=uris,
            client=client,
            server=server,
        )


# ── Convenience functions ─────────────────────────────────────────────


def parse_brute_ratel_profile(
    content: str, name: str | None = None
) -> C2Profile:
    """Parse a BRC4 profile JSON string into a C2Profile."""
    parser = BruteRatelParser()
    profile = parser.parse(content)
    if name:
        profile.name = name
    return profile


def parse_brute_ratel_file(
    path: str | Path, name: str | None = None
) -> C2Profile:
    """Parse a BRC4 profile JSON file into a C2Profile."""
    content = Path(path).read_text(encoding="utf-8")
    return parse_brute_ratel_profile(content, name)
