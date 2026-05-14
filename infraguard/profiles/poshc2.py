"""PoshC2 profile parser.

Parses PoshC2 YAML configuration into the normalized C2Profile model.
PoshC2 YAML keys used:
  GET_Requests   -> list of GET URIs
  POST_Requests  -> list of POST URIs
  UserAgent      -> implant user-agent string
  DefaultSleep   -> beacon sleep (ms)
  KillDate       -> global_options
"""

from __future__ import annotations

from pathlib import Path

import yaml

from infraguard.profiles.models import (
    C2Profile,
    ClientConfig,
    HttpTransaction,
    MessageConfig,
    ServerConfig,
)

# PoshC2 always sends these headers from its implants
_DEFAULT_HEADERS: dict[str, str] = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}


class PoshC2Parser:
    """Parse PoshC2 YAML config into a normalized C2Profile."""

    def parse(self, content: str) -> C2Profile:
        data = yaml.safe_load(content) or {}
        return self._parse_dict(data)

    def parse_file(self, path: str | Path) -> C2Profile:
        content = Path(path).read_text(encoding="utf-8")
        return self.parse(content)

    def _parse_dict(self, data: dict) -> C2Profile:
        useragent = data.get("UserAgent") or data.get("user_agent")
        get_uris: list[str] = data.get("GET_Requests") or ["/index.asp"]
        post_uris: list[str] = data.get("POST_Requests") or ["/index.asp"]
        sleep_ms = data.get("DefaultSleep", 5000)

        # PoshC2 embeds implant data in POST body
        get_message = MessageConfig(location="cookie", name="PHPSESSID")
        post_message = MessageConfig(location="body", name="")

        http_get = HttpTransaction(
            verb="GET",
            uris=get_uris,
            client=ClientConfig(headers=dict(_DEFAULT_HEADERS), message=get_message),
            server=ServerConfig(),
        )
        http_post = HttpTransaction(
            verb="POST",
            uris=post_uris,
            client=ClientConfig(headers=dict(_DEFAULT_HEADERS), message=post_message),
            server=ServerConfig(),
        )

        global_options: dict[str, str] = {}
        if data.get("PayloadCommsHost"):
            global_options["comms_host"] = str(data["PayloadCommsHost"])
        if data.get("KillDate"):
            global_options["kill_date"] = str(data["KillDate"])

        return C2Profile(
            name="PoshC2",
            http_get=http_get,
            http_post=http_post,
            useragent=useragent,
            sleeptime=sleep_ms,
            global_options=global_options,
        )


def parse_poshc2_file(path: str | Path) -> C2Profile:
    return PoshC2Parser().parse_file(path)
