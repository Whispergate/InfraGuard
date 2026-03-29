"""Normalized C2 profile data models.

These models represent a unified view of C2 profiles regardless of source
(Cobalt Strike malleable profiles, Mythic HTTPX profiles, etc.). The proxy
engine and filter pipeline operate exclusively on these normalized models.

Adapted from the Tyche project (github.com/Whispergate/Tyche).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Literal


@dataclass
class Transform:
    """A single data transform operation in a transform chain."""

    action: str  # base64, base64url, mask, netbios, netbiosu, prepend, append, strrep
    value: str = ""

    def to_dict(self) -> dict[str, str]:
        return {"action": self.action, "value": self.value}

    @classmethod
    def from_dict(cls, data: dict[str, str]) -> Transform:
        return cls(action=data["action"], value=data.get("value", ""))


@dataclass
class MessageConfig:
    """Where the beacon metadata/id/output is placed in the HTTP request."""

    location: str  # cookie, header, parameter, body, uri-append
    name: str = ""

    def to_dict(self) -> dict[str, str]:
        return {"location": self.location, "name": self.name}

    @classmethod
    def from_dict(cls, data: dict[str, str]) -> MessageConfig:
        return cls(location=data["location"], name=data.get("name", ""))


@dataclass
class ClientConfig:
    """Client-side (beacon -> redirector) HTTP configuration."""

    headers: dict[str, str] = field(default_factory=dict)
    parameters: dict[str, str] | None = None
    message: MessageConfig | None = None
    transforms: list[Transform] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"headers": self.headers}
        result["parameters"] = self.parameters
        if self.message:
            result["message"] = self.message.to_dict()
        else:
            result["message"] = {"location": "cookie", "name": "__session"}
        if self.transforms:
            result["transforms"] = [t.to_dict() for t in self.transforms]
        else:
            result["transforms"] = [{"action": "base64url", "value": ""}]
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ClientConfig:
        message = None
        if data.get("message"):
            message = MessageConfig.from_dict(data["message"])
        transforms = [Transform.from_dict(t) for t in data.get("transforms") or []]
        return cls(
            headers=data.get("headers", {}),
            parameters=data.get("parameters"),
            message=message,
            transforms=transforms,
        )


@dataclass
class ServerConfig:
    """Server-side (teamserver -> redirector -> beacon) HTTP configuration."""

    headers: dict[str, str] = field(default_factory=dict)
    transforms: list[Transform] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"headers": self.headers}
        if self.transforms:
            result["transforms"] = [t.to_dict() for t in self.transforms]
        else:
            result["transforms"] = [{"action": "base64url", "value": ""}]
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ServerConfig:
        transforms = [Transform.from_dict(t) for t in data.get("transforms") or []]
        return cls(headers=data.get("headers", {}), transforms=transforms)


@dataclass
class HttpTransaction:
    """A single HTTP transaction (GET or POST) from the C2 profile."""

    verb: str
    uris: list[str]
    client: ClientConfig
    server: ServerConfig

    def to_dict(self) -> dict[str, Any]:
        return {
            "verb": self.verb,
            "uris": self.uris,
            "client": self.client.to_dict(),
            "server": self.server.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> HttpTransaction:
        return cls(
            verb=data["verb"],
            uris=data["uris"],
            client=ClientConfig.from_dict(data["client"]),
            server=ServerConfig.from_dict(data["server"]),
        )


@dataclass
class C2Profile:
    """Normalized C2 profile - the unified representation used by InfraGuard.

    Both Cobalt Strike malleable profiles and Mythic HTTPX profiles are
    parsed into this structure. The proxy engine validates incoming requests
    against the ``http_get`` and ``http_post`` transactions.
    """

    name: str
    http_get: HttpTransaction | None = None
    http_post: HttpTransaction | None = None
    http_stager: HttpTransaction | None = None
    useragent: str | None = None
    sleeptime: int | None = None
    jitter: int | None = None

    # Raw global options preserved from the original profile
    global_options: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"name": self.name}
        if self.http_get:
            result["get"] = self.http_get.to_dict()
        if self.http_post:
            result["post"] = self.http_post.to_dict()
        if self.http_stager:
            result["stager"] = self.http_stager.to_dict()
        if self.useragent:
            result["useragent"] = self.useragent
        if self.sleeptime is not None:
            result["sleeptime"] = self.sleeptime
        if self.jitter is not None:
            result["jitter"] = self.jitter
        if self.global_options:
            result["global_options"] = self.global_options
        return result

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> C2Profile:
        http_get = HttpTransaction.from_dict(data["get"]) if "get" in data else None
        http_post = HttpTransaction.from_dict(data["post"]) if "post" in data else None
        http_stager = (
            HttpTransaction.from_dict(data["stager"]) if "stager" in data else None
        )
        return cls(
            name=data.get("name", "Unknown"),
            http_get=http_get,
            http_post=http_post,
            http_stager=http_stager,
            useragent=data.get("useragent"),
            sleeptime=data.get("sleeptime"),
            jitter=data.get("jitter"),
            global_options=data.get("global_options", {}),
        )

    @classmethod
    def from_json(cls, json_str: str) -> C2Profile:
        return cls.from_dict(json.loads(json_str))

    def all_uris(self) -> list[str]:
        """Return all URIs from all transactions."""
        uris: list[str] = []
        for txn in (self.http_get, self.http_post, self.http_stager):
            if txn:
                uris.extend(txn.uris)
        return uris

    def expected_headers(self, verb: str) -> dict[str, str]:
        """Return expected client headers for a given HTTP verb."""
        txn = self.http_get if verb.upper() == "GET" else self.http_post
        if txn:
            return txn.client.headers
        return {}
