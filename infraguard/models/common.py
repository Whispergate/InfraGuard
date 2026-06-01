"""Shared types and enums used across InfraGuard modules."""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel


class DropActionType(str, Enum):
    REDIRECT = "redirect"
    RESET = "reset"
    PROXY = "proxy"
    TARPIT = "tarpit"
    DECOY = "decoy"


class ProfileType(str, Enum):
    COBALT_STRIKE = "cobalt_strike"
    MYTHIC = "mythic"
    MYTHIC_HTTP = "mythic_http"
    BRUTE_RATEL = "brute_ratel"
    SLIVER = "sliver"
    HAVOC = "havoc"
    NIGHTHAWK = "nighthawk"
    POSHC2 = "poshc2"
    GOPHISH = "gophish"
    EVILGINX = "evilginx"
    CUDDLEPHISH = "cuddlephish"
    PHISHING_CLUB = "phishing_club"
    PASSTHROUGH = "passthrough"
    # Pivot / tunnel tooling - opaque byte streams, no profile validation
    LIGOLO = "ligolo"
    LIGOLO_MP = "ligolo_mp"
    CHISEL = "chisel"


# Profile types that represent phishing frameworks (no C2 profile file needed)
PHISHING_PROFILE_TYPES = frozenset({
    ProfileType.GOPHISH,
    ProfileType.EVILGINX,
    ProfileType.CUDDLEPHISH,
    ProfileType.PHISHING_CLUB,
    ProfileType.PASSTHROUGH,
})


# Profile types for pivot/tunnel tools - opaque streams, no C2 profile file
TUNNEL_PROFILE_TYPES = frozenset({
    ProfileType.LIGOLO,
    ProfileType.LIGOLO_MP,
    ProfileType.CHISEL,
})


class ContentBackendType(str, Enum):
    PWNDROP = "pwndrop"
    FILESYSTEM = "filesystem"
    HTTP_PROXY = "http_proxy"
    MYTHIC_FILE = "mythic_file"


class FilterAction(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    SUSPECT = "suspect"


class FilterResult(BaseModel):
    """Result returned by each filter in the pipeline."""

    action: FilterAction
    score: float = 0.0
    reason: str | None = None
    filter_name: str = ""
    terminal: bool = False  # When True + ALLOW, pipeline stops immediately (e.g. explicit whitelist)

    @classmethod
    def allow(cls, filter_name: str = "", score: float = 0.0) -> FilterResult:
        return cls(action=FilterAction.ALLOW, score=score, filter_name=filter_name)

    @classmethod
    def allow_terminal(cls, filter_name: str = "") -> FilterResult:
        return cls(action=FilterAction.ALLOW, score=0.0, filter_name=filter_name, terminal=True)

    @classmethod
    def block(
        cls, reason: str, filter_name: str = "", score: float = 1.0
    ) -> FilterResult:
        return cls(
            action=FilterAction.BLOCK,
            score=score,
            reason=reason,
            filter_name=filter_name,
        )

    @classmethod
    def suspect(
        cls, reason: str, filter_name: str = "", score: float = 0.5
    ) -> FilterResult:
        return cls(
            action=FilterAction.SUSPECT,
            score=score,
            reason=reason,
            filter_name=filter_name,
        )
