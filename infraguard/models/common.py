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


class ProfileType(str, Enum):
    COBALT_STRIKE = "cobalt_strike"
    MYTHIC = "mythic"
    BRUTE_RATEL = "brute_ratel"
    SLIVER = "sliver"


class ContentBackendType(str, Enum):
    PWNDROP = "pwndrop"
    FILESYSTEM = "filesystem"
    HTTP_PROXY = "http_proxy"


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

    @classmethod
    def allow(cls, filter_name: str = "", score: float = 0.0) -> FilterResult:
        return cls(action=FilterAction.ALLOW, score=score, filter_name=filter_name)

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
