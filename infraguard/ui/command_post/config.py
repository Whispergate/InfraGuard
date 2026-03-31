"""Configuration for the multi-instance command post."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class InstanceConfig:
    name: str
    url: str
    token: str = ""


@dataclass
class CommandPostConfig:
    instances: list[InstanceConfig] = field(default_factory=list)
    bind: str = "0.0.0.0"
    port: int = 9090
    auth_token: str = ""

    @classmethod
    def from_yaml(cls, path: str | Path) -> CommandPostConfig:
        import os
        import re

        with open(path) as f:
            raw = yaml.safe_load(f) or {}

        # Resolve env vars
        def _resolve(obj):
            if isinstance(obj, str):
                return re.sub(
                    r"\$\{([^}]+)\}",
                    lambda m: os.environ.get(m.group(1), m.group(0)),
                    obj,
                )
            elif isinstance(obj, dict):
                return {k: _resolve(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [_resolve(i) for i in obj]
            return obj

        raw = _resolve(raw)

        instances = [
            InstanceConfig(
                name=inst.get("name", f"instance-{i}"),
                url=inst.get("url", ""),
                token=inst.get("token", ""),
            )
            for i, inst in enumerate(raw.get("instances", []))
        ]
        return cls(
            instances=instances,
            bind=raw.get("bind", "0.0.0.0"),
            port=raw.get("port", 9090),
            auth_token=raw.get("auth_token", ""),
        )

    @classmethod
    def from_cli_instances(cls, instance_strs: list[str]) -> CommandPostConfig:
        """Parse --instance 'name:url:token' CLI args."""
        instances = []
        for s in instance_strs:
            parts = s.split(":", 2)
            if len(parts) == 3:
                instances.append(InstanceConfig(name=parts[0], url=parts[1], token=parts[2]))
            elif len(parts) == 2:
                instances.append(InstanceConfig(name=parts[0], url=parts[1]))
            else:
                instances.append(InstanceConfig(name=s, url=s))
        return cls(instances=instances)
