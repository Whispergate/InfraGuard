"""Shared C2 profile type auto-detection.

Extracted from ``infraguard.main._load_profile_file`` so that both the
CLI command and the config generator share the same detection logic.
"""

from __future__ import annotations

import json
from pathlib import Path

from infraguard.models.common import ProfileType


def detect_profile_type(profile_path: Path) -> ProfileType:
    """Detect C2 profile type from file extension (and content for JSON/YAML).

    Extension rules:
    - ``.profile``  -> COBALT_STRIKE
    - ``.toml``     -> HAVOC
    - ``.yml`` / ``.yaml`` -> inspect keys: POSHC2 (or raises ValueError)
    - ``.json``     -> inspect keys: BRUTE_RATEL / SLIVER / NIGHTHAWK / MYTHIC
    - anything else -> raises ValueError

    For JSON detection the file is read only if it exists locally.  When
    ``profile_path`` points to a container-relative location (e.g.
    ``/config/profiles/foo.json``) and the file is not present on disk,
    the function falls back to MYTHIC (safest default for JSON payloads).
    """
    suffix = profile_path.suffix.lower()

    if suffix == ".profile":
        return ProfileType.COBALT_STRIKE

    if suffix == ".toml":
        return ProfileType.HAVOC

    if suffix in (".yml", ".yaml"):
        if profile_path.exists():
            try:
                import yaml

                data = yaml.safe_load(profile_path.read_text(encoding="utf-8"))
                if isinstance(data, dict) and (
                    "GET_Requests" in data or "POST_Requests" in data
                ):
                    return ProfileType.POSHC2
            except Exception:
                pass
        raise ValueError(
            f"Cannot auto-detect YAML profile type for '{profile_path.name}'. "
            "Use --profile-type to specify."
        )

    if suffix == ".json":
        if profile_path.exists():
            try:
                data = json.loads(profile_path.read_text(encoding="utf-8"))
                if "listeners" in data and "c2_handler" in data:
                    return ProfileType.BRUTE_RATEL
                if "implant_config" in data and "server_config" in data:
                    return ProfileType.SLIVER
                # Nighthawk: listener.http.routes + implant
                if "listener" in data and "implant" in data:
                    listener = data.get("listener", {})
                    if isinstance(listener, dict) and "http" in listener:
                        return ProfileType.NIGHTHAWK
                if "instances" in data and isinstance(data["instances"], list):
                    return ProfileType.MYTHIC_HTTP
            except Exception:
                pass
        # Default for JSON when file is absent or unrecognised shape
        return ProfileType.MYTHIC

    raise ValueError(
        f"Cannot auto-detect profile type for '{profile_path.suffix}'. "
        "Use --profile-type to specify."
    )
