"""Plugin packaging utilities for InfraGuard.

Builds and validates plugin manifests, and packages plugin directories
into distributable archives.

A plugin package is a directory or archive containing:

- ``plugin.py`` (or a package with ``__init__.py``)
- ``manifest.json`` describing the plugin
- Optional ``requirements.txt``

Usage::

    from infraguard.plugins.sdk.packaging import build_manifest, package_plugin

    manifest = build_manifest(
        name="my_webhook",
        version="1.0.0",
        description="Custom webhook forwarder",
        author="Red Team Ops",
    )
    manifest.save("./my_plugin/manifest.json")
    package_plugin("./my_plugin", "./dist/my_plugin-1.0.0.zip")
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from infraguard.plugins.sdk.types import PluginCapability, PluginMetadata, validate_plugin

# Valid plugin name pattern (matches loader convention)
_VALID_NAME = re.compile(r"^[a-z_][a-z0-9_]*$")

# Manifest schema version
MANIFEST_VERSION = 1


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------

@dataclass
class PluginManifest:
    """Serializable plugin manifest (``manifest.json``)."""

    name: str
    version: str
    description: str = ""
    author: str = ""
    license: str = ""
    homepage: str = ""
    capabilities: list[str] = field(default_factory=list)
    requires_config: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)
    entry_point: str = "plugin"
    """Module attribute that holds the plugin instance or Plugin class."""
    min_infraguard_version: str = ""
    manifest_version: int = MANIFEST_VERSION

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def save(self, path: str | Path) -> Path:
        """Write the manifest to a JSON file."""
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(self.to_json() + "\n", encoding="utf-8")
        return p

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PluginManifest:
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})

    @classmethod
    def from_json(cls, text: str) -> PluginManifest:
        return cls.from_dict(json.loads(text))

    @classmethod
    def load(cls, path: str | Path) -> PluginManifest:
        return cls.from_json(Path(path).read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Manifest builders and validators
# ---------------------------------------------------------------------------

def build_manifest(
    name: str,
    version: str,
    description: str = "",
    author: str = "",
    license: str = "",
    homepage: str = "",
    capabilities: list[str] | None = None,
    requires_config: list[str] | None = None,
    dependencies: list[str] | None = None,
    entry_point: str = "plugin",
    min_infraguard_version: str = "",
) -> PluginManifest:
    """Create a PluginManifest with validation."""
    errors: list[str] = []

    if not _VALID_NAME.match(name):
        errors.append(
            f"Invalid plugin name '{name}': must match {_VALID_NAME.pattern}"
        )
    if not version:
        errors.append("Version must not be empty")

    if errors:
        raise ValueError("Invalid manifest: " + "; ".join(errors))

    return PluginManifest(
        name=name,
        version=version,
        description=description,
        author=author,
        license=license,
        homepage=homepage,
        capabilities=capabilities or [],
        requires_config=requires_config or [],
        dependencies=dependencies or [],
        entry_point=entry_point,
        min_infraguard_version=min_infraguard_version,
    )


def validate_manifest(manifest: PluginManifest) -> list[str]:
    """Validate a PluginManifest, returning a list of error strings."""
    errors: list[str] = []

    if not manifest.name:
        errors.append("Missing 'name'")
    elif not _VALID_NAME.match(manifest.name):
        errors.append(f"Invalid plugin name '{manifest.name}'")

    if not manifest.version:
        errors.append("Missing 'version'")

    if manifest.manifest_version > MANIFEST_VERSION:
        errors.append(
            f"Manifest version {manifest.manifest_version} is newer than "
            f"supported version {MANIFEST_VERSION}"
        )

    valid_caps = {c.value for c in PluginCapability}
    for cap in manifest.capabilities:
        if cap not in valid_caps:
            errors.append(f"Unknown capability: '{cap}'")

    return errors


# ---------------------------------------------------------------------------
# Packaging
# ---------------------------------------------------------------------------

def package_plugin(
    plugin_dir: str | Path,
    output_path: str | Path | None = None,
    include_patterns: list[str] | None = None,
) -> Path:
    """Package a plugin directory into a distributable ZIP archive.

    Parameters
    ----------
    plugin_dir:
        Directory containing the plugin source and ``manifest.json``.
    output_path:
        Where to write the archive.  Defaults to
        ``<plugin_dir>/<name>-<version>.zip``.
    include_patterns:
        Additional glob patterns to include beyond the defaults
        (``*.py``, ``manifest.json``, ``requirements.txt``, ``README*``).

    Returns
    -------
    Path to the created archive.
    """
    plugin_dir = Path(plugin_dir).resolve()

    if not plugin_dir.is_dir():
        raise FileNotFoundError(f"Plugin directory not found: {plugin_dir}")

    manifest_path = plugin_dir / "manifest.json"
    if not manifest_path.exists():
        raise FileNotFoundError(f"No manifest.json in {plugin_dir}")

    manifest = PluginManifest.load(manifest_path)
    errors = validate_manifest(manifest)
    if errors:
        raise ValueError(f"Invalid manifest: {'; '.join(errors)}")

    if output_path is None:
        output_path = plugin_dir / f"{manifest.name}-{manifest.version}.zip"
    output_path = Path(output_path)

    default_patterns = {"*.py", "manifest.json", "requirements.txt", "README*"}
    patterns = default_patterns | set(include_patterns or [])

    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for pattern in patterns:
            for fpath in sorted(plugin_dir.rglob(pattern)):
                if fpath.is_file() and fpath.suffix != ".zip":
                    arcname = str(fpath.relative_to(plugin_dir))
                    zf.write(fpath, arcname)

    return output_path


def unpack_plugin(
    archive_path: str | Path,
    dest_dir: str | Path,
) -> Path:
    """Extract a plugin archive to *dest_dir*.

    Returns the path to the extracted plugin directory.
    """
    archive_path = Path(archive_path)
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(archive_path, "r") as zf:
        zf.extractall(dest_dir)

    return dest_dir


def compute_checksum(path: str | Path, algorithm: str = "sha256") -> str:
    """Compute the hex digest of a file."""
    h = hashlib.new(algorithm)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Scaffolding
# ---------------------------------------------------------------------------

_PLUGIN_TEMPLATE = '''"""{description}"""

from __future__ import annotations

from infraguard.models.common import FilterResult
from infraguard.models.events import RequestEvent
from infraguard.pipeline.base import RequestContext
from infraguard.plugins.base import BasePlugin


class Plugin(BasePlugin):
    name = "{name}"
    version = "{version}"

    def configure(self, settings):
        super().configure(settings)

    async def on_request(self, ctx: RequestContext) -> FilterResult | None:
        # TODO: implement request filtering
        return None

    async def on_response(self, ctx: RequestContext, response) -> Response | None:
        # TODO: implement response filtering
        return None

    async def on_event(self, event: RequestEvent) -> None:
        # TODO: implement event handling
        pass

    async def on_startup(self) -> None:
        pass

    async def on_shutdown(self) -> None:
        pass


# Module-level instance (loader looks for "plugin" or "Plugin")
plugin = Plugin()
'''

_MANIFEST_TEMPLATE = """{{
  "name": "{name}",
  "version": "{version}",
  "description": "{description}",
  "author": "{author}",
  "capabilities": [],
  "requires_config": [],
  "dependencies": [],
  "entry_point": "plugin",
  "min_infraguard_version": "",
  "manifest_version": 1
}}
"""


def scaffold_plugin(
    name: str,
    dest_dir: str | Path,
    version: str = "0.1.0",
    description: str = "",
    author: str = "",
) -> Path:
    """Create a new plugin project scaffold in *dest_dir*.

    Creates the directory structure, a template plugin file, and a
    manifest.  Returns the path to the created directory.
    """
    if not _VALID_NAME.match(name):
        raise ValueError(f"Invalid plugin name '{name}'")

    dest = Path(dest_dir) / name
    dest.mkdir(parents=True, exist_ok=True)

    # Plugin module
    plugin_py = dest / "plugin.py"
    plugin_py.write_text(
        _PLUGIN_TEMPLATE.format(
            name=name,
            version=version,
            description=description or f"{name} plugin",
        ),
        encoding="utf-8",
    )

    # Manifest
    manifest_json = dest / "manifest.json"
    manifest_json.write_text(
        _MANIFEST_TEMPLATE.format(
            name=name,
            version=version,
            description=description or f"{name} plugin",
            author=author,
        ),
        encoding="utf-8",
    )

    # Requirements placeholder
    req_txt = dest / "requirements.txt"
    req_txt.write_text("# Plugin dependencies\n", encoding="utf-8")

    return dest
