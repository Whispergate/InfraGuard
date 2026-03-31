"""Cloudflare Workers Terraform provider subclass.

Deploys a dumb HTTP relay Worker that forwards traffic to a backend VPS
running the full InfraGuard stack.  The Worker has no filtering, scoring,
or persistence — it adds a CDN/edge layer for infrastructure obfuscation.
"""

from __future__ import annotations

from pathlib import Path

from infraguard.deploy.providers.base import TerraformProvider


class CloudflareProvider(TerraformProvider):
    """Terraform provider targeting the Cloudflare Workers relay module."""

    def __init__(self, work_dir: Path) -> None:
        module_path = (
            Path(__file__).parent.parent.parent.parent
            / "deploy"
            / "terraform"
            / "modules"
            / "cloudflare"
        )
        super().__init__(module_path=module_path, work_dir=work_dir)
