"""Hetzner Cloud Terraform provider subclass."""

from __future__ import annotations

from pathlib import Path

from infraguard.deploy.providers.base import TerraformProvider


class HetznerProvider(TerraformProvider):
    """Terraform provider targeting the Hetzner Cloud server module."""

    def __init__(self, work_dir: Path) -> None:
        module_path = (
            Path(__file__).parent.parent
            / "terraform"
            / "modules"
            / "hetzner"
        )
        super().__init__(module_path=module_path, work_dir=work_dir)
