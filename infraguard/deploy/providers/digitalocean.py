"""DigitalOcean Terraform provider subclass."""

from __future__ import annotations

from pathlib import Path

from infraguard.deploy.providers.base import TerraformProvider


class DigitalOceanProvider(TerraformProvider):
    """Terraform provider targeting the DigitalOcean Droplet module."""

    def __init__(self, work_dir: Path) -> None:
        module_path = (
            Path(__file__).parent.parent.parent.parent
            / "deploy"
            / "terraform"
            / "modules"
            / "digitalocean"
        )
        super().__init__(module_path=module_path, work_dir=work_dir)
