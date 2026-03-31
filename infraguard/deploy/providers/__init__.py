"""Terraform provider subclasses and factory function.

Usage:
    from infraguard.deploy.providers import get_provider

    provider = get_provider("aws", work_dir=Path(".infraguard-deploy"))
    outputs = provider.apply(tfvars)
"""

from __future__ import annotations

from pathlib import Path

from infraguard.deploy.providers.aws import AWSProvider
from infraguard.deploy.providers.azure import AzureProvider
from infraguard.deploy.providers.cloudflare import CloudflareProvider
from infraguard.deploy.providers.digitalocean import DigitalOceanProvider
from infraguard.deploy.providers.base import TerraformProvider, TerraformError

__all__ = [
    "AWSProvider",
    "AzureProvider",
    "CloudflareProvider",
    "DigitalOceanProvider",
    "TerraformProvider",
    "TerraformError",
    "get_provider",
]

_PROVIDER_MAP: dict[str, type[TerraformProvider]] = {
    "aws": AWSProvider,
    "azure": AzureProvider,
    "cloudflare": CloudflareProvider,
    "cf": CloudflareProvider,
    "do": DigitalOceanProvider,
    "digitalocean": DigitalOceanProvider,
}


def get_provider(name: str, work_dir: Path) -> TerraformProvider:
    """Factory: return the correct TerraformProvider subclass for *name*.

    Args:
        name: Provider identifier - one of ``"aws"``, ``"azure"``, ``"do"``, ``"cloudflare"``.
        work_dir: Working directory where Terraform state files will be stored.

    Returns:
        An initialised :class:`TerraformProvider` subclass.

    Raises:
        ValueError: If *name* is not a known provider.
    """
    key = name.lower()
    cls = _PROVIDER_MAP.get(key)
    if cls is None:
        raise ValueError(
            f"Unknown provider '{name}'. "
            f"Supported providers: {', '.join(sorted(set(_PROVIDER_MAP.keys())))}"
        )
    return cls(work_dir=work_dir)
