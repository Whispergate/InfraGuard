"""
Smoke tests validating Terraform module file structure.

These tests verify that each provider module contains the expected files and
exposes the shared variable/output interface required by the InfraGuard CLI.
They do NOT execute Terraform - they validate HCL source file contents only.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

# ── Constants ──────────────────────────────────────────────────────────────────

REPO_ROOT = Path(__file__).parent.parent
TF_MODULES_DIR = REPO_ROOT / "deploy" / "terraform" / "modules"
TF_ROOT = REPO_ROOT / "deploy" / "terraform"

# Shared interface variables all provider modules must declare
REQUIRED_VARIABLES = [
    "domain",
    "ssh_public_key",
    "operator_ip",
    "instance_size",
    "region",
    "docker_image",
]

# Shared interface outputs all provider modules must declare
REQUIRED_OUTPUTS = [
    "instance_ip",
    "instance_id",
    "ssh_command",
]

PROVIDERS = ["aws", "azure", "digitalocean"]

# ── Helpers ────────────────────────────────────────────────────────────────────


def _module_dir(provider: str) -> Path:
    return TF_MODULES_DIR / provider


def _read(provider: str, filename: str) -> str:
    path = _module_dir(provider) / filename
    assert path.exists(), f"Missing file: {path}"
    return path.read_text()


# ── .gitignore tests ───────────────────────────────────────────────────────────


class TestGitignore:
    """deploy/terraform/.gitignore must exclude state and secret files."""

    def test_gitignore_exists(self) -> None:
        assert (TF_ROOT / ".gitignore").exists(), (
            "deploy/terraform/.gitignore is missing - state files could be committed"
        )

    def test_gitignore_excludes_tfstate(self) -> None:
        content = (TF_ROOT / ".gitignore").read_text()
        assert "*.tfstate" in content, ".gitignore must exclude *.tfstate"

    def test_gitignore_excludes_terraform_dir(self) -> None:
        content = (TF_ROOT / ".gitignore").read_text()
        assert ".terraform/" in content, ".gitignore must exclude .terraform/ directory"

    def test_gitignore_excludes_tfvars_json(self) -> None:
        content = (TF_ROOT / ".gitignore").read_text()
        assert "*.tfvars.json" in content, ".gitignore must exclude *.tfvars.json"


# ── Module file structure tests ────────────────────────────────────────────────


@pytest.mark.parametrize("provider", PROVIDERS)
class TestModuleFileStructure:
    """Each provider module must contain the three required HCL files."""

    def test_main_tf_exists(self, provider: str) -> None:
        assert (_module_dir(provider) / "main.tf").exists(), (
            f"deploy/terraform/modules/{provider}/main.tf is missing"
        )

    def test_variables_tf_exists(self, provider: str) -> None:
        assert (_module_dir(provider) / "variables.tf").exists(), (
            f"deploy/terraform/modules/{provider}/variables.tf is missing"
        )

    def test_outputs_tf_exists(self, provider: str) -> None:
        assert (_module_dir(provider) / "outputs.tf").exists(), (
            f"deploy/terraform/modules/{provider}/outputs.tf is missing"
        )


# ── Shared variable interface tests ───────────────────────────────────────────


@pytest.mark.parametrize("provider", PROVIDERS)
@pytest.mark.parametrize("var_name", REQUIRED_VARIABLES)
def test_variable_declared(provider: str, var_name: str) -> None:
    """All 6 shared interface variables must be declared in each provider's variables.tf."""
    content = _read(provider, "variables.tf")
    pattern = rf'variable\s+"{re.escape(var_name)}"'
    assert re.search(pattern, content), (
        f"deploy/terraform/modules/{provider}/variables.tf missing: variable \"{var_name}\""
    )


# ── Shared output interface tests ─────────────────────────────────────────────


@pytest.mark.parametrize("provider", PROVIDERS)
@pytest.mark.parametrize("output_name", REQUIRED_OUTPUTS)
def test_output_declared(provider: str, output_name: str) -> None:
    """All 3 shared interface outputs must be declared in each provider's outputs.tf."""
    content = _read(provider, "outputs.tf")
    pattern = rf'output\s+"{re.escape(output_name)}"'
    assert re.search(pattern, content), (
        f"deploy/terraform/modules/{provider}/outputs.tf missing: output \"{output_name}\""
    )


# ── Provider-specific resource tests ─────────────────────────────────────────


class TestAwsModuleResources:
    """AWS-specific resources that must be present in aws/main.tf."""

    def test_aws_security_group(self) -> None:
        content = _read("aws", "main.tf")
        assert "aws_security_group" in content, (
            "aws/main.tf must declare an aws_security_group resource"
        )

    def test_aws_instance(self) -> None:
        content = _read("aws", "main.tf")
        assert "aws_instance" in content, (
            "aws/main.tf must declare an aws_instance resource"
        )

    def test_aws_key_pair(self) -> None:
        content = _read("aws", "main.tf")
        assert "aws_key_pair" in content, (
            "aws/main.tf must declare an aws_key_pair resource"
        )

    def test_aws_ami_data_source(self) -> None:
        content = _read("aws", "main.tf")
        assert "data" in content and "aws_ami" in content, (
            "aws/main.tf must use an aws_ami data source for AMI lookup"
        )

    def test_aws_ssh_restricted_to_operator(self) -> None:
        content = _read("aws", "main.tf")
        # SSH rule must reference operator_ip, not hardcode 0.0.0.0/0
        assert "var.operator_ip" in content, (
            "aws/main.tf SSH ingress must use var.operator_ip, not 0.0.0.0/0"
        )

    def test_aws_user_data_installs_docker(self) -> None:
        content = _read("aws", "main.tf")
        assert "docker" in content.lower(), (
            "aws/main.tf user_data must install Docker"
        )


class TestAzureModuleResources:
    """Azure-specific resources that must be present in azure/main.tf."""

    def test_azure_linux_vm(self) -> None:
        content = _read("azure", "main.tf")
        assert "azurerm_linux_virtual_machine" in content, (
            "azure/main.tf must declare an azurerm_linux_virtual_machine resource"
        )

    def test_azure_nsg(self) -> None:
        content = _read("azure", "main.tf")
        assert "azurerm_network_security_group" in content, (
            "azure/main.tf must declare an azurerm_network_security_group resource"
        )

    def test_azure_resource_group(self) -> None:
        content = _read("azure", "main.tf")
        assert "azurerm_resource_group" in content, (
            "azure/main.tf must declare an azurerm_resource_group resource"
        )

    def test_azure_public_ip(self) -> None:
        content = _read("azure", "main.tf")
        assert "azurerm_public_ip" in content, (
            "azure/main.tf must declare an azurerm_public_ip resource"
        )

    def test_azure_ssh_restricted_to_operator(self) -> None:
        content = _read("azure", "main.tf")
        assert "var.operator_ip" in content, (
            "azure/main.tf SSH NSG rule must use var.operator_ip"
        )


class TestDigitalOceanModuleResources:
    """DigitalOcean-specific resources that must be present in digitalocean/main.tf."""

    def test_do_droplet(self) -> None:
        content = _read("digitalocean", "main.tf")
        assert "digitalocean_droplet" in content, (
            "digitalocean/main.tf must declare a digitalocean_droplet resource"
        )

    def test_do_firewall(self) -> None:
        content = _read("digitalocean", "main.tf")
        assert "digitalocean_firewall" in content, (
            "digitalocean/main.tf must declare a digitalocean_firewall resource"
        )

    def test_do_tag(self) -> None:
        content = _read("digitalocean", "main.tf")
        assert "digitalocean_tag" in content, (
            "digitalocean/main.tf must declare a digitalocean_tag resource (for zero-exposure-window firewall attachment)"
        )

    def test_do_ssh_key(self) -> None:
        content = _read("digitalocean", "main.tf")
        assert "digitalocean_ssh_key" in content, (
            "digitalocean/main.tf must declare a digitalocean_ssh_key resource"
        )

    def test_do_firewall_uses_operator_ip(self) -> None:
        content = _read("digitalocean", "main.tf")
        assert "var.operator_ip" in content, (
            "digitalocean/main.tf firewall SSH rule must use var.operator_ip"
        )

    def test_do_droplet_uses_tag_for_firewall(self) -> None:
        """Droplet must reference the tag so the firewall attaches at creation time.

        This avoids the exposure window described in RESEARCH.md Pitfall 2.
        """
        content = _read("digitalocean", "main.tf")
        assert "digitalocean_tag" in content, (
            "digitalocean/main.tf must use a tag on the Droplet so the firewall attaches at creation"
        )


# ── Cloudflare Workers relay module tests ──────────────────────────────────


class TestCloudflareModuleStructure:
    """Cloudflare Workers module must contain expected HCL files."""

    def test_main_tf_exists(self) -> None:
        assert (_module_dir("cloudflare") / "main.tf").exists()

    def test_variables_tf_exists(self) -> None:
        assert (_module_dir("cloudflare") / "variables.tf").exists()

    def test_outputs_tf_exists(self) -> None:
        assert (_module_dir("cloudflare") / "outputs.tf").exists()


class TestCloudflareModuleVariables:
    """Cloudflare Workers module has relay-specific variables."""

    def test_domain_variable(self) -> None:
        content = _read("cloudflare", "variables.tf")
        assert re.search(r'variable\s+"domain"', content)

    def test_upstream_url_variable(self) -> None:
        content = _read("cloudflare", "variables.tf")
        assert re.search(r'variable\s+"upstream_url"', content)

    def test_worker_name_variable(self) -> None:
        content = _read("cloudflare", "variables.tf")
        assert re.search(r'variable\s+"worker_name"', content)


class TestCloudflareModuleOutputs:
    """Cloudflare Workers module exposes the shared output interface."""

    def test_instance_ip_output(self) -> None:
        content = _read("cloudflare", "outputs.tf")
        assert re.search(r'output\s+"instance_ip"', content)

    def test_instance_id_output(self) -> None:
        content = _read("cloudflare", "outputs.tf")
        assert re.search(r'output\s+"instance_id"', content)

    def test_ssh_command_output(self) -> None:
        content = _read("cloudflare", "outputs.tf")
        assert re.search(r'output\s+"ssh_command"', content)


class TestCloudflareModuleResources:
    """Cloudflare-specific resources in main.tf."""

    def test_workers_script(self) -> None:
        content = _read("cloudflare", "main.tf")
        assert "cloudflare_workers_script" in content

    def test_workers_route(self) -> None:
        content = _read("cloudflare", "main.tf")
        assert "cloudflare_workers_route" in content

    def test_relay_fetches_upstream(self) -> None:
        content = _read("cloudflare", "main.tf")
        assert "fetch(target" in content or "fetch(" in content, (
            "Worker script must relay requests to upstream via fetch()"
        )

    def test_forwards_client_ip(self) -> None:
        content = _read("cloudflare", "main.tf")
        assert "X-Forwarded-For" in content, (
            "Worker must forward original client IP via X-Forwarded-For"
        )

    def test_cloudflare_provider_declared(self) -> None:
        content = _read("cloudflare", "main.tf")
        assert "cloudflare/cloudflare" in content, (
            "main.tf must declare the cloudflare/cloudflare provider"
        )


class TestCloudflareProviderClass:
    """Python provider subclass for Cloudflare Workers."""

    def test_import(self) -> None:
        from infraguard.deploy.providers.cloudflare import CloudflareProvider
        assert CloudflareProvider is not None

    def test_registered_in_factory(self) -> None:
        from infraguard.deploy.providers import _PROVIDER_MAP
        assert "cloudflare" in _PROVIDER_MAP
        assert "cf" in _PROVIDER_MAP

    def test_module_path_points_to_cloudflare(self, tmp_path: Path) -> None:
        from infraguard.deploy.providers.cloudflare import CloudflareProvider
        provider = CloudflareProvider(work_dir=tmp_path)
        assert provider.module_path.name == "cloudflare"
        assert (provider.module_path / "main.tf").exists()
