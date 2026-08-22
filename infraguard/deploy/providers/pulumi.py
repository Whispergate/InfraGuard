"""PulumiProvider: subprocess wrapper around the Pulumi CLI.

Provider credentials are read from environment variables, not stored in
Pulumi config. State is kept in the work directory via a file backend.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path


class PulumiError(Exception):
    """Raised when a Pulumi operation fails or the binary is missing."""


_CLOUD_ALIAS: dict[str, str] = {
    "do": "digitalocean",
    "digitalocean": "digitalocean",
    "aws": "aws",
    "azure": "azure",
    "hetzner": "hetzner",
    "hz": "hetzner",
}

_PROVIDER_DEFAULTS: dict[str, dict[str, str]] = {
    "digitalocean": {"region": "nyc1", "instance_size": "s-1vcpu-1gb"},
    "aws": {"region": "us-east-1", "instance_size": "t3.micro"},
    "azure": {"region": "eastus", "instance_size": "Standard_B1s"},
    "hetzner": {"region": "fsn1", "instance_size": "cx22"},
}


class PulumiProvider:
    """Wraps pulumi stack, up, destroy, and output calls.

    Uses a file-based local backend so state lives in work_dir.
    Matches TerraformProvider's apply/destroy interface.
    """

    def __init__(self, cloud_provider: str, work_dir: Path) -> None:
        alias = _CLOUD_ALIAS.get(cloud_provider.lower())
        if alias is None:
            raise PulumiError(
                f"Pulumi does not support provider '{cloud_provider}'. "
                f"Supported: {', '.join(sorted(set(_CLOUD_ALIAS.values())))}"
            )
        self.cloud_provider = alias
        self.work_dir = work_dir
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self._project_dir = Path(__file__).parent.parent / "pulumi_project"

    @staticmethod
    def _check_pulumi() -> str:
        path = shutil.which("pulumi")
        if not path:
            raise PulumiError(
                "pulumi binary not found on PATH. "
                "Install from https://www.pulumi.com/docs/install/"
            )
        return path

    def _backend_url(self) -> str:
        p = self.work_dir.resolve().as_posix()
        if not p.startswith("/"):
            p = "/" + p
        return f"file://{p}"

    def _env(self) -> dict[str, str]:
        env = os.environ.copy()
        env["PULUMI_BACKEND_URL"] = self._backend_url()
        env["PULUMI_SKIP_UPDATE_CHECK"] = "true"
        env.setdefault("PULUMI_CONFIG_PASSPHRASE", "")
        return env

    def _run(self, *args: str) -> subprocess.CompletedProcess:
        pulumi_bin = self._check_pulumi()
        result = subprocess.run(
            [pulumi_bin, "--non-interactive", *args],
            cwd=str(self.work_dir),
            capture_output=True,
            text=True,
            env=self._env(),
        )
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip()
            raise PulumiError(f"pulumi {args[0]} failed:\n{detail}")
        return result

    def _stage_project(self) -> None:
        """Copy Pulumi project files into work_dir."""
        if not self._project_dir.exists():
            raise PulumiError(
                f"Pulumi project not found at {self._project_dir}. "
                "Ensure the deploy/pulumi/ directory exists in the repo root."
            )
        for src in self._project_dir.iterdir():
            if src.name in ("venv", "__pycache__", ".pulumi"):
                continue
            if src.name.startswith("."):
                continue
            if src.is_file():
                shutil.copy2(src, self.work_dir / src.name)

    def _init_stack(self, name: str) -> None:
        """Create or select a Pulumi stack."""
        try:
            self._run("stack", "init", name)
        except PulumiError:
            self._run("stack", "select", name)

    def _select_active_stack(self) -> None:
        """Select the existing stack in the work directory."""
        result = self._run("stack", "ls", "--json")
        stacks = json.loads(result.stdout)
        if not stacks:
            raise PulumiError("No Pulumi stacks found in work directory")
        current = next((s for s in stacks if s.get("current")), None)
        if current is None:
            self._run("stack", "select", stacks[0]["name"])

    def _set_config(self, key: str, value: str) -> None:
        self._run("config", "set", f"infraguard:{key}", value)

    def _get_outputs(self) -> dict[str, str]:
        """Read outputs from the current stack.

        Stages project files and selects the active stack if needed,
        so this works on a freshly constructed PulumiProvider that
        points to an existing work directory.
        """
        self._stage_project()
        self._select_active_stack()
        result = self._run("stack", "output", "--json")
        return {k: str(v) for k, v in json.loads(result.stdout).items()}

    def apply(self, pulumi_vars: dict) -> dict[str, str]:
        """Provision infrastructure via Pulumi.

        Accepts the same var keys the CLI builds for Terraform. Maps them
        to Pulumi config under the ``infraguard:`` namespace.

        Returns:
            Dict of outputs: instance_ip, instance_id, ssh_user,
            ssh_command, dashboard_url, provider, domain.
        """
        self._stage_project()

        stack = pulumi_vars.get("domain", "default").replace(".", "-")
        self._init_stack(stack)

        self._set_config("provider", self.cloud_provider)
        defaults = _PROVIDER_DEFAULTS.get(self.cloud_provider, {})
        for key in ("domain", "operator_ip", "ssh_public_key", "region", "instance_size"):
            val = pulumi_vars.get(key) or defaults.get(key)
            if val:
                self._set_config(key, val)

        self._run("up", "--yes")
        return self._get_outputs()

    def destroy(self, _vars: dict | None = None) -> None:
        """Destroy infrastructure managed by the current stack."""
        self._stage_project()
        self._select_active_stack()
        self._run("destroy", "--yes")
