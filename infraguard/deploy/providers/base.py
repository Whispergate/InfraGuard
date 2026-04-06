"""TerraformProvider - subprocess wrapper around Terraform CLI.

Security invariants:
- Secrets are NEVER passed as -var CLI flags.  All variables go through a
  terraform.tfvars.json file written with 0o600 permissions and deleted after
  each apply / destroy.
- State encryption is handled by the caller (infraguard/deploy/state.py).
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path


class TerraformError(Exception):
    """Raised when a Terraform operation fails or the binary is missing."""


class TerraformProvider:
    """Wraps ``terraform init``, ``apply``, ``destroy``, and ``output`` calls.

    Args:
        module_path: Path to the Terraform module (source of .tf files).
        work_dir: Working directory for Terraform state and intermediate files.
                  The tfvars file and ``.terraform/`` state directory live here.
    """

    def __init__(self, module_path: Path, work_dir: Path) -> None:
        self.module_path = module_path
        self.work_dir = work_dir
        self.work_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _check_terraform() -> str:
        """Return the absolute path to the ``terraform`` binary.

        Raises:
            TerraformError: If ``terraform`` is not found on PATH.
        """
        path = shutil.which("terraform")
        if not path:
            raise TerraformError(
                "terraform binary not found on PATH. "
                "Install from https://developer.hashicorp.com/terraform/install"
            )
        return path

    def _run_terraform(self, *args: str) -> subprocess.CompletedProcess:
        """Run a ``terraform`` subcommand in *self.work_dir*.

        Args:
            *args: Arguments passed directly after the ``terraform`` binary
                   (e.g. ``"init"``, ``"-upgrade"``).

        Returns:
            The :class:`subprocess.CompletedProcess` result.

        Raises:
            TerraformError: If the process exits with a non-zero return code.
        """
        tf_bin = self._check_terraform()
        result = subprocess.run(
            [tf_bin, *args],
            cwd=str(self.work_dir),
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise TerraformError(
                f"terraform {args[0]} failed:\n{result.stderr}"
            )
        return result

    def _write_tfvars(self, tfvars: dict) -> Path:
        """Serialise *tfvars* to ``terraform.tfvars.json`` with 0o600 perms.

        The file is always written to *self.work_dir*.  Callers are responsible
        for deleting it via :meth:`_cleanup_tfvars` after the operation
        completes (including on failure).

        Args:
            tfvars: Dictionary of Terraform variable name → value pairs.

        Returns:
            Path to the written tfvars file.
        """
        tf_file = self.work_dir / "terraform.tfvars.json"
        tf_file.write_text(json.dumps(tfvars, indent=2))
        tf_file.chmod(0o600)
        return tf_file

    def _cleanup_tfvars(self) -> None:
        """Delete ``terraform.tfvars.json`` from *self.work_dir* if it exists."""
        tf_file = self.work_dir / "terraform.tfvars.json"
        if tf_file.exists():
            tf_file.unlink()

    def _get_outputs(self) -> dict[str, str]:
        """Run ``terraform output -json`` and return a flat key → value dict.

        Returns:
            Dictionary of output name → string value.
        """
        result = self._run_terraform("output", "-json")
        raw = json.loads(result.stdout)
        return {k: v["value"] for k, v in raw.items()}

    # ------------------------------------------------------------------
    # Public operations
    # ------------------------------------------------------------------

    def _stage_module(self) -> None:
        """Copy ``.tf`` files from *module_path* into *work_dir*.

        Terraform expects configuration files in its working directory.
        We copy (not symlink) so that the work_dir is self-contained and
        can be archived or transferred to another host.

        Existing ``.tf`` files in *work_dir* are overwritten to ensure
        the latest module version is always used.
        """
        for tf_file in self.module_path.glob("*.tf"):
            dest = self.work_dir / tf_file.name
            shutil.copy2(tf_file, dest)

    def init(self) -> None:
        """Stage module files and run ``terraform init -upgrade``."""
        self._stage_module()
        self._run_terraform("init", "-upgrade")

    def apply(self, tfvars: dict) -> dict[str, str]:
        """Provision infrastructure described by *tfvars*.

        Sequence:
        1. Write ``terraform.tfvars.json`` (0o600).
        2. Run ``terraform init -upgrade``.
        3. Run ``terraform apply -auto-approve -var-file=terraform.tfvars.json``.
        4. Collect and return outputs.
        5. Delete ``terraform.tfvars.json`` regardless of success / failure.

        Args:
            tfvars: Terraform variable values (e.g. domain, ssh_public_key).

        Returns:
            Dictionary of Terraform output name → value.

        Raises:
            TerraformError: If any Terraform step fails.
        """
        self._write_tfvars(tfvars)
        try:
            self.init()
            self._run_terraform(
                "apply",
                "-auto-approve",
                "-var-file=terraform.tfvars.json",
            )
            return self._get_outputs()
        finally:
            self._cleanup_tfvars()

    def destroy(self, tfvars: dict) -> None:
        """Tear down infrastructure.

        Sequence:
        1. Write ``terraform.tfvars.json`` (0o600).
        2. Run ``terraform destroy -auto-approve -var-file=terraform.tfvars.json``.
        3. Delete ``terraform.tfvars.json`` regardless of success / failure.

        Args:
            tfvars: Terraform variable values (needed to identify resources).

        Raises:
            TerraformError: If Terraform destroy fails.
        """
        self._write_tfvars(tfvars)
        try:
            self._run_terraform(
                "destroy",
                "-auto-approve",
                "-var-file=terraform.tfvars.json",
            )
        finally:
            self._cleanup_tfvars()
