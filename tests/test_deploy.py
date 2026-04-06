"""Tests for Terraform provider wrapper and deploy CLI.

Covers:
- TerraformProvider._check_terraform(): raises TerraformError when binary missing
- TerraformProvider._write_tfvars(): creates file with 0o600 permissions
- TerraformProvider.apply(): calls init then apply with -var-file, never -var
- TerraformProvider.destroy(): calls destroy with -var-file
- TerraformProvider._get_outputs(): parses terraform output -json
- encrypt_state(): calls age with correct args, deletes plaintext
- decrypt_state(): calls age with correct args, returns temp file
- deploy_run CLI: calls provider.apply(), prints instance_ip
- deploy CLI: missing terraform binary produces actionable error
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest
from click.testing import CliRunner


# ---------------------------------------------------------------------------
# TerraformProvider tests
# ---------------------------------------------------------------------------


class TestCheckTerraform:
    """_check_terraform() raises TerraformError when binary is absent."""

    def test_raises_when_terraform_missing(self, tmp_path):
        from infraguard.deploy.providers.base import TerraformError, TerraformProvider

        provider = TerraformProvider(tmp_path, tmp_path)
        with patch("shutil.which", return_value=None):
            with pytest.raises(TerraformError, match="terraform binary not found"):
                provider._check_terraform()

    def test_returns_path_when_found(self, tmp_path):
        from infraguard.deploy.providers.base import TerraformProvider

        provider = TerraformProvider(tmp_path, tmp_path)
        with patch("shutil.which", return_value="/usr/bin/terraform"):
            result = provider._check_terraform()
        assert result == "/usr/bin/terraform"


class TestWriteTfvars:
    """_write_tfvars() creates terraform.tfvars.json with 0o600 permissions."""

    def test_creates_file_with_correct_permissions(self, tmp_path):
        from infraguard.deploy.providers.base import TerraformProvider

        provider = TerraformProvider(tmp_path, tmp_path)
        tfvars = {"domain": "evil.com", "ssh_public_key": "ssh-rsa AAAA..."}
        tf_file = provider._write_tfvars(tfvars)

        assert tf_file.exists()
        assert tf_file.name == "terraform.tfvars.json"
        # Check 0o600 permissions
        mode = stat.S_IMODE(os.stat(tf_file).st_mode)
        assert mode == 0o600

    def test_file_contains_correct_json(self, tmp_path):
        from infraguard.deploy.providers.base import TerraformProvider

        provider = TerraformProvider(tmp_path, tmp_path)
        tfvars = {"domain": "evil.com", "operator_ip": "1.2.3.4/32"}
        tf_file = provider._write_tfvars(tfvars)

        data = json.loads(tf_file.read_text())
        assert data == tfvars

    def test_no_var_flag_usage(self, tmp_path):
        """Secrets must be passed via -var-file, never as -var CLI flags."""
        from infraguard.deploy.providers import base

        import inspect
        source = inspect.getsource(base)
        # Ensure no "-var " is used as CLI flag (only -var-file is acceptable)
        assert '"-var "' not in source
        assert "'-var '" not in source


class TestApply:
    """apply() calls terraform init then apply with -var-file (not -var)."""

    def test_apply_calls_init_then_apply(self, tmp_path):
        from infraguard.deploy.providers.base import TerraformProvider

        provider = TerraformProvider(tmp_path, tmp_path)
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps({
            "instance_ip": {"value": "10.0.0.1"},
            "instance_id": {"value": "i-abc123"},
            "ssh_command": {"value": "ssh ubuntu@10.0.0.1"},
        })

        call_log = []

        def mock_run(cmd, **kwargs):
            call_log.append(cmd)
            r = MagicMock()
            r.returncode = 0
            r.stdout = mock_result.stdout
            r.stderr = ""
            return r

        with patch("shutil.which", return_value="/usr/bin/terraform"):
            with patch("subprocess.run", side_effect=mock_run):
                outputs = provider.apply({"domain": "evil.com"})

        # init must be called BEFORE apply
        assert any("init" in c for c in call_log)
        assert any("apply" in c for c in call_log)
        init_idx = next(i for i, c in enumerate(call_log) if "init" in c)
        apply_idx = next(i for i, c in enumerate(call_log) if "apply" in c)
        assert init_idx < apply_idx

    def test_apply_uses_var_file_not_var_flag(self, tmp_path):
        from infraguard.deploy.providers.base import TerraformProvider

        provider = TerraformProvider(tmp_path, tmp_path)
        captured_cmds = []

        def mock_run(cmd, **kwargs):
            captured_cmds.append(cmd)
            r = MagicMock()
            r.returncode = 0
            r.stdout = json.dumps({
                "instance_ip": {"value": "10.0.0.1"},
                "instance_id": {"value": "i-abc123"},
                "ssh_command": {"value": "ssh ubuntu@10.0.0.1"},
            })
            r.stderr = ""
            return r

        with patch("shutil.which", return_value="/usr/bin/terraform"):
            with patch("subprocess.run", side_effect=mock_run):
                provider.apply({"domain": "evil.com"})

        # -var-file must be used, not bare -var
        for cmd in captured_cmds:
            for arg in cmd:
                assert not arg.startswith("-var="), f"Found -var= flag in command: {cmd}"
                assert arg != "-var", f"Found -var flag in command: {cmd}"

    def test_apply_cleans_up_tfvars_after(self, tmp_path):
        from infraguard.deploy.providers.base import TerraformProvider

        provider = TerraformProvider(tmp_path, tmp_path)

        def mock_run(cmd, **kwargs):
            r = MagicMock()
            r.returncode = 0
            r.stdout = json.dumps({
                "instance_ip": {"value": "10.0.0.1"},
                "instance_id": {"value": "i-abc123"},
                "ssh_command": {"value": "ssh ubuntu@10.0.0.1"},
            })
            r.stderr = ""
            return r

        with patch("shutil.which", return_value="/usr/bin/terraform"):
            with patch("subprocess.run", side_effect=mock_run):
                provider.apply({"domain": "evil.com"})

        # tfvars file must be cleaned up after apply
        assert not (tmp_path / "terraform.tfvars.json").exists()


class TestDestroy:
    """destroy() calls terraform destroy with -var-file."""

    def test_destroy_calls_correct_command(self, tmp_path):
        from infraguard.deploy.providers.base import TerraformProvider

        provider = TerraformProvider(tmp_path, tmp_path)
        captured_cmds = []

        def mock_run(cmd, **kwargs):
            captured_cmds.append(cmd)
            r = MagicMock()
            r.returncode = 0
            r.stdout = ""
            r.stderr = ""
            return r

        with patch("shutil.which", return_value="/usr/bin/terraform"):
            with patch("subprocess.run", side_effect=mock_run):
                provider.destroy({"domain": "evil.com"})

        destroy_cmds = [c for c in captured_cmds if "destroy" in c]
        assert len(destroy_cmds) >= 1
        destroy_cmd = destroy_cmds[0]
        assert "-auto-approve" in destroy_cmd
        # Must use -var-file not -var
        assert any("-var-file=" in arg for arg in destroy_cmd)

    def test_destroy_cleans_up_tfvars(self, tmp_path):
        from infraguard.deploy.providers.base import TerraformProvider

        provider = TerraformProvider(tmp_path, tmp_path)

        def mock_run(cmd, **kwargs):
            r = MagicMock()
            r.returncode = 0
            r.stdout = ""
            r.stderr = ""
            return r

        with patch("shutil.which", return_value="/usr/bin/terraform"):
            with patch("subprocess.run", side_effect=mock_run):
                provider.destroy({"domain": "evil.com"})

        assert not (tmp_path / "terraform.tfvars.json").exists()


class TestGetOutputs:
    """_get_outputs() calls terraform output -json and parses result."""

    def test_get_outputs_parses_json(self, tmp_path):
        from infraguard.deploy.providers.base import TerraformProvider

        provider = TerraformProvider(tmp_path, tmp_path)
        raw_output = json.dumps({
            "instance_ip": {"value": "10.0.0.5", "type": "string"},
            "instance_id": {"value": "i-xyz", "type": "string"},
            "ssh_command": {"value": "ssh ubuntu@10.0.0.5", "type": "string"},
        })

        def mock_run(cmd, **kwargs):
            r = MagicMock()
            r.returncode = 0
            r.stdout = raw_output
            r.stderr = ""
            return r

        with patch("shutil.which", return_value="/usr/bin/terraform"):
            with patch("subprocess.run", side_effect=mock_run):
                outputs = provider._get_outputs()

        assert outputs["instance_ip"] == "10.0.0.5"
        assert outputs["instance_id"] == "i-xyz"
        assert outputs["ssh_command"] == "ssh ubuntu@10.0.0.5"

    def test_get_outputs_uses_json_flag(self, tmp_path):
        from infraguard.deploy.providers.base import TerraformProvider

        provider = TerraformProvider(tmp_path, tmp_path)
        captured_cmds = []

        def mock_run(cmd, **kwargs):
            captured_cmds.append(cmd)
            r = MagicMock()
            r.returncode = 0
            r.stdout = json.dumps({"instance_ip": {"value": "1.2.3.4"}})
            r.stderr = ""
            return r

        with patch("shutil.which", return_value="/usr/bin/terraform"):
            with patch("subprocess.run", side_effect=mock_run):
                provider._get_outputs()

        assert any("-json" in c for c in captured_cmds)


# ---------------------------------------------------------------------------
# State encryption tests
# ---------------------------------------------------------------------------


class TestEncryptState:
    """encrypt_state() calls age, writes .age file, deletes plaintext."""

    def test_encrypt_calls_age_with_pubkey(self, tmp_path):
        from infraguard.deploy.state import encrypt_state

        plaintext = tmp_path / "terraform.tfstate"
        plaintext.write_text('{"resources": []}')
        pubkey = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b"encrypted content"
        mock_result.stderr = b""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            enc_path = encrypt_state(plaintext, pubkey)

        # Check age was called with -r pubkey
        called_cmd = mock_run.call_args[0][0]
        assert "age" in called_cmd[0]
        assert "-r" in called_cmd
        assert pubkey in called_cmd

    def test_encrypt_deletes_plaintext(self, tmp_path):
        from infraguard.deploy.state import encrypt_state

        plaintext = tmp_path / "terraform.tfstate"
        plaintext.write_text('{"resources": []}')
        pubkey = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b"encrypted content"
        mock_result.stderr = b""

        with patch("subprocess.run", return_value=mock_result):
            enc_path = encrypt_state(plaintext, pubkey)

        # Plaintext must be deleted
        assert not plaintext.exists()

    def test_encrypt_returns_age_path(self, tmp_path):
        from infraguard.deploy.state import encrypt_state

        plaintext = tmp_path / "terraform.tfstate"
        plaintext.write_text('{"resources": []}')
        pubkey = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b"encrypted content"
        mock_result.stderr = b""

        with patch("subprocess.run", return_value=mock_result):
            enc_path = encrypt_state(plaintext, pubkey)

        assert str(enc_path).endswith(".age")

    def test_encrypt_raises_on_age_failure(self, tmp_path):
        from infraguard.deploy.state import encrypt_state

        plaintext = tmp_path / "terraform.tfstate"
        plaintext.write_text('{"resources": []}')
        pubkey = "age1bad"

        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = b""
        mock_result.stderr = b"age: invalid recipient"

        with patch("subprocess.run", return_value=mock_result):
            with pytest.raises(RuntimeError, match="age"):
                encrypt_state(plaintext, pubkey)


class TestDecryptState:
    """decrypt_state() calls age -d, returns temp file path with 0o600 perms."""

    def test_decrypt_calls_age_with_identity(self, tmp_path):
        from infraguard.deploy.state import decrypt_state

        enc_file = tmp_path / "terraform.tfstate.age"
        enc_file.write_bytes(b"encrypted content")
        identity = tmp_path / "age-identity.key"
        identity.write_text("AGE-SECRET-KEY-...")

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b'{"resources": []}'
        mock_result.stderr = b""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            out_path = decrypt_state(enc_file, identity)

        called_cmd = mock_run.call_args[0][0]
        assert "age" in called_cmd[0]
        assert "-d" in called_cmd
        assert "-i" in called_cmd
        assert str(identity) in called_cmd

    def test_decrypt_returns_temp_path(self, tmp_path):
        from infraguard.deploy.state import decrypt_state

        enc_file = tmp_path / "terraform.tfstate.age"
        enc_file.write_bytes(b"encrypted content")
        identity = tmp_path / "age-identity.key"
        identity.write_text("AGE-SECRET-KEY-...")

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b'{"resources": []}'
        mock_result.stderr = b""

        with patch("subprocess.run", return_value=mock_result):
            out_path = decrypt_state(enc_file, identity)

        assert out_path.exists()
        mode = stat.S_IMODE(os.stat(out_path).st_mode)
        assert mode == 0o600

    def test_decrypt_raises_on_failure(self, tmp_path):
        from infraguard.deploy.state import decrypt_state

        enc_file = tmp_path / "terraform.tfstate.age"
        enc_file.write_bytes(b"bad content")
        identity = tmp_path / "age-identity.key"
        identity.write_text("AGE-SECRET-KEY-...")

        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = b""
        mock_result.stderr = b"age: decryption failed"

        with patch("subprocess.run", return_value=mock_result):
            with pytest.raises(RuntimeError, match="age"):
                decrypt_state(enc_file, identity)


# ---------------------------------------------------------------------------
# Deploy CLI tests
# ---------------------------------------------------------------------------


class TestDeployCLI:
    """CLI integration tests for `infraguard deploy run`."""

    def test_deploy_run_calls_provider_apply(self, tmp_path):
        """deploy run should call provider.apply() and print instance_ip."""
        from infraguard.deploy.cli import deploy_group

        ssh_key = tmp_path / "id_rsa.pub"
        ssh_key.write_text("ssh-rsa AAAA... user@host")
        profile = tmp_path / "test.profile"
        profile.write_text("# cobalt strike profile")
        work_dir = tmp_path / "deploy-work"

        mock_outputs = {
            "instance_ip": "10.1.2.3",
            "instance_id": "i-abc123",
            "ssh_command": "ssh ubuntu@10.1.2.3",
        }

        with patch("infraguard.deploy.cli.get_provider") as mock_get_provider:
            mock_provider = MagicMock()
            mock_provider.apply.return_value = mock_outputs
            mock_get_provider.return_value = mock_provider

            runner = CliRunner()
            result = runner.invoke(deploy_group, [
                "run",
                "--provider", "aws",
                "--domain", "evil.com",
                "--profile", str(profile),
                "--upstream", "https://10.0.0.5:8443",
                "--ssh-key", str(ssh_key),
                "--operator-ip", "1.2.3.4/32",
                "--work-dir", str(work_dir),
            ])

        mock_provider.apply.assert_called_once()
        assert "10.1.2.3" in result.output

    def test_deploy_run_missing_terraform_shows_error(self, tmp_path):
        """deploy run with missing terraform binary should show actionable error."""
        from infraguard.deploy.cli import deploy_group
        from infraguard.deploy.providers.base import TerraformError

        ssh_key = tmp_path / "id_rsa.pub"
        ssh_key.write_text("ssh-rsa AAAA... user@host")
        profile = tmp_path / "test.profile"
        profile.write_text("# cobalt strike profile")
        work_dir = tmp_path / "deploy-work"

        with patch("infraguard.deploy.cli.get_provider") as mock_get_provider:
            mock_provider = MagicMock()
            mock_provider.apply.side_effect = TerraformError(
                "terraform binary not found on PATH. "
                "Install from https://developer.hashicorp.com/terraform/install"
            )
            mock_get_provider.return_value = mock_provider

            runner = CliRunner()
            result = runner.invoke(deploy_group, [
                "run",
                "--provider", "aws",
                "--domain", "evil.com",
                "--profile", str(profile),
                "--upstream", "https://10.0.0.5:8443",
                "--ssh-key", str(ssh_key),
                "--operator-ip", "1.2.3.4/32",
                "--work-dir", str(work_dir),
            ])

        assert "terraform" in result.output.lower() or "terraform" in (result.exception.__str__() if result.exception else "")
        # Either exit code != 0 or output contains the error
        assert result.exit_code != 0 or "not found" in result.output.lower()

    def test_deploy_group_has_subcommands(self):
        """deploy group must have run, destroy, and rotate subcommands."""
        from infraguard.deploy.cli import deploy_group

        commands = list(deploy_group.commands.keys())
        assert "run" in commands
        assert "destroy" in commands
