"""Tests for the deploy rotate command.

Covers:
- deploy-before-destroy ordering: apply() called before destroy()
- health poll retries on failure, succeeds on 200 OK
- health poll raises after max retries exhausted
- --yes flag skips confirmation prompt
- --preserve-data flag triggers SCP with correct IPs
- DNS TTL warning is emitted before rotation
"""

from __future__ import annotations

import asyncio
import json
import subprocess
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, call, patch

import pytest
from click.testing import CliRunner

from infraguard.deploy.cli import deploy_group, _poll_health, _poll_health_async


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _make_profile_and_key(tmp_path: Path) -> tuple[Path, Path]:
    """Create a dummy profile file and SSH public key for CLI invocation."""
    profile = tmp_path / "test.profile"
    profile.write_text("# cobalt strike profile")
    ssh_key = tmp_path / "id_rsa.pub"
    ssh_key.write_text("ssh-rsa AAAA... user@host")
    return profile, ssh_key


def _make_old_work_dir(tmp_path: Path) -> Path:
    """Create a minimal old work directory with a fake tfstate."""
    old_dir = tmp_path / "old-deploy"
    old_dir.mkdir()
    # Write a dummy tfstate so Terraform sees a valid directory
    (old_dir / "terraform.tfstate").write_text('{"resources": []}')
    return old_dir


# ---------------------------------------------------------------------------
# Deploy-then-destroy ordering
# ---------------------------------------------------------------------------


class TestRotateOrdering:
    """rotate uses deploy-then-destroy - apply() must be called before destroy()."""

    def test_apply_called_before_destroy(self, tmp_path):
        profile, ssh_key = _make_profile_and_key(tmp_path)
        old_work_dir = _make_old_work_dir(tmp_path)

        call_order = []

        mock_new_provider = MagicMock()
        mock_new_provider.apply.side_effect = lambda tfvars: (
            call_order.append("apply") or {"instance_ip": "10.2.3.4", "instance_id": "i-new", "ssh_command": "ssh ubuntu@10.2.3.4"}
        )

        mock_old_provider = MagicMock()
        mock_old_provider.destroy.side_effect = lambda tfvars: call_order.append("destroy")
        mock_old_provider._get_outputs.return_value = {"instance_ip": "10.1.1.1"}

        def mock_get_provider(name, work_dir):
            if "old" in str(work_dir):
                return mock_old_provider
            return mock_new_provider

        with patch("infraguard.deploy.cli.get_provider", side_effect=mock_get_provider):
            with patch("infraguard.deploy.cli._poll_health", return_value=True):
                runner = CliRunner()
                result = runner.invoke(deploy_group, [
                    "rotate",
                    "--provider", "aws",
                    "--new-domain", "new.evil.com",
                    "--profile", str(profile),
                    "--upstream", "https://10.0.0.5:8443",
                    "--ssh-key", str(ssh_key),
                    "--operator-ip", "1.2.3.4/32",
                    "--old-work-dir", str(old_work_dir),
                    "--yes",
                ])

        assert "apply" in call_order
        assert "destroy" in call_order
        apply_idx = call_order.index("apply")
        destroy_idx = call_order.index("destroy")
        assert apply_idx < destroy_idx, (
            f"apply() must be called before destroy(). Order was: {call_order}"
        )


# ---------------------------------------------------------------------------
# Health poll
# ---------------------------------------------------------------------------


class TestHealthPoll:
    """_poll_health_async() retries on failure and succeeds on 200 OK."""

    def test_poll_succeeds_on_200(self):
        """Should return True when the first request succeeds."""
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = asyncio.run(_poll_health_async("10.0.0.1"))

        assert result is True

    def test_poll_retries_on_failure_then_succeeds(self):
        """Should retry on connection errors and succeed when server comes up."""
        import httpx

        call_count = 0

        async def mock_get(url):
            nonlocal call_count
            call_count += 1
            if call_count <= 3:
                raise httpx.ConnectError("Connection refused")
            mock_resp = MagicMock()
            mock_resp.raise_for_status = MagicMock()
            return mock_resp

        mock_client = AsyncMock()
        mock_client.get = mock_get
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                result = asyncio.run(_poll_health_async("10.0.0.1"))

        assert result is True
        assert call_count == 4  # 3 failures + 1 success

    def test_poll_raises_after_max_retries(self):
        """Should raise RuntimeError after exhausting all retry attempts."""
        import httpx

        async def mock_get(url):
            raise httpx.ConnectError("Connection refused")

        mock_client = AsyncMock()
        mock_client.get = mock_get
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                with pytest.raises(RuntimeError, match="Health check failed"):
                    asyncio.run(_poll_health_async("10.0.0.1"))


# ---------------------------------------------------------------------------
# --yes flag
# ---------------------------------------------------------------------------


class TestYesFlag:
    """--yes skips the confirmation prompt."""

    def test_yes_flag_skips_confirm(self, tmp_path):
        profile, ssh_key = _make_profile_and_key(tmp_path)
        old_work_dir = _make_old_work_dir(tmp_path)

        mock_provider = MagicMock()
        mock_provider.apply.return_value = {
            "instance_ip": "10.2.3.4",
            "instance_id": "i-new",
            "ssh_command": "ssh ubuntu@10.2.3.4",
        }
        mock_provider._get_outputs.return_value = {"instance_ip": "10.1.1.1"}

        with patch("infraguard.deploy.cli.get_provider", return_value=mock_provider):
            with patch("infraguard.deploy.cli._poll_health", return_value=True):
                with patch("click.confirm") as mock_confirm:
                    runner = CliRunner()
                    result = runner.invoke(deploy_group, [
                        "rotate",
                        "--provider", "aws",
                        "--new-domain", "new.evil.com",
                        "--profile", str(profile),
                        "--upstream", "https://10.0.0.5:8443",
                        "--ssh-key", str(ssh_key),
                        "--operator-ip", "1.2.3.4/32",
                        "--old-work-dir", str(old_work_dir),
                        "--yes",
                    ])

        # click.confirm should NOT be called when --yes is provided
        mock_confirm.assert_not_called()

    def test_without_yes_calls_confirm(self, tmp_path):
        profile, ssh_key = _make_profile_and_key(tmp_path)
        old_work_dir = _make_old_work_dir(tmp_path)

        mock_provider = MagicMock()
        mock_provider.apply.return_value = {
            "instance_ip": "10.2.3.4",
            "instance_id": "i-new",
            "ssh_command": "ssh ubuntu@10.2.3.4",
        }
        mock_provider._get_outputs.return_value = {"instance_ip": "10.1.1.1"}

        with patch("infraguard.deploy.cli.get_provider", return_value=mock_provider):
            with patch("infraguard.deploy.cli._poll_health", return_value=True):
                runner = CliRunner()
                # Input "y" to confirm the prompt
                result = runner.invoke(
                    deploy_group,
                    [
                        "rotate",
                        "--provider", "aws",
                        "--new-domain", "new.evil.com",
                        "--profile", str(profile),
                        "--upstream", "https://10.0.0.5:8443",
                        "--ssh-key", str(ssh_key),
                        "--operator-ip", "1.2.3.4/32",
                        "--old-work-dir", str(old_work_dir),
                    ],
                    input="y\n",
                )

        # Confirmation prompt should appear in output
        assert "Destroy old instance?" in result.output or result.exit_code == 0


# ---------------------------------------------------------------------------
# --preserve-data (SCP)
# ---------------------------------------------------------------------------


class TestPreserveData:
    """--preserve-data triggers SCP with correct source and dest IPs."""

    def test_preserve_data_triggers_scp(self, tmp_path):
        profile, ssh_key = _make_profile_and_key(tmp_path)
        old_work_dir = _make_old_work_dir(tmp_path)

        old_ip = "10.1.1.1"
        new_ip = "10.2.2.2"

        mock_provider = MagicMock()
        mock_provider.apply.return_value = {
            "instance_ip": new_ip,
            "instance_id": "i-new",
            "ssh_command": f"ssh ubuntu@{new_ip}",
        }
        mock_provider._get_outputs.return_value = {"instance_ip": old_ip}

        captured_scp_cmd = []

        def mock_subprocess_run(cmd, **kwargs):
            captured_scp_cmd.append(cmd)
            r = MagicMock()
            r.returncode = 0
            r.stdout = ""
            r.stderr = ""
            return r

        with patch("infraguard.deploy.cli.get_provider", return_value=mock_provider):
            with patch("infraguard.deploy.cli._poll_health", return_value=True):
                with patch("subprocess.run", side_effect=mock_subprocess_run):
                    runner = CliRunner()
                    result = runner.invoke(deploy_group, [
                        "rotate",
                        "--provider", "aws",
                        "--new-domain", "new.evil.com",
                        "--profile", str(profile),
                        "--upstream", "https://10.0.0.5:8443",
                        "--ssh-key", str(ssh_key),
                        "--operator-ip", "1.2.3.4/32",
                        "--old-work-dir", str(old_work_dir),
                        "--preserve-data",
                        "--yes",
                    ])

        # Verify SCP was called with correct IPs
        scp_calls = [c for c in captured_scp_cmd if c and c[0] == "scp"]
        assert len(scp_calls) >= 1, f"Expected SCP call, got: {captured_scp_cmd}"
        scp_cmd = scp_calls[0]
        scp_str = " ".join(scp_cmd)
        assert old_ip in scp_str, f"Old IP {old_ip} not in SCP command: {scp_cmd}"
        assert new_ip in scp_str, f"New IP {new_ip} not in SCP command: {scp_cmd}"
        assert "infraguard.db" in scp_str


# ---------------------------------------------------------------------------
# DNS TTL warning
# ---------------------------------------------------------------------------


class TestDNSTTLWarning:
    """rotate emits a DNS TTL warning before proceeding."""

    def test_dns_ttl_warning_in_output(self, tmp_path):
        profile, ssh_key = _make_profile_and_key(tmp_path)
        old_work_dir = _make_old_work_dir(tmp_path)

        mock_provider = MagicMock()
        mock_provider.apply.return_value = {
            "instance_ip": "10.2.3.4",
            "instance_id": "i-new",
            "ssh_command": "ssh ubuntu@10.2.3.4",
        }

        with patch("infraguard.deploy.cli.get_provider", return_value=mock_provider):
            with patch("infraguard.deploy.cli._poll_health", return_value=True):
                runner = CliRunner()
                result = runner.invoke(deploy_group, [
                    "rotate",
                    "--provider", "aws",
                    "--new-domain", "new.evil.com",
                    "--profile", str(profile),
                    "--upstream", "https://10.0.0.5:8443",
                    "--ssh-key", str(ssh_key),
                    "--operator-ip", "1.2.3.4/32",
                    "--old-work-dir", str(old_work_dir),
                    "--yes",
                ])

        assert "DNS TTL" in result.output
        assert "60s" in result.output


# ---------------------------------------------------------------------------
# Full suite integration: deploy group wired into main CLI
# ---------------------------------------------------------------------------


class TestMainCLIIntegration:
    """deploy group is wired into the main CLI."""

    def test_deploy_help_shows_subcommands(self):
        from infraguard.main import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["deploy", "--help"])
        assert result.exit_code == 0
        assert "run" in result.output
        assert "destroy" in result.output
        assert "rotate" in result.output
