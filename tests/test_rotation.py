"""Tests for the RotationManager (blue-green deployment rotation)."""

from __future__ import annotations

import socket
import ssl
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from infraguard.deploy.rotation import (
    PreFlightError,
    PreFlightResult,
    RotationError,
    RotationManager,
    RotationResult,
)


# ── Fixtures ──────────────────────────────────────────────────────────────

@pytest.fixture
def ssh_key(tmp_path: Path) -> Path:
    key = tmp_path / "id_rsa.pub"
    key.write_text("ssh-rsa AAAA... user@host")
    return key


@pytest.fixture
def blue_dir(tmp_path: Path) -> Path:
    d = tmp_path / "blue"
    d.mkdir()
    (d / "terraform.tfstate").write_text('{"resources": []}')
    return d


@pytest.fixture
def green_dir(tmp_path: Path) -> Path:
    d = tmp_path / "green"
    d.mkdir()
    return d


@pytest.fixture
def manager(blue_dir: Path, green_dir: Path, ssh_key: Path) -> RotationManager:
    return RotationManager(
        provider_name="aws",
        blue_work_dir=blue_dir,
        green_work_dir=green_dir,
        ssh_key=ssh_key,
        operator_ip="1.2.3.4/32",
    )


# ── PreFlightResult / RotationResult dataclasses ──────────────────────────

class TestResultDataclasses:
    def test_preflight_result_defaults(self):
        r = PreFlightResult()
        assert r.dns_ok is False
        assert r.cert_ok is False
        assert r.upstream_ok is False
        assert r.passed is False

    def test_preflight_result_passed_only_when_all_ok(self):
        r = PreFlightResult(dns_ok=True, cert_ok=True, upstream_ok=False)
        assert r.passed is False
        r.upstream_ok = True
        assert r.passed is True

    def test_rotation_result_fields(self):
        r = RotationResult(success=True, strategy="blue-green", domain="test.com")
        assert r.success is True
        assert r.strategy == "blue-green"
        assert r.rollback_performed is False


# ── SSH user selection ────────────────────────────────────────────────────

class TestSSHUser:
    @pytest.mark.parametrize("provider,expected", [
        ("do", "root"),
        ("aws", "ubuntu"),
        ("azure", "operator"),
        ("hetzner", "root"),
        ("unknown", "root"),  # default
    ])
    def test_ssh_user_per_provider(self, provider, expected, blue_dir, green_dir, ssh_key):
        mgr = RotationManager(
            provider_name=provider,
            blue_work_dir=blue_dir,
            green_work_dir=green_dir,
            ssh_key=ssh_key,
        )
        assert mgr.ssh_user == expected


# ── Pre-flight: DNS check ─────────────────────────────────────────────────

class TestDNSCheck:
    def test_dns_check_success(self, manager):
        with patch("socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.2.3.4", 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.2.3.5", 0)),
            ]
            ips = manager._check_dns("example.com", expected_ip=None)
        assert ips == ["1.2.3.4", "1.2.3.5"]

    def test_dns_check_expected_ip_match(self, manager):
        with patch("socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.2.3.4", 0)),
            ]
            ips = manager._check_dns("example.com", expected_ip="1.2.3.4")
        assert ips == ["1.2.3.4"]

    def test_dns_check_expected_ip_mismatch_raises(self, manager):
        with patch("socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.2.3.4", 0)),
            ]
            with pytest.raises(RotationError, match="expected 9.9.9.9"):
                manager._check_dns("example.com", expected_ip="9.9.9.9")

    def test_dns_check_no_records_eventually_raises(self, manager):
        # Speed up: reduce attempts via patching the constants
        with patch("socket.getaddrinfo", side_effect=socket.gaierror("no dns")):
            with patch("infraguard.deploy.rotation._PREFLIGHT_DNS_MAX_ATTEMPTS", 2):
                with patch("infraguard.deploy.rotation._PREFLIGHT_DNS_INTERVAL", 0.01):
                    with pytest.raises(RotationError, match="no A records"):
                        manager._check_dns("nonexistent.example", expected_ip=None)


# ── Pre-flight: certificate check ─────────────────────────────────────────

class TestCertCheck:
    def test_cert_valid_returns_days_left(self, manager):
        # Build a fake cert 30 days in the future
        future_not_after = time.strftime(
            "%b %d %H:%M:%S %Y GMT", time.gmtime(time.time() + 30 * 86400)
        )
        mock_ssock = MagicMock()
        mock_ssock.getpeercert.return_value = {"notAfter": future_not_after}
        mock_ssock.__enter__ = MagicMock(return_value=mock_ssock)
        mock_ssock.__exit__ = MagicMock(return_value=False)

        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value = mock_ssock

        with patch("socket.create_connection", return_value=mock_sock):
            with patch("ssl.create_default_context", return_value=mock_ctx):
                days = manager._check_cert("example.com")
        assert days >= 29  # account for test runtime

    def test_cert_expiring_soon_raises(self, manager):
        # Cert expires in 3 days - below the 7-day minimum
        soon_not_after = time.strftime(
            "%b %d %H:%M:%S %Y GMT", time.gmtime(time.time() + 3 * 86400)
        )
        mock_ssock = MagicMock()
        mock_ssock.getpeercert.return_value = {"notAfter": soon_not_after}
        mock_ssock.__enter__ = MagicMock(return_value=mock_ssock)
        mock_ssock.__exit__ = MagicMock(return_value=False)

        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value = mock_ssock

        with patch("socket.create_connection", return_value=mock_sock):
            with patch("ssl.create_default_context", return_value=mock_ctx):
                with pytest.raises(RotationError, match="expires in"):
                    manager._check_cert("example.com")

    def test_cert_tls_failure_raises(self, manager):
        with patch("socket.create_connection", side_effect=ssl.SSLError("bad cert")):
            with pytest.raises(RotationError, match="TLS handshake"):
                manager._check_cert("example.com")


# ── Pre-flight: upstream health ───────────────────────────────────────────

class TestUpstreamCheck:
    def test_upstream_reachable(self, manager):
        mock_resp = MagicMock()
        mock_resp.status_code = 404  # any response = up
        mock_client = MagicMock()
        mock_client.get.return_value = mock_resp
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)

        with patch("httpx.Client", return_value=mock_client):
            manager._check_upstream("https://127.0.0.1:8443")

    def test_upstream_connect_error_raises(self, manager):
        import httpx

        mock_client = MagicMock()
        mock_client.get.side_effect = httpx.ConnectError("refused")
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)

        with patch("httpx.Client", return_value=mock_client):
            with pytest.raises(RotationError, match="Cannot connect"):
                manager._check_upstream("https://127.0.0.1:8443")


# ── Preflight orchestration ───────────────────────────────────────────────

class TestPreflight:
    def test_all_pass(self, manager):
        with patch.object(manager, "_check_dns", return_value=["1.2.3.4"]):
            with patch.object(manager, "_check_cert", return_value=30):
                with patch.object(manager, "_check_upstream"):
                    result = manager.preflight("example.com", "https://up:443")
        assert result.passed
        assert result.resolved_ips == ["1.2.3.4"]
        assert result.cert_expiry_days == 30

    def test_dns_failure_raises_preflight_error(self, manager):
        with patch.object(manager, "_check_dns", side_effect=RotationError("no dns")):
            with pytest.raises(PreFlightError, match="DNS check failed"):
                manager.preflight("example.com", "https://up:443")

    def test_cert_failure_raises_preflight_error(self, manager):
        with patch.object(manager, "_check_dns", return_value=["1.2.3.4"]):
            with patch.object(manager, "_check_cert", side_effect=RotationError("expired")):
                with pytest.raises(PreFlightError, match="Certificate check failed"):
                    manager.preflight("example.com", "https://up:443")

    def test_upstream_failure_raises_preflight_error(self, manager):
        with patch.object(manager, "_check_dns", return_value=["1.2.3.4"]):
            with patch.object(manager, "_check_cert", return_value=30):
                with patch.object(manager, "_check_upstream", side_effect=RotationError("down")):
                    with pytest.raises(PreFlightError, match="Upstream health check failed"):
                        manager.preflight("example.com", "https://up:443")


# ── Full rotate() flow ────────────────────────────────────────────────────

class TestRotateFlow:
    def test_unsupported_strategy_raises(self, manager):
        with pytest.raises(RotationError, match="Unsupported strategy"):
            manager.rotate("example.com", "https://up:443", Path("p.profile"), strategy="rolling")

    def test_rotate_success_skipping_preflight(self, manager, tmp_path):
        """rotate() with skip_preflight goes through provision → configure → health → shift → verify."""
        profile = tmp_path / "test.profile"
        profile.write_text("# test")

        with patch.object(manager, "_get_blue_ip", return_value="10.1.1.1"):
            with patch.object(manager, "_provision_green", return_value="10.2.2.2"):
                with patch.object(manager, "_configure_green"):
                    with patch.object(manager, "_health_check_green"):
                        with patch.object(manager, "_shift_traffic"):
                            with patch.object(manager, "_verify_beacon_callback"):
                                with patch.object(manager, "_encrypt_green_state"):
                                    # Don't actually destroy blue
                                    result = manager.rotate(
                                        "example.com",
                                        "https://up:443",
                                        profile,
                                        skip_preflight=True,
                                        destroy_blue=False,
                                    )
        assert result.success is True
        assert result.green_ip == "10.2.2.2"
        assert result.blue_ip == "10.1.1.1"
        assert result.rollback_performed is False

    def test_rotate_provisioning_failure_returns_error_no_rollback(self, manager, tmp_path):
        """If provisioning fails, no rollback is needed (nothing was created)."""
        profile = tmp_path / "test.profile"
        profile.write_text("# test")

        with patch.object(manager, "_get_blue_ip", return_value="10.1.1.1"):
            with patch.object(manager, "_provision_green", side_effect=RotationError("tf failed")):
                result = manager.rotate(
                    "example.com",
                    "https://up:443",
                    profile,
                    skip_preflight=True,
                    destroy_blue=False,
                )
        assert result.success is False
        assert "Provisioning failed" in result.error
        assert result.rollback_performed is False

    def test_rotate_configure_failure_triggers_rollback(self, manager, tmp_path):
        """Configure failure after provisioning triggers rollback."""
        profile = tmp_path / "test.profile"
        profile.write_text("# test")

        with patch.object(manager, "_get_blue_ip", return_value="10.1.1.1"):
            with patch.object(manager, "_provision_green", return_value="10.2.2.2"):
                with patch.object(manager, "_configure_green", side_effect=RotationError("scp failed")):
                    with patch.object(manager, "_rollback") as mock_rollback:
                        result = manager.rotate(
                            "example.com",
                            "https://up:443",
                            profile,
                            skip_preflight=True,
                            destroy_blue=False,
                        )
        assert result.success is False
        assert result.rollback_performed is True
        mock_rollback.assert_called_once_with("example.com")

    def test_rotate_health_gate_failure_triggers_rollback(self, manager, tmp_path):
        """Health check failure after configure triggers rollback."""
        profile = tmp_path / "test.profile"
        profile.write_text("# test")

        with patch.object(manager, "_get_blue_ip", return_value="10.1.1.1"):
            with patch.object(manager, "_provision_green", return_value="10.2.2.2"):
                with patch.object(manager, "_configure_green"):
                    with patch.object(manager, "_health_check_green", side_effect=RotationError("unhealthy")):
                        with patch.object(manager, "_rollback") as mock_rollback:
                            result = manager.rotate(
                                "example.com",
                                "https://up:443",
                                profile,
                                skip_preflight=True,
                                destroy_blue=False,
                            )
        assert result.success is False
        assert "Health gate failed" in result.error
        assert result.rollback_performed is True

    def test_rotate_beacon_verification_failure_triggers_rollback(self, manager, tmp_path):
        """Beacon verification failure triggers rollback even after traffic shift."""
        profile = tmp_path / "test.profile"
        profile.write_text("# test")

        with patch.object(manager, "_get_blue_ip", return_value="10.1.1.1"):
            with patch.object(manager, "_provision_green", return_value="10.2.2.2"):
                with patch.object(manager, "_configure_green"):
                    with patch.object(manager, "_health_check_green"):
                        with patch.object(manager, "_shift_traffic"):
                            with patch.object(manager, "_verify_beacon_callback", side_effect=RotationError("no callback")):
                                with patch.object(manager, "_rollback") as mock_rollback:
                                    result = manager.rotate(
                                        "example.com",
                                        "https://up:443",
                                        profile,
                                        skip_preflight=True,
                                        destroy_blue=False,
                                    )
        assert result.success is False
        assert "Beacon verification failed" in result.error
        assert result.rollback_performed is True


# ── Beacon callback verification ──────────────────────────────────────────

class TestBeaconCallbackVerification:
    def test_beacon_200_succeeds(self, manager):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_client = MagicMock()
        mock_client.get.return_value = mock_resp
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)

        with patch("httpx.Client", return_value=mock_client):
            manager._verify_beacon_callback("example.com")

    def test_beacon_non_200_retries_then_raises(self, manager):
        import httpx

        mock_client = MagicMock()
        mock_client.get.side_effect = httpx.ConnectError("refused")
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)

        with patch("httpx.Client", return_value=mock_client):
            with patch("infraguard.deploy.rotation._BEACON_CHECK_MAX_ATTEMPTS", 2):
                with patch("infraguard.deploy.rotation._BEACON_CHECK_INTERVAL", 0.01):
                    with pytest.raises(RotationError, match="Beacon callback verification failed"):
                        manager._verify_beacon_callback("example.com")


# ── State encryption ──────────────────────────────────────────────────────

class TestStateEncryption:
    def test_encrypt_skipped_when_no_state_key(self, manager, green_dir):
        """No state_key → _encrypt_green_state is a no-op."""
        manager.state_key = None
        (green_dir / "terraform.tfstate").write_text("{}")
        manager._encrypt_green_state()
        # Plaintext state should still be there
        assert (green_dir / "terraform.tfstate").exists()

    def test_encrypt_called_when_state_key_present(self, manager, green_dir):
        """state_key + tfstate file → encrypt_state is called."""
        manager.state_key = "age1..."
        (green_dir / "terraform.tfstate").write_text("{}")

        with patch("infraguard.deploy.rotation.encrypt_state") as mock_enc:
            manager._encrypt_green_state()
        mock_enc.assert_called_once()
