"""Unit tests for infraguard.core.ssl_context - SSLContextFactory."""

import ssl
import tempfile
import os

import pytest

from infraguard.core.ssl_context import build_ssl_context


class TestBuildSslContext:
    def test_ssl_verify_false_returns_false(self):
        result = build_ssl_context(ssl_verify=False)
        assert result is False

    def test_ssl_verify_false_with_ca_bundle_still_returns_false(self):
        """When ssl_verify=False, ca_bundle is irrelevant."""
        result = build_ssl_context(ssl_verify=False, ca_bundle="/any/path.pem")
        assert result is False

    def test_ssl_verify_true_no_bundle_returns_true(self):
        result = build_ssl_context(ssl_verify=True)
        assert result is True

    def test_ssl_verify_true_with_valid_ca_bundle_returns_ssl_context(self, tmp_path):
        """A valid PEM file should produce an ssl.SSLContext."""
        # Create a minimal self-signed cert PEM for testing
        pem_content = _generate_self_signed_pem()
        pem_file = tmp_path / "ca.pem"
        pem_file.write_bytes(pem_content)

        result = build_ssl_context(ssl_verify=True, ca_bundle=str(pem_file))
        assert isinstance(result, ssl.SSLContext)

    def test_ssl_verify_true_nonexistent_ca_bundle_raises(self):
        with pytest.raises((FileNotFoundError, OSError, ssl.SSLError)):
            build_ssl_context(ssl_verify=True, ca_bundle="/nonexistent/path/ca.pem")

    def test_return_type_is_bool_or_ssl_context(self, tmp_path):
        """Return type is always bool or ssl.SSLContext."""
        pem_content = _generate_self_signed_pem()
        pem_file = tmp_path / "ca.pem"
        pem_file.write_bytes(pem_content)

        false_result = build_ssl_context(ssl_verify=False)
        true_result = build_ssl_context(ssl_verify=True)
        ctx_result = build_ssl_context(ssl_verify=True, ca_bundle=str(pem_file))

        assert isinstance(false_result, bool)
        assert isinstance(true_result, bool)
        assert isinstance(ctx_result, ssl.SSLContext)


def _generate_self_signed_pem() -> bytes:
    """Generate a self-signed certificate PEM for testing using cryptography library."""
    try:
        import datetime
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Test CA"),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc))
            .not_valid_after(datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256())
        )
        return cert.public_bytes(serialization.Encoding.PEM)
    except ImportError:
        # Fall back to a pre-generated self-signed cert PEM if cryptography not available
        # This is a test-only self-signed cert for unit testing purposes
        return _FALLBACK_TEST_PEM


# Pre-generated test-only self-signed CA cert (NOT for production use)
_FALLBACK_TEST_PEM = b"""-----BEGIN CERTIFICATE-----
MIICpDCCAYwCCQDU+pQ4pHgSpDANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAl0
ZXN0LXJvb3QwHhcNMjUwMTAxMDAwMDAwWhcNMzUxMjMwMDAwMDAwWjAUMRIwEAYD
VQQDDAl0ZXN0LXJvb3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7
o4qne60TB3wolBqBCLU7aFKPbHHpLSoAiOJTOOB3s4OIiUDqTjotGk5GVAIwJhGh
yv/D5sxGjGGpqJu+q6R3+1DfxHXKaVAFWYSp3bnFSLaWvFJp5MwFXqf+BX+GkPh
kRV3Dp2tJGFTKKL6Zw3cHLnzq7e5cFBp5+nPKMQyBwDETj4J1gNvTvdgWg3yXme
1DPt+jMrxJPkH7lfKq3rKLJBJLmFf0qiHp+Zf5zBJQPkl0Gn5T5d5T8F8PAQHF
BF7RCPsUt0YRg5RLOb7uMvR5yxv7GIi6XPUJMWm0WJlE6TJ9JlzJLAKWrLvRmIy
NRBjPNnNlv2pP4N3P0pLAgMBAAEwDQYJKoZIhvcNAQELBQADggEBABOFMg0CmITv
5BYlPdimEb3YdqSrFtxn7G1yd+ZXMU1n2YiJ3fFAH5IDnFuCjlkNJPjb5r4S5cML
4P4nLuMPGFWlU5R+IUqSV3oqBFP7MLTf8a+cVBMpPIJAK8xGQXMvI0J5J+s4VTWP
QGI3cDanP5WiNS+LkJVNMGMj6pBcH+LH2UmWKHRpuTpDpCnl4n3cAGbYo/Iu4iO9
CiKLb5VmQj/H3+9UBfkH1PVFZ5LOgbRfh2eGOHJnnSVdPLTXHNf6v+JzWyAm63+1
v5FqJxpCh4kZ/A8U0k4IEMnIwfDYOvqTEp4ZvBjM5QIID2V6yFzB9VoJ3kKMm4p
GhJM3xG8j7E=
-----END CERTIFICATE-----
"""
