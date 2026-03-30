"""TLS context management for HTTPS listeners.

Generates self-signed certificates on the fly when the configured cert/key
paths don't exist, so the proxy can always start with TLS enabled.
"""

from __future__ import annotations

import datetime
import ssl
from pathlib import Path

import structlog
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from infraguard.config.schema import TLSConfig

log = structlog.get_logger()

_SELF_SIGNED_DIR = Path(".infraguard/tls")


def generate_self_signed_cert(
    domain: str = "localhost",
    output_dir: Path = _SELF_SIGNED_DIR,
) -> tuple[Path, Path]:
    """Generate a self-signed certificate and private key for *domain*.

    Returns ``(cert_path, key_path)``.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    cert_path = output_dir / f"{domain}.pem"
    key_path = output_dir / f"{domain}-key.pem"

    # If we already generated one previously, reuse it
    if cert_path.exists() and key_path.exists():
        log.info("self_signed_reused", domain=domain, cert=str(cert_path))
        return cert_path, key_path

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, domain),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "InfraGuard Self-Signed"),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(domain),
                x509.DNSName(f"*.{domain}"),
                x509.DNSName("localhost"),
                x509.IPAddress(
                    __import__("ipaddress").IPv4Address("127.0.0.1")
                ),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    log.warning(
        "self_signed_generated",
        domain=domain,
        cert=str(cert_path),
        expires=str(now + datetime.timedelta(days=365)),
    )
    return cert_path, key_path


def resolve_tls_paths(
    tls_config: TLSConfig,
    domains: list[str] | None = None,
) -> tuple[str, str]:
    """Return (cert_path, key_path), generating a self-signed cert if needed.

    If the configured paths exist, they are returned as-is. Otherwise a
    self-signed certificate is generated for the first domain (or
    ``localhost``).
    """
    cert_path = Path(tls_config.cert)
    key_path = Path(tls_config.key)

    if cert_path.exists() and key_path.exists():
        log.info("tls_loaded", cert=str(cert_path))
        return str(cert_path), str(key_path)

    # Certs not found - generate self-signed
    domain = domains[0] if domains else "localhost"
    log.warning(
        "tls_certs_not_found",
        configured_cert=str(cert_path),
        configured_key=str(key_path),
        fallback="generating self-signed certificate",
    )
    generated_cert, generated_key = generate_self_signed_cert(domain)
    return str(generated_cert), str(generated_key)


def create_ssl_context(tls_config: TLSConfig) -> ssl.SSLContext:
    """Create an SSL context, generating self-signed certs if necessary."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    cert_str, key_str = resolve_tls_paths(tls_config)
    ctx.load_cert_chain(cert_str, key_str)
    return ctx
