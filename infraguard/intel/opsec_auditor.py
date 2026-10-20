"""Runtime OPSEC auditor - validates that the running instance is hardened
against analyst, defender, and NAT-based discovery.

Each check produces a Finding with a severity (critical / warning / info / ok)
and a short recommendation.  The auditor inspects the live config, TLS state,
and network posture; it does not modify anything.
"""

from __future__ import annotations

import ipaddress
import socket
import ssl
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from infraguard.config.schema import InfraGuardConfig

Severity = Literal["critical", "warning", "info", "ok"]

REMOTE_ACCESS_PORTS = {
    22: "SSH",
    3389: "RDP",
    5900: "VNC",
    5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS",
    4444: "Metasploit",
    8291: "WinBox",
}

ANALYST_TOOL_PORTS = {
    9090: "Prometheus/Burp",
    8888: "Jupyter",
    8443: "Burp-API",
    1080: "SOCKS",
    3128: "Squid",
    8081: "Fiddler",
}


@dataclass
class Finding:
    id: str
    category: str
    severity: Severity
    title: str
    detail: str
    recommendation: str = ""


@dataclass
class AuditResult:
    timestamp: str = ""
    findings: list[Finding] = field(default_factory=list)
    score: int = 0  # 0-100, higher is more secure

    def to_dict(self) -> dict:
        counts = {"critical": 0, "warning": 0, "info": 0, "ok": 0}
        for f in self.findings:
            counts[f.severity] += 1
        return {
            "timestamp": self.timestamp,
            "score": self.score,
            "summary": counts,
            "findings": [
                {
                    "id": f.id,
                    "category": f.category,
                    "severity": f.severity,
                    "title": f.title,
                    "detail": f.detail,
                    "recommendation": f.recommendation,
                }
                for f in self.findings
            ],
        }


def run_audit(config: InfraGuardConfig) -> AuditResult:
    result = AuditResult(timestamp=datetime.now(UTC).isoformat())
    _check_network_exposure(config, result)
    _check_remote_access_ports(result)
    _check_fingerprint_resistance(config, result)
    _check_auth_hardening(config, result)
    _check_pipeline_coverage(config, result)
    _check_data_hygiene(config, result)
    _check_tls_posture(config, result)
    result.score = _compute_score(result.findings)
    return result


# ── Network Exposure ──────────────────────────────────────────────────────────


def _check_network_exposure(config: InfraGuardConfig, result: AuditResult) -> None:
    api = config.api

    # API bind address
    if api.bind in ("0.0.0.0", "::"):
        if not api.auth_token:
            result.findings.append(Finding(
                id="NET-01",
                category="network",
                severity="critical",
                title="Dashboard exposed without auth",
                detail=f"API bound to {api.bind} with no auth token",
                recommendation="Set api.auth_token or bind to 127.0.0.1",
            ))
        else:
            result.findings.append(Finding(
                id="NET-01",
                category="network",
                severity="warning",
                title="Dashboard on all interfaces",
                detail=f"API bound to {api.bind} - reachable from any network",
                recommendation="Bind to 127.0.0.1 unless remote access is required",
            ))
    else:
        result.findings.append(Finding(
            id="NET-01",
            category="network",
            severity="ok",
            title="Dashboard on loopback",
            detail=f"API bound to {api.bind}",
        ))

    # Trusted proxies
    if not api.trusted_proxies:
        result.findings.append(Finding(
            id="NET-02",
            category="network",
            severity="info",
            title="No trusted proxies configured",
            detail="X-Forwarded-For headers accepted from any source",
            recommendation="Set api.trusted_proxies to your CDN/LB CIDRs",
        ))
    else:
        result.findings.append(Finding(
            id="NET-02",
            category="network",
            severity="ok",
            title="Trusted proxies configured",
            detail=f"{len(api.trusted_proxies)} CIDR(s) trusted",
        ))

    # Check for overly broad whitelists in domains
    for domain_cfg in config.domains.values():
        for cidr_str in domain_cfg.whitelist_cidrs:
            try:
                net = ipaddress.ip_network(cidr_str, strict=False)
                if net.prefixlen < 16:
                    result.findings.append(Finding(
                        id="NET-03",
                        category="network",
                        severity="warning",
                        title="Broad whitelist CIDR",
                        detail=f"{cidr_str} on {domain_cfg.upstream} - covers {net.num_addresses:,} addresses",
                        recommendation="Narrow to specific operator IP ranges",
                    ))
            except ValueError:
                pass

    # Multiple network interfaces - potential NAT/VPN indicator
    try:
        addrs = set()
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            addr = info[4][0]
            if not addr.startswith("127."):
                addrs.add(addr)
        if len(addrs) > 1:
            result.findings.append(Finding(
                id="NET-04",
                category="network",
                severity="info",
                title="Multiple network interfaces",
                detail=f"{len(addrs)} non-loopback IPv4 addresses detected",
                recommendation="Verify all interfaces are intentional - extra NICs widen the attack surface",
            ))
        else:
            result.findings.append(Finding(
                id="NET-04",
                category="network",
                severity="ok",
                title="Single network interface",
                detail=f"{len(addrs)} non-loopback IPv4 address",
            ))
    except OSError:
        pass


def _check_remote_access_ports(result: AuditResult) -> None:
    """Probe localhost for common remote-access and analyst-tool ports."""
    exposed = []
    for port, service in {**REMOTE_ACCESS_PORTS, **ANALYST_TOOL_PORTS}.items():
        if _port_open("127.0.0.1", port):
            exposed.append((port, service))

    if exposed:
        ra = [(p, s) for p, s in exposed if p in REMOTE_ACCESS_PORTS]
        at = [(p, s) for p, s in exposed if p in ANALYST_TOOL_PORTS]

        if ra:
            services = ", ".join(f"{s}:{p}" for p, s in ra)
            result.findings.append(Finding(
                id="NET-05",
                category="network",
                severity="critical",
                title="Remote access services detected",
                detail=f"Listening on localhost: {services}",
                recommendation="Disable or firewall remote access services on the redirector host",
            ))
        if at:
            services = ", ".join(f"{s}:{p}" for p, s in at)
            result.findings.append(Finding(
                id="NET-06",
                category="network",
                severity="warning",
                title="Analyst tooling ports open",
                detail=f"Listening on localhost: {services}",
                recommendation="Unexpected services could indicate compromise or co-tenancy with analyst tools",
            ))
    else:
        result.findings.append(Finding(
            id="NET-05",
            category="network",
            severity="ok",
            title="No remote access services detected",
            detail="Common remote-admin and analyst-tool ports are closed",
        ))


def _port_open(host: str, port: int, timeout: float = 0.3) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


# ── Fingerprint Resistance ────────────────────────────────────────────────────


def _check_fingerprint_resistance(config: InfraGuardConfig, result: AuditResult) -> None:
    # Health path default
    if config.api.health_path in ("/health", "health"):
        result.findings.append(Finding(
            id="FP-01",
            category="fingerprint",
            severity="warning",
            title="Default health path",
            detail=f"Health endpoint at {config.api.health_path}",
            recommendation="Randomize to a non-guessable path (e.g. /s3cr3t-hc)",
        ))
    else:
        result.findings.append(Finding(
            id="FP-01",
            category="fingerprint",
            severity="ok",
            title="Custom health path",
            detail=f"Health endpoint at /{config.api.health_path.strip('/')}",
        ))

    # Canary prefix
    for domain_cfg in config.domains.values():
        canary = domain_cfg.drop_action.canary
        if canary.enabled and canary.prefix == "_ig":
            result.findings.append(Finding(
                id="FP-02",
                category="fingerprint",
                severity="warning",
                title="Default canary prefix",
                detail=f"Canary prefix '_ig' on {domain_cfg.upstream} is a known InfraGuard signature",
                recommendation="Set canary.prefix to a random path segment",
            ))
            break
    else:
        result.findings.append(Finding(
            id="FP-02",
            category="fingerprint",
            severity="ok",
            title="Canary prefix customized or disabled",
            detail="No domains use the default _ig prefix",
        ))

    # Persona consistency
    personas_checked = False
    for domain_cfg in config.domains.values():
        persona = domain_cfg.drop_action.persona
        if persona.server_header == "nginx" and "nginx" not in persona.error_body_404.lower():
            result.findings.append(Finding(
                id="FP-03",
                category="fingerprint",
                severity="info",
                title="Persona mismatch",
                detail="Server header says nginx but 404 body doesn't match",
                recommendation="Align error_body_404 with server_header persona",
            ))
            personas_checked = True
            break
        if persona.server_header and persona.server_header != "nginx":
            personas_checked = True
            result.findings.append(Finding(
                id="FP-03",
                category="fingerprint",
                severity="ok",
                title="Custom server persona",
                detail=f"Persona: {persona.server_header}",
            ))
            break
    if not personas_checked:
        result.findings.append(Finding(
            id="FP-03",
            category="fingerprint",
            severity="ok",
            title="Default nginx persona",
            detail="Server header and error pages use nginx persona",
        ))

    # JA3 filter
    pipeline = config.pipeline
    if not pipeline.enable_ja3_filter:
        result.findings.append(Finding(
            id="FP-04",
            category="fingerprint",
            severity="info",
            title="JA3 filter disabled",
            detail="TLS fingerprint filtering is off - known scanner fingerprints pass through",
            recommendation="Enable pipeline.enable_ja3_filter for TLS-level detection",
        ))
    else:
        ja3 = pipeline.ja3_filter
        has_lists = bool(ja3.blocked_ja3 or ja3.allowed_ja3)
        result.findings.append(Finding(
            id="FP-04",
            category="fingerprint",
            severity="ok" if has_lists else "info",
            title="JA3 filter enabled" + (" with lists" if has_lists else " (no lists)"),
            detail=f"Blocked: {len(ja3.blocked_ja3)}, Allowed: {len(ja3.allowed_ja3 or [])}",
            recommendation="" if has_lists else "Add blocked/allowed JA3 hashes for better coverage",
        ))

    # Cloud range blocking
    cloud = config.intel.cloud_ranges
    if not cloud.enabled:
        result.findings.append(Finding(
            id="FP-05",
            category="fingerprint",
            severity="warning",
            title="Cloud IP range blocking disabled",
            detail="Requests from AWS/Azure/GCP sandbox IPs are not filtered",
            recommendation="Enable intel.cloud_ranges.enabled unless beacons run in cloud",
        ))
    else:
        result.findings.append(Finding(
            id="FP-05",
            category="fingerprint",
            severity="ok",
            title="Cloud IP ranges blocked",
            detail=f"Providers: {', '.join(cloud.providers)}",
        ))


# ── Authentication & Access Control ──────────────────────────────────────────


def _check_auth_hardening(config: InfraGuardConfig, result: AuditResult) -> None:
    api = config.api

    # Auth token
    if not api.auth_token:
        result.findings.append(Finding(
            id="AUTH-01",
            category="auth",
            severity="critical",
            title="No API auth token",
            detail="Dashboard and API are completely unauthenticated",
            recommendation="Set api.auth_token to a strong random value (32+ chars)",
        ))
    elif len(api.auth_token) < 16:
        result.findings.append(Finding(
            id="AUTH-01",
            category="auth",
            severity="warning",
            title="Weak API auth token",
            detail=f"Token is {len(api.auth_token)} chars - brute-forceable",
            recommendation="Use a 32+ character random token",
        ))
    else:
        result.findings.append(Finding(
            id="AUTH-01",
            category="auth",
            severity="ok",
            title="API auth token set",
            detail=f"{len(api.auth_token)}-char token configured",
        ))

    # Rate limiting
    rl = api.rate_limit
    if rl.enabled:
        result.findings.append(Finding(
            id="AUTH-02",
            category="auth",
            severity="ok",
            title="API rate limiting active",
            detail=f"Capacity {rl.default_capacity}, refill {rl.default_refill_rate}/s",
        ))
    else:
        result.findings.append(Finding(
            id="AUTH-02",
            category="auth",
            severity="warning",
            title="API rate limiting disabled",
            detail="No brute-force protection on dashboard login",
            recommendation="Enable api.rate_limit",
        ))

    # Session TTL
    ttl_hours = api.session_ttl / 3600
    if ttl_hours > 48:
        result.findings.append(Finding(
            id="AUTH-03",
            category="auth",
            severity="info",
            title="Long session TTL",
            detail=f"Sessions valid for {ttl_hours:.0f}h - hijacked tokens stay valid longer",
            recommendation="Reduce to 24h or less",
        ))
    else:
        result.findings.append(Finding(
            id="AUTH-03",
            category="auth",
            severity="ok",
            title="Session TTL reasonable",
            detail=f"{ttl_hours:.0f}h",
        ))


# ── Pipeline Coverage ─────────────────────────────────────────────────────────


def _check_pipeline_coverage(config: InfraGuardConfig, result: AuditResult) -> None:
    p = config.pipeline
    filters = {
        "IP filter": p.enable_ip_filter,
        "Bot filter": p.enable_bot_filter,
        "Header filter": p.enable_header_filter,
        "Geo filter": p.enable_geo_filter,
        "DNS filter": p.enable_dns_filter,
        "Replay filter": p.enable_replay_filter,
        "Profile filter": p.enable_profile_filter,
        "Enumeration filter": p.enable_enumeration_filter,
        "Sandbox filter": p.enable_sandbox_filter,
        "JA3 filter": p.enable_ja3_filter,
    }

    disabled = [name for name, enabled in filters.items() if not enabled]
    enabled_count = len(filters) - len(disabled)
    total = len(filters)

    if len(disabled) >= 4:
        result.findings.append(Finding(
            id="PIPE-01",
            category="pipeline",
            severity="critical",
            title=f"{len(disabled)}/{total} filters disabled",
            detail=f"Off: {', '.join(disabled)}",
            recommendation="Enable core filters - each disabled filter is a gap analysts can exploit",
        ))
    elif len(disabled) >= 2:
        result.findings.append(Finding(
            id="PIPE-01",
            category="pipeline",
            severity="warning",
            title=f"{len(disabled)}/{total} filters disabled",
            detail=f"Off: {', '.join(disabled)}",
            recommendation="Review disabled filters for coverage gaps",
        ))
    elif disabled:
        result.findings.append(Finding(
            id="PIPE-01",
            category="pipeline",
            severity="info",
            title=f"{enabled_count}/{total} filters enabled",
            detail=f"Off: {', '.join(disabled)}",
        ))
    else:
        result.findings.append(Finding(
            id="PIPE-01",
            category="pipeline",
            severity="ok",
            title=f"All {total} filters enabled",
            detail="Full pipeline coverage",
        ))

    # Block threshold
    threshold = p.block_score_threshold
    if threshold > 0.8:
        result.findings.append(Finding(
            id="PIPE-02",
            category="pipeline",
            severity="warning",
            title="High block threshold",
            detail=f"Threshold {threshold} - borderline requests slip through",
            recommendation="Lower to 0.5-0.7 for tighter filtering",
        ))
    elif threshold < 0.2:
        result.findings.append(Finding(
            id="PIPE-02",
            category="pipeline",
            severity="info",
            title="Very low block threshold",
            detail=f"Threshold {threshold} - legitimate beacons may be blocked",
        ))
    else:
        result.findings.append(Finding(
            id="PIPE-02",
            category="pipeline",
            severity="ok",
            title="Block threshold nominal",
            detail=f"Threshold {threshold}",
        ))

    # Geo filter without country lists
    if p.enable_geo_filter:
        intel = config.intel
        if not intel.blocked_countries and not intel.allowed_countries:
            result.findings.append(Finding(
                id="PIPE-03",
                category="pipeline",
                severity="info",
                title="Geo filter has no country lists",
                detail="Filter is enabled but no countries are blocked or allowed",
                recommendation="Add blocked_countries or allowed_countries for geo-fencing",
            ))
        else:
            total_geo = len(intel.blocked_countries) + len(intel.allowed_countries)
            result.findings.append(Finding(
                id="PIPE-03",
                category="pipeline",
                severity="ok",
                title="Geo-fencing configured",
                detail=f"{len(intel.blocked_countries)} blocked, {len(intel.allowed_countries)} allowed countries",
            ))


# ── Data Hygiene ──────────────────────────────────────────────────────────────


def _check_data_hygiene(config: InfraGuardConfig, result: AuditResult) -> None:
    tracking = config.tracking

    # Retention policy
    retention = tracking.retention_days
    if retention and retention <= 90:
        result.findings.append(Finding(
            id="DATA-01",
            category="data",
            severity="ok",
            title="Data retention configured",
            detail=f"{retention}-day retention policy",
        ))
    elif retention and retention > 90:
        result.findings.append(Finding(
            id="DATA-01",
            category="data",
            severity="info",
            title="Long data retention",
            detail=f"{retention}-day retention - forensic exposure window",
            recommendation="Reduce to 30 days unless longer history is operationally needed",
        ))
    else:
        result.findings.append(Finding(
            id="DATA-01",
            category="data",
            severity="warning",
            title="No data retention policy",
            detail="Request logs accumulate indefinitely",
            recommendation="Set tracking.retention_days to auto-purge old records",
        ))

    # Database path writable check
    db_path = Path(tracking.db_path)
    if db_path.exists():
        result.findings.append(Finding(
            id="DATA-02",
            category="data",
            severity="ok",
            title="Database file present",
            detail=str(db_path),
        ))
    # else: not an error at audit time - may not have started yet


# ── TLS Posture ───────────────────────────────────────────────────────────────


def _check_tls_posture(config: InfraGuardConfig, result: AuditResult) -> None:
    for listener in config.listeners:
        if listener.protocol not in ("https",):
            continue

        if not listener.tls:
            result.findings.append(Finding(
                id="TLS-01",
                category="tls",
                severity="critical",
                title=f"HTTPS listener without TLS config",
                detail=f"{listener.bind}:{listener.port} - will use self-signed fallback",
                recommendation="Provide TLS cert/key or use Let's Encrypt",
            ))
            continue

        cert_path = Path(listener.tls.cert)
        if not cert_path.exists():
            # Check self-signed fallback
            self_signed_dir = Path(".infraguard/tls")
            possible = list(self_signed_dir.glob("*.pem")) if self_signed_dir.exists() else []
            if possible:
                result.findings.append(Finding(
                    id="TLS-04",
                    category="tls",
                    severity="warning",
                    title="Using self-signed certificate",
                    detail="Auto-generated cert - fingerprints differently from a CA-signed cert",
                    recommendation="Use a CA-signed cert for production to blend with legitimate CDN traffic",
                ))
            else:
                result.findings.append(Finding(
                    id="TLS-04",
                    category="tls",
                    severity="warning",
                    title="TLS cert not found",
                    detail=f"{cert_path} missing - self-signed will be generated at startup",
                ))
            continue

        # Inspect the live cert
        try:
            _check_cert_details(cert_path, result)
        except Exception:
            result.findings.append(Finding(
                id="TLS-02",
                category="tls",
                severity="info",
                title="Could not inspect certificate",
                detail=str(cert_path),
            ))

    # SSL verify on upstreams
    insecure = []
    for domain_cfg in config.domains.values():
        if not domain_cfg.ssl_verify and domain_cfg.upstream.startswith("https://"):
            insecure.append(domain_cfg.upstream)
    if insecure:
        result.findings.append(Finding(
            id="TLS-03",
            category="tls",
            severity="warning",
            title="TLS verify disabled for upstream(s)",
            detail=f"{len(insecure)} upstream(s) skip certificate validation",
            recommendation="Enable ssl_verify to prevent MITM between redirector and teamserver",
        ))
    else:
        result.findings.append(Finding(
            id="TLS-03",
            category="tls",
            severity="ok",
            title="Upstream TLS verification enabled",
            detail="All HTTPS upstreams verify certificates",
        ))


def _check_cert_details(cert_path: Path, result: AuditResult) -> None:
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend

        pem_data = cert_path.read_bytes()
        cert = x509.load_pem_x509_certificate(pem_data, default_backend())
        issuer = cert.issuer.rfc4514_string()
        subject = cert.subject.rfc4514_string()
        self_signed = issuer == subject

        # Check for leaking identifiers in cert fields
        leaky_terms = ("infraguard", "cobalt", "mythic", "sliver", "havoc", "c2", "beacon")
        combined = f"{issuer} {subject}".lower()
        leaked = [t for t in leaky_terms if t in combined]

        if leaked:
            result.findings.append(Finding(
                id="TLS-02",
                category="tls",
                severity="critical",
                title="Certificate leaks tool identity",
                detail=f"Found '{', '.join(leaked)}' in cert subject/issuer",
                recommendation="Regenerate cert with neutral O/CN fields",
            ))
        elif self_signed:
            result.findings.append(Finding(
                id="TLS-02",
                category="tls",
                severity="info",
                title="Self-signed certificate",
                detail=f"Subject: {subject}",
                recommendation="CA-signed certs blend better with CDN traffic",
            ))
        else:
            result.findings.append(Finding(
                id="TLS-02",
                category="tls",
                severity="ok",
                title="CA-signed certificate",
                detail=f"Issuer: {issuer}",
            ))
    except ImportError:
        result.findings.append(Finding(
            id="TLS-02",
            category="tls",
            severity="info",
            title="Cannot inspect cert (cryptography not installed)",
            detail=str(cert_path),
        ))


# ── Scoring ───────────────────────────────────────────────────────────────────

_SEVERITY_WEIGHT = {"critical": 15, "warning": 5, "info": 1, "ok": 0}


def _compute_score(findings: list[Finding]) -> int:
    """Compute a 0-100 OPSEC hardening score.  100 = fully hardened."""
    if not findings:
        return 100
    deductions = sum(_SEVERITY_WEIGHT[f.severity] for f in findings)
    return max(0, 100 - deductions)
