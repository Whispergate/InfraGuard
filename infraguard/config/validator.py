"""Configuration validation for InfraGuard.

Beyond Pydantic schema validation, this module performs operational
*semantic* checks - things that are syntactically valid YAML but indicate
broken, insecure, or sub-optimal deployments.

Three severity tiers:

* **error**   - config will not work, or exposes the operator to immediate risk
* **warning** - likely a misconfiguration; works but degrades security posture
* **info**    - best-practice suggestion

The validator operates on the parsed :class:`InfraGuardConfig` so defaults
have been applied; checks therefore reason about the effective runtime state.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

import click
from pydantic import ValidationError

from infraguard.config.loader import load_config
from infraguard.config.schema import InfraGuardConfig


Severity = Literal["error", "warning", "info"]


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    severity: Severity
    code: str            # stable machine-readable code, e.g. "SEC001"
    path: str            # dot-path to the offending setting
    message: str

    def render(self, color: bool = True) -> str:
        palette = {"error": "red", "warning": "yellow", "info": "cyan"}
        sev = self.severity.upper().ljust(7)
        if color:
            sev = click.style(sev, fg=palette[self.severity], bold=True)
        return f"  [{sev}] {self.code}  {self.path}\n             {self.message}"


@dataclass
class ValidationReport:
    findings: list[Finding] = field(default_factory=list)
    schema_error: str | None = None

    def add(self, severity: Severity, code: str, path: str, message: str) -> None:
        self.findings.append(Finding(severity, code, path, message))

    @property
    def errors(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "error"]

    @property
    def warnings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "warning"]

    @property
    def infos(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "info"]

    @property
    def ok(self) -> bool:
        return self.schema_error is None and not self.errors

    def render(self, color: bool = True) -> str:
        lines: list[str] = []
        if self.schema_error:
            head = click.style("SCHEMA INVALID", fg="red", bold=True) if color else "SCHEMA INVALID"
            lines.append(f"{head}\n  {self.schema_error}")
        for f in self.findings:
            lines.append(f.render(color=color))
        if not lines:
            msg = "No issues found."
            return click.style(msg, fg="green") if color else msg
        summary = (
            f"\n{len(self.errors)} error(s), "
            f"{len(self.warnings)} warning(s), "
            f"{len(self.infos)} info(s)."
        )
        lines.append(summary)
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------


class ConfigValidator:
    """Semantic validation of an InfraGuard config."""

    # CIDR prefixes broader than this trigger a warning (IPv4 / IPv6)
    BROAD_V4_PREFIX = 8
    BROAD_V6_PREFIX = 32

    # Auth tokens shorter than this are flagged as weak
    MIN_TOKEN_LENGTH = 16

    def __init__(self, config: InfraGuardConfig, source: Path | None = None) -> None:
        self.cfg = config
        self.source = source

    # -- entry points -------------------------------------------------------

    @classmethod
    def from_file(cls, path: Path) -> "ConfigValidator":
        return cls(load_config(path), source=path)

    def validate(self) -> ValidationReport:
        report = ValidationReport()
        self._check_listeners(report)
        self._check_domains(report)
        self._check_api(report)
        self._check_pipeline(report)
        self._check_intel(report)
        self._check_payload_tokens(report)
        self._check_phishingclub(report)
        self._check_tls_files(report)
        return report

    # -- checks -------------------------------------------------------------

    def _check_api(self, r: ValidationReport) -> None:
        api = self.cfg.api

        if not api.auth_token:
            r.add(
                "error", "SEC001", "api.auth_token",
                "API auth token is empty. The management API will accept "
                "unauthenticated requests. Set api.auth_token (or use "
                "${INFRAGUARD_API_TOKEN}).",
            )
        elif len(api.auth_token) < self.MIN_TOKEN_LENGTH:
            r.add(
                "warning", "SEC002", "api.auth_token",
                f"API auth token is only {len(api.auth_token)} chars "
                f"(recommend >= {self.MIN_TOKEN_LENGTH}).",
            )

        if api.bind not in ("127.0.0.1", "localhost", "::1"):
            if not api.auth_token:
                r.add(
                    "error", "SEC003", "api.bind",
                    f"API is bound to {api.bind} (non-loopback) without an "
                    "auth token. This is internet-exploitable.",
                )
            else:
                r.add(
                    "info", "OPS001", "api.bind",
                    f"API bound to {api.bind}; ensure firewall rules restrict "
                    "access to operator IPs.",
                )

        for cidr in api.trusted_proxies:
            self._check_cidr(r, cidr, "api.trusted_proxies")

    def _check_listeners(self, r: ValidationReport) -> None:
        if not self.cfg.listeners:
            r.add(
                "warning", "OPS002", "listeners",
                "No listeners configured - InfraGuard will not accept any traffic.",
            )
            return

        for i, lst in enumerate(self.cfg.listeners):
            path = f"listeners[{i}]"
            if lst.protocol == "https" and lst.tls is None:
                r.add(
                    "error", "TLS001", f"{path}.tls",
                    f"HTTPS listener on port {lst.port} has no TLS cert/key configured.",
                )
            if lst.protocol == "http" and lst.port == 443:
                r.add(
                    "warning", "TLS002", f"{path}.port",
                    "Plain-HTTP listener on port 443 - likely a typo (443 is HTTPS).",
                )
            if not lst.domains:
                r.add(
                    "info", "OPS003", f"{path}.domains",
                    f"Listener on port {lst.port} has no domains bound; "
                    "it will not route any virtual hosts.",
                )

    def _check_domains(self, r: ValidationReport) -> None:
        if not self.cfg.domains:
            r.add(
                "warning", "OPS004", "domains",
                "No domains configured - redirector has nothing to serve.",
            )
            return

        for name, dom in self.cfg.domains.items():
            base = f"domains.{name}"

            # Upstream sanity
            if not dom.upstream:
                r.add("error", "OPS005", f"{base}.upstream", "Domain has no upstream URL.")
            elif dom.upstream.startswith("http://") and dom.ssl_verify is False:
                r.add(
                    "info", "OPS006", f"{base}.upstream",
                    "Plain-HTTP upstream; ensure this is on a trusted internal network.",
                )

            # TLS verification
            if dom.upstream.startswith("https://") and not dom.ssl_verify:
                r.add(
                    "warning", "TLS003", f"{base}.ssl_verify",
                    f"TLS verification is DISABLED for upstream {dom.upstream}. "
                    "Vulnerable to MITM between redirector and teamserver. "
                    "Enable ssl_verify and set ssl_ca_bundle for self-signed certs.",
                )

            # Whitelist CIDRs
            for cidr in dom.whitelist_cidrs:
                self._check_cidr(r, cidr, f"{base}.whitelist_cidrs")

            # Content routes
            seen_paths: set[str] = set()
            for j, route in enumerate(dom.content_routes):
                rpath = f"{base}.content_routes[{j}]"
                if route.path in seen_paths:
                    r.add(
                        "warning", "OPS007", f"{rpath}.path",
                        f"Duplicate route path {route.path!r} - earlier entry will shadow this one.",
                    )
                seen_paths.add(route.path)

                if route.rate_limit is None or not route.rate_limit.enabled:
                    r.add(
                        "warning", "SEC004", f"{rpath}.rate_limit",
                        f"Content route {route.path!r} has NO rate limiting. "
                        "Analysts/scanners can hammer payload downloads and "
                        "fingerprint the redirector.",
                    )
                else:
                    if route.rate_limit.max_downloads > 100:
                        r.add(
                            "info", "OPS008", f"{rpath}.rate_limit.max_downloads",
                            f"max_downloads={route.rate_limit.max_downloads} is generous; "
                            "consider tighter limits for payload delivery.",
                        )

                # Backend TLS verify
                be = route.backend
                if be.target.startswith("https://") and not be.ssl_verify:
                    r.add(
                        "warning", "TLS004", f"{rpath}.backend.ssl_verify",
                        f"TLS verification DISABLED for backend {be.target}.",
                    )
                if be.type in ("pwndrop", "http_proxy") and not be.auth_token:
                    r.add(
                        "warning", "SEC005", f"{rpath}.backend.auth_token",
                        f"Backend {be.type} at {be.target} has no auth_token. "
                        "Anyone who can reach the backend can pull payloads.",
                    )
                if be.auth_token and len(be.auth_token) < self.MIN_TOKEN_LENGTH:
                    r.add(
                        "warning", "SEC006", f"{rpath}.backend.auth_token",
                        f"Backend auth_token is only {len(be.auth_token)} chars.",
                    )

            # Campaign token
            ct = dom.campaign_token
            if ct.enabled and not ct.tokens and not ct.hmac_secret:
                r.add(
                    "error", "SEC007", f"{base}.campaign_token",
                    "Campaign token validation is enabled but neither static "
                    "tokens nor an hmac_secret are configured - every request "
                    "will fail validation.",
                )

    def _check_pipeline(self, r: ValidationReport) -> None:
        p = self.cfg.pipeline
        thr = p.block_score_threshold

        if not 0.0 <= thr <= 1.0:
            r.add(
                "error", "OPS009", "pipeline.block_score_threshold",
                f"Threshold {thr} is outside [0.0, 1.0].",
            )
        elif thr < 0.3:
            r.add(
                "warning", "OPS010", "pipeline.block_score_threshold",
                f"Block threshold {thr} is very low - will block legitimate target traffic.",
            )
        elif thr > 0.95:
            r.add(
                "warning", "OPS011", "pipeline.block_score_threshold",
                f"Block threshold {thr} is very high - scanners will likely pass.",
            )

        disabled = [
            name for name in (
                "ip", "bot", "header", "geo", "dns", "replay", "profile",
            )
            if not getattr(p, f"enable_{name}_filter", True)
        ]
        if len(disabled) >= 3:
            r.add(
                "warning", "SEC008", "pipeline",
                f"Multiple core filters disabled: {', '.join(disabled)}. "
                "Redirector is exposed to scanners and sandboxes.",
            )

    def _check_intel(self, r: ValidationReport) -> None:
        intel = self.cfg.intel

        if intel.geoip_db is None and (intel.blocked_countries or intel.allowed_countries):
            r.add(
                "error", "OPS012", "intel.geoip_db",
                "Country allow/block lists configured but no geoip_db path set - "
                "GeoIP lookups will fail at runtime.",
            )

        both = set(intel.blocked_countries) & set(intel.allowed_countries)
        if both:
            r.add(
                "error", "OPS013", "intel",
                f"Countries present in BOTH blocked and allowed lists: "
                f"{', '.join(sorted(both))}.",
            )

        if intel.feeds.enabled and not intel.feeds.urls:
            r.add(
                "info", "OPS014", "intel.feeds",
                "Threat feeds enabled but no URLs configured.",
            )

        if intel.banned_ip_file:
            p = Path(intel.banned_ip_file)
            if not p.is_absolute() and self.source is not None:
                p = self.source.parent / p
            if not p.exists():
                r.add(
                    "warning", "OPS015", "intel.banned_ip_file",
                    f"banned_ip_file {intel.banned_ip_file} does not exist.",
                )

    def _check_payload_tokens(self, r: ValidationReport) -> None:
        pt = self.cfg.payload_tokens
        if not pt.enabled:
            return
        if pt.default_ttl_seconds > 86400:
            r.add(
                "info", "SEC009", "payload_tokens.default_ttl_seconds",
                f"Token TTL is {pt.default_ttl_seconds}s (>24h). Long-lived "
                "tokens increase replay risk if a URL leaks.",
            )
        if pt.default_max_uses > 5:
            r.add(
                "info", "SEC010", "payload_tokens.default_max_uses",
                f"default_max_uses={pt.default_max_uses}; 1 is the safest "
                "for one-time payload delivery.",
            )

    def _check_phishingclub(self, r: ValidationReport) -> None:
        pc = self.cfg.phishingclub
        if pc.enabled and not pc.webhook_secret:
            r.add(
                "error", "SEC011", "phishingclub.webhook_secret",
                "PhishingClub webhook enabled without a webhook_secret - "
                "anyone can forge campaign events and poison the allowlist.",
            )

    def _check_tls_files(self, r: ValidationReport) -> None:
        """Best-effort existence check for referenced TLS material."""
        for i, lst in enumerate(self.cfg.listeners):
            if lst.tls is None:
                continue
            for label, p in (("cert", lst.tls.cert), ("key", lst.tls.key)):
                if not Path(p).exists():
                    r.add(
                        "error", "TLS005", f"listeners[{i}].tls.{label}",
                        f"TLS {label} file not found: {p}",
                    )

    # -- helpers ------------------------------------------------------------

    def _check_cidr(self, r: ValidationReport, cidr: str, path: str) -> None:
        """Flag malformed or overly broad CIDRs."""
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            r.add("error", "NET001", path, f"Invalid CIDR: {cidr!r}")
            return

        if net.version == 4 and net.prefixlen <= self.BROAD_V4_PREFIX:
            r.add(
                "warning", "SEC012", path,
                f"CIDR {cidr} is very broad (/{net.prefixlen}). Whitelisting "
                "an entire /8 or broader defeats the purpose of IP filtering.",
            )
        elif net.version == 6 and net.prefixlen <= self.BROAD_V6_PREFIX:
            r.add(
                "warning", "SEC012", path,
                f"IPv6 CIDR {cidr} is very broad (/{net.prefixlen}).",
            )


# ---------------------------------------------------------------------------
# Convenience
# ---------------------------------------------------------------------------


def validate_file(path: Path) -> ValidationReport:
    """Schema + semantic validation of a config file."""
    try:
        cfg = load_config(path)
    except ValidationError as e:
        return ValidationReport(schema_error=str(e))
    except Exception as e:  # YAML errors, decryption failures, etc.
        return ValidationReport(schema_error=f"{type(e).__name__}: {e}")
    return ConfigValidator(cfg, source=path).validate()
