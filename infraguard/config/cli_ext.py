"""Extended CLI commands for interactive config management.

Note: InfraGuard configs are YAML. These commands load the file as a plain dict,
modify it, and write it back. YAML comments are not preserved (pyyaml limitation).
A .bak file is always written before any modification.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path
from typing import Any

import click
import yaml

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_CONFIG_OPT = click.option(
    "-c",
    "--config",
    "config_path",
    type=click.Path(path_type=Path),
    default=Path("config.yaml"),
    show_default=True,
    help="Path to config file.",
)


def _load_raw(config_path: Path) -> dict:
    if not config_path.exists():
        click.echo(f"Config not found: {config_path}", err=True)
        sys.exit(1)
    with config_path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return data


def _save_raw(config_path: Path, data: dict) -> None:
    bak = config_path.with_suffix(config_path.suffix + ".bak")
    shutil.copy2(config_path, bak)
    with config_path.open("w", encoding="utf-8") as f:
        yaml.dump(data, f, default_flow_style=False, allow_unicode=True, sort_keys=False)


def _validate(config_path: Path) -> None:
    from infraguard.config.loader import load_config
    try:
        load_config(config_path)
    except Exception as e:
        click.echo(f"Validation failed after write: {e}", err=True)
        click.echo(f"Backup saved at {config_path.with_suffix(config_path.suffix + '.bak')}", err=True)
        sys.exit(1)


def _deep_get(d: dict, keys: list[str]) -> Any:
    for k in keys:
        if not isinstance(d, dict) or k not in d:
            return None
        d = d[k]
    return d


def _deep_set(d: dict, keys: list[str], value: Any) -> None:
    for k in keys[:-1]:
        d = d.setdefault(k, {})
    d[keys[-1]] = value


def _deep_ensure_list(d: dict, keys: list[str]) -> list:
    for k in keys[:-1]:
        d = d.setdefault(k, {})
    lst = d.setdefault(keys[-1], [])
    if not isinstance(lst, list):
        lst = []
        d[keys[-1]] = lst
    return lst


def _coerce(value: str) -> Any:
    """Try to parse value as int, float, bool, then fall back to str."""
    if value.lower() in ("true", "yes"):
        return True
    if value.lower() in ("false", "no"):
        return False
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        pass
    return value


# ---------------------------------------------------------------------------
# config show
# ---------------------------------------------------------------------------


@click.command("show")
@_CONFIG_OPT
@click.option("--domain", default=None, help="Show detail for a specific domain.")
@click.option("--section", default=None, help="Show a specific top-level section (e.g. pipeline, intel).")
@click.option("--raw", is_flag=True, help="Dump raw YAML instead of formatted summary.")
def show_config(config_path: Path, domain: str | None, section: str | None, raw: bool) -> None:
    """Print a formatted summary of the current config."""
    data = _load_raw(config_path)

    if raw:
        click.echo(yaml.dump(data, default_flow_style=False, allow_unicode=True, sort_keys=False))
        return

    if section:
        sub = data.get(section)
        if sub is None:
            click.echo(f"Section '{section}' not found.", err=True)
            sys.exit(1)
        click.echo(yaml.dump({section: sub}, default_flow_style=False, allow_unicode=True, sort_keys=False))
        return

    if domain:
        domains = data.get("domains", {})
        d = domains.get(domain)
        if d is None:
            click.echo(f"Domain '{domain}' not configured.", err=True)
            sys.exit(1)
        click.echo(yaml.dump({domain: d}, default_flow_style=False, allow_unicode=True, sort_keys=False))
        return

    # Full summary
    domains = data.get("domains", {})
    listeners = data.get("listeners", [])
    plugins = data.get("plugins", [])
    pipeline = data.get("pipeline", {})
    intel = data.get("intel", {})

    click.secho("=== InfraGuard Config ===", bold=True)
    click.echo(f"  File:      {config_path.resolve()}")
    click.echo(f"  Domains:   {', '.join(domains.keys()) or '(none)'}")
    click.echo(f"  Listeners: {len(listeners)}")
    for lst in listeners:
        click.echo(f"    {lst.get('protocol','http')}  {lst.get('bind','0.0.0.0')}:{lst.get('port',443)}")

    click.secho("\n--- Domains ---", bold=True)
    for name, d in domains.items():
        profile_type = d.get("profile_type", "?")
        upstream = d.get("upstream", "?")
        drop = (d.get("drop_action") or {}).get("type", "?")
        routes = len(d.get("content_routes") or [])
        click.echo(f"  {name}")
        click.echo(f"    upstream:     {upstream}")
        click.echo(f"    profile_type: {profile_type}")
        click.echo(f"    drop_action:  {drop}")
        click.echo(f"    content_routes: {routes}")

    click.secho("\n--- Pipeline ---", bold=True)
    filters = {
        "ip": pipeline.get("enable_ip_filter", True),
        "bot": pipeline.get("enable_bot_filter", True),
        "header": pipeline.get("enable_header_filter", True),
        "geo": pipeline.get("enable_geo_filter", True),
        "dns": pipeline.get("enable_dns_filter", True),
        "replay": pipeline.get("enable_replay_filter", True),
        "profile": pipeline.get("enable_profile_filter", True),
        "sandbox": pipeline.get("enable_sandbox_filter", True),
        "enumeration": pipeline.get("enable_enumeration_filter", True),
        "ja3": pipeline.get("enable_ja3_filter", True),
    }
    threshold = pipeline.get("block_score_threshold", 0.6)
    click.echo(f"  Block threshold: {threshold}")
    for fname, enabled in filters.items():
        status = click.style("ON ", fg="green") if enabled else click.style("OFF", fg="red")
        click.echo(f"  [{status}] {fname}_filter")

    click.secho("\n--- Intel ---", bold=True)
    blocked_cc = intel.get("blocked_countries") or []
    allowed_cc = intel.get("allowed_countries") or []
    blocked_asns = intel.get("blocked_asns") or []
    click.echo(f"  Blocked countries:  {', '.join(blocked_cc) or '(none)'}")
    click.echo(f"  Allowed countries:  {', '.join(allowed_cc) or '(none)'}")
    click.echo(f"  Blocked ASNs:       {', '.join(str(a) for a in blocked_asns) or '(none)'}")
    feeds = intel.get("feeds", {})
    click.echo(f"  Feeds enabled:      {feeds.get('enabled', True)}")
    click.echo(f"  Plugins:  {', '.join(plugins) or '(none)'}")


# ---------------------------------------------------------------------------
# config set  KEY  VALUE
# ---------------------------------------------------------------------------


@click.command("set")
@_CONFIG_OPT
@click.argument("key")
@click.argument("value")
@click.option("--no-validate", is_flag=True, help="Skip validation after write.")
def set_value(config_path: Path, key: str, value: str, no_validate: bool) -> None:
    """Set a scalar config value by dot-path key.

    \b
    Examples:
      infraguard config set pipeline.block_score_threshold 0.7
      infraguard config set intel.dynamic_whitelist_threshold 3
      infraguard config set logging.level debug
    """
    data = _load_raw(config_path)
    keys = key.split(".")
    coerced = _coerce(value)
    _deep_set(data, keys, coerced)
    _save_raw(config_path, data)
    if not no_validate:
        _validate(config_path)
    click.echo(f"Set {key} = {coerced!r}")


# ---------------------------------------------------------------------------
# config domain  subgroup
# ---------------------------------------------------------------------------


@click.group("domain")
def domain_group() -> None:
    """Manage domain entries."""


@domain_group.command("list")
@_CONFIG_OPT
def domain_list(config_path: Path) -> None:
    """List configured domains."""
    data = _load_raw(config_path)
    domains = data.get("domains", {})
    if not domains:
        click.echo("No domains configured.")
        return
    for name, d in domains.items():
        click.echo(f"  {name}  ->  {d.get('upstream','?')}  [{d.get('profile_type','?')}]")


@domain_group.command("add")
@_CONFIG_OPT
@click.argument("domain")
@click.argument("upstream")
@click.option(
    "--profile-type",
    default="cobalt_strike",
    type=click.Choice(["cobalt_strike", "mythic", "brute_ratel", "sliver", "havoc",
                       "nighthawk", "poshc2", "gophish", "evilginx", "cuddlephish",
                       "phishing_club", "passthrough"]),
    show_default=True,
    help="C2/phishing framework type.",
)
@click.option("--profile-path", default="", help="Path to C2 profile file.")
@click.option("--drop-target", default="https://www.google.com", show_default=True, help="Redirect URL for blocked traffic.")
@click.option(
    "--drop-type",
    default="redirect",
    type=click.Choice(["redirect", "reset", "proxy", "tarpit", "decoy"]),
    show_default=True,
    help="Drop action type.",
)
def domain_add(
    config_path: Path,
    domain: str,
    upstream: str,
    profile_type: str,
    profile_path: str,
    drop_target: str,
    drop_type: str,
) -> None:
    """Add a new domain entry.

    \b
    Examples:
      infraguard config domain add c2.example.com https://10.0.0.5:8443 --profile-type sliver
      infraguard config domain add phish.evil.co https://127.0.0.1:8000 --profile-type phishing_club
      infraguard config domain add phish.evil.co https://10.0.0.6:80 --profile-type gophish
    """
    data = _load_raw(config_path)
    domains = data.setdefault("domains", {})
    if domain in domains:
        click.confirm(f"Domain '{domain}' already exists. Overwrite?", abort=True)
    domains[domain] = {
        "upstream": upstream,
        "profile_type": profile_type,
        "profile_path": profile_path,
        "drop_action": {
            "type": drop_type,
            "target": drop_target,
        },
    }
    _save_raw(config_path, data)
    _validate(config_path)
    click.echo(f"Added domain '{domain}' -> {upstream} [{profile_type}]")


@domain_group.command("remove")
@_CONFIG_OPT
@click.argument("domain")
def domain_remove(config_path: Path, domain: str) -> None:
    """Remove a domain entry."""
    data = _load_raw(config_path)
    domains = data.get("domains", {})
    if domain not in domains:
        click.echo(f"Domain '{domain}' not found.", err=True)
        sys.exit(1)
    click.confirm(f"Remove domain '{domain}'?", abort=True)
    del domains[domain]
    _save_raw(config_path, data)
    _validate(config_path)
    click.echo(f"Removed domain '{domain}'.")


@domain_group.command("set-upstream")
@_CONFIG_OPT
@click.argument("domain")
@click.argument("upstream")
def domain_set_upstream(config_path: Path, domain: str, upstream: str) -> None:
    """Change the upstream URL for a domain."""
    data = _load_raw(config_path)
    domains = data.get("domains", {})
    if domain not in domains:
        click.echo(f"Domain '{domain}' not found.", err=True)
        sys.exit(1)
    domains[domain]["upstream"] = upstream
    _save_raw(config_path, data)
    _validate(config_path)
    click.echo(f"'{domain}' upstream -> {upstream}")


@domain_group.command("set-drop")
@_CONFIG_OPT
@click.argument("domain")
@click.argument("target")
@click.option(
    "--type",
    "drop_type",
    default="redirect",
    type=click.Choice(["redirect", "reset", "proxy", "tarpit", "decoy"]),
    show_default=True,
)
def domain_set_drop(config_path: Path, domain: str, target: str, drop_type: str) -> None:
    """Set the drop action for a domain."""
    data = _load_raw(config_path)
    domains = data.get("domains", {})
    if domain not in domains:
        click.echo(f"Domain '{domain}' not found.", err=True)
        sys.exit(1)
    domains[domain].setdefault("drop_action", {})["type"] = drop_type
    domains[domain]["drop_action"]["target"] = target
    _save_raw(config_path, data)
    _validate(config_path)
    click.echo(f"'{domain}' drop_action -> {drop_type} {target}")


@domain_group.command("add-route")
@_CONFIG_OPT
@click.argument("domain")
@click.argument("path")
@click.argument("backend_url")
@click.option(
    "--backend-type",
    default="http_proxy",
    type=click.Choice(["pwndrop", "filesystem", "http_proxy", "mythic_file"]),
    show_default=True,
    help="Content backend type.",
)
@click.option("--require-token", is_flag=True, help="Require one-time payload token.")
@click.option("--require-beacon-ip", is_flag=True, help="Require whitelisted beacon IP (guard).")
@click.option("--rate-limit", type=int, default=None, help="Max downloads per window (enables rate limiting).")
@click.option("--methods", default="GET", show_default=True, help="Allowed HTTP methods (comma-separated).")
def domain_add_route(
    config_path: Path,
    domain: str,
    path: str,
    backend_url: str,
    backend_type: str,
    require_token: bool,
    require_beacon_ip: bool,
    rate_limit: int | None,
    methods: str,
) -> None:
    """Add a content route to a domain.

    \b
    Examples:
      infraguard config domain add-route c2.evil.co /dl/agent.exe https://10.0.0.5/files/agent.exe
      infraguard config domain add-route c2.evil.co /d/{file_id} https://192.168.1.10:7443 --backend-type mythic_file
    """
    data = _load_raw(config_path)
    domains = data.get("domains", {})
    if domain not in domains:
        click.echo(f"Domain '{domain}' not found.", err=True)
        sys.exit(1)

    routes = domains[domain].setdefault("content_routes", [])
    existing = [r for r in routes if r.get("path") == path]
    if existing:
        click.confirm(f"Route '{path}' already exists for '{domain}'. Overwrite?", abort=True)
        routes[:] = [r for r in routes if r.get("path") != path]

    route: dict[str, Any] = {
        "path": path,
        "backend": {
            "type": backend_type,
            "target": backend_url,
        },
        "methods": [m.strip().upper() for m in methods.split(",")],
        "track": True,
    }
    if require_token:
        route["require_token"] = True
    if require_beacon_ip:
        route["guard"] = {"require_beacon_ip": True}
    if rate_limit is not None:
        route["rate_limit"] = {"enabled": True, "max_downloads": rate_limit, "window_seconds": 300}

    routes.append(route)
    _save_raw(config_path, data)
    _validate(config_path)
    click.echo(f"Added route '{path}' to '{domain}' [{backend_type} -> {backend_url}]")


@domain_group.command("remove-route")
@_CONFIG_OPT
@click.argument("domain")
@click.argument("path")
def domain_remove_route(config_path: Path, domain: str, path: str) -> None:
    """Remove a content route from a domain."""
    data = _load_raw(config_path)
    domains = data.get("domains", {})
    if domain not in domains:
        click.echo(f"Domain '{domain}' not found.", err=True)
        sys.exit(1)
    routes = domains[domain].get("content_routes", [])
    before = len(routes)
    domains[domain]["content_routes"] = [r for r in routes if r.get("path") != path]
    if len(domains[domain]["content_routes"]) == before:
        click.echo(f"Route '{path}' not found under '{domain}'.", err=True)
        sys.exit(1)
    _save_raw(config_path, data)
    _validate(config_path)
    click.echo(f"Removed route '{path}' from '{domain}'.")


@domain_group.command("list-routes")
@_CONFIG_OPT
@click.argument("domain")
def domain_list_routes(config_path: Path, domain: str) -> None:
    """List content routes for a domain."""
    data = _load_raw(config_path)
    domains = data.get("domains", {})
    if domain not in domains:
        click.echo(f"Domain '{domain}' not found.", err=True)
        sys.exit(1)
    routes = domains[domain].get("content_routes") or []
    if not routes:
        click.echo(f"No content routes for '{domain}'.")
        return
    click.echo(f"Content routes for '{domain}':")
    for r in routes:
        be = r.get("backend", {})
        flags = []
        if r.get("require_token"):
            flags.append("token-gated")
        if (r.get("guard") or {}).get("require_beacon_ip"):
            flags.append("beacon-ip-only")
        if r.get("rate_limit", {}).get("enabled"):
            flags.append(f"rate-limit={r['rate_limit']['max_downloads']}")
        flag_str = "  [" + ", ".join(flags) + "]" if flags else ""
        click.echo(f"  {r.get('path')}  ->  {be.get('type')} {be.get('target')}{flag_str}")


# ---------------------------------------------------------------------------
# config intel  subgroup
# ---------------------------------------------------------------------------


@click.group("intel")
def intel_group() -> None:
    """Manage IP/geo/ASN intelligence settings."""


@intel_group.command("show")
@_CONFIG_OPT
def intel_show(config_path: Path) -> None:
    """Show current intel configuration."""
    data = _load_raw(config_path)
    intel = data.get("intel", {})
    click.echo(yaml.dump({"intel": intel}, default_flow_style=False, allow_unicode=True, sort_keys=False))


@intel_group.command("block-country")
@_CONFIG_OPT
@click.argument("country_code")
def intel_block_country(config_path: Path, country_code: str) -> None:
    """Block traffic from a country (2-letter ISO code).

    \b
    Example:
      infraguard config intel block-country CN
    """
    cc = country_code.upper()
    data = _load_raw(config_path)
    lst = _deep_ensure_list(data, ["intel", "blocked_countries"])
    allowed = data.get("intel", {}).get("allowed_countries") or []
    if cc in allowed:
        click.echo(f"Warning: {cc} is in allowed_countries - remove it first with unallow-country.", err=True)
    if cc not in lst:
        lst.append(cc)
        _save_raw(config_path, data)
        _validate(config_path)
        click.echo(f"Blocking country: {cc}")
    else:
        click.echo(f"{cc} already in blocked_countries.")


@intel_group.command("unblock-country")
@_CONFIG_OPT
@click.argument("country_code")
def intel_unblock_country(config_path: Path, country_code: str) -> None:
    """Remove a country from the block list."""
    cc = country_code.upper()
    data = _load_raw(config_path)
    lst = _deep_ensure_list(data, ["intel", "blocked_countries"])
    if cc in lst:
        lst.remove(cc)
        _save_raw(config_path, data)
        _validate(config_path)
        click.echo(f"Unblocked country: {cc}")
    else:
        click.echo(f"{cc} not in blocked_countries.")


@intel_group.command("allow-country")
@_CONFIG_OPT
@click.argument("country_code")
def intel_allow_country(config_path: Path, country_code: str) -> None:
    """Add a country to the allowlist (all others blocked when list is non-empty)."""
    cc = country_code.upper()
    data = _load_raw(config_path)
    lst = _deep_ensure_list(data, ["intel", "allowed_countries"])
    if cc not in lst:
        lst.append(cc)
        _save_raw(config_path, data)
        _validate(config_path)
        click.echo(f"Allowed country: {cc}")
    else:
        click.echo(f"{cc} already in allowed_countries.")


@intel_group.command("unallow-country")
@_CONFIG_OPT
@click.argument("country_code")
def intel_unallow_country(config_path: Path, country_code: str) -> None:
    """Remove a country from the allowlist."""
    cc = country_code.upper()
    data = _load_raw(config_path)
    lst = _deep_ensure_list(data, ["intel", "allowed_countries"])
    if cc in lst:
        lst.remove(cc)
        _save_raw(config_path, data)
        _validate(config_path)
        click.echo(f"Removed {cc} from allowed_countries.")
    else:
        click.echo(f"{cc} not in allowed_countries.")


@intel_group.command("block-asn")
@_CONFIG_OPT
@click.argument("asn", type=int)
def intel_block_asn(config_path: Path, asn: int) -> None:
    """Block an Autonomous System Number.

    \b
    Example:
      infraguard config intel block-asn 15169   # Google
    """
    data = _load_raw(config_path)
    lst = _deep_ensure_list(data, ["intel", "blocked_asns"])
    if asn not in lst:
        lst.append(asn)
        _save_raw(config_path, data)
        _validate(config_path)
        click.echo(f"Blocking ASN: {asn}")
    else:
        click.echo(f"ASN {asn} already blocked.")


@intel_group.command("unblock-asn")
@_CONFIG_OPT
@click.argument("asn", type=int)
def intel_unblock_asn(config_path: Path, asn: int) -> None:
    """Remove an ASN from the block list."""
    data = _load_raw(config_path)
    lst = _deep_ensure_list(data, ["intel", "blocked_asns"])
    if asn in lst:
        lst.remove(asn)
        _save_raw(config_path, data)
        _validate(config_path)
        click.echo(f"Unblocked ASN: {asn}")
    else:
        click.echo(f"ASN {asn} not in blocked_asns.")


@intel_group.command("block-ip")
@_CONFIG_OPT
@click.argument("ip_or_cidr")
@click.option("--file", "append_file", default=None, type=click.Path(path_type=Path),
              help="Append to this file instead of config (for banned_ip_file).")
def intel_block_ip(config_path: Path, ip_or_cidr: str, append_file: Path | None) -> None:
    """Block an IP or CIDR range.

    \b
    Without --file: sets intel.banned_ip_file to a sidecar file and appends
    the entry to it.  If banned_ip_file is already set, appends to that file.

    With --file: appends the entry to the specified file unconditionally.

    \b
    Examples:
      infraguard config intel block-ip 198.51.100.0/24
      infraguard config intel block-ip 198.51.100.1 --file /etc/infraguard/banned.txt
    """
    data = _load_raw(config_path)
    intel = data.setdefault("intel", {})

    if append_file is None:
        existing_file = intel.get("banned_ip_file")
        if existing_file:
            append_file = Path(existing_file)
        else:
            # Create a sidecar file next to the config
            append_file = config_path.parent / "banned_ips.txt"
            intel["banned_ip_file"] = str(append_file)
            _save_raw(config_path, data)
            _validate(config_path)

    # Append to the file (create if needed)
    with append_file.open("a", encoding="utf-8") as f:
        f.write(ip_or_cidr + "\n")
    click.echo(f"Appended {ip_or_cidr} to {append_file}")


# ---------------------------------------------------------------------------
# config pipeline  subgroup
# ---------------------------------------------------------------------------

_FILTER_NAMES = [
    "ip", "bot", "header", "geo", "dns", "replay", "profile",
    "fingerprint", "enumeration", "sandbox", "ja3",
]


@click.group("pipeline")
def pipeline_group() -> None:
    """Manage request filter pipeline settings."""


@pipeline_group.command("show")
@_CONFIG_OPT
def pipeline_show(config_path: Path) -> None:
    """Show pipeline filter status and thresholds."""
    data = _load_raw(config_path)
    pipeline = data.get("pipeline", {})
    threshold = pipeline.get("block_score_threshold", 0.6)
    mode = pipeline.get("filter_mode", "scoring")
    click.echo(f"Mode:            {mode}")
    click.echo(f"Block threshold: {threshold}")
    click.echo()
    click.echo(f"{'Filter':<20} {'Status'}")
    click.echo("-" * 30)
    for name in _FILTER_NAMES:
        key = f"enable_{name}_filter"
        enabled = pipeline.get(key, True)
        status = click.style("ENABLED ", fg="green") if enabled else click.style("DISABLED", fg="red")
        click.echo(f"  {name + '_filter':<18} {status}")

    ja3_cfg = pipeline.get("ja3_filter", {})
    blocked_ja3 = ja3_cfg.get("blocked_ja3") or []
    allowed_ja3 = ja3_cfg.get("allowed_ja3") or []
    click.echo(f"\nJA3 blocked hashes ({len(blocked_ja3)}): {', '.join(blocked_ja3[:4]) or '(none)'}")
    if allowed_ja3:
        click.echo(f"JA3 allowed hashes ({len(allowed_ja3)}): {', '.join(allowed_ja3[:4])}")

    enum = {
        "unique_path_threshold": pipeline.get("enumeration_unique_path_threshold", 20),
        "suspect_threshold": pipeline.get("enumeration_unique_path_suspect_threshold", 8),
        "window_seconds": pipeline.get("enumeration_window_seconds", 60),
    }
    click.echo(f"\nEnumeration: block>{enum['unique_path_threshold']} paths, "
               f"suspect>{enum['suspect_threshold']}, window={enum['window_seconds']}s")


@pipeline_group.command("enable")
@_CONFIG_OPT
@click.argument("filter_name", type=click.Choice(_FILTER_NAMES))
def pipeline_enable(config_path: Path, filter_name: str) -> None:
    """Enable a filter in the pipeline."""
    data = _load_raw(config_path)
    _deep_set(data, ["pipeline", f"enable_{filter_name}_filter"], True)
    _save_raw(config_path, data)
    _validate(config_path)
    click.echo(f"Enabled {filter_name}_filter.")


@pipeline_group.command("disable")
@_CONFIG_OPT
@click.argument("filter_name", type=click.Choice(_FILTER_NAMES))
def pipeline_disable(config_path: Path, filter_name: str) -> None:
    """Disable a filter in the pipeline."""
    data = _load_raw(config_path)
    _deep_set(data, ["pipeline", f"enable_{filter_name}_filter"], False)
    _save_raw(config_path, data)
    _validate(config_path)
    click.echo(f"Disabled {filter_name}_filter.")


@pipeline_group.command("set-threshold")
@_CONFIG_OPT
@click.argument("threshold", type=float)
def pipeline_set_threshold(config_path: Path, threshold: float) -> None:
    """Set the block score threshold (0.0 – 1.0)."""
    if not 0.0 <= threshold <= 1.0:
        click.echo("Threshold must be between 0.0 and 1.0.", err=True)
        sys.exit(1)
    data = _load_raw(config_path)
    _deep_set(data, ["pipeline", "block_score_threshold"], threshold)
    _save_raw(config_path, data)
    _validate(config_path)
    click.echo(f"Block score threshold set to {threshold}")


@pipeline_group.group("ja3")
def pipeline_ja3_group() -> None:
    """Manage JA3 fingerprint block/allow lists."""


@pipeline_ja3_group.command("block")
@_CONFIG_OPT
@click.argument("hash_value")
def ja3_block(config_path: Path, hash_value: str) -> None:
    """Add a JA3 hash to the block list.

    \b
    Common scanner hashes:
      Masscan:         e7d705a3286e19ea42f587b344ee6865
      Python requests: 6734f37431670b3ab4292b8f60f29984
      curl:            b386946a5a44d1ddcc843bc75336dfce
      ZGrab2:          c35b0c7bd583d49d5b0f17de25ecdf7a
    """
    data = _load_raw(config_path)
    lst = _deep_ensure_list(data, ["pipeline", "ja3_filter", "blocked_ja3"])
    if hash_value not in lst:
        lst.append(hash_value)
        _save_raw(config_path, data)
        _validate(config_path)
        click.echo(f"JA3 blocked: {hash_value}")
    else:
        click.echo(f"{hash_value} already in blocked_ja3.")


@pipeline_ja3_group.command("unblock")
@_CONFIG_OPT
@click.argument("hash_value")
def ja3_unblock(config_path: Path, hash_value: str) -> None:
    """Remove a JA3 hash from the block list."""
    data = _load_raw(config_path)
    lst = _deep_ensure_list(data, ["pipeline", "ja3_filter", "blocked_ja3"])
    if hash_value in lst:
        lst.remove(hash_value)
        _save_raw(config_path, data)
        _validate(config_path)
        click.echo(f"JA3 unblocked: {hash_value}")
    else:
        click.echo(f"{hash_value} not in blocked_ja3.")


@pipeline_ja3_group.command("allow")
@_CONFIG_OPT
@click.argument("hash_value")
def ja3_allow(config_path: Path, hash_value: str) -> None:
    """Add a JA3 hash to the allowlist (enables allowlist mode - all others blocked)."""
    data = _load_raw(config_path)
    lst = _deep_ensure_list(data, ["pipeline", "ja3_filter", "allowed_ja3"])
    if hash_value not in lst:
        lst.append(hash_value)
        _save_raw(config_path, data)
        _validate(config_path)
        click.echo(f"JA3 allowed: {hash_value}  (allowlist mode now active)")
    else:
        click.echo(f"{hash_value} already in allowed_ja3.")


@pipeline_ja3_group.command("list")
@_CONFIG_OPT
def ja3_list(config_path: Path) -> None:
    """List all JA3 hash entries."""
    data = _load_raw(config_path)
    ja3_cfg = (data.get("pipeline") or {}).get("ja3_filter") or {}
    blocked = ja3_cfg.get("blocked_ja3") or []
    allowed = ja3_cfg.get("allowed_ja3") or []
    click.echo(f"Blocked ({len(blocked)}):")
    for h in blocked:
        click.echo(f"  {h}")
    if allowed:
        click.echo(f"Allowed ({len(allowed)}):")
        for h in allowed:
            click.echo(f"  {h}")
    else:
        click.echo("Allowed: (none - block list only, no allowlist)")


# ---------------------------------------------------------------------------
# config diff
# ---------------------------------------------------------------------------


@click.command("diff")
@_CONFIG_OPT
@click.argument("other", type=click.Path(path_type=Path), required=False)
@click.option(
    "--against-defaults",
    is_flag=True,
    help="Diff against the generated default config instead of another file.",
)
@click.option(
    "--ignore",
    multiple=True,
    help="Dot-path to ignore (repeatable), e.g. api.auth_token.",
)
@click.option("--no-color", is_flag=True, help="Disable colored output.")
def config_diff(
    config_path: Path,
    other: Path | None,
    against_defaults: bool,
    ignore: tuple[str, ...],
    no_color: bool,
) -> None:
    """Diff the active config against another file (or defaults).

    \b
    Examples:
      infraguard config diff other-config.yaml
      infraguard config diff --against-defaults
      infraguard -c prod.yaml config diff staging.yaml --ignore api.auth_token
    """
    from infraguard.config.diff import ConfigDiffer

    differ = ConfigDiffer(ignore_paths=ignore)
    try:
        if against_defaults:
            result = differ.diff_against_defaults(config_path)
            left_label = "defaults"
            right_label = str(config_path)
        else:
            if other is None:
                click.echo(
                    "Provide a file to diff against, or pass --against-defaults.",
                    err=True,
                )
                sys.exit(2)
            result = differ.diff_files(other, config_path)
            left_label = str(other)
            right_label = str(config_path)
    except FileNotFoundError as e:
        click.echo(str(e), err=True)
        sys.exit(1)

    color = not no_color
    click.secho(f"--- {left_label}", fg="red" if color else None)
    click.secho(f"+++ {right_label}", fg="green" if color else None)
    click.echo(differ.render(result, color=color))
    sys.exit(0 if not result else 1)


# ---------------------------------------------------------------------------
# config validate
# ---------------------------------------------------------------------------


@click.command("validate")
@_CONFIG_OPT
@click.option("--no-color", is_flag=True, help="Disable colored output.")
@click.option(
    "--strict",
    is_flag=True,
    help="Exit non-zero on warnings as well as errors.",
)
def config_validate(config_path: Path, no_color: bool, strict: bool) -> None:
    """Validate a config file (schema + security/best-practice checks).

    \b
    Checks for:
      - Empty or weak auth tokens
      - Disabled TLS verification on HTTPS upstreams/backends
      - Overly broad whitelist CIDRs (e.g. /8)
      - Missing rate limits on content routes
      - Listener TLS misconfiguration, filter coverage, and more
    """
    from infraguard.config.validator import validate_file

    report = validate_file(config_path)
    click.secho(f"Validating {config_path}\n", bold=True)
    click.echo(report.render(color=not no_color))

    if report.schema_error is not None or report.errors:
        sys.exit(1)
    if strict and report.warnings:
        sys.exit(1)
    sys.exit(0)


# ---------------------------------------------------------------------------
# config test
# ---------------------------------------------------------------------------


@click.command("test")
@_CONFIG_OPT
@click.option("--no-color", is_flag=True, help="Disable colored output.")
def config_test(config_path: Path, no_color: bool) -> None:
    """Full pre-flight test: schema load, semantic validation, diff vs defaults.

    Use this in CI or before restarting a production redirector.
    Exits 0 only when the config loads cleanly AND has no errors.
    """
    from infraguard.config.diff import ConfigDiffer
    from infraguard.config.validator import validate_file

    color = not no_color

    # 1. Schema + semantic validation
    click.secho(f"[1/2] Validating {config_path}", bold=True)
    report = validate_file(config_path)
    click.echo(report.render(color=color))

    # 2. Diff against defaults to surface non-standard settings
    click.secho("\n[2/2] Drift from defaults", bold=True)
    try:
        result = ConfigDiffer().diff_against_defaults(config_path)
        if result:
            click.echo(
                f"{len(result.changes)} setting(s) differ from generated defaults "
                "(informational only)."
            )
        else:
            click.echo("Config matches generated defaults.")
    except FileNotFoundError as e:
        click.echo(str(e), err=True)

    if report.schema_error is not None or report.errors:
        click.secho("\nTEST FAILED", fg="red" if color else None, bold=True)
        sys.exit(1)
    click.secho("\nTEST PASSED", fg="green" if color else None, bold=True)
    sys.exit(0)
