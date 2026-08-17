"""CLI commands for managing scheduled rotation policies.

Commands:
    infraguard schedule add      - add a rotation policy to the config
    infraguard schedule list     - list configured rotation policies
    infraguard schedule remove   - remove a rotation policy by name

These commands modify the YAML config file directly (same pattern as
``infraguard config set``). The rotation scheduler reads the config at
startup and on SIGHUP reload.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

import click
import yaml

# ---------------------------------------------------------------------------
# Helpers (mirrors infraguard.config.cli_ext patterns)
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
        click.echo(
            f"Backup saved at {config_path.with_suffix(config_path.suffix + '.bak')}",
            err=True,
        )
        sys.exit(1)


def _ensure_rotation(data: dict) -> dict:
    """Ensure the rotation section exists in raw config dict."""
    if "rotation" not in data or not isinstance(data["rotation"], dict):
        data["rotation"] = {}
    rot = data["rotation"]
    if "policies" not in rot or not isinstance(rot["policies"], list):
        rot["policies"] = []
    return rot


# ---------------------------------------------------------------------------
# schedule CLI group
# ---------------------------------------------------------------------------


@click.group("schedule")
def schedule_group() -> None:
    """Manage automated rotation policies."""


# ---------------------------------------------------------------------------
# schedule add
# ---------------------------------------------------------------------------


@schedule_group.command("add")
@click.option("--name", required=True, help="Unique name for this policy.")
@click.option(
    "--type",
    "policy_type",
    type=click.Choice(["schedule", "on_burn_detected", "on_threshold", "stagger"]),
    default="schedule",
    show_default=True,
    help="Rotation trigger type.",
)
@click.option(
    "--domain",
    "domains",
    multiple=True,
    help="Domain(s) to rotate. Repeat for multiple. Empty = all domains.",
)
@click.option(
    "--provider",
    type=click.Choice(["aws", "azure", "do", "cloudflare", "hetzner"]),
    default="do",
    show_default=True,
    help="Cloud provider for replacement instances.",
)
@click.option("--region", default=None, help="Cloud region override.")
@click.option("--instance-size", default=None, help="Instance size/type override.")
@click.option(
    "--ssh-key",
    default="",
    help="Path to SSH public key file.",
)
@click.option(
    "--operator-ip",
    default="",
    help="Operator IP in CIDR notation (e.g. 1.2.3.4/32).",
)
@click.option("--upstream", default="", help="C2 teamserver URL.")
@click.option("--c2-profile", default="", help="Path to C2 profile file.")
@click.option(
    "--interval-hours",
    type=float,
    default=24.0,
    show_default=True,
    help="Hours between rotations (schedule/stagger types).",
)
@click.option(
    "--request-threshold",
    type=int,
    default=10000,
    show_default=True,
    help="Request count to trigger rotation (on_threshold type).",
)
@click.option(
    "--threshold-window",
    type=int,
    default=3600,
    show_default=True,
    help="Rolling window in seconds for request counting (on_threshold type).",
)
@click.option(
    "--stagger-delay",
    type=int,
    default=30,
    show_default=True,
    help="Minutes between rotating each domain (stagger type).",
)
@click.option(
    "--burn-cooldown",
    type=int,
    default=5,
    show_default=True,
    help="Minutes to wait after burn detection before rotating (on_burn_detected type).",
)
@click.option("--state-key", default=None, help="age public key for state encryption.")
@click.option(
    "--state-identity",
    default=None,
    help="Path to age identity file for state decryption.",
)
@click.option("--disabled", is_flag=True, help="Create the policy in disabled state.")
@_CONFIG_OPT
def schedule_add(
    name: str,
    policy_type: str,
    domains: tuple[str, ...],
    provider: str,
    region: str | None,
    instance_size: str | None,
    ssh_key: str,
    operator_ip: str,
    upstream: str,
    c2_profile: str,
    interval_hours: float,
    request_threshold: int,
    threshold_window: int,
    stagger_delay: int,
    burn_cooldown: int,
    state_key: str | None,
    state_identity: str | None,
    disabled: bool,
    config_path: Path,
) -> None:
    """Add a rotation policy to the configuration.

    \b
    Examples:
      # Rotate all domains every 12 hours via DigitalOcean
      infraguard schedule add --name nightly --type schedule \\
          --interval-hours 12 --provider do --ssh-key ~/.ssh/id_rsa.pub \\
          --operator-ip 1.2.3.4/32 --upstream https://10.0.0.5:8443

      # Rotate on burn detection for specific domains
      infraguard schedule add --name burn-response --type on_burn_detected \\
          --domain c2.example.com --provider do --ssh-key ~/.ssh/id_rsa.pub \\
          --operator-ip 1.2.3.4/32 --upstream https://10.0.0.5:8443

      # Rotate after 50k requests per domain
      infraguard schedule add --name high-traffic --type on_threshold \\
          --request-threshold 50000 --provider aws ...
    """
    data = _load_raw(config_path)
    rot = _ensure_rotation(data)

    # Check for duplicate name
    existing_names = {p.get("name") for p in rot["policies"]}
    if name in existing_names:
        click.echo(
            f"Policy '{name}' already exists. Remove it first or use a different name.",
            err=True,
        )
        sys.exit(1)

    policy_dict: dict = {
        "name": name,
        "type": policy_type,
        "enabled": not disabled,
        "domains": list(domains),
        "provider": provider,
        "ssh_key": ssh_key,
        "operator_ip": operator_ip,
        "upstream": upstream,
        "c2_profile": c2_profile,
        "interval_hours": interval_hours,
        "request_threshold": request_threshold,
        "threshold_window_seconds": threshold_window,
        "stagger_delay_minutes": stagger_delay,
        "burn_cooldown_minutes": burn_cooldown,
    }
    if region:
        policy_dict["region"] = region
    if instance_size:
        policy_dict["instance_size"] = instance_size
    if state_key:
        policy_dict["state_key"] = state_key
    if state_identity:
        policy_dict["state_identity"] = state_identity

    rot["policies"].append(policy_dict)

    # Enable rotation globally if not already
    if not rot.get("enabled"):
        rot["enabled"] = True
        click.echo("Note: set rotation.enabled = true (was not set)")

    _save_raw(config_path, data)
    _validate(config_path)

    click.echo(f"Policy '{name}' added ({policy_type}).")
    click.echo(f"  Domains: {', '.join(domains) if domains else '(all)'}")
    click.echo(f"  Provider: {provider}")
    if policy_type == "schedule":
        click.echo(f"  Interval: every {interval_hours}h")
    elif policy_type == "on_threshold":
        click.echo(f"  Threshold: {request_threshold} requests / {threshold_window}s")
    elif policy_type == "stagger":
        click.echo(f"  Stagger delay: {stagger_delay}m between domains")
    elif policy_type == "on_burn_detected":
        click.echo(f"  Burn cooldown: {burn_cooldown}m")


# ---------------------------------------------------------------------------
# schedule list
# ---------------------------------------------------------------------------


@schedule_group.command("list")
@_CONFIG_OPT
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
def schedule_list(config_path: Path, as_json: bool) -> None:
    """List all configured rotation policies."""
    data = _load_raw(config_path)
    rot = _ensure_rotation(data)
    policies = rot.get("policies", [])

    if as_json:
        click.echo(yaml.dump({"rotation": rot}, default_flow_style=False, allow_unicode=True))
        return

    if not policies:
        click.echo("No rotation policies configured.")
        enabled = rot.get("enabled", False)
        click.echo(f"Rotation scheduler: {'enabled' if enabled else 'disabled'}")
        return

    enabled = rot.get("enabled", False)
    click.echo(f"Rotation scheduler: {'enabled' if enabled else 'disabled'}")
    click.echo(f"Check interval: {rot.get('check_interval_seconds', 60)}s")
    click.echo()

    # Table header
    click.echo(
        f"  {'Name':<20} {'Type':<18} {'Enabled':<8} {'Provider':<10} "
        f"{'Domains':<30} {'Rotations':<10} Details"
    )
    click.echo(f"  {'-' * 120}")

    for p in policies:
        name = p.get("name", "?")
        ptype = p.get("type", "schedule")
        en = "yes" if p.get("enabled", True) else "no"
        provider = p.get("provider", "?")
        domains = p.get("domains", [])
        domain_str = ", ".join(domains) if domains else "(all)"
        if len(domain_str) > 28:
            domain_str = domain_str[:25] + "..."
        rotations = p.get("rotation_count", 0)

        # Build detail string based on type
        details = ""
        if ptype == "schedule":
            details = f"every {p.get('interval_hours', 24)}h"
        elif ptype == "on_threshold":
            details = (
                f">{p.get('request_threshold', 10000)} reqs"
                f" / {p.get('threshold_window_seconds', 3600)}s"
            )
        elif ptype == "stagger":
            details = (
                f"every {p.get('interval_hours', 24)}h,"
                f" {p.get('stagger_delay_minutes', 30)}m apart"
            )
        elif ptype == "on_burn_detected":
            details = f"cooldown {p.get('burn_cooldown_minutes', 5)}m"

        click.echo(
            f"  {name:<20} {ptype:<18} {en:<8} {provider:<10} "
            f"{domain_str:<30} {rotations:<10} {details}"
        )

    click.echo()


# ---------------------------------------------------------------------------
# schedule remove
# ---------------------------------------------------------------------------


@schedule_group.command("remove")
@click.argument("name")
@_CONFIG_OPT
@click.confirmation_option(prompt="Remove this rotation policy?")
def schedule_remove(name: str, config_path: Path) -> None:
    """Remove a rotation policy by name."""
    data = _load_raw(config_path)
    rot = _ensure_rotation(data)
    policies = rot.get("policies", [])

    original_len = len(policies)
    rot["policies"] = [p for p in policies if p.get("name") != name]

    if len(rot["policies"]) == original_len:
        click.echo(f"Policy '{name}' not found.", err=True)
        sys.exit(1)

    # Disable rotation globally if no policies remain
    if not rot["policies"]:
        rot["enabled"] = False
        click.echo("Note: no policies remain, rotation.enabled set to false")

    _save_raw(config_path, data)
    _validate(config_path)

    click.echo(f"Policy '{name}' removed.")
