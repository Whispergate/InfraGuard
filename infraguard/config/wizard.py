"""Interactive CLI wizard for common InfraGuard tasks.

Provides step-by-step guided flows for:
    init            — create a starter configuration file
    deploy run      — provision a new cloud redirector
    deploy rotate   — rotate to a new redirector instance
    profile create  — convert a raw C2 profile to InfraGuard JSON

Each wizard collects parameters interactively with validation,
sensible defaults, and inline help text, then delegates to the
same underlying functions as the non-interactive CLI commands.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import click

# ── Shared helpers ────────────────────────────────────────────────────

_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
_URL_RE = re.compile(r"^https?://[^\s/$.?#].[^\s]*$", re.IGNORECASE)
_CIDR_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$")

_PROVIDERS = ["aws", "azure", "do", "cloudflare", "hetzner"]
_PROFILE_TYPES = [
    "cobalt_strike",
    "mythic",
    "mythic_http",
    "brute_ratel",
    "sliver",
    "havoc",
    "nighthawk",
    "poshc2",
    "gophish",
    "evilginx",
    "cuddlephish",
    "phishing_club",
    "passthrough",
]
_DROP_TYPES = ["redirect", "reset", "proxy", "tarpit", "decoy"]


def _banner(title: str) -> None:
    """Print a wizard section banner."""
    click.echo()
    click.secho(f"  ┌{'─' * (len(title) + 4)}┐", fg="cyan")
    click.secho(f"  │  {title}  │", fg="cyan", bold=True)
    click.secho(f"  └{'─' * (len(title) + 4)}┘", fg="cyan")
    click.echo()


def _prompt(
    label: str,
    default: str | None = None,
    help_text: str = "",
    required: bool = True,
    password: bool = False,
) -> str:
    """Prompt the user for a value with optional help text."""
    if help_text:
        click.echo(click.style(f"  ℹ  {help_text}", fg="bright_black"))

    kwargs: dict = {}
    if password:
        kwargs["hide_input"] = True
        kwargs["confirmation_prompt"] = False

    if default is not None:
        value = click.prompt(f"  {label}", default=default, show_default=True, **kwargs)
    elif required:
        value = click.prompt(f"  {label}", **kwargs)
    else:
        value = click.prompt(f"  {label}", default="", show_default=False, **kwargs)
    return value


def _prompt_choice(
    label: str,
    choices: list[str],
    default: str | None = None,
    help_text: str = "",
) -> str:
    """Prompt the user to pick from a list of choices."""
    if help_text:
        click.echo(click.style(f"  ℹ  {help_text}", fg="bright_black"))

    click.echo(f"  {label}:")
    for i, c in enumerate(choices, 1):
        marker = "→" if c == default else " "
        click.echo(f"    {marker} {i}. {c}")

    while True:
        raw = click.prompt(f"  Select (1-{len(choices)})", default=str(choices.index(default) + 1) if default else None)
        try:
            idx = int(raw) - 1
            if 0 <= idx < len(choices):
                return choices[idx]
        except ValueError:
            # Maybe they typed the name directly
            if raw.lower() in [c.lower() for c in choices]:
                return [c for c in choices if c.lower() == raw.lower()][0]
        click.echo(click.style(f"  Invalid selection: {raw}", fg="red"))


def _prompt_path(
    label: str,
    default: Path | None = None,
    must_exist: bool = False,
    help_text: str = "",
) -> Path:
    """Prompt for a file/directory path with optional existence check."""
    if help_text:
        click.echo(click.style(f"  ℹ  {help_text}", fg="bright_black"))

    while True:
        raw = _prompt(label, default=str(default) if default else None)
        p = Path(raw).expanduser()
        if must_exist and not p.exists():
            click.echo(click.style(f"  ✗ Path does not exist: {p}", fg="red"))
            continue
        return p


def _prompt_domain(label: str = "Domain", default: str | None = None, help_text: str = "") -> str:
    """Prompt for a domain name with basic validation."""
    if help_text:
        click.echo(click.style(f"  ℹ  {help_text}", fg="bright_black"))

    while True:
        value = _prompt(label, default=default)
        if _DOMAIN_RE.match(value):
            return value
        click.echo(click.style(f"  ✗ Invalid domain format: {value}", fg="red"))
        click.echo(click.style("    Expected: something.example.com", fg="bright_black"))


def _prompt_url(label: str = "URL", default: str | None = None, help_text: str = "") -> str:
    """Prompt for a URL with basic validation."""
    if help_text:
        click.echo(click.style(f"  ℹ  {help_text}", fg="bright_black"))

    while True:
        value = _prompt(label, default=default)
        if _URL_RE.match(value):
            return value
        click.echo(click.style(f"  ✗ Invalid URL: {value}", fg="red"))
        click.echo(click.style("    Expected: https://host:port or http://host", fg="bright_black"))


def _prompt_cidr(label: str = "IP/CIDR", default: str | None = None, help_text: str = "") -> str:
    """Prompt for an IP in CIDR notation with basic validation."""
    if help_text:
        click.echo(click.style(f"  ℹ  {help_text}", fg="bright_black"))

    while True:
        value = _prompt(label, default=default)
        if _CIDR_RE.match(value):
            # Validate octets and prefix length
            ip_part, prefix_part = value.split("/")
            octets = ip_part.split(".")
            prefix = int(prefix_part)
            if all(0 <= int(o) <= 255 for o in octets) and 0 <= prefix <= 32:
                return value
        click.echo(click.style(f"  ✗ Invalid CIDR: {value}", fg="red"))
        click.echo(click.style("    Expected: 1.2.3.4/32", fg="bright_black"))


def _confirm(prompt: str, default: bool = True) -> bool:
    """Ask for confirmation."""
    return click.confirm(f"  {prompt}", default=default)


def _summary(title: str, pairs: list[tuple[str, str]]) -> None:
    """Print a summary box."""
    click.echo()
    click.secho(f"  ── {title} ──", fg="cyan", bold=True)
    for k, v in pairs:
        click.echo(f"    {k:<20} {v}")
    click.echo()


def _success(msg: str) -> None:
    click.echo(click.style(f"  ✓ {msg}", fg="green"))


def _warn(msg: str) -> None:
    click.echo(click.style(f"  ⚠ {msg}", fg="yellow"))


def _err(msg: str) -> None:
    click.echo(click.style(f"  ✗ {msg}", fg="red"))


# ── Wizard: config init ──────────────────────────────────────────────


def wizard_init() -> None:
    """Interactive wizard for 'infraguard config init'."""
    from infraguard.config.loader import generate_default_config

    _banner("InfraGuard — Initialize Configuration")

    click.echo("  This wizard creates a starter InfraGuard configuration file.")
    click.echo("  It will generate a YAML config with sensible defaults that")
    click.echo("  you can customize afterward.\n")

    # Output path
    output = _prompt_path(
        "Output config file path",
        default=Path("config.yaml"),
        must_exist=False,
        help_text="Where to write the generated YAML configuration.",
    )

    if output.exists():
        if not _confirm(f"{output} already exists. Overwrite?", default=False):
            _warn("Aborted.")
            return

    # Optional: ask about basic settings to customize the default config
    click.echo()
    click.secho("  Optional customizations (press Enter to use defaults):", bold=True)
    click.echo()

    log_level = _prompt_choice(
        "Log level",
        ["INFO", "DEBUG", "WARNING", "ERROR"],
        default="INFO",
        help_text="Controls verbosity of InfraGuard logging.",
    )

    api_port_raw = _prompt(
        "Dashboard/API port",
        default="8080",
        help_text="Port for the built-in web dashboard and REST API.",
    )
    try:
        api_port = int(api_port_raw)
        if not (1 <= api_port <= 65535):
            raise ValueError
    except ValueError:
        _warn(f"Invalid port '{api_port_raw}', using 8080.")
        api_port = 8080

    retention_raw = _prompt(
        "Data retention (days)",
        default="30",
        help_text="How long to keep request logs and tracking data.",
    )
    try:
        retention = int(retention_raw)
        if retention < 1:
            raise ValueError
    except ValueError:
        _warn(f"Invalid retention '{retention_raw}', using 30.")
        retention = 30

    # Generate
    try:
        config_text = generate_default_config()

        # Apply user customizations by patching the generated YAML
        # (simple string replacement for well-known default keys)
        if log_level != "INFO":
            config_text = config_text.replace("level: INFO", f"level: {log_level}")
        if api_port != 8080:
            config_text = config_text.replace("port: 8080", f"port: {api_port}")
        if retention != 30:
            config_text = config_text.replace("retention_days: 30", f"retention_days: {retention}")

        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(config_text, encoding="utf-8")
    except Exception as e:
        _err(f"Failed to generate config: {e}")
        sys.exit(1)

    _summary("Configuration Created", [
        ("File", str(output.resolve())),
        ("Log level", log_level),
        ("API port", str(api_port)),
        ("Retention", f"{retention} days"),
    ])

    _success(f"Config written to {output}")
    click.echo()
    click.echo("  Next steps:")
    click.echo("    1. Edit the config to add your domains and upstream C2 servers.")
    click.echo("    2. Or run: infraguard wizard deploy   (to provision cloud infra)")
    click.echo("    3. Or run: infraguard config show     (to review current config)")
    click.echo()


# ── Wizard: deploy run ───────────────────────────────────────────────


def wizard_deploy() -> None:
    """Interactive wizard for 'infraguard deploy run'."""
    _banner("InfraGuard — Deploy New Redirector")

    click.echo("  This wizard provisions a new cloud redirector instance")
    click.echo("  via Terraform, configures InfraGuard on it, and starts")
    click.echo("  the proxy and dashboard services.\n")

    # Provider
    provider = _prompt_choice(
        "Cloud provider",
        _PROVIDERS,
        default="do",
        help_text=(
            "Which cloud to deploy to. DigitalOcean is simplest; "
            "AWS/Azure offer more regions; Cloudflare is serverless."
        ),
    )

    # Domain
    domain = _prompt_domain(
        "Primary domain for this redirector",
        help_text=(
            "The public domain that points to this redirector. "
            "Make sure DNS is configured to resolve to the instance IP."
        ),
    )

    # C2 profile
    c2_profile = _prompt_path(
        "Path to C2 profile file",
        must_exist=True,
        help_text=(
            "Your C2 framework profile (e.g., Cobalt Strike .profile, "
            "Mythic config, etc.). InfraGuard auto-detects the format."
        ),
    )

    # Upstream
    upstream = _prompt_url(
        "C2 teamserver URL",
        default="https://10.0.0.5:8443",
        help_text=(
            "The internal URL where your actual C2 teamserver is running. "
            "InfraGuard proxies filtered traffic to this address."
        ),
    )

    # Region (optional)
    region = _prompt(
        "Cloud region (press Enter for provider default)",
        default="",
        required=False,
        help_text=(
            "e.g. nyc3, us-east-1, westeurope. "
            "Leave blank to use the provider's default region."
        ),
    ) or None

    # Instance size (optional)
    instance_size = _prompt(
        "Instance size (press Enter for default)",
        default="",
        required=False,
        help_text=(
            "e.g. s-1vcpu-1gb, t3.micro, Standard_B1s. "
            "Leave blank for the smallest/cheapest option."
        ),
    ) or None

    # SSH key
    ssh_key = _prompt_path(
        "Path to SSH public key",
        default=Path("~/.ssh/id_rsa.pub"),
        must_exist=True,
        help_text=(
            "Used for provisioning access to the instance. "
            "The private key must exist alongside it."
        ),
    )

    # Operator IP
    operator_ip = _prompt_cidr(
        "Your IP in CIDR notation (e.g. 1.2.3.4/32)",
        help_text=(
            "Firewall rules will restrict management access to this IP. "
            "Use /32 for a single IP."
        ),
    )

    # State encryption key (optional)
    state_key = _prompt(
        "age public key for state encryption (press Enter to skip)",
        default="",
        required=False,
        help_text=(
            "If provided, Terraform state will be encrypted with age "
            "after apply. Recommended for OPSEC."
        ),
    ) or None

    # Work directory
    work_dir = _prompt_path(
        "Working directory for Terraform state",
        default=Path("./.infraguard-deploy"),
        must_exist=False,
        help_text="Where Terraform state files and deployment bundles are stored.",
    )

    # Confirmation
    _summary("Deployment Plan", [
        ("Provider", provider),
        ("Domain", domain),
        ("C2 profile", str(c2_profile)),
        ("Upstream", upstream),
        ("Region", region or "(default)"),
        ("Instance size", instance_size or "(default)"),
        ("SSH key", str(ssh_key)),
        ("Operator IP", operator_ip),
        ("State encryption", state_key[:16] + "..." if state_key else "(none)"),
        ("Work dir", str(work_dir)),
    ])

    if not _confirm("Proceed with deployment?", default=True):
        _warn("Aborted.")
        return

    # Delegate to the actual deploy_run command via Click's context
    from infraguard.deploy.cli import deploy_run

    ctx = click.Context(deploy_run)
    ctx.invoke(
        deploy_run,
        provider=provider,
        domain=domain,
        c2_profile=c2_profile,
        upstream=upstream,
        region=region,
        instance_size=instance_size,
        ssh_key=ssh_key,
        operator_ip=operator_ip,
        state_key=state_key,
        work_dir=work_dir,
    )


# ── Wizard: deploy rotate ────────────────────────────────────────────


def wizard_rotate() -> None:
    """Interactive wizard for 'infraguard deploy rotate'."""
    _banner("InfraGuard — Rotate Redirector")

    click.echo("  This wizard performs a blue/green rotation: it provisions a")
    click.echo("  new redirector instance, waits for it to become healthy,")
    click.echo("  optionally migrates data, then destroys the old instance.\n")

    _warn("Ensure DNS TTL for the old domain is set to 60s before rotation!")
    click.echo()

    # Old work dir
    old_work_dir = _prompt_path(
        "Working directory of the existing deployment",
        must_exist=True,
        help_text=(
            "The directory containing Terraform state for the current "
            "deployment (set by a previous 'deploy run')."
        ),
    )

    # Provider
    provider = _prompt_choice(
        "Cloud provider",
        _PROVIDERS,
        default="do",
        help_text="Must match the provider of the existing deployment.",
    )

    # New domain
    new_domain = _prompt_domain(
        "New domain for the rotated instance",
        help_text="The new public domain for the replacement redirector.",
    )

    # C2 profile
    c2_profile = _prompt_path(
        "Path to C2 profile file",
        must_exist=True,
        help_text="Your C2 framework profile for the new instance.",
    )

    # Upstream
    upstream = _prompt_url(
        "C2 teamserver URL",
        default="https://10.0.0.5:8443",
        help_text="The internal URL where your C2 teamserver is running.",
    )

    # SSH key
    ssh_key = _prompt_path(
        "Path to SSH public key",
        default=Path("~/.ssh/id_rsa.pub"),
        must_exist=True,
        help_text="Used for provisioning and health checks on the new instance.",
    )

    # Operator IP
    operator_ip = _prompt_cidr(
        "Your IP in CIDR notation",
        help_text="Firewall rules will restrict management access to this IP.",
    )

    # Region (optional)
    region = _prompt(
        "Cloud region (press Enter for same as existing)",
        default="",
        required=False,
        help_text="Leave blank to keep the same region.",
    ) or None

    # Instance size (optional)
    instance_size = _prompt(
        "Instance size (press Enter for same as existing)",
        default="",
        required=False,
        help_text="Leave blank to keep the same size.",
    ) or None

    # State encryption
    state_key = _prompt(
        "age public key for state encryption (press Enter to skip)",
        default="",
        required=False,
        help_text="Encrypt Terraform state for the new instance.",
    ) or None

    state_identity = _prompt_path(
        "age identity file (for decrypting old state)",
        default=None,
        must_exist=False,
        help_text="Only needed if the old deployment used state encryption.",
    )
    if not state_identity.exists():
        state_identity = None

    # New work dir (auto-generated)
    new_work_dir = _prompt_path(
        "Working directory for new deployment",
        default=None,
        must_exist=False,
        help_text="Leave blank to auto-generate based on timestamp.",
    )

    # Preserve data
    preserve_data = _confirm(
        "Migrate SQLite tracking database from old to new instance?",
        default=False,
    )

    # Confirmation
    _summary("Rotation Plan", [
        ("Provider", provider),
        ("Old work dir", str(old_work_dir)),
        ("New domain", new_domain),
        ("C2 profile", str(c2_profile)),
        ("Upstream", upstream),
        ("Preserve data", "Yes" if preserve_data else "No"),
    ])

    if not _confirm("Proceed with rotation?", default=True):
        _warn("Aborted.")
        return

    from infraguard.deploy.cli import deploy_rotate

    ctx = click.Context(deploy_rotate)
    ctx.invoke(
        deploy_rotate,
        provider=provider,
        new_domain=new_domain,
        c2_profile=c2_profile,
        upstream=upstream,
        ssh_key=ssh_key,
        operator_ip=operator_ip,
        region=region,
        instance_size=instance_size,
        state_key=state_key,
        state_identity=state_identity,
        old_work_dir=old_work_dir,
        new_work_dir=new_work_dir,
        preserve_data=preserve_data,
        yes=False,  # Always ask before destroying old instance
    )


# ── Wizard: profile create ───────────────────────────────────────────


def wizard_profile_create() -> None:
    """Interactive wizard for creating an InfraGuard profile from a raw C2 profile."""
    _banner("InfraGuard — Create Profile")

    click.echo("  This wizard converts a raw C2 framework profile into")
    click.echo("  InfraGuard's internal JSON format.\n")

    # Source profile file
    source_file = _prompt_path(
        "Path to raw C2 profile file",
        must_exist=True,
        help_text=(
            "Your C2 framework's profile file. Supported formats: "
            "Cobalt Strike, Mythic, Brute Ratel, Sliver, Havoc, Nighthawk, PoshC2."
        ),
    )

    # Profile type
    profile_type = _prompt_choice(
        "Profile type",
        ["auto"] + _PROFILE_TYPES[:8],  # auto + C2 types only
        default="auto",
        help_text=(
            "Select 'auto' to auto-detect from file contents. "
            "Only needed if auto-detection fails."
        ),
    )

    # Profile name (optional override)
    name = _prompt(
        "Profile name (press Enter to use filename)",
        default="",
        required=False,
        help_text="A friendly name for this profile within InfraGuard.",
    ) or None

    # Output file
    default_output = Path(f"{source_file.stem}.json")
    output = _prompt_path(
        "Output JSON file path",
        default=default_output,
        must_exist=False,
        help_text="Where to write the InfraGuard JSON profile.",
    )

    # Confirmation
    _summary("Profile Conversion", [
        ("Source", str(source_file)),
        ("Type", profile_type),
        ("Name", name or source_file.stem),
        ("Output", str(output)),
    ])

    if not _confirm("Convert profile?", default=True):
        _warn("Aborted.")
        return

    # Delegate to the profile convert logic
    from infraguard.main import _load_profile_file

    try:
        parsed = _load_profile_file(source_file, profile_type, name)
        json_output = parsed.to_json(indent=2)

        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json_output, encoding="utf-8")

        _success(f"Profile written to {output}")
        click.echo()
        click.echo("  Profile summary:")
        click.echo(f"    Name: {parsed.name}")
        click.echo(f"    User-Agent: {parsed.useragent or '(not set)'}")
        if parsed.sleeptime is not None:
            click.echo(f"    Sleep: {parsed.sleeptime}ms")
        if parsed.jitter is not None:
            click.echo(f"    Jitter: {parsed.jitter}%")
        click.echo()
        click.echo("  Reference this profile in your config with:")
        click.echo(f"    profile_path: {output}")
        click.echo()

    except Exception as e:
        _err(f"Profile conversion failed: {e}")
        sys.exit(1)


# ── Click command group ──────────────────────────────────────────────


@click.group("wizard")
def wizard_group() -> None:
    """Interactive wizards for common InfraGuard tasks."""


@wizard_group.command("init")
def wizard_init_cmd() -> None:
    """Create a starter InfraGuard configuration file (interactive)."""
    wizard_init()


@wizard_group.command("deploy")
def wizard_deploy_cmd() -> None:
    """Provision a new cloud redirector (interactive)."""
    wizard_deploy()


@wizard_group.command("rotate")
def wizard_rotate_cmd() -> None:
    """Rotate to a new redirector instance (interactive)."""
    wizard_rotate()


@wizard_group.command("profile")
def wizard_profile_cmd() -> None:
    """Create/convert a C2 profile (interactive)."""
    wizard_profile_create()
