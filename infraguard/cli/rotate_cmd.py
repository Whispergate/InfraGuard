"""``infraguard rotate`` - one-click blue-green infrastructure rotation."""

from __future__ import annotations

from pathlib import Path

import click

from infraguard.cli import cli


@cli.command("rotate")
@click.option("--domain", required=True, help="Domain to rotate.")
@click.option("--strategy", type=click.Choice(["blue-green"]),
              default="blue-green", show_default=True, help="Rotation strategy.")
@click.option("--provider",
              type=click.Choice(["aws", "azure", "do", "cloudflare", "hetzner"]),
              required=True, help="Cloud provider.")
@click.option("--upstream", required=True,
              help="C2 teamserver URL (e.g. https://10.0.0.5:8443).")
@click.option("--profile", "c2_profile", required=True,
              type=click.Path(exists=True, path_type=Path),
              help="Path to C2 profile file.")
@click.option("--blue-work-dir", type=click.Path(exists=True, path_type=Path),
              required=True, help="Work dir of the existing (blue) deployment.")
@click.option("--green-work-dir", type=click.Path(path_type=Path), default=None,
              help="Work dir for the new (green) deployment (auto-generated if omitted).")
@click.option("--ssh-key", required=True,
              type=click.Path(exists=True, path_type=Path),
              help="Path to SSH public key file.")
@click.option("--operator-ip", required=True,
              help="Your IP in CIDR notation (e.g. 1.2.3.4/32).")
@click.option("--region", default=None, help="Cloud region override.")
@click.option("--instance-size", default=None, help="Instance size override.")
@click.option("--state-key", default=None,
              help="age public key for state encryption.")
@click.option("--state-identity", default=None,
              type=click.Path(exists=True, path_type=Path),
              help="age identity file for decrypting existing state.")
@click.option("--skip-preflight", is_flag=True,
              help="Skip DNS/cert/upstream pre-flight checks (not recommended).")
@click.option("--keep-blue", is_flag=True,
              help="Do not destroy the blue instance after successful rotation.")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation prompt.")
def rotate_cmd(
    domain: str,
    strategy: str,
    provider: str,
    upstream: str,
    c2_profile: Path,
    blue_work_dir: Path,
    green_work_dir: Path | None,
    ssh_key: Path,
    operator_ip: str,
    region: str | None,
    instance_size: str | None,
    state_key: str | None,
    state_identity: Path | None,
    skip_preflight: bool,
    keep_blue: bool,
    yes: bool,
) -> None:
    """One-click blue-green infrastructure rotation.

    \b
    Example:
      infraguard rotate --domain evil.com --strategy blue-green \\
        --provider do --upstream https://10.0.0.5:8443 \\
        --profile cs.profile --blue-work-dir .infraguard-deploy \\
        --ssh-key ~/.ssh/id_rsa.pub --operator-ip 1.2.3.4/32
    """
    from infraguard.deploy.rotation import (
        PreFlightError,
        RotationError,
        RotationManager,
    )

    if not yes:
        click.confirm(
            f"Rotate {domain} on {provider} using strategy '{strategy}'?",
            abort=True,
        )

    mgr = RotationManager(
        provider_name=provider,
        blue_work_dir=blue_work_dir,
        green_work_dir=green_work_dir,
        ssh_key=ssh_key,
        state_key=state_key,
        state_identity=state_identity,
        operator_ip=operator_ip,
    )

    # ── Pre-flight ────────────────────────────────────────────────────
    if not skip_preflight:
        click.echo("[pre-flight] DNS propagation, certificate, upstream health...")
        try:
            blue_ip: str | None = None
            try:
                blue_ip = mgr._get_blue_ip()
            except RotationError:
                pass
            pf = mgr.preflight(domain, upstream, expected_ip=blue_ip)
            click.echo(
                f"  DNS:      OK ({', '.join(pf.resolved_ips)})\n"
                f"  Cert:     OK ({pf.cert_expiry_days} days remaining)\n"
                f"  Upstream: OK"
            )
        except PreFlightError as exc:
            raise click.ClickException(str(exc)) from exc
    else:
        click.echo("[pre-flight] Skipped (--skip-preflight)")

    # ── Rotation ──────────────────────────────────────────────────────
    click.echo(f"[rotate] Provisioning green instance for {domain}...")
    try:
        result = mgr.rotate(
            domain=domain,
            upstream=upstream,
            c2_profile=c2_profile,
            strategy=strategy,
            region=region,
            instance_size=instance_size,
            skip_preflight=True,  # already ran above
            destroy_blue=not keep_blue,
        )
    except RotationError as exc:
        raise click.ClickException(str(exc)) from exc

    # ── Report ────────────────────────────────────────────────────────
    if result.success:
        click.echo(f"\n{'=' * 50}")
        click.echo(f"  Rotation complete ({result.strategy})")
        click.echo(f"  Domain:    {result.domain}")
        click.echo(f"  Green IP:  {result.green_ip}")
        if result.blue_ip:
            click.echo(f"  Blue IP:   {result.blue_ip} ({'kept' if keep_blue else 'destroyed'})")
        if result.green_work_dir:
            click.echo(f"  Work dir:  {result.green_work_dir}")
        click.echo(f"  Elapsed:   {result.elapsed_seconds:.1f}s")
        click.echo(f"{'=' * 50}")
    else:
        click.echo("\nRotation FAILED.", err=True)
        if result.rollback_performed:
            click.echo("  Rollback performed: green destroyed, traffic reverted to blue.", err=True)
        raise click.ClickException(result.error or "unknown error")
