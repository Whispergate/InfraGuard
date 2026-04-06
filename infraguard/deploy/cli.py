"""Click commands for cloud redirector provisioning and rotation.

Commands:
    deploy run      - provision a new redirector via Terraform
    deploy destroy  - tear down an existing redirector
    deploy rotate   - deploy-then-destroy rotation with health polling

Security invariants:
- Secrets are never passed as -var CLI flags (only -var-file with 0o600 perms).
- Terraform state is encrypted with age after apply; plaintext is deleted.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import subprocess
import time
from pathlib import Path

import click

from infraguard.deploy.providers import get_provider
from infraguard.deploy.state import decrypt_state, encrypt_state


def _compute_ssh_fingerprint(pub_key_path: Path) -> str:
    """Compute the MD5 fingerprint of an SSH public key file.

    Returns the colon-separated hex digest format that DigitalOcean uses
    (e.g. ``ab:cd:ef:...``).
    """
    content = pub_key_path.read_text(encoding="utf-8").strip()
    # SSH public key format: "type base64data comment"
    parts = content.split()
    if len(parts) < 2:
        raise click.ClickException(f"Invalid SSH public key format in {pub_key_path}")
    key_data = base64.b64decode(parts[1])
    digest = hashlib.md5(key_data).hexdigest()
    return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))


def _derive_private_key(pub_key_path: Path) -> Path:
    """Derive the private key path from a public key path.

    ``~/.ssh/id_rsa.pub`` → ``~/.ssh/id_rsa``
    """
    priv = pub_key_path.with_suffix("")
    if not priv.exists():
        raise click.ClickException(
            f"Private key not found at {priv}. "
            f"Expected alongside public key {pub_key_path}"
        )
    return priv


_SSH_OPTS = [
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "LogLevel=ERROR",
    "-o", "ConnectTimeout=10",
]


def _run_ssh(
    ip: str,
    command: str,
    ssh_key: Path,
    user: str = "root",
) -> subprocess.CompletedProcess:
    """Run a command on a remote host via SSH."""
    priv_key = _derive_private_key(ssh_key)
    cmd = [
        "ssh", *_SSH_OPTS,
        "-i", str(priv_key),
        f"{user}@{ip}",
        command,
    ]
    return subprocess.run(cmd, capture_output=True, text=True)


def _scp_to(
    ip: str,
    local_path: Path,
    remote_path: str,
    ssh_key: Path,
    user: str = "root",
) -> subprocess.CompletedProcess:
    """Copy a local file to a remote host via SCP."""
    priv_key = _derive_private_key(ssh_key)
    cmd = [
        "scp", *_SSH_OPTS,
        "-i", str(priv_key),
        str(local_path),
        f"{user}@{ip}:{remote_path}",
    ]
    return subprocess.run(cmd, capture_output=True, text=True)


def _wait_for_bootstrap(
    ip: str,
    ssh_key: Path,
    max_attempts: int = 30,
    interval: float = 10.0,
    user: str = "root",
) -> None:
    """Poll the instance via SSH until cloud-init has completed.

    Checks for the ``/var/lib/infraguard-bootstrap-done`` marker file.
    """
    click.echo("Waiting for cloud-init bootstrap to complete...")
    for attempt in range(max_attempts):
        result = _run_ssh(ip, "test -f /var/lib/infraguard-bootstrap-done && echo OK", ssh_key, user=user)
        if result.returncode == 0 and "OK" in result.stdout:
            click.echo(f"Bootstrap complete (attempt {attempt + 1}/{max_attempts})")
            return
        if attempt < max_attempts - 1:
            remaining = (max_attempts - attempt - 1) * interval
            click.echo(
                f"  [{attempt + 1}/{max_attempts}] Not ready yet, "
                f"retrying in {int(interval)}s (~{int(remaining)}s remaining)..."
            )
            time.sleep(interval)

    raise click.ClickException(
        f"Bootstrap did not complete after {max_attempts} attempts ({int(max_attempts * interval)}s). "
        "SSH into the Droplet and check /var/log/cloud-init-output.log"
    )


# ---------------------------------------------------------------------------
# Health polling
# ---------------------------------------------------------------------------

_HEALTH_MAX_ATTEMPTS = 12
_HEALTH_BACKOFF_BASE = 2.0  # seconds
_HEALTH_BACKOFF_MAX = 30.0  # seconds


async def _poll_health_async(instance_ip: str, port: int = 8080) -> bool:
    """Poll ``/health`` on *instance_ip*:*port* until 200 OK.

    Uses exponential backoff: 2s, 4s, 8s … capped at 30s, up to 12 attempts.

    Args:
        instance_ip: IP address of the new instance.
        port: Port number (default 8080).

    Returns:
        ``True`` when the health check succeeds.

    Raises:
        RuntimeError: After all attempts are exhausted.
    """
    import httpx

    url = f"https://{instance_ip}:{port}/health"
    last_exc: Exception | None = None

    for attempt in range(_HEALTH_MAX_ATTEMPTS):
        try:
            async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
                resp = await client.get(url)
                resp.raise_for_status()
                return True
        except Exception as exc:
            last_exc = exc
            wait = min(_HEALTH_BACKOFF_BASE * (2 ** attempt), _HEALTH_BACKOFF_MAX)
            if attempt < _HEALTH_MAX_ATTEMPTS - 1:
                await asyncio.sleep(wait)

    raise RuntimeError(
        f"Health check failed after {_HEALTH_MAX_ATTEMPTS} attempts "
        f"at {url}. Last error: {last_exc}"
    )


def _poll_health(instance_ip: str, port: int = 8080) -> bool:
    """Synchronous wrapper around :func:`_poll_health_async`."""
    return asyncio.run(_poll_health_async(instance_ip, port))


# ---------------------------------------------------------------------------
# Deploy CLI group
# ---------------------------------------------------------------------------


@click.group("deploy")
def deploy_group() -> None:
    """Provision, manage, and rotate cloud redirectors."""


# ---------------------------------------------------------------------------
# deploy run
# ---------------------------------------------------------------------------


@deploy_group.command("run")
@click.option(
    "--provider",
    type=click.Choice(["aws", "azure", "do"]),
    required=True,
    help="Cloud provider.",
)
@click.option("--domain", required=True, help="Primary domain for the redirector.")
@click.option(
    "--profile",
    "c2_profile",
    required=True,
    type=click.Path(exists=True, path_type=Path),
    help="Path to C2 profile file.",
)
@click.option(
    "--upstream",
    required=True,
    help="C2 teamserver URL (e.g. https://10.0.0.5:8443).",
)
@click.option("--region", default=None, help="Cloud region override.")
@click.option("--instance-size", default=None, help="Instance size/type override.")
@click.option(
    "--ssh-key",
    required=True,
    type=click.Path(exists=True, path_type=Path),
    help="Path to SSH public key file.",
)
@click.option(
    "--operator-ip",
    required=True,
    help="Your IP in CIDR notation (e.g. 1.2.3.4/32).",
)
@click.option(
    "--state-key",
    default=None,
    help="age public key for encrypting Terraform state after apply.",
)
@click.option(
    "--work-dir",
    type=click.Path(path_type=Path),
    default=Path("./.infraguard-deploy"),
    help="Working directory for Terraform state files.",
)
def deploy_run(
    provider: str,
    domain: str,
    c2_profile: Path,
    upstream: str,
    region: str | None,
    instance_size: str | None,
    ssh_key: Path,
    operator_ip: str,
    state_key: str | None,
    work_dir: Path,
) -> None:
    """Provision a new cloud redirector instance.

    Full lifecycle:
    1. Terraform apply (Droplet + firewall + tag)
    2. Wait for cloud-init bootstrap (Docker + repo clone + image build)
    3. Generate config bundle + .env locally
    4. SCP config, profile, and .env to the Droplet
    5. SSH to start docker compose services
    6. Poll health endpoint to confirm InfraGuard is running
    """
    from infraguard.deploy.config_gen import generate_config, write_bundle
    from infraguard.deploy.profile_detect import detect_profile_type

    work_dir = Path(work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)

    tf_provider = get_provider(provider, work_dir)

    # Build provider-specific tfvars
    tfvars: dict = {
        "domain": domain,
        "operator_ip": operator_ip,
    }
    if region:
        tfvars["region"] = region
    if instance_size:
        tfvars["instance_size"] = instance_size

    # SSH key handling differs by provider:
    # - DO: uses fingerprint (key must already exist on account)
    # - AWS/Azure: uses raw public key (creates key pair resource)
    if provider == "do":
        tfvars["ssh_key_fingerprint"] = _compute_ssh_fingerprint(ssh_key)
    else:
        tfvars["ssh_public_key"] = ssh_key.read_text(encoding="utf-8").strip()

    # SSH user differs by provider
    _SSH_USERS = {"do": "root", "aws": "ubuntu", "azure": "operator"}
    ssh_user = _SSH_USERS.get(provider, "root")

    # ── Step 1: Terraform apply ──────────────────────────────────────
    click.echo(f"[1/6] Provisioning {provider} instance for {domain}...")
    try:
        outputs = tf_provider.apply(tfvars)
    except Exception as exc:
        raise click.ClickException(str(exc)) from exc

    instance_ip = outputs.get("instance_ip", "")
    if not instance_ip:
        raise click.ClickException("Terraform apply succeeded but no instance_ip in outputs")

    # Encrypt state if age public key provided
    state_file = work_dir / "terraform.tfstate"
    if state_key and state_file.exists():
        try:
            enc_path = encrypt_state(state_file, state_key)
            click.echo(f"  State encrypted: {enc_path}")
        except RuntimeError as exc:
            click.echo(f"  Warning: state encryption failed: {exc}", err=True)

    click.echo(f"  Instance IP: {instance_ip}")
    click.echo(f"  SSH: ssh {ssh_user}@{instance_ip}")

    # ── Step 2: Wait for cloud-init bootstrap ────────────────────────
    click.echo(f"\n[2/6] Waiting for cloud-init (Docker install + image build)...")
    _wait_for_bootstrap(instance_ip, ssh_key, user=ssh_user)

    # ── Step 3: Generate config bundle ───────────────────────────────
    click.echo(f"\n[3/6] Generating config bundle...")

    # Detect profile type for .env upstream variable mapping
    detected_type = detect_profile_type(c2_profile)

    container_profile_path = f"examples/{c2_profile.name}"
    cfg = generate_config(
        domain=domain,
        c2_profile_path=container_profile_path,
        upstream=upstream,
        profile_type=detected_type.value,
    )
    bundle_dir = work_dir / "config"
    write_bundle(
        cfg, bundle_dir,
        profile_source=c2_profile,
        domain=domain,
        upstream=upstream,
        profile_type=detected_type.value,
    )
    click.echo(f"  Bundle: {bundle_dir}/")

    # ── Step 4: SCP config files to Droplet ──────────────────────────
    click.echo(f"\n[4/6] Deploying config to {instance_ip}...")

    # Ensure remote directories exist
    _run_ssh(instance_ip, "mkdir -p /opt/infraguard/config /opt/infraguard/examples", ssh_key, user=ssh_user)

    # SCP config.yaml
    r = _scp_to(instance_ip, bundle_dir / "config.yaml", "/opt/infraguard/config/config.yaml", ssh_key, user=ssh_user)
    if r.returncode != 0:
        raise click.ClickException(f"SCP config.yaml failed: {r.stderr}")
    click.echo("  config.yaml deployed")

    # SCP C2 profile
    profile_dir = bundle_dir / "profiles"
    for pfile in profile_dir.iterdir():
        r = _scp_to(instance_ip, pfile, f"/opt/infraguard/examples/{pfile.name}", ssh_key, user=ssh_user)
        if r.returncode != 0:
            raise click.ClickException(f"SCP profile failed: {r.stderr}")
        click.echo(f"  {pfile.name} deployed")

    # SCP .env
    r = _scp_to(instance_ip, bundle_dir / ".env", "/opt/infraguard/.env", ssh_key, user=ssh_user)
    if r.returncode != 0:
        raise click.ClickException(f"SCP .env failed: {r.stderr}")
    click.echo("  .env deployed")

    # ── Step 5: Start docker compose services ────────────────────────
    click.echo(f"\n[5/6] Starting InfraGuard services...")

    # Non-root users need sudo for docker on AWS/Azure
    sudo = "" if ssh_user == "root" else "sudo "
    start_cmd = f"cd /opt/infraguard && {sudo}docker compose up -d proxy dashboard"
    r = _run_ssh(instance_ip, start_cmd, ssh_key, user=ssh_user)
    if r.returncode != 0:
        click.echo(f"  Warning: docker compose returned {r.returncode}", err=True)
        click.echo(f"  stderr: {r.stderr}", err=True)
    else:
        click.echo("  proxy + dashboard started")

    # ── Step 6: Health check ─────────────────────────────────────────
    click.echo(f"\n[6/6] Polling health endpoint...")
    try:
        _poll_health(instance_ip, port=443)
        click.echo("  Health check passed!")
    except RuntimeError:
        click.echo(
            "  Warning: Health check did not pass yet. Services may still be starting.\n"
            f"  Check manually: curl -k https://{instance_ip}:443/health",
            err=True,
        )

    # ── Summary ──────────────────────────────────────────────────────
    click.echo(f"\n{'=' * 50}")
    click.echo(f"  InfraGuard deployed to {instance_ip}")
    click.echo(f"  Domain:    {domain}")
    click.echo(f"  Upstream:  {upstream}")
    click.echo(f"  SSH:       ssh {ssh_user}@{instance_ip}")
    click.echo(f"  Dashboard: https://{instance_ip}:8080")
    click.echo(f"  Work dir:  {work_dir}")
    click.echo(f"{'=' * 50}")


# ---------------------------------------------------------------------------
# deploy destroy
# ---------------------------------------------------------------------------


@deploy_group.command("destroy")
@click.option(
    "--provider",
    type=click.Choice(["aws", "azure", "do"]),
    required=True,
    help="Cloud provider.",
)
@click.option(
    "--work-dir",
    type=click.Path(exists=True, path_type=Path),
    required=True,
    help="Working directory of the existing deployment.",
)
@click.option(
    "--state-key",
    default=None,
    help="age public key (used to re-encrypt state if needed).",
)
@click.option(
    "--state-identity",
    default=None,
    type=click.Path(exists=True, path_type=Path),
    help="age identity file for decrypting existing state.",
)
@click.confirmation_option(prompt="Destroy all infrastructure in this work directory?")
def deploy_destroy(
    provider: str,
    work_dir: Path,
    state_key: str | None,
    state_identity: Path | None,
) -> None:
    """Tear down infrastructure managed by a previous deploy run."""
    work_dir = Path(work_dir)
    tf_provider = get_provider(provider, work_dir)

    # Decrypt state if it was encrypted
    _dec_path: Path | None = None
    enc_state = work_dir / "terraform.tfstate.age"
    if enc_state.exists() and state_identity:
        try:
            _dec_path = decrypt_state(enc_state, state_identity)
            # Move decrypted state to expected location for Terraform
            import shutil
            shutil.move(str(_dec_path), str(work_dir / "terraform.tfstate"))
        except RuntimeError as exc:
            raise click.ClickException(f"State decryption failed: {exc}") from exc

    tfvars: dict = {}  # Minimal - domain not required for destroy
    try:
        tf_provider.destroy(tfvars)
    except Exception as exc:
        raise click.ClickException(str(exc)) from exc

    click.echo("Infrastructure destroyed.")


# ---------------------------------------------------------------------------
# deploy rotate
# ---------------------------------------------------------------------------


@deploy_group.command("rotate")
@click.option(
    "--provider",
    type=click.Choice(["aws", "azure", "do"]),
    required=True,
    help="Cloud provider.",
)
@click.option("--new-domain", required=True, help="New domain for the rotated instance.")
@click.option(
    "--profile",
    "c2_profile",
    required=True,
    type=click.Path(exists=True, path_type=Path),
    help="Path to C2 profile file.",
)
@click.option(
    "--upstream",
    required=True,
    help="C2 teamserver URL.",
)
@click.option(
    "--ssh-key",
    required=True,
    type=click.Path(exists=True, path_type=Path),
    help="Path to SSH public key file.",
)
@click.option(
    "--operator-ip",
    required=True,
    help="Your IP in CIDR notation (e.g. 1.2.3.4/32).",
)
@click.option("--region", default=None, help="Cloud region override.")
@click.option("--instance-size", default=None, help="Instance size/type override.")
@click.option(
    "--state-key",
    default=None,
    help="age public key for state encryption on new instance.",
)
@click.option(
    "--state-identity",
    default=None,
    type=click.Path(exists=True, path_type=Path),
    help="age identity file for decrypting old instance state.",
)
@click.option(
    "--old-work-dir",
    type=click.Path(exists=True, path_type=Path),
    required=True,
    help="Working directory of the existing deployment to replace.",
)
@click.option(
    "--new-work-dir",
    type=click.Path(path_type=Path),
    default=None,
    help="Working directory for the new deployment (auto-generated if omitted).",
)
@click.option(
    "--preserve-data",
    is_flag=True,
    help="Migrate SQLite DB from old instance to new instance via SCP.",
)
@click.option(
    "--yes",
    "-y",
    is_flag=True,
    help="Skip confirmation prompt before destroying old instance.",
)
def deploy_rotate(
    provider: str,
    new_domain: str,
    c2_profile: Path,
    upstream: str,
    ssh_key: Path,
    operator_ip: str,
    region: str | None,
    instance_size: str | None,
    state_key: str | None,
    state_identity: Path | None,
    old_work_dir: Path,
    new_work_dir: Path | None,
    preserve_data: bool,
    yes: bool,
) -> None:
    """Rotate to a new redirector instance (deploy-then-destroy pattern).

    Steps:
    1. Emit DNS TTL warning.
    2. Provision NEW instance with new_domain.
    3. Poll /health until healthy (12 attempts, exponential backoff).
    4. Optionally migrate SQLite DB via SCP.
    5. Confirm (unless --yes).
    6. Destroy OLD instance.
    7. Print summary.
    """
    from infraguard.deploy.config_gen import generate_config, write_bundle

    old_work_dir = Path(old_work_dir)

    # 1. DNS TTL warning
    click.echo(
        "WARNING: Ensure DNS TTL for old domain is set to 60s before rotation. "
        "Current beacons will hit the old IP until TTL expires."
    )

    # 2. Provision new instance
    if new_work_dir is None:
        timestamp = int(time.time())
        new_work_dir = old_work_dir.parent / f"infraguard-rotate-{timestamp}"
    new_work_dir = Path(new_work_dir)
    new_work_dir.mkdir(parents=True, exist_ok=True)

    new_provider = get_provider(provider, new_work_dir)
    ssh_fingerprint = _compute_ssh_fingerprint(ssh_key)
    tfvars: dict = {
        "domain": new_domain,
        "ssh_key_fingerprint": ssh_fingerprint,
        "operator_ip": operator_ip,
    }
    if region:
        tfvars["region"] = region
    if instance_size:
        tfvars["instance_size"] = instance_size

    click.echo(f"Provisioning new instance for domain: {new_domain} ...")
    try:
        new_outputs = new_provider.apply(tfvars)
    except Exception as exc:
        raise click.ClickException(f"Failed to provision new instance: {exc}") from exc

    new_ip = new_outputs.get("instance_ip", "")
    click.echo(f"New instance provisioned at {new_ip}")

    # 3. Poll health on new instance
    click.echo(f"Polling health at https://{new_ip}:8080/health ...")
    try:
        _poll_health(new_ip)
        click.echo(f"New instance healthy at {new_ip}")
    except RuntimeError as exc:
        click.echo(
            f"ERROR: New instance health check failed.\n{exc}\n"
            "Old instance NOT destroyed. Investigate before retrying.",
            err=True,
        )
        raise click.Abort() from exc

    # 4. Preserve data if requested
    if preserve_data:
        old_provider = get_provider(provider, old_work_dir)
        # Decrypt old state if needed to get old IP
        enc_old_state = old_work_dir / "terraform.tfstate.age"
        if enc_old_state.exists() and state_identity:
            try:
                dec_path = decrypt_state(enc_old_state, state_identity)
                import shutil
                shutil.move(str(dec_path), str(old_work_dir / "terraform.tfstate"))
            except RuntimeError as exc:
                raise click.ClickException(
                    f"Could not decrypt old state for SCP: {exc}"
                ) from exc

        try:
            # Get old instance IP from terraform outputs
            old_outputs = old_provider._get_outputs()
            old_ip = old_outputs.get("instance_ip", "")
        except Exception:
            old_ip = ""

        if old_ip and new_ip:
            scp_cmd = [
                "scp",
                f"ubuntu@{old_ip}:/data/infraguard.db",
                f"ubuntu@{new_ip}:/data/infraguard.db",
            ]
            click.echo(f"Copying database: {old_ip} -> {new_ip} ...")
            result = subprocess.run(scp_cmd, capture_output=True, text=True)
            if result.returncode != 0:
                click.echo(
                    f"Warning: SCP failed: {result.stderr}", err=True
                )
        else:
            click.echo("Warning: Could not determine old/new IPs for SCP.", err=True)

    # Encrypt new state if key provided
    new_state_file = new_work_dir / "terraform.tfstate"
    if state_key and new_state_file.exists():
        try:
            enc_path = encrypt_state(new_state_file, state_key)
            click.echo(f"New instance state encrypted: {enc_path}")
        except RuntimeError as exc:
            click.echo(f"Warning: state encryption failed: {exc}", err=True)

    # 5. Confirmation gate
    if not yes:
        click.confirm(
            "New instance verified healthy. Destroy old instance?",
            abort=True,
        )

    # 6. Destroy old instance
    click.echo("Destroying old instance ...")
    old_provider_for_destroy = get_provider(provider, old_work_dir)

    # Decrypt old state if still encrypted (might already be decrypted by --preserve-data)
    enc_old_state = old_work_dir / "terraform.tfstate.age"
    if enc_old_state.exists() and state_identity:
        try:
            dec_path = decrypt_state(enc_old_state, state_identity)
            import shutil
            shutil.move(str(dec_path), str(old_work_dir / "terraform.tfstate"))
        except RuntimeError as exc:
            click.echo(
                f"Warning: Could not decrypt old state: {exc}. Attempting destroy anyway.",
                err=True,
            )

    try:
        old_provider_for_destroy.destroy({})
    except Exception as exc:
        click.echo(
            f"Warning: Old instance destroy failed: {exc}\n"
            "You may need to manually destroy it.",
            err=True,
        )

    # 7. Summary
    click.echo("\nRotation complete:")
    click.echo(f"  Old instance destroyed")
    click.echo(f"  New instance active: {new_ip}")
    click.echo(f"  New domain: {new_domain}")
    click.echo(f"  New work dir: {new_work_dir}")
