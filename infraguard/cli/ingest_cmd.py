"""``infraguard ingest`` - parse .htaccess / robots.txt into blocklists."""

from __future__ import annotations

from pathlib import Path

import click

from infraguard.cli import cli


@cli.command("ingest")
@click.argument("files", nargs=-1, required=True, type=click.Path(exists=True))
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["summary", "json", "blocklist"]),
    default="summary",
    help="Output format.",
)
@click.option(
    "-o",
    "--output",
    type=click.Path(path_type=Path),
    default=None,
    help="Write blocklist to file (one IP/pattern per line).",
)
def ingest_rules(files: tuple[str, ...], output_format: str, output: Path | None) -> None:
    """Ingest .htaccess / robots.txt rules into blocklists.

    Parses IP deny rules, User-Agent blocks, and disallowed paths from
    server configuration files. Output can be used directly as an IP
    blocklist file or to extend InfraGuard's bot filter patterns.

    \b
    Examples:
      infraguard ingest .htaccess robots.txt
      infraguard ingest .htaccess --format blocklist -o banned_ips.txt
      infraguard ingest robots.txt --format json
    """
    from infraguard.intel.rule_ingest import ingest_files

    result = ingest_files(list(files))

    if output_format == "json":
        import json

        click.echo(
            json.dumps(
                {
                    "blocked_ips": result.blocked_ips,
                    "allowed_ips": result.allowed_ips,
                    "blocked_user_agents": result.blocked_user_agents,
                    "blocked_paths": result.blocked_paths,
                    "source_files": result.source_files,
                },
                indent=2,
            )
        )
    elif output_format == "blocklist":
        lines: list[str] = []
        if result.blocked_ips:
            lines.append("# Blocked IPs/CIDRs")
            lines.extend(result.blocked_ips)
        if result.blocked_user_agents:
            lines.append("")
            lines.append("# Blocked User-Agents")
            for ua in result.blocked_user_agents:
                lines.append(f"# UA: {ua}")
        text = "\n".join(lines) + "\n"

        if output:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(text, encoding="utf-8")
            click.echo(f"Blocklist written to {output}")
        else:
            click.echo(text)
    else:
        click.echo(f"Ingested {len(result.source_files)} file(s):")
        click.echo(f"  Blocked IPs:         {len(result.blocked_ips)}")
        click.echo(f"  Allowed IPs:         {len(result.allowed_ips)}")
        click.echo(f"  Blocked User-Agents: {len(result.blocked_user_agents)}")
        click.echo(f"  Blocked Paths:       {len(result.blocked_paths)}")
        if result.blocked_ips:
            click.echo("\n  Top blocked IPs:")
            for ip in result.blocked_ips[:10]:
                click.echo(f"    {ip}")
            if len(result.blocked_ips) > 10:
                click.echo(f"    ... and {len(result.blocked_ips) - 10} more")
        if result.blocked_user_agents:
            click.echo("\n  Blocked User-Agents:")
            for ua in result.blocked_user_agents[:10]:
                click.echo(f"    {ua}")
            if len(result.blocked_user_agents) > 10:
                click.echo(f"    ... and {len(result.blocked_user_agents) - 10} more")
