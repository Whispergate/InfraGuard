"""Adversary-emulation self-test.

Runs common scanners against the redirector and reports which of them
reached (or passed) each pipeline filter. Anything that got through
the front-line filters is a tuning bug for the operator to fix before
going live.

Correlates probe timestamps with rows in the tracking DB so the
report can name the filter that dropped each probe.

Drives ``curl``, ``nmap``, and ``nuclei`` when they are on PATH.
"""

from __future__ import annotations

import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from infraguard.tracking.database import Database

log = structlog.get_logger()


@dataclass
class ScannerRun:
    name: str
    ran: bool
    exit_code: int = 0
    output_head: str = ""
    started_at: float = 0.0
    finished_at: float = 0.0


@dataclass
class SelfTestReport:
    target: str
    runs: list[ScannerRun] = field(default_factory=list)
    correlated_events: list[dict] = field(default_factory=list)

    def summary(self) -> str:
        lines = [f"# InfraGuard adversary-emulation report against {self.target}", ""]
        for r in self.runs:
            status = "ran" if r.ran else "skipped (not installed)"
            lines.append(f"- **{r.name}**: {status} (exit={r.exit_code})")
            if r.output_head:
                lines.append(f"    head: {r.output_head[:120]!r}")
        if self.correlated_events:
            lines.append("")
            lines.append("## Pipeline correlation (probe -> filter that fired)")
            lines.append("")
            lines.append("| ts | client_ip | uri | verdict | reason |")
            lines.append("|---|---|---|---|---|")
            for e in self.correlated_events:
                lines.append(
                    f"| {e['timestamp']} | {e['client_ip']} | "
                    f"{e['uri'][:40]} | {e['filter_result']} | "
                    f"{(e['filter_reason'] or '')[:60]} |"
                )
        return "\n".join(lines)


def _run(cmd: list[str], *, timeout: int = 60) -> ScannerRun:
    binary = cmd[0]
    if shutil.which(binary) is None:
        return ScannerRun(name=binary, ran=False)
    started = time.time()
    try:
        p = subprocess.run(
            cmd, timeout=timeout, capture_output=True, text=True, check=False,
        )
        head = (p.stdout or p.stderr).strip().splitlines()
        return ScannerRun(
            name=binary,
            ran=True,
            exit_code=p.returncode,
            output_head=head[0] if head else "",
            started_at=started,
            finished_at=time.time(),
        )
    except subprocess.TimeoutExpired:
        return ScannerRun(
            name=binary, ran=True, exit_code=-1, output_head="timeout",
            started_at=started, finished_at=time.time(),
        )


def run_self_test(target: str) -> SelfTestReport:
    """Fire the scanners we know about against ``target``.

    Callers that want the pipeline-correlation table should follow up
    with :func:`correlate_with_tracking`.
    """
    report = SelfTestReport(target=target)
    report.runs.append(_run(
        ["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}", target]
    ))
    report.runs.append(_run(
        ["nmap", "-sV", "-Pn", "--script=http-title", target]
    ))
    report.runs.append(_run(["nuclei", "-u", target, "-silent"], timeout=120))
    return report


async def correlate_with_tracking(
    report: SelfTestReport, db: Database,
) -> None:
    """Look up tracking-DB rows in each scanner's time window.

    Populates ``report.correlated_events`` with the filter verdict for
    every probe the pipeline saw during the scanner runs.
    """
    for r in report.runs:
        if not r.ran or r.finished_at == 0:
            continue
        rows = await db.fetchall(
            "SELECT timestamp, client_ip, uri, filter_result, filter_reason "
            "FROM requests WHERE timestamp >= ? AND timestamp <= ? "
            "ORDER BY id ASC LIMIT 200",
            (
                time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(r.started_at - 1)),
                time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(r.finished_at + 1)),
            ),
        )
        report.correlated_events.extend(rows)


def write_report(report: SelfTestReport, out_path: Path) -> Path:
    """Write the Markdown report to ``out_path``. Returns the path."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(report.summary(), encoding="utf-8")
    return out_path


__all__ = [
    "ScannerRun",
    "SelfTestReport",
    "correlate_with_tracking",
    "run_self_test",
    "write_report",
]
