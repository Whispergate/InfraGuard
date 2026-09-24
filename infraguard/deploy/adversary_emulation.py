"""Adversary-emulation self-test.

Runs common scanners against the redirector and reports which of them
reached the profile filter (i.e. bypassed IP / bot / header filters).
Findings surface as a table for the operator anything that got past
the front-line filters is a bug in the tuning.

Scaffold: shells out to the scanners the operator has installed
locally, parses their output, correlates with the tracking DB to see
what the pipeline made of each probe.

Supported (when the binary is on PATH):

  * ``nmap -sV -Pn --script=http-title <target>``
  * ``nuclei -u <target> -tags cve,exposure -silent``
  * ``curl -s -o /dev/null -w "%{http_code}" <target>``

TODOs:

  1. Structured result parser per scanner.
  2. Correlate probe timestamps with tracking DB rows to compute
     "which filter caught this scanner?"
  3. HTML/Markdown report generator.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field

import structlog

log = structlog.get_logger()


@dataclass
class ScannerRun:
    name: str
    ran: bool
    exit_code: int = 0
    output_head: str = ""


@dataclass
class SelfTestReport:
    target: str
    runs: list[ScannerRun] = field(default_factory=list)

    def summary(self) -> str:
        lines = [f"# InfraGuard adversary-emulation report against {self.target}"]
        for r in self.runs:
            status = "ran" if r.ran else "skipped (not installed)"
            lines.append(f"- {r.name}: {status}")
            if r.output_head:
                lines.append(f"    head: {r.output_head[:120]!r}")
        return "\n".join(lines)


def _run(cmd: list[str], *, timeout: int = 60) -> ScannerRun:
    binary = cmd[0]
    if shutil.which(binary) is None:
        return ScannerRun(name=binary, ran=False)
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
        )
    except subprocess.TimeoutExpired:
        return ScannerRun(name=binary, ran=True, exit_code=-1, output_head="timeout")


def run_self_test(target: str) -> SelfTestReport:
    """Fire the scanners we know about against ``target``."""
    report = SelfTestReport(target=target)
    report.runs.append(_run(["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}", target]))
    report.runs.append(_run(["nmap", "-sV", "-Pn", "--script=http-title", target]))
    report.runs.append(_run(["nuclei", "-u", target, "-silent"], timeout=120))
    return report


__all__ = ["ScannerRun", "SelfTestReport", "run_self_test"]
