"""Auto-commit every dashboard config mutation to a local git history.

Two-line contract for callers:

    from infraguard.config.git_history import ConfigHistory
    hist = ConfigHistory(path='~/.config/infraguard/history.git')
    hist.record(config_path, actor='dashboard:alice', summary='blocked 1.2.3.4')

On first use, creates a bare git repo alongside the config file. Each
``record`` writes the current config into the working tree and makes a
new commit. Never fails callers on git errors logs and moves on.

Read/revert from the CLI:

    infraguard config log
    infraguard config revert HEAD~1
"""

from __future__ import annotations

import subprocess
import time
from pathlib import Path

import structlog

log = structlog.get_logger()


class ConfigHistory:
    def __init__(self, repo_path: str | Path):
        self._repo = Path(repo_path).expanduser()

    def _ensure_repo(self) -> bool:
        try:
            self._repo.mkdir(parents=True, exist_ok=True)
            if not (self._repo / ".git").exists():
                subprocess.run(
                    ["git", "init", "--initial-branch=main", "-q", str(self._repo)],
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                # Committer identity so commits work without user config.
                for k, v in [
                    ("user.email", "infraguard@localhost"),
                    ("user.name", "infraguard"),
                ]:
                    subprocess.run(
                        ["git", "-C", str(self._repo), "config", k, v],
                        check=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
            return True
        except Exception as exc:
            log.debug("config_history_init_failed", error=str(exc))
            return False

    def record(
        self,
        config_path: str | Path,
        *,
        actor: str = "unknown",
        summary: str = "config change",
    ) -> str | None:
        """Snapshot ``config_path`` into the history repo. Returns commit SHA."""
        if not self._ensure_repo():
            return None
        src = Path(config_path)
        if not src.is_file():
            return None
        dst = self._repo / src.name
        try:
            dst.write_bytes(src.read_bytes())
            subprocess.run(
                ["git", "-C", str(self._repo), "add", src.name],
                check=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            msg = f"{summary}\n\nActor: {actor}\nTimestamp: {int(time.time())}\n"
            subprocess.run(
                ["git", "-C", str(self._repo), "commit", "--allow-empty", "-m", msg],
                check=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            sha = subprocess.check_output(
                ["git", "-C", str(self._repo), "rev-parse", "HEAD"],
            ).decode().strip()
            log.info("config_history_commit", sha=sha[:12], actor=actor)
            return sha
        except Exception as exc:
            log.debug("config_history_record_failed", error=str(exc))
            return None

    def log(self, limit: int = 20) -> list[dict]:
        if not self._ensure_repo():
            return []
        try:
            out = subprocess.check_output([
                "git", "-C", str(self._repo), "log",
                f"-n{limit}", "--pretty=format:%h\t%at\t%s",
            ]).decode()
        except subprocess.CalledProcessError:
            return []
        rows = []
        for line in out.splitlines():
            parts = line.split("\t", 2)
            if len(parts) == 3:
                rows.append({"sha": parts[0], "ts": int(parts[1]), "summary": parts[2]})
        return rows

    def revert(self, ref: str, into: str | Path) -> bool:
        """Restore the config file's contents at ``ref`` into ``into``."""
        try:
            content = subprocess.check_output(
                ["git", "-C", str(self._repo), "show", f"{ref}:{Path(into).name}"],
            )
            Path(into).write_bytes(content)
            return True
        except subprocess.CalledProcessError as exc:
            log.warning("config_history_revert_failed", ref=ref, error=str(exc))
            return False


__all__ = ["ConfigHistory"]
