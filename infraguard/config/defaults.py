"""Default configuration values for InfraGuard."""

import os
from pathlib import Path

_CONFIG_DIR = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "infraguard"
_CONFIG_DIR.mkdir(parents=True, exist_ok=True)

DEFAULT_BLOCK_SCORE_THRESHOLD = 0.7
DEFAULT_DB_PATH = str(_CONFIG_DIR / "infraguard.db")
DEFAULT_RETENTION_DAYS = 30
DEFAULT_API_BIND = "127.0.0.1"
DEFAULT_API_PORT = 8080
DEFAULT_LOG_LEVEL = "INFO"
DEFAULT_LOG_FORMAT = "json"
DEFAULT_DYNAMIC_WHITELIST_THRESHOLD = 3
