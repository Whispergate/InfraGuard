"""Default configuration values for InfraGuard."""

import os
from pathlib import Path

_CONFIG_DIR = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "infraguard"

# Inside the Docker container the data volume is at /app/data and the
# home config dir sits on a read-only filesystem. Detect the container
# by the writable data mount and default there.
_DOCKER_DATA_DIR = Path("/app/data")
_IN_CONTAINER = _DOCKER_DATA_DIR.is_dir()


def ensure_config_dir():
    """Create the config directory if it doesn't exist."""
    if not _IN_CONTAINER:
        _CONFIG_DIR.mkdir(parents=True, exist_ok=True)

DEFAULT_BLOCK_SCORE_THRESHOLD = 0.7
DEFAULT_DB_PATH = (
    str(_DOCKER_DATA_DIR / "infraguard.db") if _IN_CONTAINER
    else str(_CONFIG_DIR / "infraguard.db")
)
DEFAULT_RETENTION_DAYS = 30
DEFAULT_API_BIND = "127.0.0.1"
DEFAULT_API_PORT = 8080
DEFAULT_LOG_LEVEL = "INFO"
DEFAULT_LOG_FORMAT = "json"
DEFAULT_DYNAMIC_WHITELIST_THRESHOLD = 3
