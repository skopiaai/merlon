import os
import tempfile
from pathlib import Path

# `/data` is the volume mounted by docker-compose. It is the right default in a
# container and wrong everywhere else: running the test suite or the API from a
# plain checkout crashed at *import* time with
#
#     PermissionError: [Errno 13] Permission denied: '/data'
#
# which names a path that appears nowhere in the project's documentation and
# gives no hint that SENTINEL_DB_PATH exists. The first thing a new contributor
# did was fail before a single test ran. Fall back to a writable directory
# instead, and say so once, so an explicit configuration is still honoured and
# an unconfigured checkout still works.
_CONTAINER_DATA = Path("/data")


def _fallback_root() -> Path:
    """Where to keep state when the container volume isn't there.

    Prefers a directory next to the source tree so repeated runs reuse the same
    database — a scan history that vanishes between runs is its own bug — and
    drops to the system temp directory only if even that is read-only.
    """
    local = Path(__file__).resolve().parents[2] / ".sentinel-data"
    try:
        local.mkdir(parents=True, exist_ok=True)
        probe = local / ".writable"
        probe.touch()
        probe.unlink()
        return local
    except OSError:
        return Path(tempfile.gettempdir()) / "sentinel-data"


def _writable(path: Path) -> bool:
    try:
        path.mkdir(parents=True, exist_ok=True)
        return os.access(path, os.W_OK)
    except OSError:
        return False


_explicit_db = os.getenv("SENTINEL_DB_PATH")
_explicit_art = os.getenv("SENTINEL_ARTIFACT_DIR")

if _explicit_db or _explicit_art or _writable(_CONTAINER_DATA):
    DATA_ROOT = _CONTAINER_DATA
else:
    DATA_ROOT = _fallback_root()

DB_PATH = Path(_explicit_db or DATA_ROOT / "sentinel.db")
ARTIFACT_DIR = Path(_explicit_art or DATA_ROOT / "artifacts")

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://host.docker.internal:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:14b")
OLLAMA_TIMEOUT = float(os.getenv("OLLAMA_TIMEOUT", "180"))

MAX_CONCURRENT_SCANS = int(os.getenv("SENTINEL_MAX_CONCURRENT_SCANS", "2"))

# Global rate ceilings. Individual scans may request less, never more.
MAX_RATE_LIMIT = int(os.getenv("SENTINEL_MAX_RATE_LIMIT", "150"))   # requests/sec
MAX_CONCURRENCY = int(os.getenv("SENTINEL_MAX_CONCURRENCY", "25"))  # parallel conns

ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH.parent.mkdir(parents=True, exist_ok=True)
