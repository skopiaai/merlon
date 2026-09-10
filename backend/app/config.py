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
# gives no hint that PARAPET_DB_PATH exists. The first thing a new contributor
# did was fail before a single test ran. Fall back to a writable directory
# instead, and say so once, so an explicit configuration is still honoured and
# an unconfigured checkout still works.
_CONTAINER_DATA = Path("/data")

# This project was called Sentinel before it was called Parapet. Anyone who set
# up a `.env` under the old name should not have their configuration silently
# ignored on upgrade — an ignored rate limit means the scan runs at the default
# rate against a target the operator deliberately throttled, which is both hard
# to notice and the sort of thing that gets someone's IP blocked.
#
# The legacy prefix is spelled in pieces so a future project-wide
# find-and-replace cannot quietly collapse it into the new one. That is not
# hypothetical: the rename commit did exactly that, turning this whole shim
# into a no-op that still read like it worked.
_PREFIX = "PARAPET_"
_LEGACY_PREFIX = "SENT" + "INEL_"
_LEGACY_NAME = "sent" + "inel"


def env(name: str, default: str | None = None) -> str | None:
    """Read `PARAPET_<name>`, falling back to the pre-rename `SENTINEL_<name>`."""
    return os.getenv(_PREFIX + name) or os.getenv(_LEGACY_PREFIX + name) or default


def _fallback_root() -> Path:
    """Where to keep state when the container volume isn't there.

    Prefers a directory next to the source tree so repeated runs reuse the same
    database — a scan history that vanishes between runs is its own bug — and
    drops to the system temp directory only if even that is read-only.
    """
    root = Path(__file__).resolve().parents[2]
    local = root / ".parapet-data"

    # Adopt the pre-rename directory rather than starting empty beside it.
    # Renaming a product should not look, to the person using it, like it
    # deleted every scan they had ever run.
    legacy = root / f".{_LEGACY_NAME}-data"
    if legacy.is_dir() and not local.exists():
        try:
            legacy.rename(local)
        except OSError:
            # Cannot rename (permissions, a mount boundary) — keep using the
            # old directory rather than losing the data.
            return legacy

    try:
        local.mkdir(parents=True, exist_ok=True)
        probe = local / ".writable"
        probe.touch()
        probe.unlink()
        return local
    except OSError:
        return Path(tempfile.gettempdir()) / "parapet-data"


def _writable(path: Path) -> bool:
    try:
        path.mkdir(parents=True, exist_ok=True)
        return os.access(path, os.W_OK)
    except OSError:
        return False


def _db_in(root: Path) -> Path:
    """The database file, adopting the pre-rename name if that is what exists.

    Inside the container this matters most: the volume survives the upgrade, so
    a fresh `parapet.db` next to a populated `sentinel.db` would present as a
    total loss of history while the real data sat untouched one filename away.

    SQLite's -wal and -shm siblings are renamed with it. Leaving them behind
    would be worse than not renaming at all: SQLite would treat an orphaned WAL
    as belonging to the new file and could refuse to open it.
    """
    current = root / "parapet.db"
    legacy = root / f"{_LEGACY_NAME}.db"
    if legacy.exists() and not current.exists():
        try:
            for suffix in ("", "-wal", "-shm"):
                old = Path(str(legacy) + suffix)
                if old.exists():
                    old.rename(Path(str(current) + suffix))
        except OSError:
            return legacy
    return current


_explicit_db = env("DB_PATH")
_explicit_art = env("ARTIFACT_DIR")

if _explicit_db or _explicit_art or _writable(_CONTAINER_DATA):
    DATA_ROOT = _CONTAINER_DATA
else:
    DATA_ROOT = _fallback_root()

DB_PATH = Path(_explicit_db) if _explicit_db else _db_in(DATA_ROOT)
ARTIFACT_DIR = Path(_explicit_art or DATA_ROOT / "artifacts")

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://host.docker.internal:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:14b")
OLLAMA_TIMEOUT = float(os.getenv("OLLAMA_TIMEOUT", "180"))

MAX_CONCURRENT_SCANS = int(env("MAX_CONCURRENT_SCANS", "2"))

# Global rate ceilings. Individual scans may request less, never more.
MAX_RATE_LIMIT = int(env("MAX_RATE_LIMIT", "150"))   # requests/sec
MAX_CONCURRENCY = int(env("MAX_CONCURRENCY", "25"))  # parallel conns

ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH.parent.mkdir(parents=True, exist_ok=True)
