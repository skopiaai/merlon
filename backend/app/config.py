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

# This project has been renamed twice: Sentinel, then Parapet, now Merlon.
# Each rename is cosmetic everywhere except configuration and data, where
# getting it wrong silently destroys someone's work — an ignored rate limit
# means the next scan runs at full speed against a target the operator
# deliberately throttled, and a fresh database beside a populated one reads as
# "the upgrade deleted all my scans".
#
# So the old names are a *list*, checked newest-first, not a single fallback.
# A one-step shim would have stranded anyone already running Parapet, which by
# the time of this rename included the only person using it.
#
# The legacy names are spelled in fragments so a project-wide find-and-replace
# cannot quietly collapse them into the current one. That is not hypothetical:
# the Parapet rename did exactly that, turning the whole shim into a no-op that
# still read like it worked, and every test that checked only the new name
# still passed.
_NAME = "merlon"
_PREFIX = "MERLON_"
_LEGACY_NAMES = ["para" + "pet", "sent" + "inel"]          # newest first
_LEGACY_PREFIXES = [n.upper() + "_" for n in _LEGACY_NAMES]


def env(name: str, default: str | None = None) -> str | None:
    """Read `MERLON_<name>`, falling back through every previous project name."""
    value = os.getenv(_PREFIX + name)
    if value:
        return value
    for prefix in _LEGACY_PREFIXES:
        value = os.getenv(prefix + name)
        if value:
            return value
    return default


def _fallback_root() -> Path:
    """Where to keep state when the container volume isn't there.

    Prefers a directory next to the source tree so repeated runs reuse the same
    database — a scan history that vanishes between runs is its own bug — and
    drops to the system temp directory only if even that is read-only.
    """
    root = Path(__file__).resolve().parents[2]
    local = root / f".{_NAME}-data"

    # Adopt the newest pre-rename directory rather than starting empty beside
    # it. Renaming a product should not look, to the person using it, like it
    # deleted every scan they had ever run.
    if not local.exists():
        for old in _LEGACY_NAMES:
            legacy = root / f".{old}-data"
            if not legacy.is_dir():
                continue
            try:
                legacy.rename(local)
            except OSError:
                # Cannot rename (permissions, a mount boundary) — keep using
                # the old directory rather than losing the data.
                return legacy
            break

    try:
        local.mkdir(parents=True, exist_ok=True)
        probe = local / ".writable"
        probe.touch()
        probe.unlink()
        return local
    except OSError:
        return Path(tempfile.gettempdir()) / f"{_NAME}-data"


def _writable(path: Path) -> bool:
    try:
        path.mkdir(parents=True, exist_ok=True)
        return os.access(path, os.W_OK)
    except OSError:
        return False


def _db_in(root: Path) -> Path:
    """The database file, adopting the pre-rename name if that is what exists.

    Inside the container this matters most: the volume survives the upgrade, so
    a fresh `merlon.db` next to a populated `parapet.db` would present as a
    total loss of history while the real data sat untouched one filename away.

    SQLite's -wal and -shm siblings are renamed with it. Leaving them behind
    would be worse than not renaming at all: SQLite would treat an orphaned WAL
    as belonging to the new file and could refuse to open it.
    """
    current = root / f"{_NAME}.db"
    if current.exists():
        return current

    for old in _LEGACY_NAMES:
        legacy = root / f"{old}.db"
        if not legacy.exists():
            continue
        try:
            for suffix in ("", "-wal", "-shm"):
                stale = Path(str(legacy) + suffix)
                if stale.exists():
                    stale.rename(Path(str(current) + suffix))
        except OSError:
            return legacy
        return current
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
