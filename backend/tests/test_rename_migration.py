"""The upgrade path from the old project name.

This project has been renamed twice: Sentinel, then Parapet, now Merlon. A
rename is a cosmetic change everywhere except the two places where it silently
destroys user data:

  * old-prefix environment variables in someone's existing `.env` — an ignored
    rate limit means the next scan runs at the default rate against a target
    the operator deliberately throttled;
  * the database and data directory — a fresh empty database created beside a
    populated one presents as "the upgrade deleted all my scans" while the real
    data sits untouched, one filename away.

The fallback is a *chain*, not one hop. A single-step shim would have stranded
anyone already running Parapet, which by the time of the second rename included
the only person using it.

These tests exist because the rename commit broke the compatibility shim while
writing it: a project-wide find-and-replace rewrote the *legacy* constants too,
so `_LEGACY_PREFIX` became identical to `_PREFIX` and the whole thing turned
into a no-op that still read like it worked. The constants are now assembled
from fragments specifically so that cannot happen again, and these tests fail
if it does.
"""
from __future__ import annotations

import importlib
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[1]


def _isolated_tree(tmp_path: Path) -> Path:
    """A throwaway copy of the package, so config resolves paths inside tmp.

    `_fallback_root()` walks up from `__file__`, not from the working
    directory — deliberately, so state lives next to the source tree rather
    than wherever you happened to launch from. That means a test cannot isolate
    it by changing cwd: the first attempt at these tests read the *real* repo's
    database and failed on a UnicodeDecodeError, which is the correct behaviour
    reporting a wrong test.
    """
    pkg = tmp_path / "backend" / "app"
    pkg.mkdir(parents=True)
    (tmp_path / "backend" / "__init__.py").unlink(missing_ok=True)
    for name in ("__init__.py", "config.py"):
        src = BACKEND / "app" / name
        (pkg / name).write_text(src.read_text() if src.exists() else "")
    return tmp_path / "backend"


def _run_in(tmp_path: Path, env: dict[str, str] | None = None,
            code: str = "") -> str:
    """Import config in a fresh interpreter against an isolated tree.

    A subprocess rather than a reload: config resolves paths at import time and
    caches them at module scope, so testing the migration in-process would
    measure whichever import happened first.
    """
    import os

    environ = {**os.environ, **(env or {})}
    for var in ("PARAPET_DB_PATH", "PARAPET_ARTIFACT_DIR",
                "SENTINEL_DB_PATH", "SENTINEL_ARTIFACT_DIR"):
        environ.pop(var, None)
    result = subprocess.run(
        [sys.executable, "-c", textwrap.dedent(code)],
        cwd=tmp_path, env=environ, capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


LEGACY_NAMES = ["parapet", "sentinel"]


def _seed_legacy_install(tmp_path: Path, name: str = "sentinel") -> None:
    """An install under a previous name: database, WAL sibling, artifacts."""
    legacy = tmp_path / f".{name}-data"
    (legacy / "artifacts").mkdir(parents=True)
    (legacy / f"{name}.db").write_text("PRECIOUS SCAN HISTORY")
    (legacy / f"{name}.db-wal").write_text("wal contents")
    (legacy / "artifacts" / "evidence.txt").write_text("old evidence")


@pytest.mark.parametrize("legacy", LEGACY_NAMES)
def test_legacy_data_directory_is_adopted(tmp_path: Path, legacy: str):
    """Every previous name is adopted, contents intact.

    Parametrised over the whole chain: the Parapet case is the one that would
    have silently stranded the only real install if this were a single hop.
    """
    _seed_legacy_install(tmp_path, legacy)
    tree = _isolated_tree(tmp_path)
    out = _run_in(tmp_path, code=f"""
        import sys; sys.path.insert(0, {str(tree)!r})
        from app import config
        print(config.DB_PATH.name)
        print(config.DB_PATH.read_text())
        print((config.DB_PATH.parent / 'merlon.db-wal').exists())
        print((config.ARTIFACT_DIR / 'evidence.txt').exists())
    """)
    name, contents, wal, artifact = out.splitlines()
    assert name == "merlon.db"
    assert contents == "PRECIOUS SCAN HISTORY", "scan history was lost on rename"
    assert wal == "True", "the WAL sibling was left behind — SQLite may refuse to open"
    assert artifact == "True", "captured evidence was lost on rename"
    assert not (tmp_path / f".{legacy}-data").exists()


def test_a_fresh_install_uses_the_new_names(tmp_path: Path):
    tree = _isolated_tree(tmp_path)
    out = _run_in(tmp_path, code=f"""
        import sys; sys.path.insert(0, {str(tree)!r})
        from app import config
        print(config.DB_PATH.name)
        print(config.DB_PATH.parent.name)
    """)
    assert out.splitlines() == ["merlon.db", ".merlon-data"]


def test_existing_new_data_is_not_overwritten_by_legacy(tmp_path: Path):
    """If both exist, the current one wins and neither is clobbered."""
    _seed_legacy_install(tmp_path)
    current = tmp_path / ".merlon-data"
    current.mkdir()
    (current / "merlon.db").write_text("CURRENT DATA")
    tree = _isolated_tree(tmp_path)

    out = _run_in(tmp_path, code=f"""
        import sys; sys.path.insert(0, {str(tree)!r})
        from app import config
        print(config.DB_PATH.read_text())
    """)
    assert out == "CURRENT DATA"
    # The legacy directory is left alone rather than merged or deleted.
    assert (tmp_path / ".sentinel-data" / "sentinel.db").exists()


ALL_PREFIXES = ["MERLON_", "PARAPET_", "SENTINEL_"]


@pytest.fixture
def clean_env(monkeypatch):
    """No rate-limit variable from any generation leaking in from the shell."""
    for prefix in ALL_PREFIXES:
        monkeypatch.delenv(prefix + "MAX_RATE_LIMIT", raising=False)
    yield monkeypatch
    from app import config
    importlib.reload(config)


@pytest.mark.parametrize("prefix", ["PARAPET_", "SENTINEL_"])
def test_every_previous_prefix_is_honoured(clean_env, prefix: str):
    """An old `.env` must keep working, whichever generation wrote it."""
    from app import config

    clean_env.setenv(prefix + "MAX_RATE_LIMIT", "42")
    importlib.reload(config)
    assert config.MAX_RATE_LIMIT == 42


def test_prefixes_resolve_newest_first(clean_env):
    """With every generation set at once, the current name must win."""
    from app import config

    clean_env.setenv("SENTINEL_MAX_RATE_LIMIT", "11")
    clean_env.setenv("PARAPET_MAX_RATE_LIMIT", "22")
    importlib.reload(config)
    assert config.MAX_RATE_LIMIT == 22, "the newer legacy prefix should win"

    clean_env.setenv("MERLON_MAX_RATE_LIMIT", "33")
    importlib.reload(config)
    assert config.MAX_RATE_LIMIT == 33


def test_the_compatibility_shim_has_not_collapsed():
    """The failure mode that actually happened, caught directly.

    A project-wide find-and-replace rewrote the legacy constants along with
    everything else, leaving `_LEGACY_PREFIX == _PREFIX`. Every test that only
    checked the *new* name still passed, and the shim did nothing.
    """
    from app import config

    assert config._PREFIX == "MERLON_"
    assert config._NAME == "merlon"
    # Every previous generation is still listed, newest first, and none of them
    # has been rewritten into the current name.
    assert config._LEGACY_NAMES == ["parapet", "sentinel"]
    assert config._PREFIX not in config._LEGACY_PREFIXES
    assert config._NAME not in config._LEGACY_NAMES


def test_env_helper_prefers_new_then_legacy_then_default(monkeypatch):
    from app import config

    for prefix in ALL_PREFIXES:
        monkeypatch.delenv(prefix + "WIDGET", raising=False)
    assert config.env("WIDGET", "fallback") == "fallback"

    monkeypatch.setenv("SENTINEL_WIDGET", "oldest")
    assert config.env("WIDGET", "fallback") == "oldest"

    monkeypatch.setenv("PARAPET_WIDGET", "middle")
    assert config.env("WIDGET", "fallback") == "middle"

    monkeypatch.setenv("MERLON_WIDGET", "current")
    assert config.env("WIDGET", "fallback") == "current"
