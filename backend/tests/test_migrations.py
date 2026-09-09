"""Schema migration tests.

Written after a real outage: adding columns to the models broke every existing
database. `create_all()` creates tables but never alters them, so the backend
started, then died on the first query with "no such column" — which looks from
the UI like the backend simply isn't running.
"""

import sqlite3

import pytest
from sqlalchemy import create_engine, inspect, text

import app.models  # noqa: F401  — registers the mappers
from app.db import Base, ensure_schema

# An engagements table as it existed before authenticated scanning was added.
OLD_SCHEMA = """
CREATE TABLE engagements (
  id INTEGER PRIMARY KEY, name VARCHAR(200), kind VARCHAR(50),
  authorized_by VARCHAR(200), authorization_ref TEXT, authorized_at DATETIME,
  expires_at DATETIME, allow_rules JSON, deny_rules JSON, notes TEXT,
  created_at DATETIME);
INSERT INTO engagements (id, name, allow_rules, deny_rules, notes)
  VALUES (1, 'pre-existing', '["a.com"]', '[]', 'must survive');
"""


@pytest.fixture
def legacy(tmp_path):
    path = tmp_path / "legacy.db"
    con = sqlite3.connect(path)
    con.executescript(OLD_SCHEMA)
    con.commit()
    con.close()
    return create_engine(f"sqlite:///{path}")


def test_missing_columns_are_added(legacy):
    applied = ensure_schema(legacy)
    assert any("auth_headers" in c for c in applied)

    cols = {c["name"] for c in inspect(legacy).get_columns("engagements")}
    assert {"auth_headers", "auth_check_url", "auth_check_string"} <= cols


def test_existing_rows_are_preserved(legacy):
    ensure_schema(legacy)
    with legacy.connect() as conn:
        row = conn.execute(text(
            "SELECT name, notes, allow_rules FROM engagements WHERE id = 1")).one()
    assert row[0] == "pre-existing"
    assert row[1] == "must survive"
    assert "a.com" in row[2]


def test_new_not_null_columns_get_parseable_defaults(legacy):
    ensure_schema(legacy)
    with legacy.connect() as conn:
        value = conn.execute(text(
            "SELECT auth_headers FROM engagements WHERE id = 1")).scalar()
    assert value in ("{}", None)


def test_json_list_columns_default_to_a_list(tmp_path):
    """A JSON column defaulting to {} where the code expects [] would crash later."""
    path = tmp_path / "l.db"
    con = sqlite3.connect(path)
    con.executescript(
        "CREATE TABLE findings (id INTEGER PRIMARY KEY, scan_id INTEGER, "
        "engine VARCHAR(50), rule_id VARCHAR(200), name TEXT, severity VARCHAR(20), "
        "host VARCHAR(255), url TEXT, dedupe_key VARCHAR(200));")
    con.commit(); con.close()

    eng = create_engine(f"sqlite:///{path}")
    ensure_schema(eng)
    with eng.connect() as conn:
        rows = {r[1]: r[4] for r in conn.execute(text("PRAGMA table_info(findings)"))}
    assert rows.get("references") == "'[]'", "list-valued JSON must default to []"
    assert rows.get("compliance") == "'{}'", "dict-valued JSON must default to {}"


def test_migration_is_idempotent(legacy):
    ensure_schema(legacy)
    assert ensure_schema(legacy) == [], "second run must be a no-op"


def test_untouched_database_needs_nothing(tmp_path):
    eng = create_engine(f"sqlite:///{tmp_path / 'fresh.db'}")
    Base.metadata.create_all(eng)
    assert ensure_schema(eng) == []


# =================================================== upgrading a real database

LEGACY_SCHEMA = """
CREATE TABLE engagements (
  id INTEGER PRIMARY KEY, name VARCHAR(200), kind VARCHAR(50),
  authorized_by VARCHAR(200), authorization_ref TEXT, authorized_at DATETIME,
  expires_at DATETIME, allow_rules JSON, deny_rules JSON,
  auth_headers JSON, auth_check_url TEXT, auth_check_string TEXT,
  notes TEXT, created_at DATETIME);
CREATE TABLE scans (
  id INTEGER PRIMARY KEY, engagement_id INTEGER, seeds JSON, profile VARCHAR(50),
  stages JSON, state VARCHAR(20), stage_current VARCHAR(50), progress FLOAT,
  error TEXT, stats JSON, rejected_hosts JSON, started_at DATETIME,
  finished_at DATETIME, created_at DATETIME);
CREATE TABLE findings (
  id INTEGER PRIMARY KEY, scan_id INTEGER, engine VARCHAR(50), rule_id VARCHAR(200),
  name TEXT, severity VARCHAR(20), host VARCHAR(255), url TEXT, matched_at TEXT,
  description TEXT, evidence TEXT, remediation TEXT, tags JSON,
  cve JSON, cwe JSON, cvss_score FLOAT, compliance JSON, dedupe_key VARCHAR(200),
  occurrences INTEGER, status VARCHAR(20), triage_confidence FLOAT,
  triage_note TEXT, analyst_note TEXT, raw JSON, created_at DATETIME);
INSERT INTO engagements (id, name, kind, authorized_by, authorization_ref,
  allow_rules, deny_rules, auth_headers, notes)
  VALUES (1, 'legacy', 'bug_bounty', 'me', 'ref', '["a.example.com"]', '[]', '{}', '');
INSERT INTO findings (id, scan_id, engine, rule_id, name, severity, host,
  dedupe_key, occurrences, status)
  VALUES (1, 1, 'httpx', 'missing-hsts', 'No HSTS', 'low', 'a.example.com', 'k', 1, 'new');
"""


def _legacy_engine(tmp_path):
    """A database written before several columns existed — the real upgrade
    path, not a fresh one."""
    import sqlite3

    from sqlalchemy import create_engine

    path = tmp_path / "legacy.db"
    con = sqlite3.connect(path)
    con.executescript(LEGACY_SCHEMA)
    con.commit()
    con.close()
    return create_engine(f"sqlite:///{path}", future=True)


def test_legacy_rows_are_backfilled_not_left_null(tmp_path):
    """ADD COLUMN leaves every existing row NULL. A JSON list column then reads
    back as None rather than [], and the next response that serialises that row
    fails validation — which presents as endpoints returning 500 on a database
    that upgraded "successfully"."""
    from sqlalchemy import text

    from app.db import ensure_schema

    engine = _legacy_engine(tmp_path)
    applied = ensure_schema(engine)
    assert any("auth_identities" in a for a in applied)

    with engine.begin() as conn:
        row = conn.execute(text(
            "SELECT auth_identities, authorized_at, created_at "
            "FROM engagements WHERE id = 1")).one()
    assert row[0] == "[]", "a new JSON list column must not be NULL on old rows"
    assert row[1] is not None, "a required timestamp must not be NULL"
    assert row[2] is not None


def test_new_finding_columns_are_usable_on_legacy_rows(tmp_path):
    from sqlalchemy import text

    from app.db import ensure_schema

    engine = _legacy_engine(tmp_path)
    ensure_schema(engine)
    with engine.begin() as conn:
        row = conn.execute(text(
            "SELECT reproduced, verification, \"references\" "
            "FROM findings WHERE id = 1")).one()
    assert row[0] == 0, "boolean columns must default to false, not NULL"
    assert row[1] == "{}"
    assert row[2] == "[]"


def test_migrating_twice_changes_nothing(tmp_path):
    from app.db import ensure_schema

    engine = _legacy_engine(tmp_path)
    ensure_schema(engine)
    assert ensure_schema(engine) == [], "a second migration should be a no-op"


def test_backfill_never_overwrites_real_data(tmp_path):
    """It only touches NULLs. A migration that rewrote populated columns would
    be far worse than one that left them alone."""
    from sqlalchemy import text

    from app.db import ensure_schema

    engine = _legacy_engine(tmp_path)
    ensure_schema(engine)
    with engine.begin() as conn:
        assert conn.execute(text(
            "SELECT name FROM engagements WHERE id = 1")).scalar() == "legacy"
        assert conn.execute(text(
            "SELECT allow_rules FROM engagements WHERE id = 1")).scalar() \
            == '["a.example.com"]'
