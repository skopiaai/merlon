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
