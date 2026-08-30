import sqlite3

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, DeclarativeBase

from .config import DB_PATH


class Base(DeclarativeBase):
    pass


engine = create_engine(
    f"sqlite:///{DB_PATH}",
    connect_args={"check_same_thread": False, "timeout": 30},
    future=True,
)


@event.listens_for(engine, "connect")
def _sqlite_pragmas(dbapi_conn, _record):
    """Configure each connection, degrading rather than failing.

    WAL is the right mode — concurrent readers while a scan writes — but it
    depends on shared-memory mmap. On virtualised filesystems (a Docker bind
    mount on macOS, some network shares) that mmap fails and SQLite raises
    "disk I/O error" on the very first connection, which surfaces as the app
    refusing to start. Fall back to TRUNCATE there: slower under concurrency,
    but correct everywhere.
    """
    cur = dbapi_conn.cursor()
    for mode in ("WAL", "TRUNCATE", "DELETE"):
        try:
            cur.execute(f"PRAGMA journal_mode={mode}")
            if (cur.fetchone() or [""])[0].lower() == mode.lower():
                break
        except sqlite3.OperationalError:
            continue
    cur.execute("PRAGMA synchronous=NORMAL")
    cur.execute("PRAGMA foreign_keys=ON")
    cur.execute("PRAGMA busy_timeout=15000")
    cur.close()


SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def _sqlite_default(col) -> str:
    """A literal DEFAULT for ADD COLUMN, since SQLite requires one for NOT NULL."""
    name = col.type.__class__.__name__.upper()
    if "JSON" in name:
        # Best guess from the Python-side default: list columns get [], dicts {}.
        factory = getattr(col.default, "arg", None)
        if factory in (list,) or getattr(factory, "__name__", "") == "list":
            return "'[]'"
        return "'{}'"
    if any(k in name for k in ("INT", "FLOAT", "NUMERIC", "DECIMAL")):
        return "0"
    if "BOOLEAN" in name:
        return "0"
    if "DATETIME" in name or "DATE" in name:
        return "NULL"
    if isinstance(getattr(col.default, "arg", None), str):
        return "'" + col.default.arg.replace("'", "''") + "'"
    return "''"


def ensure_schema(target=None) -> list[str]:
    """Add columns the models declare but the database is missing.

    SQLAlchemy's create_all() only creates *tables*; it will never alter an
    existing one. So every time a model gained a column, an existing database
    kept working until the first query touched it and then failed with
    "no such column" — which presents as the backend simply not starting.

    SQLite supports ALTER TABLE ADD COLUMN, which covers every schema change
    this project has made. Anything more complex (dropping or retyping a
    column) would need a real migration tool; we'd rather fail loudly there
    than silently corrupt data.
    """
    from sqlalchemy import inspect, text

    eng = target or engine
    applied: list[str] = []
    insp = inspect(eng)
    with eng.begin() as conn:
        for table in Base.metadata.sorted_tables:
            if not insp.has_table(table.name):
                continue
            existing = {c["name"] for c in insp.get_columns(table.name)}
            for col in table.columns:
                if col.name in existing:
                    continue
                coltype = col.type.compile(eng.dialect)
                ddl = f'ALTER TABLE "{table.name}" ADD COLUMN "{col.name}" {coltype}'
                if not col.nullable:
                    ddl += f" NOT NULL DEFAULT {_sqlite_default(col)}"
                conn.execute(text(ddl))
                applied.append(f"{table.name}.{col.name}")
    return applied


def init_db():
    from . import models  # noqa: F401  (registers mappers)
    Base.metadata.create_all(engine)
    return ensure_schema()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
