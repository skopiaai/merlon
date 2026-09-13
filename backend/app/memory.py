"""What previous scans learned, carried into the next one.

Every scan here used to start from zero. The same operator works the same
programme for months, finds `impersonate` on one host and `x-account-id` on
another, and none of it makes the next scan smarter — the candidate wordlists
are identical on scan one and scan two hundred.

This is the smallest useful fix: remember which parameter names actually
yielded findings, and try those first next time. It is a *prioritiser*, not a
detector. Nothing here decides that a bug exists — it changes which guesses are
spent first, and adds names learned from real findings that no built-in list
could have known about.

Two properties it must keep:

  * **Never a source of findings.** Memory reorders candidates. If it ever
    promoted something to a finding it would be laundering yesterday's guess
    into today's evidence, and the verification gate exists precisely to stop
    that.
  * **Proof is weighted, not just presence.** A name that produced a `proven`
    finding is worth much more than one that produced something merely
    reported, because the second may never have been real.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import String, select
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base

# A proven finding says the target demonstrated the bug. A name that got there
# is worth far more as a hint than one that merely appeared in a report.
PROVEN_WEIGHT = 5
PLAIN_WEIGHT = 1


class Knowledge(Base):
    """One remembered fact, keyed by kind and key.

    Deliberately generic: `kind` says what sort of fact this is ("param" today),
    `key` is the fact itself. Adding a second kind later needs no migration.
    """

    __tablename__ = "knowledge"

    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(String(32), index=True)
    key: Mapped[str] = mapped_column(String(200), index=True)
    score: Mapped[int] = mapped_column(default=0)
    hits: Mapped[int] = mapped_column(default=0)
    proven_hits: Mapped[int] = mapped_column(default=0)
    last_seen: Mapped[datetime] = mapped_column(
        default=lambda: datetime.now(timezone.utc))


def _param_of(finding) -> str:
    """The parameter a finding is about, if it names one.

    Engines record it in `raw`, which is where the injection engines already put
    the parameter they tested.
    """
    raw = getattr(finding, "raw", None) or {}
    if not isinstance(raw, dict):
        return ""
    name = raw.get("param") or raw.get("parameter") or ""
    return str(name).strip()[:200]


def record(db, kind: str, key: str, *, proven: bool) -> None:
    """Add one observation. Safe to call repeatedly for the same key."""
    if not key:
        return
    weight = PROVEN_WEIGHT if proven else PLAIN_WEIGHT
    entry = db.scalar(
        select(Knowledge).where(Knowledge.kind == kind, Knowledge.key == key))
    if entry is None:
        entry = Knowledge(kind=kind, key=key, score=0, hits=0, proven_hits=0)
        db.add(entry)
        # The session runs with autoflush off, so without this the *next*
        # lookup for the same key would not see this pending row and would
        # insert a second one. learn_from_findings records many findings in a
        # single call and the same parameter name recurs constantly, so the
        # scores would fragment across duplicate rows and the ordering would be
        # quietly wrong.
        db.flush()
    entry.score += weight
    entry.hits += 1
    if proven:
        entry.proven_hits += 1
    entry.last_seen = datetime.now(timezone.utc)


def learn_from_findings(db, findings) -> int:
    """Record what a verified scan's findings taught. Returns entries touched."""
    touched = 0
    for finding in findings:
        param = _param_of(finding)
        if not param:
            continue
        verification = getattr(finding, "verification", None) or {}
        proven = verification.get("tier") == "proven"
        record(db, "param", param, proven=proven)
        touched += 1
    return touched


def hot_params(db, limit: int = 40) -> list[str]:
    """Parameter names worth trying first, best-scoring first."""
    rows = db.scalars(
        select(Knowledge)
        .where(Knowledge.kind == "param")
        .order_by(Knowledge.score.desc(), Knowledge.last_seen.desc())
        .limit(limit)).all()
    return [r.key for r in rows]


def prioritise(candidates: list[str], remembered: list[str]) -> list[str]:
    """Remembered names first, then the built-in list, with no duplicates.

    Two things happen, and it is worth being exact about both. Names already in
    the built-in list are *reordered* to the front. A remembered name that is
    not in that list is *added* to it — which is the point: a parameter learned
    from a real finding on one target is worth trying on the next, and the
    built-in list cannot know about it.

    Nothing is ever dropped. A remembered name that stops being interesting
    sinks back down the list rather than disappearing from it.
    """
    seen: set[str] = set()
    out: list[str] = []
    for name in list(remembered) + list(candidates):
        low = name.lower()
        if low in seen:
            continue
        seen.add(low)
        out.append(name)
    return out


def recall_params(limit: int = 40) -> list[str]:
    """hot_params against the app's own database, for engines to call.

    Never raises: a database that is missing or mid-migration must not stop a
    scan, it must only mean the scan runs without a memory.
    """
    try:
        from .db import SessionLocal
        with SessionLocal() as db:
            return hot_params(db, limit)
    except Exception:  # noqa: BLE001 — a scan without memory is still a scan
        return []
