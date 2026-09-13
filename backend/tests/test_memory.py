"""Cross-target memory.

Every scan used to start from zero: identical wordlists on scan one and scan
two hundred. This remembers which parameter names actually yielded findings and
tries those first.

The property that matters most is the one it must *not* have: memory can never
produce a finding. It reorders guesses. If it could promote something into a
result it would be laundering yesterday's guess into today's evidence, which is
exactly what the verification gate exists to prevent.
"""

import pytest

from app import memory


@pytest.fixture
def db():
    from app.db import SessionLocal, init_db
    init_db()
    with SessionLocal() as s:
        # start from a clean slate so ordering assertions are deterministic
        for row in s.scalars(memory.select(memory.Knowledge)).all():
            s.delete(row)
        s.commit()
        yield s
        for row in s.scalars(memory.select(memory.Knowledge)).all():
            s.delete(row)
        s.commit()


# ---------------------------------------------------------------- recording

def test_records_and_accumulates(db):
    memory.record(db, "param", "impersonate", proven=False)
    memory.record(db, "param", "impersonate", proven=False)
    db.commit()
    entry = db.scalar(memory.select(memory.Knowledge).where(
        memory.Knowledge.key == "impersonate"))
    assert entry.hits == 2
    assert entry.score == 2 * memory.PLAIN_WEIGHT


def test_proof_outweighs_mere_presence(db):
    memory.record(db, "param", "proven_one", proven=True)
    for _ in range(4):
        memory.record(db, "param", "noisy_one", proven=False)
    db.commit()
    hot = memory.hot_params(db)
    assert hot[0] == "proven_one", (
        "a name that reached 'proven' must outrank one merely reported often")


def test_empty_key_is_ignored(db):
    memory.record(db, "param", "", proven=True)
    db.commit()
    assert memory.hot_params(db) == []


# ---------------------------------------------------------------- learning

class _F:
    def __init__(self, raw, tier=None):
        self.raw = raw
        self.verification = {"tier": tier} if tier else {}


def test_learns_the_parameter_and_its_tier(db):
    memory.learn_from_findings(db, [
        _F({"param": "redirect_to"}, tier="proven"),
        _F({"param": "note"}, tier="reproduced"),
        _F({}, tier="proven"),            # no param — nothing to learn
        _F(None, tier="proven"),          # tolerate a missing raw
    ])
    db.commit()
    hot = memory.hot_params(db)
    assert hot[0] == "redirect_to"
    assert "note" in hot
    assert len(hot) == 2


def test_learning_survives_odd_raw(db):
    memory.learn_from_findings(db, [_F("not-a-dict", tier="proven")])
    db.commit()
    assert memory.hot_params(db) == []


# ---------------------------------------------------------------- ordering

def test_prioritise_puts_remembered_first_without_losing_anything():
    builtin = ["debug", "admin", "url"]
    out = memory.prioritise(builtin, ["impersonate", "admin"])
    assert out[0] == "impersonate"
    # nothing dropped
    assert set(builtin) <= set(out)
    # no duplicates even though 'admin' appears in both
    assert len(out) == len(set(out))
    assert out.count("admin") == 1


def test_prioritise_is_case_insensitive_about_duplicates():
    out = memory.prioritise(["Admin"], ["admin"])
    assert len(out) == 1


def test_prioritise_with_no_memory_is_the_builtin_list():
    builtin = ["a", "b", "c"]
    assert memory.prioritise(builtin, []) == builtin


# ---------------------------------------------------------------- safety

def test_recall_never_raises(monkeypatch):
    """A broken database means a scan without memory, not a failed scan."""
    def boom():
        raise RuntimeError("database is gone")
    monkeypatch.setattr("app.db.SessionLocal", boom)
    assert memory.recall_params() == []


def test_memory_module_exposes_no_finding_builder():
    """Memory reorders guesses; it must not be able to emit a finding."""
    for name in dir(memory):
        assert "finding" not in name.lower() or name == "learn_from_findings"


def test_repeated_keys_in_one_batch_do_not_duplicate(db):
    """The session has autoflush off; without a flush this made two rows.

    learn_from_findings records many findings at once and the same parameter
    name recurs constantly, so duplicates would fragment the score and make the
    ordering quietly wrong.
    """
    memory.learn_from_findings(db, [
        _F({"param": "id"}, tier="proven"),
        _F({"param": "id"}, tier="proven"),
        _F({"param": "id"}, tier="reproduced"),
    ])
    db.commit()
    rows = db.scalars(memory.select(memory.Knowledge).where(
        memory.Knowledge.key == "id")).all()
    assert len(rows) == 1, "the same key must accumulate, not duplicate"
    assert rows[0].hits == 3
    assert rows[0].proven_hits == 2


def test_a_learned_name_absent_from_the_builtin_list_is_added():
    """The point of memory: a name no built-in list could have known about.

    `prioritise` reorders names it already has and adds ones it does not, which
    is how a parameter learned on one target reaches the next.
    """
    builtin = ["debug", "admin"]
    out = memory.prioritise(builtin, ["x-internal-actor"])
    assert out[0] == "x-internal-actor"
    assert len(out) == len(builtin) + 1
    assert set(builtin) <= set(out)
