"""Diffing findings between two scans.

The load-bearing test here is test_absence_is_not_a_fix. A finding missing from
a newer scan usually means it was fixed — and means nothing of the sort if the
engine that found it never ran. Reporting that as fixed would tell someone a
vulnerability is gone when nobody looked, which is the most damaging thing this
tool could say.
"""

import pytest

from app import watch
from app.db import SessionLocal, init_db
from app.models import Engagement, Finding, Scan, ScanState, Severity


def _mk_scan(db, eng_id, stages, completed, finished=None):
    # Real completed scans always carry finished_at; _finish sets it.
    from datetime import datetime, timezone
    s = Scan(engagement_id=eng_id, seeds=["diff.test"], profile="standard",
             stages=stages, state=ScanState.completed, completed_stages=completed,
             finished_at=finished or datetime.now(timezone.utc))
    db.add(s); db.commit(); db.refresh(s)
    return s.id


def _mk_finding(db, scan_id, key, engine="sqli", sev=Severity.high, host="a.diff.test"):
    db.add(Finding(scan_id=scan_id, engine=engine, rule_id=f"{engine}-rule",
                   name=f"{engine} finding", severity=sev, host=host,
                   url=f"https://{host}/x", dedupe_key=key))
    db.commit()


@pytest.fixture
def pair():
    init_db()
    with SessionLocal() as db:
        eng = Engagement(name="diff.test", kind="self_owned", authorized_by="me",
                         authorization_ref="x", allow_rules=["diff.test"], deny_rules=[])
        db.add(eng); db.commit(); db.refresh(eng)
        from datetime import datetime, timedelta, timezone
        now = datetime.now(timezone.utc)
        old = _mk_scan(db, eng.id, ["sqli", "xss"], ["sqli", "xss"],
                       finished=now - timedelta(days=7))
        new = _mk_scan(db, eng.id, ["sqli", "xss"], ["sqli", "xss"], finished=now)
        return eng.id, old, new


# ---------------------------------------------------------------- buckets

def test_new_findings_are_new(pair):
    _, old, new = pair
    with SessionLocal() as db:
        _mk_finding(db, old, "k1")
        _mk_finding(db, new, "k1")
        _mk_finding(db, new, "k2")
    d = watch.diff_findings(old, new)
    assert [f["dedupe_key"] for f in d["new"]] == ["k2"]
    assert [f["dedupe_key"] for f in d["still_open"]] == ["k1"]
    assert d["fixed"] == []


def test_a_finding_that_went_away_is_fixed_when_the_engine_reran(pair):
    _, old, new = pair
    with SessionLocal() as db:
        _mk_finding(db, old, "gone", engine="sqli")
        # the new scan ran sqli (it is in completed_stages) and found nothing
        _mk_finding(db, new, "other", engine="xss")
    d = watch.diff_findings(old, new)
    assert [f["dedupe_key"] for f in d["fixed"]] == ["gone"]
    assert d["not_rechecked"] == []


def test_absence_is_not_a_fix(pair):
    """The one that matters: a shallower rescan must not report fixes."""
    eng_id, old, _ = pair
    with SessionLocal() as db:
        _mk_finding(db, old, "sqli-key", engine="sqli")
        # the rescan never ran sqli at all
        shallow = _mk_scan(db, eng_id, ["xss"], ["xss"])
        _mk_finding(db, shallow, "xss-key", engine="xss")

    d = watch.diff_findings(old, shallow)
    assert d["fixed"] == [], "a finding was called fixed though nobody rechecked it"
    assert [f["dedupe_key"] for f in d["not_rechecked"]] == ["sqli-key"]
    assert "not known to be fixed" in watch.summarise_findings(d)


def test_severity_ordering(pair):
    _, old, new = pair
    with SessionLocal() as db:
        _mk_finding(db, new, "low1", sev=Severity.low, host="b.diff.test")
        _mk_finding(db, new, "crit", sev=Severity.critical, host="a.diff.test")
        _mk_finding(db, new, "med", sev=Severity.medium, host="c.diff.test")
    d = watch.diff_findings(old, new)
    assert [f["severity"] for f in d["new"]] == ["critical", "medium", "low"]


# ---------------------------------------------------------------- helpers

def test_engines_that_ran_includes_engines_that_produced_findings(pair):
    """An older scan predating stage tracking still counts as having run."""
    eng_id, _old, _new = pair
    with SessionLocal() as db:
        s = _mk_scan(db, eng_id, ["sqli"], [])      # no completed_stages recorded
        _mk_finding(db, s, "k", engine="sqli")
    assert "sqli" in watch.engines_that_ran(s)


def test_finding_index_keys_on_dedupe_key(pair):
    _, _old, new = pair
    with SessionLocal() as db:
        _mk_finding(db, new, "stable-key")
    idx = watch.finding_index(new)
    assert "stable-key" in idx
    assert idx["stable-key"]["engine"] == "sqli"


# ---------------------------------------------------------------- summary

def test_summary_reads_plainly(pair):
    _, old, new = pair
    with SessionLocal() as db:
        _mk_finding(db, old, "shared")
        _mk_finding(db, new, "shared")
        _mk_finding(db, new, "fresh", sev=Severity.critical)
    text = watch.summarise_findings(watch.diff_findings(old, new))
    assert "New: 1" in text and "critical" in text
    assert "Still open: 1" in text


def test_no_change_says_so(pair):
    _, old, new = pair
    assert watch.summarise_findings(watch.diff_findings(old, new)) == "No change."


# ---------------------------------------------------------------- engagement

def test_engagement_diff_uses_the_last_two_completed_scans(pair):
    eng_id, old, new = pair
    with SessionLocal() as db:
        _mk_finding(db, new, "only-in-new")
    d = watch.diff_findings_engagement(eng_id)
    assert "error" not in d
    assert [f["dedupe_key"] for f in d["new"]] == ["only-in-new"]


def test_engagement_with_one_scan_says_so():
    init_db()
    with SessionLocal() as db:
        eng = Engagement(name="single.test", kind="self_owned", authorized_by="me",
                         authorization_ref="x", allow_rules=["single.test"], deny_rules=[])
        db.add(eng); db.commit(); db.refresh(eng)
        _mk_scan(db, eng.id, ["sqli"], ["sqli"])
        eid = eng.id
    d = watch.diff_findings_engagement(eid)
    assert "only one completed scan" in d["error"]
