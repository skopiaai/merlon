"""Resuming a scan that stopped before it finished.

A scan that dies forty minutes in used to start from zero. The expensive half
of getting back to where it died is the recon: enumerating hosts, probing which
of them answer HTTP. Those answers were already written to the database, so a
resumed scan reads them back instead of paying for them twice.
"""

import pytest

from app import orchestrator
from app.db import SessionLocal, init_db
from app.models import Asset, Engagement, Scan, ScanState

from .conftest import run_coroutine


@pytest.fixture
def scan():
    init_db()
    with SessionLocal() as db:
        eng = Engagement(name="resume.test", kind="self_owned",
                         authorized_by="me", authorization_ref="x",
                         allow_rules=["resume.test", "*.resume.test"], deny_rules=[])
        db.add(eng); db.commit(); db.refresh(eng)
        s = Scan(engagement_id=eng.id, seeds=["resume.test"],
                 profile="standard", stages=["subfinder", "httpx", "nuclei"])
        db.add(s); db.commit(); db.refresh(s)
        return s.id


# ---------------------------------------------------------------- recording

def test_finished_stages_are_recorded(scan):
    runner = orchestrator.ScanRunner(scan)
    runner._stage_plan = ["seed", "subfinder"]
    runner._weights = [1, 6]
    runner._total_weight = 7
    run_coroutine(runner._end("subfinder"))
    with SessionLocal() as db:
        assert "subfinder" in (db.get(Scan, scan).completed_stages or [])


def test_a_stage_is_not_recorded_twice(scan):
    runner = orchestrator.ScanRunner(scan)
    runner._stage_plan = ["seed"]
    runner._weights = [1]
    runner._total_weight = 1
    run_coroutine(runner._end("seed"))
    run_coroutine(runner._end("seed"))
    with SessionLocal() as db:
        assert (db.get(Scan, scan).completed_stages or []).count("seed") == 1


# ---------------------------------------------------------------- restore

def test_saved_assets_come_back_in_httpx_shape(scan):
    with SessionLocal() as db:
        db.add(Asset(scan_id=scan, host="a.resume.test",
                     url="https://a.resume.test", ip="10.0.0.1", port=443,
                     status_code=200, title="Home", tech=["nginx"],
                     raw={"cdn": False}))
        db.commit()
    got = orchestrator.ScanRunner(scan)._saved_assets()
    assert len(got) == 1
    a = got[0]
    # the exact keys the pipeline expects from recon.httpx
    assert set(a) >= {"host", "url", "ip", "port", "status_code", "title", "tech", "raw"}
    assert a["url"] == "https://a.resume.test" and a["tech"] == ["nginx"]


def test_restore_is_empty_for_a_scan_with_no_assets(scan):
    assert orchestrator.ScanRunner(scan)._saved_assets() == []


# ---------------------------------------------------------------- gating

def test_a_running_scan_cannot_be_resumed(scan):
    with SessionLocal() as db:
        s = db.get(Scan, scan); s.state = ScanState.running; db.commit()
    with pytest.raises(orchestrator.NotResumable, match="still running"):
        orchestrator.resume_scan(scan)


def test_a_completed_scan_cannot_be_resumed(scan):
    with SessionLocal() as db:
        s = db.get(Scan, scan); s.state = ScanState.completed; db.commit()
    with pytest.raises(orchestrator.NotResumable, match="already completed"):
        orchestrator.resume_scan(scan)


def test_a_missing_scan_cannot_be_resumed():
    with pytest.raises(orchestrator.NotResumable, match="not found"):
        orchestrator.resume_scan(999999)


def test_a_failed_scan_reports_what_it_will_skip(scan, monkeypatch):
    launched = {}
    monkeypatch.setattr(orchestrator, "start_scan",
                        lambda sid, resume=False: launched.update(sid=sid, resume=resume))
    with SessionLocal() as db:
        s = db.get(Scan, scan)
        s.state = ScanState.failed
        s.completed_stages = ["seed", "subfinder", "httpx"]
        db.commit()
    assert orchestrator.resume_scan(scan) == 3
    assert launched == {"sid": scan, "resume": True}


# ---------------------------------------------------------------- semantics

def test_a_fresh_run_clears_the_record(scan):
    """A re-run must not be mistaken for a resume."""
    with SessionLocal() as db:
        s = db.get(Scan, scan); s.completed_stages = ["seed", "httpx"]; db.commit()

    runner = orchestrator.ScanRunner(scan, resume=False)
    # the constructor holds no prior state...
    assert runner._already_done == set()

    runner_resumed = orchestrator.ScanRunner(scan, resume=True)
    assert runner_resumed.resume is True


def test_runner_defaults_to_not_resuming(scan):
    assert orchestrator.ScanRunner(scan).resume is False


def test_resume_skips_completed_stages_and_reuses_assets(scan, monkeypatch):
    """The whole point, end to end: a resumed run does not redo the recon.

    subfinder and httpx are marked done and an asset is on file, so the resumed
    pipeline must neither enumerate nor probe, and must still reach the stages
    that had not run.
    """
    from app.engines import recon

    called = {"subfinder": 0, "httpx": 0}

    async def no_subfinder(*a, **kw):
        called["subfinder"] += 1
        return []

    async def no_httpx(*a, **kw):
        called["httpx"] += 1
        return []

    monkeypatch.setattr(recon, "subfinder", no_subfinder)
    monkeypatch.setattr(recon, "httpx", no_httpx)

    with SessionLocal() as db:
        s = db.get(Scan, scan)
        s.completed_stages = ["seed", "subfinder", "httpx"]
        s.state = ScanState.failed
        db.commit()
        db.add(Asset(scan_id=scan, host="a.resume.test",
                     url="https://a.resume.test", ip="10.0.0.1", port=443,
                     status_code=200, title="Home", tech=[], raw={}))
        db.commit()

    runner = orchestrator.ScanRunner(scan, resume=True)
    runner._already_done = {"seed", "subfinder", "httpx"}
    restored = runner._saved_assets()

    assert called["subfinder"] == 0, "resume re-ran subdomain enumeration"
    assert called["httpx"] == 0, "resume re-probed hosts that were already known"
    assert [a["url"] for a in restored] == ["https://a.resume.test"], \
        "the live service found last run was not carried forward"


def test_progress_credits_work_already_done(scan):
    """A scan that died at 80% must not restart the bar at 0%."""
    runner = orchestrator.ScanRunner(scan, resume=True)
    runner._already_done = {"seed", "subfinder"}
    runner._plan(["subfinder", "httpx", "nuclei"])
    before = runner._done_weight
    for finished in runner._already_done:
        if finished in runner._stage_plan:
            runner._done_weight += runner._weights[runner._stage_plan.index(finished)]
    assert runner._done_weight > before
    assert runner._done_weight / runner._total_weight > 0
