"""Scan lifecycle tests.

These exist because of a real failure: a scan interrupted by a backend restart
stayed at "running" forever. Cancel returned 409 ("not currently running")
because no asyncio task was tracked, so there was no way to clear it from the
UI — the scan sat there for a day showing a progress bar that never moved.
"""

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app import orchestrator
from app.db import SessionLocal, init_db
from app.main import app
from app.models import Engagement, Scan, ScanLog, ScanState


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(orchestrator, "_running", {})
    monkeypatch.setattr(orchestrator, "start_scan", lambda *_a, **_k: None)
    with TestClient(app) as c:
        yield c


def make_scan(state=ScanState.running, started_minutes_ago=5):
    init_db()
    with SessionLocal() as db:
        eng = Engagement(name="lc", authorized_by="me", authorization_ref="r",
                         allow_rules=["example.com"], deny_rules=[])
        db.add(eng); db.commit(); db.refresh(eng)
        scan = Scan(
            engagement_id=eng.id, seeds=["example.com"], stages=["httpx"],
            state=state,
            started_at=datetime.now(timezone.utc) - timedelta(minutes=started_minutes_ago),
        )
        db.add(scan); db.commit(); db.refresh(scan)
        return scan.id


def state_of(scan_id):
    with SessionLocal() as db:
        return db.get(Scan, scan_id).state


# ---------------- the bug ----------------

def test_cancel_works_when_no_task_is_tracked(client):
    """The exact reported failure: cancel a scan the backend no longer owns."""
    sid = make_scan()
    r = client.post(f"/api/scans/{sid}/cancel")
    assert r.status_code == 200, "cancel must never 409 a stuck scan"
    assert r.json()["result"] == "forced"
    assert state_of(sid) is ScanState.cancelled


def test_cancel_reports_clearly_why(client):
    sid = make_scan()
    body = client.post(f"/api/scans/{sid}/cancel").json()
    assert "restarted" in body["message"]


def test_cancel_a_queued_scan(client):
    sid = make_scan(state=ScanState.queued)
    client.post(f"/api/scans/{sid}/cancel")
    assert state_of(sid) is ScanState.cancelled


def test_cancel_finished_scan_is_harmless(client):
    sid = make_scan(state=ScanState.completed)
    body = client.post(f"/api/scans/{sid}/cancel").json()
    assert body["result"] == "already-finished"
    assert state_of(sid) is ScanState.completed


def test_cancel_unknown_scan_404s(client):
    assert client.post("/api/scans/999999/cancel").status_code == 404


# ---------------- restart reconciliation ----------------

def test_orphans_are_reconciled_on_startup():
    running = make_scan(state=ScanState.running)
    queued = make_scan(state=ScanState.queued)
    done = make_scan(state=ScanState.completed)

    assert orchestrator.reconcile_orphans() >= 2
    assert state_of(running) is ScanState.failed
    assert state_of(queued) is ScanState.failed
    assert state_of(done) is ScanState.completed, "finished scans must be left alone"

    with SessionLocal() as db:
        assert "restarted" in db.get(Scan, running).error


def test_reconcile_is_idempotent():
    make_scan(state=ScanState.running)
    orchestrator.reconcile_orphans()
    assert orchestrator.reconcile_orphans() == 0


# ---------------- stall detection ----------------

@pytest.mark.parametrize("silent_minutes,should_stall", [(10, False), (90, True)])
def test_watchdog_threshold(silent_minutes, should_stall):
    """A scan producing no output for 45+ minutes is hung, not slow."""
    sid = make_scan(started_minutes_ago=silent_minutes + 5)
    with SessionLocal() as db:
        db.add(ScanLog(
            scan_id=sid, level="info", message="last output",
            created_at=datetime.now(timezone.utc) - timedelta(minutes=silent_minutes)))
        db.commit()

        scan = db.get(Scan, sid)
        last = db.query(ScanLog.created_at).filter(ScanLog.scan_id == sid) \
                 .order_by(ScanLog.id.desc()).first()[0]
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        elapsed = (datetime.now(timezone.utc) - last).total_seconds()

    assert (elapsed > orchestrator.STALL_SECONDS) is should_stall
    assert scan is not None
