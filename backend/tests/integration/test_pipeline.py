"""End-to-end pipeline tests against deliberately vulnerable targets.

Everything else in this suite tests components in isolation — parsers, scope
rules, mappings. Those all passed while the actual scanner was broken in five
different ways: `/dev/stdin` failing under asyncio, the 64 KiB stream limit,
`create_task` with no event loop, unmigrated schema columns, missing arm64
packages. Every one of those would have been caught here.

This runs the *real* orchestrator against a *real* vulnerable application over
a *real* network and asserts what it should find.

Run with:
    ./run-lab-tests.sh

The targets are OWASP Juice Shop and DVWA on an internal Docker network with
no host ports and no internet route. They are intentionally insecure; they must
never be exposed.
"""

import asyncio
import socket

import pytest
from sqlalchemy import select

from app import orchestrator
from app.db import SessionLocal, init_db
from app.models import Asset, Engagement, Finding, Scan, ScanLog, ScanState

pytestmark = pytest.mark.integration

JUICE = "juiceshop.test"
JUICE_PORT = 3000


def _reachable(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


requires_lab = pytest.mark.skipif(
    not _reachable(JUICE, JUICE_PORT),
    reason=f"{JUICE}:{JUICE_PORT} unreachable — start the lab with "
           f"`docker compose --profile lab up -d`",
)


def _run_scan(stages: list[str], seeds: list[str] | None = None,
              profile: str = "standard", timeout: float = 600) -> int:
    """Run the genuine pipeline to completion and return the scan id."""
    init_db()
    with SessionLocal() as db:
        eng = Engagement(
            name="lab", kind="lab",
            authorized_by="integration test suite",
            authorization_ref="local lab containers, owned by this project",
            allow_rules=[JUICE, "dvwa.test"], deny_rules=[],
        )
        db.add(eng)
        db.commit()
        db.refresh(eng)
        scan = Scan(engagement_id=eng.id, seeds=seeds or [f"{JUICE}:{JUICE_PORT}"],
                    profile=profile, stages=stages)
        db.add(scan)
        db.commit()
        db.refresh(scan)
        scan_id = scan.id

    async def go():
        orchestrator.bind_loop(asyncio.get_running_loop())
        await asyncio.wait_for(orchestrator.ScanRunner(scan_id).run(), timeout=timeout)

    asyncio.new_event_loop().run_until_complete(go())
    return scan_id


def _scan(scan_id: int) -> Scan:
    with SessionLocal() as db:
        return db.get(Scan, scan_id)


def _findings(scan_id: int) -> list[Finding]:
    with SessionLocal() as db:
        return list(db.scalars(select(Finding).where(Finding.scan_id == scan_id)))


# ------------------------------------------------------------------ basics

@requires_lab
def test_scan_completes_without_error():
    """The single most valuable assertion in the suite."""
    sid = _run_scan(["httpx"])
    scan = _scan(sid)
    assert scan.state is ScanState.completed, f"scan failed: {scan.error}"
    assert scan.error == ""
    assert scan.progress == 1.0


@requires_lab
def test_live_service_is_discovered():
    """Proves the subprocess layer, temp-file input and JSONL parsing all work."""
    sid = _run_scan(["httpx"])
    with SessionLocal() as db:
        assets = list(db.scalars(select(Asset).where(Asset.scan_id == sid)))
    assert assets, "httpx found no live service on a target that is definitely up"
    assert any(JUICE in a.host for a in assets)
    assert any(a.status_code == 200 for a in assets)


@requires_lab
def test_response_headers_are_captured():
    """The header audit is worthless if httpx isn't returning headers."""
    sid = _run_scan(["httpx"])
    with SessionLocal() as db:
        assets = list(db.scalars(select(Asset).where(Asset.scan_id == sid)))
    assert any(a.raw.get("header") or a.raw.get("response_headers") for a in assets), \
        "no response headers captured — the -include-response-header flag is broken"


# ------------------------------------------------------- expected findings

@requires_lab
def test_missing_security_headers_are_found():
    """Juice Shop ships without CSP, HSTS or frame protection. If we don't
    report those, the header auditor has regressed."""
    sid = _run_scan(["httpx"])
    rules = {f.rule_id for f in _findings(sid)}
    assert "missing-csp" in rules
    assert rules & {"missing-xfo", "missing-nosniff"}, \
        f"expected browser-control findings, got {rules}"


@requires_lab
def test_findings_carry_compliance_mapping():
    """Every finding must be traceable to a control, or the audit report lies."""
    sid = _run_scan(["httpx"])
    found = _findings(sid)
    assert found
    for f in found:
        assert f.compliance, f"{f.rule_id} has no compliance mapping"
        assert f.compliance.get("owasp_top10"), f"{f.rule_id} has no OWASP category"


@requires_lab
def test_findings_have_remediation_and_evidence():
    for f in _findings(_run_scan(["httpx"])):
        assert f.remediation.strip(), f"{f.rule_id} has no remediation text"
        assert f.name.strip()


@requires_lab
def test_no_duplicate_findings():
    """Dedupe is what keeps the triage queue usable."""
    found = _findings(_run_scan(["httpx"]))
    keys = [f.dedupe_key for f in found]
    assert len(keys) == len(set(keys))


# ----------------------------------------------------------- scope safety

@requires_lab
def test_out_of_scope_host_is_never_scanned():
    """The most important safety property in the whole system."""
    init_db()
    with SessionLocal() as db:
        eng = Engagement(
            name="narrow", kind="lab", authorized_by="test",
            authorization_ref="lab", allow_rules=["dvwa.test"], deny_rules=[])
        db.add(eng); db.commit(); db.refresh(eng)
        scan = Scan(engagement_id=eng.id, seeds=[f"{JUICE}:{JUICE_PORT}"],
                    profile="standard", stages=["httpx"])
        db.add(scan); db.commit(); db.refresh(scan)
        sid = scan.id

    async def go():
        orchestrator.bind_loop(asyncio.get_running_loop())
        await orchestrator.ScanRunner(sid).run()

    asyncio.new_event_loop().run_until_complete(go())

    scan = _scan(sid)
    assert scan.state is ScanState.failed
    assert "scope" in scan.error.lower()
    assert _findings(sid) == [], "an out-of-scope host produced findings"


# --------------------------------------------------------------- pipeline

@requires_lab
def test_correlation_runs_after_findings():
    sid = _run_scan(["httpx"])
    scan = _scan(sid)
    assert scan.stage_current in ("done", "correlate")


@requires_lab
def test_progress_reaches_completion():
    sid = _run_scan(["httpx"])
    assert _scan(sid).progress == 1.0


@requires_lab
def test_scan_is_cancellable_midway():
    """Cancel must leave a terminal state, not a scan stuck at 'running'."""
    init_db()
    with SessionLocal() as db:
        eng = Engagement(name="cancel", kind="lab", authorized_by="test",
                         authorization_ref="lab", allow_rules=[JUICE], deny_rules=[])
        db.add(eng); db.commit(); db.refresh(eng)
        scan = Scan(engagement_id=eng.id, seeds=[f"{JUICE}:{JUICE_PORT}"],
                    profile="thorough", stages=["httpx", "katana", "nuclei"])
        db.add(scan); db.commit(); db.refresh(scan)
        sid = scan.id

    async def go():
        orchestrator.bind_loop(asyncio.get_running_loop())
        task = asyncio.create_task(orchestrator.ScanRunner(sid).run())
        orchestrator._running[sid] = task
        await asyncio.sleep(6)
        orchestrator.cancel_scan(sid)
        try:
            await asyncio.wait_for(task, timeout=60)
        except (asyncio.CancelledError, asyncio.TimeoutError):
            pass

    asyncio.new_event_loop().run_until_complete(go())
    assert _scan(sid).state in (ScanState.cancelled, ScanState.failed,
                                ScanState.completed)


# ------------------------------------------------------- nuclei (slower)

@requires_lab
@pytest.mark.slow
def test_nuclei_runs_and_parses():
    """Nuclei emits very large JSON lines — this is the stream-limit regression."""
    sid = _run_scan(["httpx", "nuclei"], profile="passive", timeout=1800)
    scan = _scan(sid)
    assert scan.state is ScanState.completed, f"nuclei stage failed: {scan.error}"

    with SessionLocal() as db:
        messages = list(db.scalars(
            select(ScanLog.message).where(ScanLog.scan_id == sid)))
    joined = " ".join(messages)
    assert "nuclei" in joined
    assert "exceeded" not in joined, "nuclei hit its timeout"
    assert "Separator is found" not in joined, "stream limit regression"
    assert "no such device" not in joined, "stdin input regression"
