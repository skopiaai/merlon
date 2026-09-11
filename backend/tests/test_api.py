"""API-level tests.

The scan-launch tests exist because of a real bug: FastAPI runs `def`
endpoints in a worker thread with no event loop, so `asyncio.create_task`
inside them raised "RuntimeError: no running event loop" and no scan could
ever start. Health checks passed the whole time, so nothing looked wrong until
you pressed the button.
"""

import asyncio

import pytest
from fastapi.testclient import TestClient

from app import orchestrator
from app.main import app


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(orchestrator, "_running", {})
    # Replace the real pipeline with a no-op so tests don't shell out to scanners.
    started: list[int] = []

    async def fake_run(self):
        started.append(self.scan_id)
        await asyncio.sleep(0)

    monkeypatch.setattr(orchestrator.ScanRunner, "run", fake_run)
    with TestClient(app) as c:
        c.started = started  # type: ignore[attr-defined]
        yield c


def _engagement(client, **over):
    body = {
        "name": over.get("name", "test-engagement"),
        "authorized_by": "IT Services",
        "authorization_ref": "RE: permission to test, 2026-08-02",
        "allow_rules": over.get("allow_rules", ["*.example.com"]),
        "deny_rules": over.get("deny_rules", []),
    }
    r = client.post("/api/engagements", json=body)
    assert r.status_code == 201, r.text
    return r.json()


# ---------- the regression that mattered ----------

def test_quickscan_actually_starts(client):
    r = client.post("/api/quickscan", json={
        "target": "example.com", "depth": "quick", "authorized": True,
    })
    assert r.status_code == 201, r.text
    assert r.json()["state"] in ("queued", "running")


def test_create_scan_actually_starts(client):
    eng = _engagement(client)
    r = client.post("/api/scans", json={
        "engagement_id": eng["id"], "seeds": ["api.example.com"], "stages": ["httpx"],
    })
    assert r.status_code == 201, r.text


def test_scheduler_raises_clearly_if_loop_unbound(monkeypatch):
    """The failure mode should name itself, not surface as a stack trace."""
    monkeypatch.setattr(orchestrator, "_main_loop", None)
    monkeypatch.setattr(orchestrator, "_running", {})
    with pytest.raises(RuntimeError, match="not ready"):
        orchestrator.start_scan(999)


# ---------- authorization and scope ----------

def test_quickscan_requires_consent(client):
    r = client.post("/api/quickscan", json={"target": "example.com", "authorized": False})
    assert r.status_code == 403


def test_quickscan_rejects_junk_target(client):
    r = client.post("/api/quickscan", json={"target": "   ", "authorized": True})
    assert r.status_code in (400, 422)


def test_scan_rejects_out_of_scope_seed(client):
    eng = _engagement(client, name="scoped")
    r = client.post("/api/scans", json={
        "engagement_id": eng["id"], "seeds": ["evil.com"], "stages": ["httpx"],
    })
    assert r.status_code == 400


def test_scan_rejects_unknown_stage(client):
    eng = _engagement(client, name="stages")
    r = client.post("/api/scans", json={
        "engagement_id": eng["id"], "seeds": ["a.example.com"], "stages": ["rm-rf"],
    })
    assert r.status_code == 422


def test_engagement_rejects_invalid_rule(client):
    r = client.post("/api/engagements", json={
        "name": "bad", "authorized_by": "x", "authorization_ref": "y",
        "allow_rules": ["!!not a domain!!"],
    })
    assert r.status_code == 422


def test_scope_dry_run(client):
    eng = _engagement(client, name="dryrun")
    r = client.post("/api/scope/check", json={
        "engagement_id": eng["id"], "hosts": ["a.example.com", "evil.com"],
    })
    results = {x["input"]: x["allowed"] for x in r.json()["results"]}
    assert results == {"a.example.com": True, "evil.com": False}


def test_quickscan_derives_scope_from_target(client):
    client.post("/api/quickscan", json={
        "target": "https://example.com/pricing", "authorized": True,
        "include_subdomains": True,
    })
    engs = client.get("/api/engagements").json()
    match = [e for e in engs if e["name"] == "example.com"]
    assert match, "quickscan should create an engagement named for the apex domain"
    assert set(match[0]["allow_rules"]) == {"example.com", "*.example.com"}


def test_health_reports_ollama_state(client):
    body = client.get("/api/health").json()
    assert body["status"] == "ok"
    assert "reachable" in body["ollama"]


# ------------------------------------------------- upload hardening (audit)

def test_upload_suffix_is_whitelisted():
    """The tempfile suffix comes from the client's filename.

    Nothing here reaches a shell — every tool runs through
    `create_subprocess_exec` — so this is not an injection fix. It stops an
    attacker-chosen string becoming part of a filename on disk, which is what
    trips up whichever tool opens it next.
    """
    from app.main import safe_suffix

    assert safe_suffix("dump.mem") == ".mem"
    assert safe_suffix("shell.PHP") == ".php"          # normalised
    assert safe_suffix("x.$(whoami)") == ""            # not an extension
    assert safe_suffix("a.b/../../c.sh") == ""         # not on the list
    assert safe_suffix("evil." + "A" * 5000) == ""     # unbounded input
    assert safe_suffix(None) == ""
    assert safe_suffix("noextension") == ""


def test_artifact_upload_is_size_capped():
    """The write loop ran until the client stopped sending.

    Uploads land in the data volume, so one request could fill the disk — and a
    full volume is what makes SQLite start returning "disk I/O error" on every
    later scan, which presents as the whole app being broken.
    """
    from app import main

    assert main.MAX_UPLOAD <= 1 << 30, "cap is too loose to bound disk use"
    src = __import__("inspect").getsource(main.analyze_artifact)
    assert "MAX_UPLOAD" in src and "413" in src, \
        "the artifact upload no longer enforces a size cap"
