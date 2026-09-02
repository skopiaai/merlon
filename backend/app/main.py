from __future__ import annotations

import asyncio
import logging
import os
import tempfile
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import (
    Depends,
    FastAPI,
    File,
    HTTPException,
    Query,
    UploadFile,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import (
    analyzer,
    audit_report,
    auth,
    cryptosolve,
    ctf,
    ctf_writeup,
    forensics,
    intel,
    llm,
    orchestrator,
    reporting,
    sarif,
    schemas,
    scope,
    scopeimport,
    updater,
    verify,
    watch,
)
from .config import ARTIFACT_DIR, DB_PATH
from .db import get_db, init_db
from .engines import nuclei as nuclei_engine
from .events import hub
from .models import (
    Asset,
    Challenge,
    ChallengeStatus,
    Engagement,
    Finding,
    Lead,
    Scan,
    ScanLog,
    ScanState,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


@asynccontextmanager
async def lifespan(_: FastAPI):
    # Endpoints that launch scans run in a threadpool and can't create asyncio
    # tasks themselves; give the orchestrator a handle on this loop.
    orchestrator.bind_loop(asyncio.get_running_loop())
    try:
        migrated = init_db()
        if migrated:
            logging.info("Schema updated — added column(s): %s", ", ".join(migrated))
    except Exception as exc:  # noqa: BLE001
        # A failure here kills the container before anything is logged usefully,
        # so spell out the likely cause rather than leaving a SQLAlchemy trace.
        logging.error(
            "\n"
            "=========================================================\n"
            " Could not open the database at %s\n"
            "   %s: %s\n\n"
            " Most often this means the data volume is unhealthy.\n"
            " Reset it with:\n"
            "     docker compose down -v && ./start.sh\n"
            " (that deletes previous scan results, nothing else)\n"
            "=========================================================",
            DB_PATH, type(exc).__name__, exc,
        )
        raise

    # A scan that was running when the process died leaves its row saying
    # "running" forever — nothing else will ever change it.
    orphans = orchestrator.reconcile_orphans()
    if orphans:
        logging.warning("Reconciled %d scan(s) interrupted by a restart", orphans)

    # Named `watchdog_task`, not `watch` — the `watch` module is imported above
    # and a local of the same name would shadow it for the rest of this
    # function. Harmless today; a trap for whoever adds a line here next.
    watchdog_task = asyncio.create_task(orchestrator.watchdog())
    # Detection content goes stale in days, not months. Keeping it current
    # automatically is the difference between finding a newly published issue
    # and reading about someone else finding it.
    refresh = asyncio.create_task(updater.daily())
    try:
        yield
    finally:
        watchdog_task.cancel()
        refresh.cancel()


app = FastAPI(title="Sentinel", version="0.1.0", lifespan=lifespan)

# Local-only UI. The whole stack binds to 127.0.0.1 in compose.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------- system ----------------

@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "ollama": {
            "reachable": await llm.available(),
            "models": await llm.list_models(),
        },
    }


@app.get("/api/system/engines")
def list_engines():
    """Every registered detection engine, self-described.

    The UI reads stage labels from here, so a new engine names itself in the
    progress view without any frontend change.
    """
    from .engines import registry
    return {
        "engines": registry.describe(),
        "core_stages": schemas.CORE_STAGES,
        "labels": {
            "seed": "Validating target scope",
            "subfinder": "Enumerating subdomains",
            "dnsx": "Resolving DNS records",
            "cdncheck": "Fingerprinting CDN / WAF",
            "naabu": "Scanning ports",
            "httpx": "Probing live services",
            "nmap": "Identifying services and versions",
            "tlsx": "Auditing TLS certificates",
            "ffuf": "Fuzzing for hidden paths",
            "katana": "Crawling endpoints",
            "nuclei": "Running vulnerability templates",
            "correlate": "Correlating attack paths",
            "triage": "AI reviewing findings",
            "intel": "AI mapping attack surface",
            "done": "Complete",
            **registry.labels(),
        },
    }


@app.post("/api/system/update-templates")
async def update_templates():
    """Official nuclei templates only — the fast path, ~20 seconds."""
    out = await nuclei_engine.update_templates()
    return {"output": out or "templates already current"}


@app.get("/api/system/update")
def update_status():
    """What detection content is installed and how old it is."""
    return updater.status()


@app.post("/api/system/update")
async def run_update(tools: bool = Query(True, description="Self-update scanner binaries"),
                     community: bool = Query(True, description="Sync community template repos")):
    """Update everything: templates, community repos, fingerprints, wordlists,
    and the scanner binaries.

    Runs in the background and returns immediately — a full run takes a few
    minutes and holding the request open for it would time out the UI. Progress
    goes to the scan log stream; poll GET for the result.
    """
    if updater.status()["running"]:
        return {"started": False, "detail": "an update is already running"}

    async def broadcast(level: str, message: str, stage: str = "update") -> None:
        await hub.publish(0, {"type": "log", "level": level,
                              "message": message, "stage": stage})

    asyncio.create_task(
        updater.run_all(include_tools=tools, include_community=community,
                        log=broadcast))
    return {"started": True, "detail": "update running — watch the log stream"}


# ---------------- engagements ----------------

@app.post("/api/engagements", response_model=schemas.EngagementOut, status_code=201)
def create_engagement(payload: schemas.EngagementCreate, db: Session = Depends(get_db)):
    eng = Engagement(**payload.model_dump())
    db.add(eng)
    db.commit()
    db.refresh(eng)
    return eng


@app.get("/api/engagements", response_model=list[schemas.EngagementOut])
def list_engagements(db: Session = Depends(get_db)):
    return list(db.scalars(select(Engagement).order_by(Engagement.created_at.desc())))


@app.get("/api/engagements/{eid}", response_model=schemas.EngagementOut)
def get_engagement(eid: int, db: Session = Depends(get_db)):
    eng = db.get(Engagement, eid)
    if not eng:
        raise HTTPException(404, "engagement not found")
    return eng


@app.delete("/api/engagements/{eid}", status_code=204)
def delete_engagement(eid: int, db: Session = Depends(get_db)):
    eng = db.get(Engagement, eid)
    if not eng:
        raise HTTPException(404, "engagement not found")
    db.delete(eng)
    db.commit()


@app.post("/api/scope/check")
def check_scope(payload: schemas.ScopeCheckRequest, db: Session = Depends(get_db)):
    """Dry-run scope evaluation. Use this before every scan."""
    eng = db.get(Engagement, payload.engagement_id)
    if not eng:
        raise HTTPException(404, "engagement not found")
    results = [
        {"input": h, **vars(scope.check(h, eng.allow_rules, eng.deny_rules))}
        for h in payload.hosts
    ]
    return {"expired": eng.is_expired, "results": results}


# ---------------- scans ----------------

@app.post("/api/scans", response_model=schemas.ScanOut, status_code=201)
def create_scan(payload: schemas.ScanCreate, db: Session = Depends(get_db)):
    eng = db.get(Engagement, payload.engagement_id)
    if not eng:
        raise HTTPException(404, "engagement not found")
    if eng.is_expired:
        raise HTTPException(403, "engagement authorization has expired")

    # Fail fast rather than starting a scan that will immediately abort.
    rejected = [
        d for d in (scope.check(h, eng.allow_rules, eng.deny_rules) for h in payload.seeds)
        if not d.allowed
    ]
    if rejected:
        raise HTTPException(400, {
            "error": "seeds out of scope",
            "rejected": [{"host": d.host, "reason": d.reason} for d in rejected],
        })

    scan = Scan(**payload.model_dump())
    db.add(scan)
    db.commit()
    db.refresh(scan)
    orchestrator.start_scan(scan.id)
    return scan


@app.post("/api/quickscan", response_model=schemas.ScanOut, status_code=201)
def quick_scan(payload: schemas.QuickScanRequest, db: Session = Depends(get_db)):
    """Type a domain, get a scan. Derives scope, reuses the engagement."""
    if not payload.authorized:
        raise HTTPException(403, "You must confirm you own or are authorized to test this target.")

    try:
        host = scope.normalize_host(payload.target)
    except scope.ScopeViolation as exc:
        raise HTTPException(400, f"Could not read that as a domain: {exc}") from exc

    rules = [host] + ([f"*.{host}"] if payload.include_subdomains else [])

    eng = db.scalar(select(Engagement).where(Engagement.name == host))
    if eng is None:
        eng = Engagement(
            name=host,
            kind="self_owned",
            authorized_by=payload.authorized_by,
            authorization_ref=payload.authorization_ref or f"Self-attested ownership of {host}",
            allow_rules=rules,
            deny_rules=[],
        )
        db.add(eng)
        db.commit()
        db.refresh(eng)
    elif sorted(eng.allow_rules) != sorted(rules):
        eng.allow_rules = rules
        db.commit()

    profile, stages = schemas.DEPTH_PRESETS[payload.depth]
    scan = Scan(engagement_id=eng.id, seeds=[host], profile=profile, stages=stages)
    db.add(scan)
    db.commit()
    db.refresh(scan)
    orchestrator.start_scan(scan.id)
    return scan


@app.get("/api/scans", response_model=list[schemas.ScanOut])
def list_scans(engagement_id: int | None = None, limit: int = 50, db: Session = Depends(get_db)):
    stmt = select(Scan).order_by(Scan.created_at.desc()).limit(limit)
    if engagement_id:
        stmt = stmt.where(Scan.engagement_id == engagement_id)
    return list(db.scalars(stmt))


@app.get("/api/scans/{sid}", response_model=schemas.ScanOut)
def get_scan(sid: int, db: Session = Depends(get_db)):
    scan = db.get(Scan, sid)
    if not scan:
        raise HTTPException(404, "scan not found")
    return scan


@app.post("/api/scans/{sid}/cancel")
def cancel_scan(sid: int, db: Session = Depends(get_db)):
    """Cancel a scan. Always succeeds if the scan exists.

    This used to return 409 when no task was tracked, which left scans
    interrupted by a backend restart permanently stuck at "running" with no
    way to clear them from the UI.
    """
    scan = db.get(Scan, sid)
    if not scan:
        raise HTTPException(404, "scan not found")

    result = orchestrator.cancel_scan(sid)
    messages = {
        "cancelled": "Scan cancelled.",
        "forced": "No running task found — the scan was marked cancelled. "
                  "The backend was most likely restarted while it was running.",
        "already-finished": "That scan had already finished.",
    }
    return {"result": result, "message": messages[result]}


@app.get("/api/scans/{sid}/assets", response_model=list[schemas.AssetOut])
def scan_assets(sid: int, db: Session = Depends(get_db)):
    return list(db.scalars(select(Asset).where(Asset.scan_id == sid).order_by(Asset.host)))


@app.get("/api/scans/{sid}/logs")
def scan_logs(sid: int, level: str | None = None, limit: int = 500, db: Session = Depends(get_db)):
    stmt = select(ScanLog).where(ScanLog.scan_id == sid)
    if level:
        stmt = stmt.where(ScanLog.level == level)
    rows = list(db.scalars(stmt.order_by(ScanLog.id.desc()).limit(limit)))
    return [
        {"id": r.id, "level": r.level, "stage": r.stage,
         "message": r.message, "ts": r.created_at.isoformat()}
        for r in reversed(rows)
    ]


@app.websocket("/ws/scans/{sid}")
async def scan_socket(ws: WebSocket, sid: int):
    await ws.accept()
    q = hub.subscribe(sid)
    try:
        while True:
            try:
                event = await asyncio.wait_for(q.get(), timeout=25)
                await ws.send_json(event)
            except asyncio.TimeoutError:
                await ws.send_json({"type": "ping"})
    except WebSocketDisconnect:
        pass
    finally:
        hub.unsubscribe(sid, q)


# ---------------- findings ----------------

@app.get("/api/findings", response_model=list[schemas.FindingOut])
def list_findings(
    scan_id: int | None = None,
    severity: str | None = None,
    status: str | None = None,
    engine: str | None = None,
    q: str | None = Query(None, description="substring match on name or host"),
    limit: int = 500,
    db: Session = Depends(get_db),
):
    stmt = select(Finding)
    if scan_id:
        stmt = stmt.where(Finding.scan_id == scan_id)
    if severity:
        stmt = stmt.where(Finding.severity.in_(severity.split(",")))
    if status:
        stmt = stmt.where(Finding.status.in_(status.split(",")))
    if engine:
        stmt = stmt.where(Finding.engine == engine)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(Finding.name.like(like) | Finding.host.like(like))
    rows = list(db.scalars(stmt.limit(limit)))
    rows.sort(key=lambda f: (-f.severity.rank, -(f.triage_confidence or 0), f.host))
    return rows


@app.get("/api/findings/{fid}", response_model=schemas.FindingOut)
def get_finding(fid: int, db: Session = Depends(get_db)):
    f = db.get(Finding, fid)
    if not f:
        raise HTTPException(404, "finding not found")
    return f


@app.patch("/api/findings/{fid}", response_model=schemas.FindingOut)
def update_finding(fid: int, payload: schemas.FindingUpdate, db: Session = Depends(get_db)):
    f = db.get(Finding, fid)
    if not f:
        raise HTTPException(404, "finding not found")
    for k, v in payload.model_dump(exclude_none=True).items():
        setattr(f, k, v)
    db.commit()
    db.refresh(f)
    return f


@app.post("/api/findings/{fid}/retriage")
async def retriage(fid: int):
    from .triage import triage_one
    ok = await triage_one(fid)
    if not ok:
        raise HTTPException(503, "triage unavailable — is Ollama running?")
    return {"triaged": True}


# ---------------- leads (the hunting workspace) ----------------

@app.get("/api/scans/{sid}/leads", response_model=list[schemas.LeadOut])
def scan_leads(sid: int, status: str | None = None, db: Session = Depends(get_db)):
    stmt = select(Lead).where(Lead.scan_id == sid)
    if status:
        stmt = stmt.where(Lead.status.in_(status.split(",")))
    rows = list(db.scalars(stmt))
    order = {"high": 0, "medium": 1, "low": 2}
    rows.sort(key=lambda lead: (order.get(lead.priority, 1), lead.source != "ai"))
    return rows


@app.get("/api/scans/{sid}/surface")
def scan_surface(sid: int, db: Session = Depends(get_db)):
    """The deterministic map. Available even if the LLM never ran."""
    scan = db.get(Scan, sid)
    if not scan:
        raise HTTPException(404, "scan not found")
    stored = (scan.stats or {}).get("intel", {}).get("surface")
    return stored or intel.build_surface(sid)


@app.patch("/api/leads/{lid}", response_model=schemas.LeadOut)
def update_lead(lid: int, payload: schemas.LeadUpdate, db: Session = Depends(get_db)):
    lead = db.get(Lead, lid)
    if not lead:
        raise HTTPException(404, "lead not found")
    for k, v in payload.model_dump(exclude_none=True).items():
        setattr(lead, k, v)
    db.commit()
    db.refresh(lead)
    return lead


@app.post("/api/leads/{lid}/deep-dive")
async def lead_deep_dive(lid: int):
    """Generate (or return cached) a fuller test plan for one lead."""
    text = await intel.deep_dive(lid)
    if not text:
        raise HTTPException(503, "Deep dive unavailable — is Ollama running?")
    return {"deep_dive": text}


@app.post("/api/scans/{sid}/reanalyze")
async def reanalyze(sid: int, db: Session = Depends(get_db)):
    """Re-run attack surface analysis, e.g. after starting Ollama."""
    scan = db.get(Scan, sid)
    if not scan:
        raise HTTPException(404, "scan not found")
    host = scan.seeds[0] if scan.seeds else ""
    analysis = await intel.analyze(sid, host)
    if not analysis:
        raise HTTPException(422, "Nothing to analyse — the scan found no endpoints")
    added = intel.store_intel(sid, analysis)
    return {"leads_added": added, "total_leads": len(analysis.get("leads", []))}


# ---------------- CTF workspace ----------------

@app.post("/api/ctf/analyze")
async def analyze_artifact(file: UploadFile = File(...)):
    """Drop any challenge file; run the full triage chain for its type.

    Most Jeopardy challenges start with a file and the same ten minutes of
    commands. This does all of them at once and puts flag candidates first.
    """
    suffix = os.path.splitext(file.filename or "")[1][:16]
    fd, tmp = tempfile.mkstemp(prefix="ctf_", suffix=suffix, dir=str(ARTIFACT_DIR))
    try:
        with os.fdopen(fd, "wb") as out:
            while chunk := await file.read(1 << 20):
                out.write(chunk)
        report = await analyzer.analyze(tmp, original_name=file.filename or "artifact")
        return report.as_dict()
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


@app.post("/api/forensics/logs")
async def analyse_logs(file: UploadFile = File(...)):
    """Analyse a web server access log for evidence of compromise.

    Only useful with logs the system owner has given you — this is incident
    response, not something you can obtain by scanning from outside.
    """
    raw = await file.read(80 * 1024 * 1024)
    text = raw.decode("utf-8", "replace")
    return forensics.analyse(text).as_dict()


@app.post("/api/ctf/decode")
def decode_text(payload: schemas.DecodeRequest):
    """Peel encoding layers breadth-first — base64 of hex of rot13 and so on."""
    chains = cryptosolve.decode_chain(payload.text)
    caesar = cryptosolve.caesar_all(payload.text) if payload.include_caesar else []
    # The flag lives in a *decoded* layer, not the input — search everything.
    haystack = "\n".join(
        [payload.text] + [c["output"] for c in chains] + [c["output"] for c in caesar]
    )
    return {"chains": chains, "caesar": caesar, "flags": analyzer.find_flags(haystack)}


@app.post("/api/ctf/rsa")
def analyse_rsa(payload: schemas.RSARequest):
    """Check RSA parameters for the classic implementation failures."""
    try:
        return cryptosolve.analyse_rsa(
            int(payload.n), int(payload.e),
            int(payload.c) if payload.c else None,
            [int(x) for x in payload.other_n],
        )
    except ValueError as exc:
        raise HTTPException(400, f"Could not read those as integers: {exc}") from exc


@app.get("/api/ctf/arsenal")
def ctf_arsenal():
    """Per-category tools, triage order, patterns, plus the event timeline."""
    return ctf.arsenal()


@app.post("/api/ctf/challenges", response_model=schemas.ChallengeOut, status_code=201)
def create_challenge(payload: schemas.ChallengeCreate, db: Session = Depends(get_db)):
    ch = Challenge(**payload.model_dump())
    db.add(ch)
    db.commit()
    db.refresh(ch)
    return ch


@app.get("/api/ctf/challenges", response_model=list[schemas.ChallengeOut])
def list_challenges(category: str | None = None, status: str | None = None,
                    db: Session = Depends(get_db)):
    stmt = select(Challenge)
    if category:
        stmt = stmt.where(Challenge.category == category)
    if status:
        stmt = stmt.where(Challenge.status.in_(status.split(",")))
    rows = list(db.scalars(stmt))
    order = {"working": 0, "stuck": 1, "todo": 2, "solved": 3, "abandoned": 4}
    rows.sort(key=lambda c: (order.get(c.status.value, 9), -c.points))
    return rows


@app.patch("/api/ctf/challenges/{cid}", response_model=schemas.ChallengeOut)
def update_challenge(cid: int, payload: schemas.ChallengeUpdate,
                     db: Session = Depends(get_db)):
    ch = db.get(Challenge, cid)
    if not ch:
        raise HTTPException(404, "challenge not found")
    data = payload.model_dump(exclude_none=True)
    for k, v in data.items():
        setattr(ch, k, v)
    if data.get("status") == ChallengeStatus.solved and not ch.solved_at:
        ch.solved_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(ch)
    return ch


@app.delete("/api/ctf/challenges/{cid}", status_code=204)
def delete_challenge(cid: int, db: Session = Depends(get_db)):
    ch = db.get(Challenge, cid)
    if not ch:
        raise HTTPException(404, "challenge not found")
    db.delete(ch)
    db.commit()


@app.get("/api/ctf/stats")
def ctf_stats(db: Session = Depends(get_db)):
    rows = list(db.scalars(select(Challenge)))
    by_cat: dict[str, dict] = {}
    for c in rows:
        entry = by_cat.setdefault(c.category, {"total": 0, "solved": 0, "points": 0})
        entry["total"] += 1
        if c.status is ChallengeStatus.solved:
            entry["solved"] += 1
            entry["points"] += c.points
    return {
        "total": len(rows),
        "solved": sum(1 for c in rows if c.status is ChallengeStatus.solved),
        "points": sum(c.points for c in rows if c.status is ChallengeStatus.solved),
        "by_category": by_cat,
    }


@app.post("/api/ctf/challenges/{cid}/writeup", response_class=PlainTextResponse)
async def challenge_writeup(cid: int, db: Session = Depends(get_db)):
    """Draft the documentation. The finale is graded on methodology, so this
    is worth points in its own right — not an afterthought."""
    ch = db.get(Challenge, cid)
    if not ch:
        raise HTTPException(404, "challenge not found")
    text = await ctf_writeup.generate(cid)
    ch.writeup = text
    db.commit()
    return text


# ---------------- reports ----------------

@app.get("/api/scans/{sid}/report", response_class=PlainTextResponse)
def scan_report(sid: int):
    try:
        return reporting.summary_report(sid)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc


@app.get("/api/scans/{sid}/sarif")
def scan_sarif(sid: int, include_false_positives: bool = False):
    """SARIF 2.1.0 — ingestible by GitHub Security, DefectDojo and most SIEMs."""
    try:
        return sarif.generate(sid, include_false_positives=include_false_positives)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc


@app.get("/api/scans/{sid}/audit-report", response_class=PlainTextResponse)
def audit_report_endpoint(sid: int):
    """Formal report: methodology, tool versions, control coverage, evidence hashes."""
    try:
        return audit_report.generate(sid)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc


@app.put("/api/engagements/{eid}/auth", response_model=schemas.EngagementOut)
def set_engagement_auth(eid: int, payload: schemas.AuthConfig, db: Session = Depends(get_db)):
    """Configure credentials for authenticated scanning."""
    eng = db.get(Engagement, eid)
    if not eng:
        raise HTTPException(404, "engagement not found")
    eng.auth_headers = payload.headers
    eng.auth_check_url = payload.check_url
    eng.auth_check_string = payload.check_string
    eng.auth_identities = [i.model_dump() for i in payload.identities]
    db.commit()
    db.refresh(eng)
    return eng


@app.get("/api/engagements/{eid}/auth")
def get_engagement_auth(eid: int, db: Session = Depends(get_db)):
    """What is configured — described, never echoed.

    The stored header values are deliberately not returned. A local tool has no
    reason to hand a session cookie back over HTTP, and an endpoint that does
    turns any request-forgery bug in this UI into credential theft.
    """
    eng = db.get(Engagement, eid)
    if not eng:
        raise HTTPException(404, "engagement not found")
    return {
        "configured": bool(eng.auth_headers),
        "describes": auth.describe(eng.auth_headers),
        "check_url": eng.auth_check_url,
        "check_string": eng.auth_check_string,
        "header_names": sorted(eng.auth_headers or {}),
        "identities": [
            {"name": i.get("name"), "role": i.get("role", ""),
             "check_url": i.get("check_url", ""),
             "header_names": sorted(i.get("headers") or {})}
            for i in (eng.auth_identities or [])
        ],
    }


@app.post("/api/engagements/{eid}/auth/verify")
async def verify_engagement_auth(eid: int, db: Session = Depends(get_db)):
    """Check every stored session still works, primary and additional."""
    eng = db.get(Engagement, eid)
    if not eng:
        raise HTTPException(404, "engagement not found")
    ok, reason = await auth.verify_session(
        eng.auth_check_url, eng.auth_check_string, eng.auth_headers)

    identities = []
    for index, identity in enumerate(eng.auth_identities or []):
        name = identity.get("name") or f"identity-{index + 1}"
        i_ok, i_reason = await auth.verify_session(
            identity.get("check_url", ""), identity.get("check_string", ""),
            identity.get("headers") or {})
        identities.append({"name": name, "role": identity.get("role", ""),
                           "ok": i_ok, "reason": i_reason})

    return {
        "ok": ok, "reason": reason,
        "configured": auth.describe(eng.auth_headers),
        "identities": identities,
        "access_control_testing": ok and any(i["ok"] for i in identities),
    }


@app.post("/api/scope/parse")
def parse_scope(payload: schemas.ScopeImport):
    """Turn a pasted program scope table into allow and deny rules.

    Parses only — it does not create anything. The operator reads the result
    against the program page and then creates the engagement, because scope is
    the one piece of configuration where being wrong is a legal problem rather
    than a bug.

    Note there is deliberately no "fetch this program URL and parse it" here.
    Deriving an authorization decision from a regex over someone else's markup
    is not a shortcut worth taking.
    """
    parsed = scopeimport.parse(payload.text)
    return {**parsed.as_dict(), "summary": scopeimport.summarise(parsed)}


@app.get("/api/engagements/{eid}/diff")
def engagement_diff(eid: int, db: Session = Depends(get_db)):
    """What changed in this engagement's attack surface since the last scan.

    The diff is the product, not the scan. A full report is a list you've
    already read; three lines saying a host appeared four hours ago is the
    thing worth acting on, because a host nobody has scanned yet is a host
    nobody has hunted.
    """
    if not db.get(Engagement, eid):
        raise HTTPException(404, "engagement not found")
    return watch.diff_engagement(eid)


@app.get("/api/watch")
def watch_status():
    """Engagements eligible for re-scanning, and when each was last looked at.

    Expired engagements are excluded — a scheduler is exactly where a scan
    against lapsed authorization would happen without anyone noticing.
    """
    return {"engagements": watch.watch_targets()}


@app.post("/api/engagements/{eid}/rescan", response_model=schemas.ScanOut,
          status_code=201)
def rescan(eid: int, db: Session = Depends(get_db)):
    """Re-run the most recent scan's configuration, to diff against it."""
    eng = db.get(Engagement, eid)
    if not eng:
        raise HTTPException(404, "engagement not found")
    if eng.is_expired:
        raise HTTPException(403, "engagement authorization has expired")

    last = db.scalars(
        select(Scan).where(Scan.engagement_id == eid,
                           Scan.state == ScanState.completed)
        .order_by(Scan.finished_at.desc()).limit(1)).first()
    if not last:
        raise HTTPException(400, "no completed scan to repeat — run one first")

    scan = Scan(engagement_id=eid, seeds=list(last.seeds),
                profile=last.profile, stages=list(last.stages))
    db.add(scan)
    db.commit()
    db.refresh(scan)
    orchestrator.start_scan(scan.id)
    return scan


@app.get("/api/scans/{sid}/queue")
def submission_queue(sid: int, db: Session = Depends(get_db)):
    """Findings split by whether they are ready to submit.

    The split is on reproducibility and evidence, not severity. A critical that
    doesn't reproduce is worth less than an informational finding that does —
    the first wastes a triager's time and costs you acceptance rate, which in
    2026 is what determines how fast your next report gets looked at.
    """
    findings = list(db.scalars(
        select(Finding).where(Finding.scan_id == sid)
        .order_by(Finding.severity.desc(), Finding.verify_confidence.desc())))

    # Which of these you have already seen in an earlier scan of the same
    # engagement. A weekly scan reports the same thirty findings every week;
    # without this the two that are actually new are buried in twenty-eight
    # you already read.
    history = watch.previously_seen(sid)

    ready, review, failed = [], [], []
    for f in findings:
        entry = {
            "id": f.id, "name": f.name, "severity": f.severity,
            "host": f.host, "url": f.url, "engine": f.engine,
            "rule_id": f.rule_id, "status": f.status,
            "dedupe_key": f.dedupe_key,
            "confidence": f.verify_confidence,
            "reproduced": f.reproduced,
            "verified_at": f.verified_at,
            "reasons": (f.verification or {}).get("reasons", []),
        }
        if f.verify_confidence is None:
            review.append({**entry, "why": "not yet verified"})
        elif not f.reproduced:
            failed.append({**entry, "why": "did not reproduce on retest"})
        elif f.verify_confidence >= verify.SUBMIT_THRESHOLD:
            ready.append(entry)
        else:
            review.append({**entry, "why": "reproduced, but evidence is not "
                                           "strong enough to submit unreviewed"})

    for bucket in (ready, review, failed):
        watch.annotate_new(bucket, history)

    return {
        "threshold": verify.SUBMIT_THRESHOLD,
        "ready": ready,
        "needs_review": review,
        "did_not_reproduce": failed,
        "counts": {"ready": len(ready), "needs_review": len(review),
                   "did_not_reproduce": len(failed), "total": len(findings),
                   "new": sum(1 for f in ready if f.get("is_new")),
                   "seen_before": len(history)},
    }


@app.post("/api/findings/{fid}/verify")
async def verify_one(fid: int, db: Session = Depends(get_db)):
    """Re-verify a single finding on demand."""
    finding = db.get(Finding, fid)
    if not finding:
        raise HTTPException(404, "finding not found")

    scan = db.get(Scan, finding.scan_id)
    eng = db.get(Engagement, scan.engagement_id) if scan else None
    ctx = {
        "auth_headers": dict(eng.auth_headers or {}) if eng else {},
        "allow": list(eng.allow_rules) if eng else [],
        "deny": list(eng.deny_rules) if eng else [],
    }

    verdict = await verify.verify_finding({
        "engine": finding.engine, "rule_id": finding.rule_id,
        "url": finding.url, "matched_at": finding.matched_at,
        "evidence": finding.evidence, "remediation": finding.remediation,
        "references": finding.references, "cwe": finding.cwe,
    }, ctx)

    finding.verify_confidence = round(verdict.confidence, 3)
    finding.reproduced = verdict.reproduced
    finding.verified_at = datetime.now(timezone.utc)
    finding.verification = verdict.as_dict()
    db.commit()
    return verdict.as_dict()


@app.get("/api/findings/{fid}/evidence", response_class=PlainTextResponse)
def finding_evidence(fid: int, db: Session = Depends(get_db)):
    """The reproduction section, ready to paste into a report."""
    finding = db.get(Finding, fid)
    if not finding:
        raise HTTPException(404, "finding not found")
    if not finding.verification:
        return "Not yet verified. POST /api/findings/{id}/verify first."
    return verify.evidence_block(finding.verification)


@app.get("/api/findings/{fid}/disclosure", response_class=PlainTextResponse)
async def finding_disclosure(fid: int):
    try:
        return await reporting.disclosure_report(fid)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc
