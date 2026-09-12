"""The Merlon MCP server.

Two things matter most here. The protocol dispatch is pure — one request dict
to one response dict — so most of this needs no database and no process. And the
authorization gate is tested directly: start_scan must refuse without
authorized=true, and must not touch the database or launch a scan when it does.
"""

import pytest

from app.mcp_server import MerlonMCP


def req(method, params=None, mid=1):
    m = {"jsonrpc": "2.0", "method": method}
    if mid is not None:
        m["id"] = mid
    if params is not None:
        m["params"] = params
    return m


# ---------------------------------------------------------------- protocol

def test_initialize_announces_server():
    r = MerlonMCP().handle(req("initialize"))
    assert r["result"]["serverInfo"]["name"] == "merlon"
    assert r["result"]["protocolVersion"]
    assert "tools" in r["result"]["capabilities"]


def test_initialized_notification_gets_no_response():
    assert MerlonMCP().handle(req("notifications/initialized", mid=None)) is None


def test_tools_list_has_every_tool():
    r = MerlonMCP().handle(req("tools/list"))
    names = {t["name"] for t in r["result"]["tools"]}
    assert names == {"list_engines", "list_scan_profiles", "start_scan",
                     "list_scans", "get_scan", "get_findings"}
    for t in r["result"]["tools"]:
        assert t["inputSchema"]["type"] == "object"


def test_unknown_method_is_an_error():
    r = MerlonMCP().handle(req("does/not/exist"))
    assert r["error"]["code"] == -32601


def test_non_jsonrpc_is_rejected():
    r = MerlonMCP().handle({"method": "initialize", "id": 1})
    assert r["error"]["code"] == -32600


def test_ping():
    assert MerlonMCP().handle(req("ping"))["result"] == {}


# ---------------------------------------------------------------- read tools (no DB)

def test_list_engines_reflects_the_registry():
    r = MerlonMCP().handle(req("tools/call",
                               {"name": "list_engines", "arguments": {}}))
    import json
    payload = json.loads(r["result"]["content"][0]["text"])
    names = {e["name"] for e in payload["engines"]}
    # engines added this session must be present
    assert {"jwt", "ssti", "cachepoison", "authz"} <= names
    assert payload["count"] == len(payload["engines"])


def test_list_scan_profiles():
    r = MerlonMCP().handle(req("tools/call",
                               {"name": "list_scan_profiles", "arguments": {}}))
    import json
    payload = json.loads(r["result"]["content"][0]["text"])
    assert "standard" in payload["profiles"]
    assert "jwt" in payload["profiles"]["standard"]


# ---------------------------------------------------------------- the gate

def test_start_scan_refuses_without_authorization():
    launched = []

    def _must_not_run(_sid):
        launched.append(_sid)

    def _must_not_open():
        raise AssertionError("database opened before the authorization gate")

    mcp = MerlonMCP(session_factory=_must_not_open, start_scan_fn=_must_not_run)
    r = mcp.handle(req("tools/call", {"name": "start_scan",
                                      "arguments": {"target": "example.com"}}))
    assert r["result"]["isError"] is True
    assert "authorized" in r["result"]["content"][0]["text"].lower()
    assert launched == [], "a scan was launched without authorization"


def test_start_scan_gate_rejects_explicit_false():
    mcp = MerlonMCP(session_factory=lambda: (_ for _ in ()).throw(
        AssertionError("db opened")), start_scan_fn=lambda s: None)
    r = mcp.handle(req("tools/call",
                       {"name": "start_scan",
                        "arguments": {"target": "example.com", "authorized": False}}))
    assert r["result"]["isError"] is True


# ---------------------------------------------------------------- DB-backed tools

@pytest.fixture
def db_ready():
    """Use the configured database and ensure the schema exists.

    init_db() is create_all — idempotent, so this is safe to call per test and
    does not disturb rows other tests created. Seeded rows use unique names and
    are referenced by returned id, so tests stay independent without a private
    database each.
    """
    from app import db as dbmod
    dbmod.init_db()
    return dbmod


def test_start_scan_creates_and_launches(db_ready):
    launched = []
    mcp = MerlonMCP(session_factory=db_ready.SessionLocal,
                    start_scan_fn=launched.append)
    r = mcp.handle(req("tools/call", {
        "name": "start_scan",
        "arguments": {"target": "example.com", "authorized": True, "depth": "quick"},
    }))
    import json
    payload = json.loads(r["result"]["content"][0]["text"])
    assert "isError" not in r["result"]
    sid = payload["scan_id"]
    assert launched == [sid], "the scan was created but not launched"

    # and it is now visible through the read tools
    got = mcp.handle(req("tools/call",
                         {"name": "get_scan", "arguments": {"scan_id": sid}}))
    assert json.loads(got["result"]["content"][0]["text"])["seeds"] == ["example.com"]


def test_get_scan_missing_is_tool_error(db_ready):
    mcp = MerlonMCP(session_factory=db_ready.SessionLocal, start_scan_fn=lambda s: None)
    r = mcp.handle(req("tools/call",
                       {"name": "get_scan", "arguments": {"scan_id": 99999}}))
    assert r["result"]["isError"] is True


def test_get_findings_filters_by_severity(db_ready):
    from app.models import Engagement, Finding, Scan, Severity
    with db_ready.SessionLocal() as s:
        eng = Engagement(name="ex.com", kind="self_owned", authorized_by="me",
                         authorization_ref="x", allow_rules=["ex.com"], deny_rules=[])
        s.add(eng); s.commit(); s.refresh(eng)
        scan = Scan(engagement_id=eng.id, seeds=["ex.com"], profile="standard", stages=[])
        s.add(scan); s.commit(); s.refresh(scan)
        s.add_all([
            Finding(scan_id=scan.id, engine="jwt", name="crit", severity=Severity.critical,
                    host="ex.com", dedupe_key="a"),
            Finding(scan_id=scan.id, engine="cors", name="low", severity=Severity.low,
                    host="ex.com", dedupe_key="b"),
        ])
        s.commit()
        sid = scan.id

    mcp = MerlonMCP(session_factory=db_ready.SessionLocal, start_scan_fn=lambda s: None)
    import json
    allf = json.loads(mcp.handle(req("tools/call",
        {"name": "get_findings", "arguments": {"scan_id": sid}}))["result"]["content"][0]["text"])
    assert allf["count"] == 2
    assert allf["findings"][0]["severity"] == "critical"   # most severe first

    crit = json.loads(mcp.handle(req("tools/call",
        {"name": "get_findings", "arguments": {"scan_id": sid, "severity": "critical"}}
        ))["result"]["content"][0]["text"])
    assert crit["count"] == 1


def test_unknown_tool_is_error():
    r = MerlonMCP().handle(req("tools/call", {"name": "nope", "arguments": {}}))
    assert r["result"]["isError"] is True
