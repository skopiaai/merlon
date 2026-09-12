"""Merlon as an MCP server — drive the scanner from any agent.

Merlon already *detects* Model Context Protocol servers left exposed on a
target. This exposes one deliberately: a local MCP server, over stdio, that lets
Claude Code, Cursor, or any MCP client run scans, read findings, and enumerate
engines — the same engine that runs behind the UI, with no API key and nothing
leaving the machine.

Why this is safe to hand an agent:

  * **Authorization is not optional.** `start_scan` refuses unless the caller
    passes `authorized: true`, exactly as the HTTP quick-scan does. An agent
    cannot talk the tool into scanning a host the operator has not affirmed they
    may test — the gate is in the tool, not the prompt.
  * **Scope still applies.** Scans go through the same engagement and scope
    machinery as every other entry point, so a derived scope cannot widen past
    the target.
  * **Read tools only read.** Everything else lists engines, profiles, scans and
    findings from the local database.

The transport is newline-delimited JSON-RPC 2.0 on stdin/stdout, which is what
MCP stdio clients speak. The dispatch layer is pure — `handle()` maps one
request dict to one response dict — so the whole protocol is testable without a
process, a socket, or a running scan.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from typing import Any

PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "merlon"
SERVER_VERSION = "0.1.0"

# JSON-RPC error codes actually used here.
_PARSE_ERROR = -32700
_INVALID_REQUEST = -32600
_METHOD_NOT_FOUND = -32601
_INVALID_PARAMS = -32602
_INTERNAL_ERROR = -32603


def _depths() -> list[str]:
    from . import schemas
    return list(schemas.DEPTH_PRESETS.keys())


class MerlonMCP:
    """The protocol handler. Dependencies are injected so tests can drive it
    without a real database session or a real scan being launched."""

    def __init__(self, session_factory: Callable | None = None,
                 start_scan_fn: Callable[[int], Any] | None = None):
        if session_factory is None:
            from .db import SessionLocal
            session_factory = SessionLocal
        if start_scan_fn is None:
            from . import orchestrator
            start_scan_fn = orchestrator.start_scan
        self._session = session_factory
        self._start_scan = start_scan_fn
        self._initialized = False

    # ---------------------------------------------------------------- tools

    def _tool_specs(self) -> list[dict]:
        return [
            {
                "name": "list_engines",
                "description": "List every Merlon detection engine with its "
                               "description, phase and depth profiles.",
                "inputSchema": {"type": "object", "properties": {}},
            },
            {
                "name": "list_scan_profiles",
                "description": "List the scan depth profiles (quick, standard, "
                               "deep) and which engines each runs.",
                "inputSchema": {"type": "object", "properties": {}},
            },
            {
                "name": "start_scan",
                "description": "Start a scan against a target you are authorized "
                               "to test. Requires authorized=true; refuses "
                               "otherwise. Returns the scan id to poll.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string",
                                   "description": "Domain or URL, e.g. example.com"},
                        "authorized": {"type": "boolean",
                                       "description": "Must be true — you confirm "
                                       "you own or may test this target"},
                        "authorized_by": {"type": "string",
                                          "description": "Who authorized the work"},
                        "depth": {"type": "string", "enum": _depths(),
                                  "description": "Scan depth (default standard)"},
                        "include_subdomains": {"type": "boolean"},
                    },
                    "required": ["target", "authorized"],
                },
            },
            {
                "name": "list_scans",
                "description": "List recent scans with their state and progress.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"limit": {"type": "integer"}},
                },
            },
            {
                "name": "get_scan",
                "description": "Get one scan's state, progress and statistics.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"scan_id": {"type": "integer"}},
                    "required": ["scan_id"],
                },
            },
            {
                "name": "get_findings",
                "description": "List findings for a scan, most severe first, "
                               "optionally filtered by severity.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "scan_id": {"type": "integer"},
                        "severity": {"type": "string",
                                     "description": "comma-separated: "
                                     "critical,high,medium,low,info"},
                        "limit": {"type": "integer"},
                    },
                    "required": ["scan_id"],
                },
            },
        ]

    # ---- tool implementations -------------------------------------------

    def _call_tool(self, name: str, args: dict) -> dict:
        fn = getattr(self, f"_tool_{name}", None)
        if fn is None:
            raise _ToolError(f"unknown tool: {name}")
        return fn(args or {})

    def _tool_list_engines(self, _args: dict) -> dict:
        from .engines import registry
        registry.discover()
        engines = []
        for spec in sorted(registry.all_engines().values(), key=lambda s: s.name):
            engines.append({
                "name": spec.name,
                "label": spec.label,
                "description": spec.description,
                "phase": spec.phase,
                "profiles": list(spec.default_in),
            })
        return {"count": len(engines), "engines": engines}

    def _tool_list_scan_profiles(self, _args: dict) -> dict:
        from .engines import registry
        registry.discover()
        out = {}
        for depth in _depths():
            out[depth] = sorted(registry.defaults_for(depth))
        return {"profiles": out}

    def _tool_start_scan(self, args: dict) -> dict:
        target = (args.get("target") or "").strip()
        if not target:
            raise _ToolError("target is required")
        # The gate. An agent cannot remove it by phrasing the request differently.
        if args.get("authorized") is not True:
            raise _ToolError(
                "Refused: scanning a target requires authorized=true, confirming "
                "you own or are permitted to test it. Set it only when that is "
                "genuinely the case — it is the record that protects the operator.")

        from sqlalchemy import select

        from . import schemas, scope
        from .models import Engagement, Scan

        try:
            host = scope.normalize_host(target)
        except scope.ScopeViolation as exc:
            raise _ToolError(f"could not read that as a domain: {exc}") from exc

        depth = args.get("depth") or "standard"
        if depth not in schemas.DEPTH_PRESETS:
            raise _ToolError(f"unknown depth {depth!r}; choose from {_depths()}")
        include_subs = args.get("include_subdomains", True)
        rules = [host] + ([f"*.{host}"] if include_subs else [])

        with self._session() as db:
            eng = db.scalar(select(Engagement).where(Engagement.name == host))
            if eng is None:
                eng = Engagement(
                    name=host, kind="self_owned",
                    authorized_by=args.get("authorized_by") or "self-attested (owner)",
                    authorization_ref=f"Self-attested ownership of {host} (via MCP)",
                    allow_rules=rules, deny_rules=[],
                )
                db.add(eng)
                db.commit()
                db.refresh(eng)
            elif sorted(eng.allow_rules) != sorted(rules):
                eng.allow_rules = rules
                db.commit()

            profile, stages = schemas.DEPTH_PRESETS[depth]
            scan = Scan(engagement_id=eng.id, seeds=[host],
                        profile=profile, stages=stages)
            db.add(scan)
            db.commit()
            db.refresh(scan)
            scan_id = scan.id

        self._start_scan(scan_id)
        return {"scan_id": scan_id, "target": host, "depth": depth,
                "message": f"scan {scan_id} started against {host}"}

    def _tool_list_scans(self, args: dict) -> dict:
        from sqlalchemy import select

        from .models import Scan
        limit = int(args.get("limit") or 20)
        with self._session() as db:
            rows = list(db.scalars(
                select(Scan).order_by(Scan.created_at.desc()).limit(limit)))
            return {"scans": [self._scan_dict(s) for s in rows]}

    def _tool_get_scan(self, args: dict) -> dict:
        from .models import Scan
        sid = args.get("scan_id")
        with self._session() as db:
            scan = db.get(Scan, sid)
            if not scan:
                raise _ToolError(f"scan {sid} not found")
            return self._scan_dict(scan)

    def _tool_get_findings(self, args: dict) -> dict:
        from sqlalchemy import select

        from .models import Finding
        sid = args.get("scan_id")
        limit = int(args.get("limit") or 100)
        with self._session() as db:
            stmt = select(Finding).where(Finding.scan_id == sid)
            if args.get("severity"):
                stmt = stmt.where(Finding.severity.in_(args["severity"].split(",")))
            rows = list(db.scalars(stmt.limit(limit)))
            rows.sort(key=lambda f: (-f.severity.rank,
                                     -(f.triage_confidence or 0), f.host))
            return {"scan_id": sid, "count": len(rows),
                    "findings": [self._finding_dict(f) for f in rows]}

    @staticmethod
    def _scan_dict(s) -> dict:
        return {
            "id": s.id, "seeds": s.seeds, "profile": s.profile,
            "state": s.state.value if hasattr(s.state, "value") else s.state,
            "stage": s.stage_current, "progress": round(s.progress, 3),
            "error": s.error or "",
            "findings": len(s.findings) if s.findings is not None else 0,
        }

    @staticmethod
    def _finding_dict(f) -> dict:
        return {
            "id": f.id, "engine": f.engine, "rule_id": f.rule_id,
            "name": f.name,
            "severity": f.severity.value if hasattr(f.severity, "value") else f.severity,
            "host": f.host, "url": f.url,
            "description": (f.description or "")[:600],
            "cwe": f.cwe, "cve": f.cve,
        }

    # ---------------------------------------------------------------- protocol

    def handle(self, msg: dict) -> dict | None:
        """One JSON-RPC message in, one response out (or None for a notification)."""
        if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
            return self._error(msg.get("id") if isinstance(msg, dict) else None,
                               _INVALID_REQUEST, "not a JSON-RPC 2.0 message")

        method = msg.get("method")
        mid = msg.get("id")
        is_notification = "id" not in msg

        try:
            if method == "initialize":
                self._initialized = True
                result = {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
                }
            elif method in ("notifications/initialized", "initialized"):
                return None
            elif method == "ping":
                result = {}
            elif method == "tools/list":
                result = {"tools": self._tool_specs()}
            elif method == "tools/call":
                params = msg.get("params") or {}
                name = params.get("name")
                args = params.get("arguments") or {}
                try:
                    payload = self._call_tool(name, args)
                    result = {"content": [{"type": "text",
                                           "text": json.dumps(payload, indent=2, default=str)}]}
                except _ToolError as exc:
                    # A tool-level failure is reported as an unsuccessful tool
                    # result, not a protocol error — the agent sees the reason.
                    result = {"content": [{"type": "text", "text": str(exc)}],
                              "isError": True}
            else:
                if is_notification:
                    return None
                return self._error(mid, _METHOD_NOT_FOUND, f"unknown method: {method}")
        except Exception as exc:  # noqa: BLE001 — a handler bug must not kill the loop
            if is_notification:
                return None
            return self._error(mid, _INTERNAL_ERROR, str(exc))

        if is_notification:
            return None
        return {"jsonrpc": "2.0", "id": mid, "result": result}

    @staticmethod
    def _error(mid, code: int, message: str) -> dict:
        return {"jsonrpc": "2.0", "id": mid,
                "error": {"code": code, "message": message}}

    # ---------------------------------------------------------------- stdio loop

    def serve(self, stdin=None, stdout=None) -> None:
        stdin = stdin or sys.stdin
        stdout = stdout or sys.stdout
        for line in stdin:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                self._write(stdout, self._error(None, _PARSE_ERROR, "invalid JSON"))
                continue
            response = self.handle(msg)
            if response is not None:
                self._write(stdout, response)

    @staticmethod
    def _write(stdout, obj: dict) -> None:
        stdout.write(json.dumps(obj) + "\n")
        stdout.flush()


class _ToolError(Exception):
    """A tool could not complete — surfaced to the agent as an error result."""


def main() -> None:
    MerlonMCP().serve()


if __name__ == "__main__":
    main()
