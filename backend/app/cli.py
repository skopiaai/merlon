"""Headless scanning from a terminal.

The web UI is the good way to work a target by hand. This is for the other
cases: a scheduled scan, a scan from someone else's CI, a scan whose output
feeds a script. It runs the same pipeline, writes the same findings, and
applies the same authorisation gate — the scan is created by
`scans.create_quick_scan`, shared with the HTTP API and the MCP tool, so there
is no third set of scope rules to drift.

    python -m app.cli scan --target example.com --authorized --json out.json

Exit status is 0 whenever the scan completed, including when it found things,
*unless* `--fail-on` is given. That flag exists so CI can gate on severity
without reimplementing the severity table in shell — the GitHub Action just
passes it through and propagates the exit code, which keeps the gating logic
here where it is tested rather than inline in a workflow.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# "never" is a real choice: run the scan, publish the report, fail nothing.
_NEVER = "never"


def count_breaching(findings: list[dict], fail_on: str,
                    only_proven: bool = False) -> int:
    """How many findings meet or exceed `fail_on`.

    Severity is ordered, so `--fail-on high` counts criticals too. An unknown
    threshold is treated as `high` rather than silently passing everything —
    a typo in a CI config must not quietly disable the gate.

    `only_proven` restricts the count to findings the target demonstrated,
    which is the setting that makes a build gate tolerable: it cannot fire on
    something merely inferred.
    """
    if fail_on == _NEVER:
        return 0
    threshold = _SEVERITY_ORDER.get(fail_on, _SEVERITY_ORDER["high"])
    n = 0
    for f in findings:
        sev = str(f.get("severity", "info")).lower()
        if _SEVERITY_ORDER.get(sev, 4) > threshold:
            continue
        if only_proven and f.get("tier") != "proven":
            continue
        n += 1
    return n


def _finding_dict(f) -> dict:
    verification = f.verification or {}
    return {
        "id": f.id,
        "engine": f.engine,
        "rule_id": f.rule_id,
        "name": f.name,
        "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
        "host": f.host,
        "url": f.url,
        "matched_at": f.matched_at,
        "description": f.description,
        "evidence": f.evidence,
        "remediation": f.remediation,
        "references": f.references,
        "cwe": f.cwe,
        "cve": f.cve,
        # The tier is what a CI gate should read: `proven` means the target
        # demonstrated it, not that a pattern matched.
        "tier": verification.get("tier"),
        "confidence": verification.get("confidence"),
        "submittable": verification.get("submittable"),
    }


async def _run_scan(scan_id: int, *, verify: bool) -> None:
    from . import orchestrator
    from . import verify as verify_mod

    await orchestrator.ScanRunner(scan_id).run()
    if verify:
        await verify_mod.verify_scan(scan_id)


def cmd_scan(args: argparse.Namespace) -> int:
    from sqlalchemy import select

    from . import scans as scans_mod
    from .db import SessionLocal, init_db
    from .models import Finding, Scan

    init_db()

    with SessionLocal() as db:
        try:
            scan = scans_mod.create_quick_scan(
                db, args.target,
                authorized=args.authorized,
                depth=args.depth,
                include_subdomains=not args.no_subdomains,
                authorized_by=args.authorized_by,
                source="cli",
            )
        except scans_mod.NotAuthorized as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        except scans_mod.BadTarget as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        scan_id = scan.id
        target = scan.seeds[0]

    if not args.quiet:
        print(f"scan {scan_id}: {target} (depth: {args.depth})", file=sys.stderr)

    asyncio.run(_run_scan(scan_id, verify=not args.no_verify))

    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        rows = list(db.scalars(select(Finding).where(Finding.scan_id == scan_id)))
        rows.sort(key=lambda f: (
            _SEVERITY_ORDER.get(
                f.severity.value if hasattr(f.severity, "value") else str(f.severity), 4),
            f.host))
        report = {
            "scan_id": scan_id,
            "target": target,
            "depth": args.depth,
            "state": scan.state.value if hasattr(scan.state, "value") else str(scan.state),
            "error": scan.error or "",
            "findings": [_finding_dict(f) for f in rows],
        }

    if args.json:
        path = Path(args.json)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
        if not args.quiet:
            print(f"report written to {path}", file=sys.stderr)
    else:
        print(json.dumps(report, indent=2, default=str))

    if not args.quiet:
        counts: dict[str, int] = {}
        proven = 0
        for f in report["findings"]:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1
            if f.get("tier") == "proven":
                proven += 1
        summary = ", ".join(f"{n} {sev}" for sev, n in
                            sorted(counts.items(),
                                   key=lambda kv: _SEVERITY_ORDER.get(kv[0], 4))) or "none"
        print(f"{len(report['findings'])} finding(s): {summary}"
              f"{f' — {proven} proven' if proven else ''}", file=sys.stderr)

    if args.fail_on:
        breaching = count_breaching(report["findings"], args.fail_on,
                                    only_proven=args.only_proven)
        if not args.quiet:
            print(f"{breaching} finding(s) at or above '{args.fail_on}'"
                  f"{' (proven only)' if args.only_proven else ''}",
                  file=sys.stderr)
        if breaching:
            return 1

    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="merlon",
        description="Merlon — self-hosted attack surface scanner.")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan a target you are authorised to test")
    scan.add_argument("--target", required=True,
                      help="domain or URL, e.g. example.com")
    scan.add_argument("--authorized", action="store_true",
                      help="REQUIRED. You confirm you own this target or are "
                           "permitted to test it. The scan refuses without it.")
    scan.add_argument("--authorized-by", default="self-attested (owner)",
                      dest="authorized_by",
                      help="who authorised the work; recorded on the engagement")
    scan.add_argument("--depth", default="standard",
                      help="quick | standard | deep")
    scan.add_argument("--no-subdomains", action="store_true",
                      help="scan only the exact host, not *.host")
    scan.add_argument("--no-verify", action="store_true",
                      help="skip the verification pass (findings get no tier)")
    scan.add_argument("--json", metavar="PATH",
                      help="write the JSON report here instead of stdout")
    scan.add_argument("--quiet", action="store_true",
                      help="suppress progress output on stderr")
    scan.add_argument("--fail-on", dest="fail_on", default=None,
                      metavar="SEVERITY",
                      help="exit 1 if a finding at or above this severity is "
                           "found: critical | high | medium | low | info | never")
    scan.add_argument("--only-proven", dest="only_proven", action="store_true",
                      help="with --fail-on, count only findings the scanner "
                           "proved (the target demonstrated them)")
    scan.set_defaults(func=cmd_scan)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
