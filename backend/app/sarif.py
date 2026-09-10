"""SARIF 2.1.0 export.

SARIF is the OASIS standard for static analysis results, and it's what GitHub
Advanced Security, DefectDojo, Azure DevOps and most SIEMs ingest. Exporting it
means findings from this tool land in the same queue as everything else the
team already uses, instead of living in a markdown file nobody opens twice.

It also matters for a competition writeup: "results export in a standard
interchange format" is the difference between a script and a tool.

Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from sqlalchemy import select

from . import compliance
from .db import SessionLocal
from .models import Engagement, Finding, FindingStatus, Scan

SARIF_VERSION = "2.1.0"
SCHEMA = ("https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/"
          "sarif-schema-2.1.0.json")

# SARIF has three failure levels plus "none". Mapping is lossy in one
# direction, so the original severity is preserved in properties.
_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

# GitHub's UI sorts by security-severity (a CVSS-like number), not by level,
# so without this everything shows up as "medium" regardless.
_SECURITY_SEVERITY = {
    "critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "1.0",
}


def _rule(finding: Finding) -> dict:
    """One SARIF reportingDescriptor per rule_id."""
    comp = finding.compliance or compliance.controls_for({
        "rule_id": finding.rule_id, "tags": finding.tags,
        "cwe": finding.cwe, "cve": finding.cve,
    }).as_dict()

    tags = ["security"] + list(finding.tags or [])
    tags += [f"external/cwe/{c.lower()}" for c in (finding.cwe or [])]
    if comp.get("owasp_top10"):
        tags.append(f"OWASP:{comp['owasp_top10'].split(':')[0]}")

    return {
        "id": finding.rule_id or finding.engine,
        "name": finding.name[:120],
        "shortDescription": {"text": finding.name[:200]},
        "fullDescription": {"text": (finding.description or finding.name)[:1000]},
        "help": {
            "text": finding.remediation or "No remediation recorded.",
            "markdown": (
                f"**Remediation**\n\n{finding.remediation}\n\n"
                f"{'**References**: ' + ', '.join(finding.references[:5]) if finding.references else ''}"
            ),
        },
        "defaultConfiguration": {
            "level": _LEVEL.get(finding.severity.value, "warning"),
        },
        "properties": {
            "tags": tags,
            "security-severity": _SECURITY_SEVERITY.get(finding.severity.value, "5.5"),
            "precision": "high" if (finding.triage_confidence or 0) >= 0.8 else "medium",
            "owasp-top10": comp.get("owasp_top10", ""),
            "asvs": comp.get("asvs", []),
            "iso27001": comp.get("iso27001", []),
            "cis": comp.get("cis", []),
            "gigw": comp.get("gigw", ""),
            "cve": finding.cve or [],
        },
    }


def _result(finding: Finding, rule_index: int) -> dict:
    """One SARIF result.

    Findings here are about live hosts, not files, so the artifact URI is the
    affected URL. That is valid SARIF — `artifactLocation.uri` accepts any URI —
    and it keeps the host visible in every consumer.
    """
    location_uri = finding.url or f"https://{finding.host}"
    message = finding.description or finding.name

    result = {
        "ruleId": finding.rule_id or finding.engine,
        "ruleIndex": rule_index,
        "level": _LEVEL.get(finding.severity.value, "warning"),
        "message": {"text": message[:2000]},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": location_uri},
                # Consumers expect a region; findings are host-level, so this
                # is a stable placeholder rather than a real line number.
                "region": {"startLine": 1},
            },
            "logicalLocations": [{
                "name": finding.host,
                "kind": "resource",
            }],
        }],
        "partialFingerprints": {
            # Stable across scans, so a consumer can tell "same finding again"
            # from "new finding" — that's what drives triage state in GitHub.
            "parapetDedupeKey": finding.dedupe_key,
        },
        "properties": {
            "engine": finding.engine,
            "severity": finding.severity.value,
            "status": finding.status.value,
            "occurrences": finding.occurrences,
        },
    }
    if finding.evidence:
        result["properties"]["evidence"] = finding.evidence[:3000]
    if finding.triage_confidence is not None:
        result["properties"]["triageConfidence"] = finding.triage_confidence
    if finding.analyst_note:
        result["properties"]["analystNote"] = finding.analyst_note
    return result


def generate(scan_id: int, include_false_positives: bool = False) -> dict:
    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        if not scan:
            raise ValueError("scan not found")
        eng = db.get(Engagement, scan.engagement_id)
        findings = list(db.scalars(select(Finding).where(Finding.scan_id == scan_id)))

    if not include_false_positives:
        findings = [f for f in findings if f.status is not FindingStatus.false_positive]
    findings.sort(key=lambda f: (-f.severity.rank, f.host, f.rule_id))

    # SARIF wants unique rules once, and results referencing them by index.
    rules: list[dict] = []
    rule_index: dict[str, int] = {}
    results: list[dict] = []
    for f in findings:
        key = f.rule_id or f.engine
        if key not in rule_index:
            rule_index[key] = len(rules)
            rules.append(_rule(f))
        results.append(_result(f, rule_index[key]))

    now = datetime.now(timezone.utc)
    return {
        "$schema": SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Bug Bounty Webapp",
                    "informationUri": "https://github.com/",
                    "version": "1.0.0",
                    "rules": rules,
                },
            },
            "invocations": [{
                "executionSuccessful": scan.state.value == "completed",
                "startTimeUtc": scan.started_at.isoformat() if scan.started_at else None,
                "endTimeUtc": scan.finished_at.isoformat() if scan.finished_at else None,
                "commandLine": f"scan --profile {scan.profile} "
                               f"--stages {','.join(scan.stages)} "
                               f"{' '.join(scan.seeds)}",
                "properties": {"stages": scan.stages, "profile": scan.profile},
            }],
            "results": results,
            "properties": {
                "scanId": scan.id,
                "engagement": eng.name if eng else "",
                "authorizedBy": eng.authorized_by if eng else "",
                "authorizationRef": eng.authorization_ref if eng else "",
                "scope": eng.allow_rules if eng else [],
                "exported": now.isoformat(),
                # Stated explicitly: a consumer should not read "0 results" in a
                # category as assurance that the category was assessed.
                "notAssessed": list(compliance.OWASP_NOT_TESTABLE),
            },
        }],
    }


def generate_json(scan_id: int, **kw) -> str:
    return json.dumps(generate(scan_id, **kw), indent=2)
