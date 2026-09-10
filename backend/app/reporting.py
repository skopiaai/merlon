"""Report generation — disclosure reports and internal summaries."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select

from . import llm
from .db import SessionLocal
from .models import Engagement, Finding, FindingStatus, Scan

SEV_ORDER = ["critical", "high", "medium", "low", "info"]

DISCLOSURE_SYSTEM = """You write vulnerability disclosure reports for security
programs. Your reports are factual, concise, and respectful of the receiving
team's time. You never include exploit code — you describe the issue, the
evidence observed, the impact, and the fix. You never overstate severity."""

DISCLOSURE_PROMPT = """Write a vulnerability disclosure report for this finding.

Title: {name}
Severity: {severity}
Affected: {url}
CVE: {cve}
CWE: {cwe}

Technical description:
{description}

Observed evidence:
{evidence}

Recommended remediation:
{remediation}

Structure the report with these markdown sections:
## Summary
## Affected Asset
## Description
## Steps to Reproduce  (describe the observation in neutral terms — no payloads)
## Impact
## Recommended Remediation
## References

Keep it under 500 words. Write in plain professional English."""


def _md_escape(text: str) -> str:
    return (text or "").replace("|", "\\|").replace("\n", " ").strip()


def summary_report(scan_id: int) -> str:
    """Deterministic markdown summary. No LLM — always works."""
    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        if not scan:
            raise ValueError("scan not found")
        eng = db.get(Engagement, scan.engagement_id)
        findings = list(db.scalars(
            select(Finding).where(Finding.scan_id == scan_id)
        ))

    findings.sort(key=lambda f: (-f.severity.rank, f.host, f.name))
    counts = {s: 0 for s in SEV_ORDER}
    for f in findings:
        counts[f.severity.value] += 1

    live = [f for f in findings if f.status != FindingStatus.false_positive]

    L = [
        f"# Security Assessment — {eng.name}",
        "",
        f"**Scan ID:** {scan.id}  ",
        f"**Profile:** {scan.profile}  ",
        f"**Seeds:** {', '.join(scan.seeds)}  ",
        f"**Started:** {scan.started_at:%Y-%m-%d %H:%M UTC}  " if scan.started_at else "",
        f"**Finished:** {scan.finished_at:%Y-%m-%d %H:%M UTC}  " if scan.finished_at else "",
        "",
        "## Authorization",
        "",
        f"- Authorized by: **{eng.authorized_by}**",
        f"- Reference: {eng.authorization_ref}",
        f"- Scope: `{'`, `'.join(eng.allow_rules)}`",
        f"- Exclusions: `{'`, `'.join(eng.deny_rules) or 'none'}`",
        "",
        "## Findings Summary",
        "",
        "| Severity | Count |",
        "| --- | --- |",
    ]
    L += [f"| {s.title()} | {counts[s]} |" for s in SEV_ORDER]
    L += [
        f"| **Total** | **{len(findings)}** |",
        "",
        f"Excluding {len(findings) - len(live)} finding(s) marked false positive, "
        f"{len(live)} require attention.",
        "",
        "## Scan Statistics",
        "",
    ]
    for k, v in (scan.stats or {}).items():
        if k != "findings_by_severity":
            L.append(f"- {k.replace('_', ' ').title()}: {v}")

    if scan.rejected_hosts:
        L += ["", f"- Out-of-scope hosts filtered: {len(scan.rejected_hosts)}"]

    L += ["", "## Findings", ""]

    for sev in SEV_ORDER:
        group = [f for f in live if f.severity.value == sev]
        if not group:
            continue
        L += [f"### {sev.title()} ({len(group)})", ""]
        for f in group:
            L += [
                f"#### {f.name}",
                "",
                f"- **Asset:** `{f.url or f.host}`",
                f"- **Detected by:** {f.engine}" + (f" (`{f.rule_id}`)" if f.rule_id else ""),
                f"- **Status:** {f.status.value}",
            ]
            if f.cve:
                L.append(f"- **CVE:** {', '.join(f.cve)}")
            if f.cwe:
                L.append(f"- **CWE:** {', '.join(f.cwe)}")
            if f.triage_confidence is not None:
                L.append(f"- **Triage confidence:** {f.triage_confidence:.0%}")
            if f.occurrences > 1:
                L.append(f"- **Occurrences:** {f.occurrences}")
            L.append("")
            if f.description:
                L += [f.description.strip(), ""]
            if f.remediation:
                L += ["**Recommended action:** " + f.remediation.strip(), ""]
            if f.triage_note:
                L += ["<details><summary>Triage notes</summary>", "",
                      f.triage_note.strip(), "", "</details>", ""]
            if f.references:
                L += ["References: " + ", ".join(f"<{r}>" for r in f.references[:5]), ""]

    L += [
        "---",
        "",
        f"*Generated {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC} by Merlon. "
        "Automated findings require human verification before disclosure.*",
    ]
    return "\n".join(x for x in L if x is not None)


async def disclosure_report(finding_id: int) -> str:
    """LLM-drafted single-finding disclosure. Falls back to a template."""
    with SessionLocal() as db:
        f = db.get(Finding, finding_id)
        if not f:
            raise ValueError("finding not found")
        data = {
            "name": f.name, "severity": f.severity.value, "url": f.url or f.host,
            "cve": ", ".join(f.cve) or "none", "cwe": ", ".join(f.cwe) or "none",
            "description": f.description[:2000], "evidence": f.evidence[:2500],
            "remediation": f.remediation[:1200],
        }

    drafted = await llm.complete(DISCLOSURE_PROMPT.format(**data), system=DISCLOSURE_SYSTEM,
                                 temperature=0.2)
    if drafted:
        return drafted + "\n\n---\n*Draft generated locally. Verify every claim before submitting.*"

    return "\n".join([
        "## Summary", "", data["name"], "",
        "## Affected Asset", "", f"`{data['url']}`", "",
        "## Description", "", data["description"] or "_(fill in)_", "",
        "## Impact", "", "_(fill in)_", "",
        "## Recommended Remediation", "", data["remediation"] or "_(fill in)_", "",
        "---", "*Ollama unavailable — template only.*",
    ])
