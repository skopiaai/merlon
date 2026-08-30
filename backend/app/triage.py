"""LLM-assisted triage.

What the model is asked to do:
  * judge whether a finding is plausibly real or scanner noise
  * write remediation guidance in the target's actual context
  * flag findings worth a human's manual attention

What the model is NOT asked to do:
  * generate exploits or attack payloads
  * decide anything autonomously — every verdict is advisory, and the
    analyst's status always overrides `triage_confidence`

Small local models hallucinate. Treat confidence as a sort order, not truth.
"""

from __future__ import annotations

import asyncio

from sqlalchemy import select

from . import llm
from .db import SessionLocal
from .models import Finding, FindingStatus, Severity

SYSTEM = """You are a defensive security analyst reviewing automated scanner output.
Your job is to separate real issues from false positives and to write clear,
actionable remediation guidance for the team that owns the system.

Rules:
- Be conservative. If the evidence does not support the finding, say so.
- Never write exploit code or attack payloads. Describe impact in prose.
- Remediation must be concrete: the specific header, config directive, patch
  version, or code change. No generic advice like "validate input".
- Reply with JSON only."""

PROMPT = """Review this scanner finding.

Engine: {engine}
Rule: {rule_id}
Reported severity: {severity}
Title: {name}
Host: {host}
URL: {url}
Tags: {tags}
CVE: {cve}

Description:
{description}

Evidence:
{evidence}

Vendor remediation text (may be empty):
{remediation}

Return JSON with exactly these keys:
{{
  "verdict": "likely_real" | "likely_false_positive" | "needs_manual_review",
  "confidence": 0.0-1.0,
  "adjusted_severity": "info"|"low"|"medium"|"high"|"critical",
  "reasoning": "2-3 sentences on why you reached this verdict",
  "impact": "what an attacker could achieve, in business terms, 1-2 sentences",
  "remediation": "concrete fix steps, 2-4 sentences",
  "manual_check": "one specific thing a human should verify, or empty string"
}}"""

_VERDICT_TO_STATUS = {
    "likely_false_positive": FindingStatus.false_positive,
    "likely_real": FindingStatus.confirmed,
    "needs_manual_review": FindingStatus.triaging,
}


def _truncate(text: str, limit: int) -> str:
    text = text or ""
    return text if len(text) <= limit else text[:limit] + "\n…[truncated]"


async def triage_one(finding_id: int) -> bool:
    with SessionLocal() as db:
        f = db.get(Finding, finding_id)
        if not f:
            return False
        payload = {
            "engine": f.engine, "rule_id": f.rule_id, "severity": f.severity.value,
            "name": f.name, "host": f.host, "url": f.url,
            "tags": ", ".join(f.tags or []) or "none",
            "cve": ", ".join(f.cve or []) or "none",
            "description": _truncate(f.description, 1500),
            "evidence": _truncate(f.evidence, 3000),
            "remediation": _truncate(f.remediation, 800),
        }

    result = await llm.complete_json(PROMPT.format(**payload), system=SYSTEM)
    if not result:
        return False

    verdict = str(result.get("verdict", "")).strip()
    try:
        confidence = max(0.0, min(1.0, float(result.get("confidence", 0.5))))
    except (TypeError, ValueError):
        confidence = 0.5

    with SessionLocal() as db:
        f = db.get(Finding, finding_id)
        if not f or f.status not in (FindingStatus.new, FindingStatus.triaging):
            return False  # an analyst already ruled on this; don't overwrite

        f.triage_confidence = confidence
        f.triage_note = "\n\n".join(filter(None, [
            f"Verdict: {verdict} (confidence {confidence:.2f})",
            f"Reasoning: {result.get('reasoning', '')}",
            f"Impact: {result.get('impact', '')}",
            f"Manual check: {result.get('manual_check', '')}" if result.get("manual_check") else "",
        ]))

        if result.get("remediation"):
            f.remediation = str(result["remediation"])

        # Only auto-close as FP at high confidence, and never for high/critical —
        # a wrongly dismissed critical is far more costly than a noisy queue.
        status = _VERDICT_TO_STATUS.get(verdict, FindingStatus.triaging)
        if status is FindingStatus.false_positive:
            if confidence < 0.8 or f.severity.rank >= Severity.high.rank:
                status = FindingStatus.triaging
        f.status = status

        adj = str(result.get("adjusted_severity", "")).lower()
        if adj in Severity.__members__ and f.engine != "nuclei":
            # Trust nuclei's own severity over a small local model's; only let
            # the LLM re-rank our own heuristic findings.
            f.severity = Severity(adj)

        db.commit()
    return True


async def triage_findings(scan_id: int, *, log=None, concurrency: int = 2) -> int:
    if not await llm.available():
        if log:
            await log("warn", "Ollama unreachable — skipping triage. Findings remain 'new'.")
        return 0

    with SessionLocal() as db:
        ids = list(db.scalars(
            select(Finding.id)
            .where(Finding.scan_id == scan_id, Finding.status == FindingStatus.new)
            .order_by(Finding.severity.desc())
        ))

    if not ids:
        return 0
    if log:
        await log("info", f"triaging {len(ids)} finding(s) via local model", "triage")

    sem = asyncio.Semaphore(concurrency)
    done = 0

    async def worker(fid: int):
        nonlocal done
        async with sem:
            if await triage_one(fid):
                done += 1

    await asyncio.gather(*(worker(i) for i in ids), return_exceptions=True)
    return done
