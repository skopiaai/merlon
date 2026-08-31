"""Independent re-verification and confidence scoring.

In 2026 the scarce thing in bug bounty is not finding issues — it is proving
them. Autonomous agents reached the top of HackerOne's leaderboard, and at the
same time Google stopped accepting AI-generated vulnerability reports and the
Internet Bug Bounty suspended payouts, because the volume of machine-generated
findings made triage impossible. Programs are drowning in plausible-looking
reports that don't reproduce.

That changes the economics for the person submitting. A researcher with 200
reports and 50 accepted gets slower triage and smaller payouts than one with 50
reports and 40 accepted. **Acceptance rate is the currency, not volume.**

So this module exists to answer one question about every finding before it is
ever shown as submittable:

    If a triager runs this right now, does it still happen?

The design rule is that **confidence comes from evidence, never from opinion.**
The local LLM already writes triage notes, and those are useful commentary —
but an LLM's belief that a finding is real is exactly the input that produced
the report flood. So the score here is computed from deterministic facts: did
the request reproduce, did it reproduce twice, did the control case behave
differently, is the evidence self-consistent. The LLM's view is recorded
alongside and deliberately given no weight.

Every verified finding carries a signed-in-time record: the exact request, the
exact response, a SHA-256 of the response body, and a UTC timestamp. That is
what a triager needs and rarely gets.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlparse

from .engines import fetch

# A finding at or above this reproduces reliably and has evidence to show.
# Below it, the finding is kept — it may well be real — but it is not offered
# as something to submit until a human has looked.
SUBMIT_THRESHOLD = 0.75

# Findings whose truth doesn't depend on a reproducible HTTP response. A
# missing DMARC record is a fact about DNS; re-fetching a URL says nothing
# about it. These are scored on their own terms rather than marked unverifiable.
NON_HTTP_ENGINES = {"domainsec", "netblock", "dnsx", "tlsdeep", "nse", "buckets"}

# Engines whose findings are inherently a judgement call and should always get
# a human look regardless of how cleanly they reproduce.
ALWAYS_REVIEW = {"seospam", "intel", "favicon"}


@dataclass
class Evidence:
    """A reproduction attempt, captured for the report."""
    url: str
    method: str = "GET"
    status: int = 0
    request_headers: dict = field(default_factory=dict)
    response_headers: dict = field(default_factory=dict)
    body_sha256: str = ""
    body_length: int = 0
    excerpt: str = ""
    at: str = ""
    reproduced: bool = False
    note: str = ""

    def as_dict(self) -> dict:
        return {
            "url": self.url, "method": self.method, "status": self.status,
            "request_headers": self.request_headers,
            "response_headers": self.response_headers,
            "body_sha256": self.body_sha256, "body_length": self.body_length,
            "excerpt": self.excerpt, "at": self.at,
            "reproduced": self.reproduced, "note": self.note,
        }


@dataclass
class Verdict:
    confidence: float
    reproduced: bool
    reasons: list[str]
    evidence: list[dict]

    @property
    def submittable(self) -> bool:
        return self.confidence >= SUBMIT_THRESHOLD

    def as_dict(self) -> dict:
        return {
            "confidence": round(self.confidence, 2),
            "reproduced": self.reproduced,
            "submittable": self.submittable,
            "reasons": self.reasons,
            "evidence": self.evidence,
        }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sha256(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8", "replace")).hexdigest()


def _redact(text: str) -> str:
    """Evidence must not become a second copy of a leaked credential."""
    patterns = [
        (re.compile(r"(?i)((?:password|passwd|secret|token|api[_-]?key|"
                    r"authorization|cookie)\w*\s*[=:]\s*)(\S{6,})"), r"\1[redacted]"),
        (re.compile(r"(AKIA[0-9A-Z]{16})"), "[redacted-aws-key]"),
        (re.compile(r"(-----BEGIN [A-Z ]*PRIVATE KEY-----)[\s\S]+"), r"\1[redacted]"),
        (re.compile(r"(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.)[A-Za-z0-9_-]+"),
         r"\1[redacted]"),
    ]
    out = text or ""
    for pattern, replacement in patterns:
        out = pattern.sub(replacement, out)
    return out


async def capture(url: str, ctx: dict | None = None, *, method: str = "GET",
                  headers: dict | None = None,
                  authenticated: bool = True) -> Evidence:
    """One reproduction attempt, recorded in full."""
    resp = await fetch.request(url, method=method, headers=headers, ctx=ctx,
                               authenticated=authenticated, timeout=15)
    body = resp.body or ""
    return Evidence(
        url=url, method=method, status=resp.status,
        request_headers={k: ("[redacted]" if k.lower() in
                             ("cookie", "authorization") else v)
                         for k, v in (headers or {}).items()},
        response_headers=dict(list(resp.headers.items())[:25]),
        body_sha256=sha256(body), body_length=len(body),
        excerpt=_redact(body[:600]), at=_now(),
        reproduced=resp.ok,
    )


def _evidence_quality(finding: dict) -> tuple[float, list[str]]:
    """How much the finding's own evidence supports it, before any re-request.

    This is deliberately picky. Findings that assert something without showing
    it are the ones that waste a triager's time, and an engine that produces
    them should score badly enough to be caught here.
    """
    score, reasons = 0.0, []
    evidence = finding.get("evidence") or ""

    if len(evidence) >= 80:
        score += 0.15
    else:
        reasons.append("evidence is thin — a triager can't see what happened")

    # Evidence that shows an actual exchange rather than a claim about one.
    if re.search(r"\bHTTP/?\s?\d{3}\b|→ HTTP|GET |POST |Location:|Allow:", evidence):
        score += 0.1
    else:
        reasons.append("evidence doesn't show a request/response exchange")

    if finding.get("remediation"):
        score += 0.05
    if finding.get("references"):
        score += 0.05
    if finding.get("cwe"):
        score += 0.05

    return score, reasons


async def verify_finding(finding: dict, ctx: dict | None = None) -> Verdict:
    """Re-test a finding independently and score it on what actually happened.

    The scoring is additive and every term is a fact:

      +0.45  the finding reproduces on a fresh request
      +0.15  it reproduced twice, so it isn't a transient
      +0.15  a control request behaves differently, so the result is specific
             to the thing being reported rather than to every request
      +0.40  cumulative evidence quality from the engine itself
      -0.30  it did not reproduce at all
    """
    engine = str(finding.get("engine", ""))
    url = finding.get("matched_at") or finding.get("url") or ""

    base_score, reasons = _evidence_quality(finding)
    captures: list[dict] = []

    # --- findings that aren't about an HTTP response ---
    if engine in NON_HTTP_ENGINES or not url.startswith("http"):
        # These are facts about DNS records, certificates, open ports or bucket
        # ACLs. They don't reproduce via a URL fetch, and pretending otherwise
        # would mark every one of them unverified.
        confidence = min(1.0, 0.55 + base_score)
        reasons.insert(0, f"{engine} findings are verified at collection time, "
                          f"not by re-fetching a URL")
        return Verdict(confidence, True, reasons, captures)

    # --- reproduce ---
    first = await capture(url, ctx)
    captures.append(first.as_dict())

    if not first.reproduced:
        reasons.insert(0, "did NOT reproduce — the host did not respond on retest")
        return Verdict(max(0.0, base_score - 0.30), False, reasons, captures)

    score = base_score + 0.45
    reasons.insert(0, f"reproduced: HTTP {first.status} at {first.at}")

    # --- reproduce again: transients are the most common false positive ---
    await asyncio.sleep(0.4)
    second = await capture(url, ctx)
    captures.append(second.as_dict())

    if second.reproduced and second.status == first.status:
        score += 0.15
        if second.body_sha256 == first.body_sha256:
            reasons.append("identical response on both attempts — stable, not a fluke")
        else:
            reasons.append("same status twice with differing bodies — dynamic page, "
                           "still consistent")
    else:
        reasons.append("second attempt differed — the result may be intermittent, "
                       "check before reporting")

    # --- control: does this host answer everything the same way? ---
    parsed = urlparse(url)
    control_url = f"{parsed.scheme}://{parsed.netloc}/zzz-control-{abs(hash(url)) % 99999}"
    control = await capture(control_url, ctx)
    control.note = "control request for a path that should not exist"
    captures.append(control.as_dict())

    if control.status != first.status or \
            abs(control.body_length - first.body_length) > 64:
        score += 0.15
        reasons.append(f"control path returns HTTP {control.status} — this result "
                       f"is specific to the reported URL")
    else:
        score -= 0.10
        reasons.append(f"control path returns the same HTTP {control.status} and a "
                       f"similar body — this host answers everything alike, so the "
                       f"finding may be an artefact")

    if engine in ALWAYS_REVIEW:
        score = min(score, SUBMIT_THRESHOLD - 0.01)
        reasons.append(f"{engine} findings are a judgement call and always get a "
                       f"human look before submission")

    return Verdict(max(0.0, min(1.0, score)), True, reasons, captures)


async def verify_scan(scan_id: int, ctx: dict | None = None, *,
                      limit: int = 120, concurrency: int = 4,
                      log=None) -> tuple[int, int]:
    """Re-verify a scan's findings. Returns (checked, submittable).

    Ordered by severity so that a capped run spends its budget on the findings
    you would actually submit. An informational finding that goes unverified
    costs nothing; an unverified critical is the one that wastes a triager's
    afternoon and your reputation.
    """
    from sqlalchemy import select

    from .db import SessionLocal
    from .models import Finding, Severity

    order = {Severity.critical: 0, Severity.high: 1, Severity.medium: 2,
             Severity.low: 3, Severity.info: 4}

    with SessionLocal() as db:
        findings = list(db.scalars(
            select(Finding).where(Finding.scan_id == scan_id)))
        queue = sorted(findings, key=lambda f: order.get(f.severity, 5))[:limit]
        pending = [(f.id, {
            "engine": f.engine, "rule_id": f.rule_id, "url": f.url,
            "matched_at": f.matched_at, "evidence": f.evidence,
            "remediation": f.remediation, "references": f.references,
            "cwe": f.cwe,
        }) for f in queue]

    if not pending:
        return 0, 0

    semaphore = asyncio.Semaphore(concurrency)

    async def one(finding_id: int, payload: dict):
        async with semaphore:
            try:
                return finding_id, await verify_finding(payload, ctx)
            except Exception as exc:  # noqa: BLE001
                return finding_id, Verdict(0.0, False,
                                           [f"verification error: {exc}"], [])

    results = await asyncio.gather(*(one(i, p) for i, p in pending))

    submittable = 0
    with SessionLocal() as db:
        for finding_id, verdict in results:
            finding = db.get(Finding, finding_id)
            if not finding:
                continue
            finding.verify_confidence = round(verdict.confidence, 3)
            finding.reproduced = verdict.reproduced
            finding.verified_at = datetime.now(timezone.utc)
            finding.verification = verdict.as_dict()
            if verdict.submittable:
                submittable += 1
        db.commit()

    if log:
        dead = sum(1 for _i, v in results if not v.reproduced)
        if dead:
            await log("warn",
                      f"[verify] {dead} finding(s) did not reproduce on retest — "
                      f"they are kept but held out of the submission queue",
                      "verify")
    return len(results), submittable


def evidence_block(verdict_data: dict) -> str:
    """The reproduction section of a report, from captured evidence.

    Triagers reject reports they cannot reproduce. This gives them the exact
    request, the exact response, a hash they can compare, and the time it was
    observed — which is the difference between "I saw this" and "here it is".
    """
    if not verdict_data:
        return ""
    lines = ["## Reproduction", ""]
    for item in verdict_data.get("evidence", []):
        note = f"  ({item['note']})" if item.get("note") else ""
        lines += [
            f"**{item['method']} {item['url']}**{note}",
            "```http",
            f"HTTP {item['status']}",
        ]
        for key, value in list(item.get("response_headers", {}).items())[:8]:
            lines.append(f"{key}: {value}")
        lines += ["", (item.get("excerpt") or "")[:400], "```",
                  f"Observed {item['at']} · {item['body_length']} bytes · "
                  f"sha256 `{item['body_sha256'][:16]}…`", ""]

    confidence = verdict_data.get("confidence")
    if confidence is not None:
        lines += [f"**Verification confidence: {confidence:.0%}**", ""]
        for reason in verdict_data.get("reasons", []):
            lines.append(f"- {reason}")
    return "\n".join(lines)
