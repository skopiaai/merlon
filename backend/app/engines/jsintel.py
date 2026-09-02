"""Reading JavaScript for authorization and logic flaws.

Every other engine in this package matches patterns. This one reasons, because
the bugs it looks for have no pattern:

    if (user.role === 'admin') { showAdminPanel(); }

There is nothing wrong with that line. Whether it is a vulnerability depends
entirely on whether the *server* also checks, and no regex can tell you that.
What the line does tell you is where to look — and a model reading the
surrounding code can say "this gates an admin route on a client-side value that
comes from a JWT the browser can edit", which is a hypothesis worth testing.

That is the only thing the model is used for here: **generating hypotheses from
code a human would have to read.** It is the one job in this tool where a local
model beats a regex, and it is deliberately not allowed to do anything else.

The architecture is the hybrid pattern that works — an LLM explores, and
deterministic code verifies — because the failure mode of skipping the second
half is exactly what got AI-generated vulnerability reports banned by major
programs in 2026. Concretely:

  1. **Deterministic extraction.** Regions of the bundle that carry
     authorization, role logic, feature flags, token handling or crypto are cut
     out by pattern. The model never sees a whole bundle, which keeps it in
     context and stops it inventing findings about code that isn't there.

  2. **The model reasons over those regions only**, and must return structured
     output: a claim, a severity, and a verbatim snippet it is talking about.

  3. **Every claim is verified against the source.** If the snippet the model
     cites does not literally appear in the file, the finding is discarded as a
     hallucination and counted. This is the whole safeguard, and it is cheap:
     one substring check per claim.

  4. **Nothing from here is submittable unreviewed.** Findings are tagged for
     human review regardless of how confident the model sounds. A hypothesis
     about server-side behaviour, derived from client-side code, is a lead —
     the verification stage cannot confirm it, and neither can the model.

Without Ollama running the engine does nothing and says so. It is an
accelerant, never a dependency.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from .. import llm
from ..models import Severity
from ..normalize import make_dedupe_key
from . import fetch
from .registry import EngineSpec, register

SCRIPT_SRC = re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"']", re.I)

# Code shapes worth a model's attention. Each is a place where an application
# makes a decision, which is where logic flaws live — as opposed to the 99% of
# a bundle that is framework runtime and vendor code.
INTERESTING = [
    (re.compile(r"\b(?:is|has|can|check|verify|validate|require|allow|deny)"
                r"[A-Z_]\w*\s*[=(]", re.I), "permission check"),
    (re.compile(r"\brole\s*(?:===?|!==?|\.includes|\.indexOf|\bin\b)", re.I),
     "role comparison"),
    (re.compile(r"\b(?:isAdmin|is_admin|isStaff|isSuperuser|admin\s*===?|"
                r"permissions?\s*\.|scopes?\s*\.|privileges?\s*\.)", re.I),
     "privilege logic"),
    (re.compile(r"\b(?:localStorage|sessionStorage)\s*\.\s*(?:get|set)Item\s*\("
                r"\s*[\"'][^\"']*(?:token|auth|jwt|session|key|secret)", re.I),
     "credential storage"),
    (re.compile(r"\b(?:atob|jwt_decode|jwtDecode|decodeToken|parseJwt)\s*\(", re.I),
     "token decoding"),
    (re.compile(r"\bfeature(?:Flag|s)?\s*[\[.]|\bflags?\s*\[[\"']", re.I),
     "feature flag"),
    (re.compile(r"\b(?:Math\.random|Date\.now)\s*\(\s*\)[^;]{0,60}"
                r"(?:token|id|key|nonce|secret|password|otp)", re.I),
     "predictable value generation"),
    (re.compile(r"\b(?:innerHTML|outerHTML|insertAdjacentHTML|document\.write|"
                r"dangerouslySetInnerHTML)\s*[=:(]", re.I), "HTML sink"),
    (re.compile(r"\b(?:eval|Function|setTimeout|setInterval)\s*\(\s*"
                r"(?!function|\(\)|\s*\d)", re.I), "dynamic execution"),
    (re.compile(r"\bpostMessage\s*\(|addEventListener\s*\(\s*[\"']message[\"']", re.I),
     "cross-window messaging"),
    (re.compile(r"\.(?:bypass|skip|disable|override|force)[A-Z_]\w*\s*[=(]", re.I),
     "bypass switch"),
]

# Regions to ignore entirely — vendor runtime is huge, uninteresting, and would
# consume the model's whole context.
VENDOR = re.compile(
    r"webpack|__webpack_require__|regeneratorRuntime|/\*! For license|"
    r"Copyright \(c\) (?:Facebook|Google|Microsoft)|"
    r"react-dom\.production|angular\.min|jquery\.min", re.I)

SYSTEM = """You are a security engineer reading JavaScript from a web application.

Identify places where the CLIENT-SIDE code suggests a possible SERVER-SIDE
authorization or logic weakness worth testing manually.

Rules you must follow:
- Only comment on code that is present in the excerpt. Never speculate about
  code you cannot see.
- Every finding MUST include a `snippet` copied VERBATIM from the excerpt,
  character for character. Findings whose snippet is not an exact copy are
  discarded.
- A client-side check is not itself a vulnerability. It is a signal that the
  same rule may be missing on the server. Phrase findings as what to test.
- Do not report code style, missing types, minification, or performance.
- If nothing in the excerpt is security-relevant, return an empty list. An
  empty answer is a correct and useful answer.

Return JSON only:
{"findings": [{"title": "...", "why": "...", "test": "...",
               "severity": "info|low|medium|high", "snippet": "..."}]}"""


def is_vendor(text: str) -> bool:
    return bool(VENDOR.search(text or ""))


def extract_regions(source: str, window: int = 400,
                    cap: int = 12) -> list[tuple[str, str]]:
    """(reason, code excerpt) for parts of a bundle worth reading.

    A minified bundle is a megabyte on one line; handing that to a model wastes
    the context window on framework internals and produces confident nonsense
    about code the model half-saw. Cutting windows around decision points keeps
    the input small, relevant, and — because the excerpt is verbatim — checkable
    afterwards.
    """
    if not source:
        return []

    regions: list[tuple[str, str]] = []
    seen: set[int] = set()

    for pattern, reason in INTERESTING:
        for match in pattern.finditer(source):
            start = max(0, match.start() - window)
            end = min(len(source), match.end() + window)

            # Skip windows we've already covered — patterns overlap heavily in
            # real code and duplicate excerpts are wasted tokens.
            bucket = start // window
            if bucket in seen:
                continue
            seen.add(bucket)

            excerpt = source[start:end]
            if is_vendor(excerpt):
                continue
            regions.append((reason, excerpt))
            if len(regions) >= cap:
                return regions
    return regions


def claim_is_grounded(claim: dict, source: str) -> bool:
    """Does the snippet the model cited actually exist in the file?

    The single safeguard that separates this engine from the report flood.
    Models produce plausible code when asked about code, and a finding citing a
    line that was never there is worse than no finding — it is confidently
    wrong, which is the thing programs are now rejecting outright.

    Whitespace is normalised before comparing, because minified JavaScript gets
    reflowed in a model's output and that is not evidence of invention.
    """
    snippet = str(claim.get("snippet") or "").strip()
    if len(snippet) < 12:
        return False      # too short to be evidence of anything

    def squash(text: str) -> str:
        return re.sub(r"\s+", "", text)

    return squash(snippet) in squash(source)


def usable_claims(response: dict | None, source: str) -> tuple[list[dict], int]:
    """(grounded claims, number rejected as ungrounded)."""
    if not isinstance(response, dict):
        return [], 0
    raw = response.get("findings")
    if not isinstance(raw, list):
        return [], 0

    kept, rejected = [], 0
    for claim in raw:
        if not isinstance(claim, dict) or not claim.get("title"):
            rejected += 1
            continue
        if not claim_is_grounded(claim, source):
            rejected += 1
            continue
        kept.append(claim)
    return kept, rejected


def severity_of(claim: dict) -> Severity:
    """Model-suggested severity, capped.

    Capped at medium on purpose. Everything here is a hypothesis about
    server-side behaviour inferred from client-side code, and no such
    hypothesis is a high-severity finding until someone has tested the server.
    Letting a model hand out criticals for reading a bundle is how a tool stops
    being trusted.
    """
    mapping = {"info": Severity.info, "low": Severity.low,
               "medium": Severity.medium, "high": Severity.medium}
    return mapping.get(str(claim.get("severity", "low")).lower(), Severity.low)


@register(EngineSpec(
    name="jsintel",
    label="Reading JavaScript for logic flaws",
    description="Uses the local model to reason over authorization and logic code "
                "in the site's own bundles — the one job here a regex cannot do. "
                "Every claim is checked against the source before it becomes a "
                "finding, and nothing from this engine is submittable unreviewed.",
    phase="post_http",
    takes="urls",
    produces="findings",
    weight=10,
    limit=6,
    default_in=("deep",),
))
async def _engine(targets: list[str], ctx: dict) -> list[dict]:
    log = ctx.get("log")

    if not await llm.available():
        if log:
            await log("info",
                      "[jsintel] no local model reachable — skipping. This engine "
                      "reasons over code rather than matching patterns, so it has "
                      "nothing to fall back to.", "jsintel")
        return []

    findings: list[dict] = []
    hallucinated = 0
    read = 0

    for page in targets[:6]:
        host = (urlparse(page).hostname or "").lower()
        html = await fetch.request(page, ctx=ctx, follow=True, timeout=20)
        if not html.ok:
            continue

        scripts = [urljoin(page, src) for src in SCRIPT_SRC.findall(html.body)]
        scripts = [s for s in scripts
                   if (urlparse(s).hostname or "").lower().endswith(host)]

        for script in scripts[:5]:
            body = await fetch.request(script, ctx=ctx, timeout=25)
            if not body.ok or len(body.body) < 200:
                continue
            read += 1

            regions = extract_regions(body.body)
            if not regions:
                continue

            excerpt_blob = "\n\n---\n\n".join(
                f"[{reason}]\n{code}" for reason, code in regions)

            response = await llm.complete_json(
                f"Application: {host}\nFile: {script}\n\n"
                f"Excerpts from the bundle, cut around security-relevant code:\n\n"
                f"{excerpt_blob[:14000]}",
                system=SYSTEM, temperature=0.1)

            claims, rejected = usable_claims(response, body.body)
            hallucinated += rejected

            for claim in claims[:5]:
                title = str(claim["title"])[:180]
                # Built outside the f-string: nesting quotes inside a
                # multi-line f-string expression is only legal from Python 3.12
                # (PEP 701), and this has to import on 3.10.
                how_to_test = claim.get("test") or (
                    "Compare what the client-side check allows against what the "
                    "server actually enforces.")
                findings.append({
                    "engine": "jsintel", "rule_id": "js-logic-lead",
                    "name": f"Client-side logic worth testing: {title}",
                    "severity": severity_of(claim),
                    "host": host, "url": script, "matched_at": script,
                    "description": (
                        f"{claim.get('why', '')}\n\n"
                        f"**How to test it:** {how_to_test}\n\n"
                        f"**This is a lead, not a confirmed finding.** It came from "
                        f"a model reading `{script.rsplit('/', 1)[-1]}` and "
                        f"reasoning about what the server might not be doing. The "
                        f"cited code was verified to exist in the file — but "
                        f"whether the server enforces the same rule can only be "
                        f"established by testing the server, which is why nothing "
                        f"from this engine is offered as ready to submit.\n\n"
                        f"Client-side checks are not vulnerabilities in themselves. "
                        f"They are a map of what the application believes its rules "
                        f"are, which is the fastest way to find the endpoint where "
                        f"a rule is missing."),
                    "evidence": (f"{script}\n\n"
                                 f"Verified present in the source:\n"
                                 f"{str(claim.get('snippet', ''))[:600]}"),
                    "remediation": (
                        "If testing confirms the server does not enforce this: move "
                        "the decision server-side. A client-side check is a user "
                        "interface convenience — it tells the browser what to show, "
                        "and the browser is under the user's control.\n\n"
                        "Authorization belongs in the handler, on data the client "
                        "cannot influence: the session's identity, looked up "
                        "server-side, not a role claim read out of a token in "
                        "localStorage.\n\n"
                        "If testing shows the server does enforce it, there is "
                        "nothing to fix — close this lead."),
                    "references": [
                        "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
                    ],
                    "tags": ["logic", "ai-assisted", "needs-review"],
                    "cve": [], "cwe": ["CWE-602", "CWE-284"], "cvss_score": None,
                    "dedupe_key": make_dedupe_key(
                        "jsintel", f"lead-{title[:60]}", host, script),
                    "raw": {"script": script,
                            "model_severity": claim.get("severity"),
                            "grounded": True},
                })

    if log:
        await log("info",
                  f"[jsintel] read {read} bundle(s) → {len(findings)} lead(s)",
                  "jsintel")
        if hallucinated:
            await log("warn",
                      f"[jsintel] discarded {hallucinated} model claim(s) citing "
                      f"code that does not appear in the file. This is the check "
                      f"that keeps AI-assisted findings honest — without it those "
                      f"would have been reported as real.", "jsintel")
        if findings:
            await log("info",
                      "[jsintel] these are leads for manual testing, not confirmed "
                      "findings — they are held out of the submission queue by "
                      "design", "jsintel")
    return findings
