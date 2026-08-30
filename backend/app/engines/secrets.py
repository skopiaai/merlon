"""Client-side secret exposure.

Demonstrates the plugin path: this whole detection is one file. It declares its
own stage name, progress weight, inputs and depth presets at the bottom, and
needs no edits anywhere else in the codebase.

What it looks for: API keys and tokens shipped in JavaScript bundles, and
source maps left enabled in production. Both are extremely common and both are
real findings — a live Stripe or AWS key in a bundle is a critical, and an
exposed `.map` hands over the entire frontend source including comments and
internal endpoints.
"""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urljoin, urlparse

from ..models import Severity
from ..normalize import make_dedupe_key
from .registry import EngineSpec, register

# High-confidence credential patterns. Deliberately narrow: a generic
# "looks like a key" regex produces mostly noise, and noise is what makes
# people stop reading a report.
SECRET_PATTERNS: list[tuple[str, str, Severity, str]] = [
    ("aws-access-key", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", Severity.critical,
     "AWS access key ID"),
    ("google-api-key", r"\bAIza[0-9A-Za-z_\-]{35}\b", Severity.high,
     "Google API key"),
    ("slack-token", r"\bxox[baprs]-[0-9A-Za-z\-]{10,72}\b", Severity.critical,
     "Slack token"),
    ("stripe-live-key", r"\bsk_live_[0-9a-zA-Z]{24,}\b", Severity.critical,
     "Stripe live secret key"),
    ("github-token", r"\bgh[pousr]_[0-9A-Za-z]{36,}\b", Severity.critical,
     "GitHub token"),
    ("private-key", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
     Severity.critical, "Private key material"),
    ("jwt", r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b",
     Severity.medium, "JSON Web Token"),
    ("firebase-url", r"https://[a-z0-9\-]+\.firebaseio\.com", Severity.medium,
     "Firebase database URL"),
    ("mongodb-uri", r"mongodb(?:\+srv)?://[^\s\"'<>]{10,}", Severity.critical,
     "MongoDB connection string"),
    ("postgres-uri", r"postgres(?:ql)?://[^\s\"'<>:]+:[^\s\"'<>@]+@[^\s\"'<>]+",
     Severity.critical, "PostgreSQL connection string with credentials"),
]

SCRIPT_SRC = re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"']", re.I)
SOURCEMAP = re.compile(r"//[#@]\s*sourceMappingURL=([^\s*]+)", re.I)


async def _get(url: str, timeout: int = 15) -> str:
    """Fetch a URL with curl. Read-only; nothing is modified."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "curl", "-sS", "-L", "--max-time", str(timeout), "--max-redirs", "3", url,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 5)
    except (asyncio.TimeoutError, OSError):
        return ""
    return out.decode("utf-8", "replace")


def _finding(rule_id, name, sev, host, url, desc, fix, evidence, cwe):
    return {
        "engine": "secrets",
        "rule_id": rule_id,
        "name": name,
        "severity": sev,
        "host": host,
        "url": url,
        "matched_at": url,
        "description": desc,
        "evidence": evidence[:1500],
        "remediation": fix,
        "references": ["https://owasp.org/www-project-top-ten/"],
        "tags": ["secrets", "client-side", "disclosure"],
        "cve": [], "cwe": cwe, "cvss_score": None,
        "dedupe_key": make_dedupe_key("secrets", rule_id, host, url),
        "raw": {},
    }


def scan_text(text: str, host: str, url: str) -> list[dict]:
    """Pure function over some JavaScript. Trivially unit-testable."""
    out: list[dict] = []
    seen: set[str] = set()

    for rule_id, pattern, sev, label in SECRET_PATTERNS:
        for match in re.findall(pattern, text or ""):
            token = match if isinstance(match, str) else match[0]
            if rule_id in seen:
                break
            seen.add(rule_id)
            redacted = token[:6] + "…" + token[-4:] if len(token) > 14 else token[:4] + "…"
            out.append(_finding(
                f"secret-{rule_id}", f"{label} exposed in client-side code",
                sev, host, url,
                f"A {label.lower()} appears in JavaScript served to every visitor. "
                f"Anything in a bundle is public — minification is not protection. "
                f"If this credential is live, treat it as already compromised: "
                f"bundles are archived by crawlers and cached by browsers.",
                f"Revoke and rotate this credential now, then move it server-side. "
                f"If the frontend genuinely needs to call that service, proxy the "
                f"call through your backend so the secret never reaches the browser. "
                f"Afterwards, add secret scanning to CI so the next one is caught "
                f"before it ships.",
                f"Matched in {url}\nValue (redacted): {redacted}",
                cwe=["CWE-798", "CWE-200"],
            ))

    for smap in SOURCEMAP.findall(text or "")[:1]:
        out.append(_finding(
            "sourcemap-exposed", "Source map exposed in production",
            Severity.low, host, url,
            "The bundle references a source map, which reconstructs the original "
            "source including comments, variable names and internal API routes. "
            "It's not a vulnerability by itself, but it removes most of the effort "
            "of understanding the application.",
            "Stop publishing .map files to production, or restrict them to "
            "authenticated internal users. In most bundlers this is one config flag.",
            f"sourceMappingURL={smap}", cwe=["CWE-540"],
        ))
    return out


# ----------------------------------------------------------------- engine

@register(EngineSpec(
    name="secrets",
    label="Scanning client-side code for secrets",
    description="Pulls JavaScript bundles referenced by each page and looks for "
                "credentials and exposed source maps. Keys in a bundle are public "
                "by definition.",
    phase="post_http",
    takes="urls",
    weight=8,
    limit=10,
    default_in=("standard", "deep"),
))
async def _engine(targets: list[str], ctx: dict) -> list[dict]:
    log = ctx.get("log")
    if log:
        await log("info", f"[secrets] inspecting scripts on {len(targets)} page(s)",
                  "secrets")

    findings: list[dict] = []
    seen_scripts: set[str] = set()

    for page in targets:
        html = await _get(page)
        if not html:
            continue
        host = (urlparse(page).hostname or page).lower()

        # The page itself sometimes carries inline secrets.
        findings += scan_text(html, host, page)

        scripts = [urljoin(page, src) for src in SCRIPT_SRC.findall(html)]
        # Only same-origin scripts: a third-party CDN's bundle isn't the
        # target's finding, and fetching it is out of scope.
        scripts = [s for s in scripts
                   if (urlparse(s).hostname or "").lower().endswith(host)]

        for script in scripts[:12]:
            if script in seen_scripts:
                continue
            seen_scripts.add(script)
            body = await _get(script)
            if body:
                findings += scan_text(body, host, script)

    return findings
