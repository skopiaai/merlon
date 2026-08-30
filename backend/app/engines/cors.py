"""Cross-origin resource sharing misconfiguration.

The same-origin policy is what stops a page on one site from reading responses
from another. CORS is the deliberate exemption to it, and it is very easy to
write an exemption wider than intended — usually by reflecting whatever
`Origin` the request carried, because that makes the error messages stop.

Reflection plus `Access-Control-Allow-Credentials: true` is the dangerous
combination. It means any website the victim visits can make authenticated
requests to this API *with the victim's session cookies* and read the replies.
No XSS required, no phishing, no user interaction beyond loading a page.

The tests here are deliberately shaped around the bypasses that actually work
in the wild, because the naive check — send `Origin: evil.com` and see if it
comes back — misses most real cases. Parsers that "validate" the origin with a
substring or prefix match are the common failure, so the probes include
`target.com.attacker.invalid` and `attacker-target.com`.

Every probe origin uses the reserved `.invalid` TLD (RFC 2606), which can never
resolve. Nothing here reaches a third party.
"""

from __future__ import annotations

from urllib.parse import urlparse

from ..models import Severity
from ..normalize import make_dedupe_key
from . import fetch
from .registry import EngineSpec, register

CANARY = "attacker.invalid"


def probe_origins(host: str) -> list[tuple[str, str]]:
    """(origin_to_send, what_it_tests) for a target host."""
    return [
        (f"https://{CANARY}", "arbitrary-origin"),
        ("null", "null-origin"),
        (f"https://{host}.{CANARY}", "suffix-bypass"),
        (f"https://{CANARY}/{host}", "path-confusion"),
        (f"https://not{host}", "prefix-bypass"),
        (f"http://{host}", "scheme-downgrade"),
        (f"https://evil.{host}", "subdomain-trust"),
    ]


def analyse(sent_origin: str, kind: str, headers: dict[str, str],
            host: str) -> dict | None:
    """Judge one response. Pure — the whole detection logic, testable offline."""
    acao = (headers.get("access-control-allow-origin") or "").strip()
    acac = (headers.get("access-control-allow-credentials") or "").strip().lower()
    creds = acac == "true"

    if not acao:
        return None

    reflected = acao.lower() == sent_origin.lower()
    wildcard = acao == "*"

    # `*` with credentials is rejected by every browser, so it isn't
    # exploitable — but it means the server is guessing, and the same handler
    # usually reflects on a different path.
    if wildcard and creds:
        return {"rule": "cors-wildcard-with-credentials", "severity": Severity.low,
                "detail": "Access-Control-Allow-Origin: * together with "
                          "Allow-Credentials: true. Browsers refuse this "
                          "combination, so it is not directly exploitable, but it "
                          "shows the CORS policy is not deliberate."}

    if wildcard:
        return {"rule": "cors-wildcard", "severity": Severity.info,
                "detail": "Access-Control-Allow-Origin: * — any site can read "
                          "responses from this endpoint. Safe only if everything "
                          "served here is genuinely public."}

    if not reflected:
        # Reflecting *something else* that isn't the request origin is normal
        # (a fixed allowed origin). Not a finding.
        return None

    if kind == "null-origin":
        return {
            "rule": "cors-null-origin",
            "severity": Severity.high if creds else Severity.medium,
            "detail": "The server echoes `Origin: null` as an allowed origin. "
                      "`null` is what a sandboxed iframe sends, and any site can "
                      "create one — so this is equivalent to allowing everybody, "
                      "while looking like a restriction."}

    if kind == "scheme-downgrade":
        return {"rule": "cors-scheme-downgrade",
                "severity": Severity.medium if creds else Severity.low,
                "detail": "The plaintext http:// origin of this same host is "
                          "allowed. Anyone able to intercept an HTTP connection "
                          "on the victim's network can then read authenticated "
                          "cross-origin responses."}

    if kind == "subdomain-trust":
        return {"rule": "cors-subdomain-trust",
                "severity": Severity.medium if creds else Severity.low,
                "detail": "Any subdomain is trusted as an origin. That converts "
                          "one XSS or one subdomain takeover anywhere in the zone "
                          "into full read access to this API."}

    sev = Severity.critical if creds else Severity.medium
    return {
        "rule": f"cors-{kind}",
        "severity": sev,
        "detail": (
            f"The server reflected `{sent_origin}` back as an allowed origin"
            + (" **with credentials enabled**." if creds else ".")
            + (" Any website the victim visits can make authenticated requests "
               "here and read the responses." if creds else
               " Credentials are not allowed, so this only exposes data already "
               "reachable without a session — still worth fixing.")
            + ("" if kind == "arbitrary-origin" else
               f" This one passed a *validation* attempt: `{sent_origin}` is not "
               f"your domain, but the check accepted it, which points at a "
               f"substring or prefix comparison rather than an exact match."))
    }


@register(EngineSpec(
    name="cors",
    label="Testing cross-origin policy",
    description="CORS misconfiguration — reflected origins, null origin, and the "
                "prefix/suffix bypasses that defeat substring-based origin "
                "validation. Reflection plus credentials means any site can read "
                "this API as the logged-in victim.",
    phase="post_http",
    takes="urls",
    produces="findings",
    weight=5,
    limit=40,
    default_in=("standard", "deep"),
))
async def _engine(targets: list[str], ctx: dict) -> list[dict]:
    log = ctx.get("log")
    findings: list[dict] = []
    seen: set[str] = set()

    async def check(url: str) -> list[dict]:
        host = (urlparse(url).hostname or "").lower()
        if not host:
            return []
        out = []
        for origin, kind in probe_origins(host):
            resp = await fetch.request(url, headers={"Origin": origin}, timeout=12, ctx=ctx)
            if not resp.ok:
                continue
            issue = analyse(origin, kind, resp.headers, host)
            if not issue:
                continue

            key = f"{host}|{issue['rule']}"
            if key in seen:
                continue
            seen.add(key)

            acao = resp.header("access-control-allow-origin")
            acac = resp.header("access-control-allow-credentials")
            out.append({
                "engine": "cors", "rule_id": issue["rule"],
                "name": issue["rule"].replace("cors-", "CORS: ").replace("-", " "),
                "severity": issue["severity"],
                "host": host, "url": url, "matched_at": url,
                "description": issue["detail"],
                "evidence": (f"Request:  Origin: {origin}\n"
                             f"Response: Access-Control-Allow-Origin: {acao}\n"
                             f"          Access-Control-Allow-Credentials: "
                             f"{acac or '(absent)'}\n"
                             f"          HTTP {resp.status}"),
                "remediation": (
                    "Validate the Origin header against an explicit allowlist and "
                    "echo back only exact matches — never the raw request value, "
                    "and never a value that merely *contains* your domain.\n\n"
                    "  ALLOWED = {'https://app.example.com', 'https://example.com'}\n"
                    "  if request.origin in ALLOWED:\n"
                    "      response['Access-Control-Allow-Origin'] = request.origin\n"
                    "      response['Vary'] = 'Origin'\n\n"
                    "Set Allow-Credentials only on endpoints that genuinely need "
                    "the session, and never together with `*`. Add `Vary: Origin` "
                    "so a shared cache can't serve one origin's response to "
                    "another."),
                "references": [
                    "https://portswigger.net/web-security/cors",
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
                ],
                "tags": ["cors", "misconfig", "access-control"],
                "cve": [], "cwe": ["CWE-942", "CWE-346"], "cvss_score": None,
                "dedupe_key": make_dedupe_key("cors", issue["rule"], host, url),
                "raw": {"origin_sent": origin, "acao": acao, "acac": acac},
            })
        return out

    results = await fetch.gather_limited([check(u) for u in targets], limit=6)
    for group in results:
        findings += group or []

    if log:
        await log("info", f"[cors] {len(findings)} misconfiguration(s) across "
                          f"{len(targets)} endpoint(s)", "cors")
    return findings
