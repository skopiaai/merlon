"""HTTP methods and access-control bypasses.

Two related checks live here because they exploit the same gap: the rules that
decide *who may see this* are usually enforced somewhere other than the code
that serves the content — a reverse proxy, a WAF rule, an `<Limit GET>` block —
and those two layers disagree about what the request says.

**Dangerous methods.** TRACE, PUT, DELETE and friends left enabled on a server
that only needs GET and POST. TRACE in particular echoes the request back
including headers, which historically turned into a way to read HttpOnly
cookies.

**403 bypass.** When a path returns 403, that answer often comes from a proxy
matching on the literal path string. Change the string in a way the proxy reads
differently from the origin — `/admin/.`, `//admin`, `/%2e/admin` — or hand the
origin a header the proxy forgot to strip (`X-Original-URL`, `X-Forwarded-For`)
and the restriction evaporates. Finding one of these is finding that the access
control is decorative.

Everything here is read-only. No PUT or DELETE is ever sent: proving those work
means writing to or removing something on a server you don't own, and a
disabled-method finding isn't worth a modified target. The `Allow` header and
the OPTIONS response say what's enabled without touching anything.
"""

from __future__ import annotations

from urllib.parse import urlparse, urlunparse

from ..models import Severity
from ..normalize import make_dedupe_key
from . import fetch
from .registry import EngineSpec, register

RISKY_METHODS = {
    "PUT": ("write files directly to the web root", Severity.high),
    "DELETE": ("remove files from the server", Severity.high),
    "TRACE": ("echo the request back, including headers a script cannot "
              "otherwise read", Severity.medium),
    "TRACK": ("echo the request back (the IIS equivalent of TRACE)", Severity.medium),
    "CONNECT": ("open a tunnel through this host to somewhere else", Severity.high),
    "PATCH": ("modify resources in place", Severity.low),
    "PROPFIND": ("enumerate WebDAV resources and their properties", Severity.medium),
    "MKCOL": ("create WebDAV collections", Severity.medium),
}


def parse_allow(header: str) -> list[str]:
    return [m.strip().upper() for m in (header or "").split(",") if m.strip()]


def risky(methods: list[str]) -> list[str]:
    return [m for m in methods if m in RISKY_METHODS]


@register(EngineSpec(
    name="methods",
    label="Checking enabled HTTP methods",
    description="Dangerous methods left enabled (PUT, DELETE, TRACE, WebDAV verbs). "
                "Read-only: reported from OPTIONS and the Allow header, never by "
                "writing to the target.",
    phase="post_http",
    takes="urls",
    produces="findings",
    weight=3,
    limit=30,
    default_in=("standard", "deep"),
))
async def _methods(targets: list[str], ctx: dict) -> list[dict]:
    log = ctx.get("log")
    findings: list[dict] = []
    seen: set[str] = set()

    for origin in fetch.origins(targets)[:30]:
        host = (urlparse(origin).hostname or "").lower()
        if host in seen:
            continue
        seen.add(host)

        resp = await fetch.request(origin, method="OPTIONS", timeout=10, ctx=ctx)
        allowed = parse_allow(resp.header("allow") or resp.header("public"))
        bad = risky(allowed)

        # TRACE is worth confirming directly: many servers omit it from Allow
        # and still honour it.
        trace = await fetch.request(origin, method="TRACE", timeout=10, ctx=ctx)
        trace_on = trace.status == 200 and "TRACE " in (trace.body or "")[:200]
        if trace_on and "TRACE" not in bad:
            bad.append("TRACE")

        if not bad:
            continue

        detail = "\n".join(f"  {m} — could {RISKY_METHODS[m][0]}" for m in bad)
        worst = max((RISKY_METHODS[m][1] for m in bad),
                    key=lambda s: ["info", "low", "medium", "high", "critical"]
                    .index(s.value if hasattr(s, "value") else str(s)))

        findings.append({
            "engine": "methods", "rule_id": "dangerous-http-methods",
            "name": f"Risky HTTP methods enabled: {', '.join(bad)}",
            "severity": worst,
            "host": host, "url": origin, "matched_at": origin,
            "description": (
                f"The server accepts methods it almost certainly doesn't need:\n\n"
                f"{detail}\n\n"
                f"This was read from the server's own OPTIONS response"
                + (" and confirmed by a TRACE that echoed the request back."
                   if trace_on else ".")
                + " Nothing was written or deleted to establish it — if PUT or "
                  "DELETE are listed, verify them yourself on a path you control "
                  "before reporting them as exploitable, because some servers "
                  "advertise methods the application layer then rejects."),
            "evidence": (f"OPTIONS {origin} → HTTP {resp.status}\n"
                         f"Allow: {resp.header('allow') or '(absent)'}\n"
                         + (f"TRACE {origin} → HTTP {trace.status}, request echoed"
                            if trace_on else "")),
            "remediation": (
                "Restrict methods at the server, not in application code.\n\n"
                "  nginx:   if ($request_method !~ ^(GET|HEAD|POST)$) { return 405; }\n"
                "  Apache:  <LimitExcept GET HEAD POST> Require all denied </LimitExcept>\n"
                "           TraceEnable off\n"
                "  IIS:     remove the WebDAV module; disable TRACK\n\n"
                "If WebDAV verbs are present and you aren't intentionally running "
                "WebDAV, the module is enabled by default — remove it rather than "
                "filtering it."),
            "references": [
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods",
            ],
            "tags": ["misconfig", "methods"], "cve": [],
            "cwe": ["CWE-650", "CWE-16"], "cvss_score": None,
            "dedupe_key": make_dedupe_key("methods", "dangerous-http-methods",
                                          host, origin),
            "raw": {"allow": allowed, "risky": bad, "trace": trace_on},
        })

    if log:
        await log("info", f"[methods] {len(findings)} host(s) with risky methods",
                  "methods")
    return findings


# ---------------------------------------------------------------------------
# 403 bypass

BYPASS_HEADERS = [
    ({"X-Original-URL": "{path}"}, "X-Original-URL rewrite"),
    ({"X-Rewrite-URL": "{path}"}, "X-Rewrite-URL rewrite"),
    ({"X-Forwarded-For": "127.0.0.1"}, "trusted-source spoof"),
    ({"X-Forwarded-Host": "localhost"}, "forwarded-host spoof"),
    ({"X-Real-IP": "127.0.0.1"}, "real-IP spoof"),
    ({"X-Custom-IP-Authorization": "127.0.0.1"}, "IP authorisation header"),
    ({"X-Originating-IP": "127.0.0.1"}, "originating-IP spoof"),
    ({"X-Client-IP": "127.0.0.1"}, "client-IP spoof"),
    ({"Referer": "{origin}"}, "same-origin referer"),
]


def path_variants(path: str) -> list[tuple[str, str]]:
    """(variant_path, what_it_exploits). Read-only URL rewrites only."""
    clean = path if path.startswith("/") else "/" + path
    stripped = clean.rstrip("/")
    return [
        (stripped + "/", "trailing slash"),
        (stripped + "/.", "dot segment"),
        (stripped + "/..;/", "path parameter"),
        ("/" + stripped.lstrip("/"), "double slash") if not stripped.startswith("//")
        else ("//" + stripped.lstrip("/"), "double slash"),
        ("//" + stripped.lstrip("/"), "leading double slash"),
        (stripped + "%20", "trailing space"),
        (stripped + "%09", "trailing tab"),
        (stripped + "?", "empty query"),
        (stripped + "#", "fragment"),
        (stripped.upper(), "case change") if stripped != stripped.upper() else ("", ""),
        ("/%2e" + stripped, "encoded dot prefix"),
        (stripped + ".json", "extension append"),
    ]


@register(EngineSpec(
    name="authbypass",
    label="Testing 403 responses for bypasses",
    description="When a path returns 403, tries the path and header rewrites that "
                "make a proxy and an origin disagree about the request. A hit means "
                "the access control is enforced in the wrong place.",
    phase="post_http",
    takes="urls",
    produces="findings",
    weight=6,
    limit=40,
    default_in=("deep",),
))
async def _authbypass(targets: list[str], ctx: dict) -> list[dict]:
    log = ctx.get("log")
    findings: list[dict] = []
    blocked: list[str] = []

    # Find the forbidden ones first — there's nothing to bypass otherwise.
    async def probe(url: str):
        resp = await fetch.request(url, timeout=10, ctx=ctx)
        return url, resp.status, len(resp.body)

    states = await fetch.gather_limited([probe(u) for u in targets], limit=8)
    for state in states:
        if state and state[1] in (401, 403):
            blocked.append(state[0])

    if not blocked:
        if log:
            await log("info", "[authbypass] no 401/403 responses to test", "authbypass")
        return []

    async def bypass(url: str) -> dict | None:
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        host = (parsed.hostname or "").lower()
        path = parsed.path or "/"

        attempts: list[tuple[str, dict, str]] = []
        for variant, why in path_variants(path):
            if not variant:
                continue
            attempts.append((urlunparse(parsed._replace(path=variant)), {}, why))
        for template, why in BYPASS_HEADERS:
            hdrs = {k: v.replace("{path}", path).replace("{origin}", origin)
                    for k, v in template.items()}
            attempts.append((url, hdrs, why))

        for probe_url, hdrs, why in attempts:
            resp = await fetch.request(probe_url, headers=hdrs or None, timeout=10, ctx=ctx)
            if resp.status not in (200, 201, 206):
                continue
            # A 200 that's actually the site's error page isn't a bypass.
            if len(resp.body) < 200 and "not found" in resp.body.lower():
                continue

            shown = (f"{probe_url}" if not hdrs else
                     f"{url}  with  " + ", ".join(f"{k}: {v}" for k, v in hdrs.items()))
            return {
                "engine": "methods", "rule_id": "access-control-bypass",
                "name": f"403 bypassed via {why}",
                "severity": Severity.high,
                "host": host, "url": url, "matched_at": probe_url,
                "description": (
                    f"`{path}` returns 403, but the same content comes back with "
                    f"HTTP {resp.status} using a **{why}**.\n\n"
                    f"That tells you where the access control lives: something in "
                    f"front of the application is matching on the literal request "
                    f"string, and the application behind it resolves a different "
                    f"string to the same resource. Anything protected only by that "
                    f"front layer is reachable — this path, and every other path "
                    f"protected the same way.\n\n"
                    f"Confirm what the bypassed content actually is before "
                    f"reporting severity: a 200 on an empty directory index is not "
                    f"the same finding as a 200 on an admin console."),
                "evidence": (f"GET {url} → HTTP 403\n"
                             f"GET {shown} → HTTP {resp.status} "
                             f"({len(resp.body)} bytes)"),
                "remediation": (
                    "Enforce authorisation in the application, on the *resolved* "
                    "resource, after the framework has normalised the path — not in "
                    "a proxy rule matching a path string.\n\n"
                    "If a proxy must be part of it:\n"
                    "  • normalise the path (collapse `//`, resolve `.` and `..`, "
                    "decode once) before matching\n"
                    "  • strip `X-Original-URL`, `X-Rewrite-URL` and every "
                    "`X-Forwarded-*` header at the edge unless you set them yourself\n"
                    "  • never treat a client-supplied IP header as an "
                    "authentication signal\n\n"
                    "Then re-test every other path the same rule protects, because "
                    "this is a class of failure, not one path."),
                "references": [
                    "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
                    "https://portswigger.net/web-security/access-control",
                ],
                "tags": ["auth-bypass", "access-control"], "cve": [],
                "cwe": ["CWE-284", "CWE-425"], "cvss_score": 7.5,
                "dedupe_key": make_dedupe_key("methods", "access-control-bypass",
                                              host, url),
                "raw": {"technique": why, "probe": probe_url, "headers": hdrs},
            }
        return None

    results = await fetch.gather_limited([bypass(u) for u in blocked[:25]], limit=4)
    findings = [r for r in results if r]

    if log:
        await log("info",
                  f"[authbypass] {len(blocked)} forbidden path(s) tested, "
                  f"{len(findings)} bypassed", "authbypass")
    return findings
