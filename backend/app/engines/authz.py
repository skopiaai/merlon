"""Broken access control.

This is the bug class that pays most and the one automated scanners almost
never find, for a structural reason: a scanner with one session can see what
that session can reach, but "should this session be able to reach it?" is a
question about the application's intent, and the intent isn't in the response.

The way around that is comparison. Ask the same question as different callers
and the difference between the answers *is* the intent, made observable:

  **Missing authentication.** Fetch an endpoint with the session, then again
  without it. If the logged-out request returns the same content, the endpoint
  never required a session — it was simply unlinked. That's A01 Broken Access
  Control, and it's usually reachable by anyone who knows the URL.

  **Horizontal privilege escalation (IDOR).** Fetch a resource as account A,
  then request the identical URL as account B. If B receives A's content, one
  user can read another's data. This needs two logged-in accounts, which is why
  it's absent from every single-session tool.

Both comparisons are only sound if the session was verified first, and only
report when the response is substantive. A 200 carrying a login page is not
access; a scanner that counts it as access produces confident nonsense, and
this class of false positive is particularly damaging because "IDOR" gets a
triage team's attention and then wastes it.

Nothing is modified. Every request is a GET, and the engine reads resources
that the configured accounts already have access to.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlparse

from ..models import Severity
from ..normalize import make_dedupe_key
from . import fetch
from .registry import EngineSpec, register

# Pages that answer 200 while meaning "no". Length alone can't distinguish
# these from real content, because a login page is a perfectly substantial
# document.
LOGIN_MARKERS = re.compile(
    r"<input[^>]+type=[\"']password[\"']|sign\s?in|log\s?in to|please log in|"
    r"authentication required|session expired|your session has|access denied|"
    r"not authori[sz]ed|forbidden|permission denied|csrf", re.I)

# URL shapes that address a specific record. An endpoint without one of these
# is usually a page rather than a resource, and comparing pages across accounts
# produces noise — two users legitimately see the same dashboard.
IDENTIFIER = re.compile(
    r"/\d{2,}(?:/|$)"                     # /orders/1042
    r"|/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"   # uuid
    r"|/[0-9a-f]{24,64}(?:/|$)",          # object id / hash
    re.I)

ID_PARAMS = {"id", "uid", "user", "user_id", "userid", "account", "account_id",
             "customer", "customer_id", "order", "order_id", "invoice",
             "invoice_id", "doc", "document", "file", "file_id", "record",
             "profile", "member", "team", "org", "org_id", "project",
             "project_id", "ticket", "case", "ref", "key", "token", "num"}


def addresses_a_record(url: str) -> bool:
    """Does this URL identify a specific resource rather than a page?"""
    parsed = urlparse(url)
    if IDENTIFIER.search(parsed.path or ""):
        return True
    for key, value in parse_qsl(parsed.query):
        if key.lower() in ID_PARAMS and value:
            return True
    return False


def is_real_content(status: int, body: str, min_length: int = 200) -> bool:
    """Is this an answer, or a polite refusal wearing a 200?

    The single most important function in this file. Every false positive this
    engine could produce comes from treating a login page, an error page or an
    empty shell as successful access.
    """
    if status not in (200, 201, 206):
        return False
    if len(body or "") < min_length:
        return False
    head = body[:4000]
    if LOGIN_MARKERS.search(head):
        return False
    return True


def same_resource(a: str, b: str, tolerance: float = 0.02) -> bool:
    """Are these two responses the same underlying resource?

    Compared by length within a tolerance rather than byte equality: the same
    page rendered for two sessions differs by the CSRF token, the greeting and
    the timestamp, so byte equality would miss every real case. The tolerance
    is deliberately tight — a genuinely different record almost always differs
    by more than two per cent.
    """
    if not a or not b:
        return False
    longest = max(len(a), len(b))
    return abs(len(a) - len(b)) <= max(64, longest * tolerance)


def _base(rule: str, name: str, severity: Severity, url: str,
          description: str, evidence: str, remediation: str,
          cwe: list[str], cvss: float | None) -> dict:
    host = (urlparse(url).hostname or "").lower()
    return {
        "engine": "authz", "rule_id": rule, "name": name, "severity": severity,
        "host": host, "url": url, "matched_at": url,
        "description": description, "evidence": evidence,
        "remediation": remediation,
        "references": [
            "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
            "https://portswigger.net/web-security/access-control/idor",
        ],
        "tags": ["access-control", "auth-bypass", "authenticated"],
        "cve": [], "cwe": cwe, "cvss_score": cvss,
        "dedupe_key": make_dedupe_key("authz", rule, host, url),
        "raw": {},
    }


@register(EngineSpec(
    name="authz",
    label="Testing access control across sessions",
    description="Compares what each configured account can reach. Finds endpoints "
                "that need no session at all, and — with a second account — data "
                "one user can read that belongs to another. Requires credentials; "
                "skipped without them.",
    phase="post_http",
    takes="urls",
    produces="findings",
    weight=8,
    limit=80,
    default_in=("standard", "deep"),
))
async def _engine(targets: list[str], ctx: dict) -> list[dict]:
    log = ctx.get("log")
    auth_headers = ctx.get("auth_headers") or {}
    identities = ctx.get("identities") or []

    if not auth_headers:
        if log:
            await log("info",
                      "[authz] no credentials configured — access control cannot be "
                      "tested. This is the largest coverage gap in an unauthenticated "
                      "scan: paste a session cookie under Credentials to close it.",
                      "authz")
        return []

    findings: list[dict] = []
    checked = 0

    async def examine(url: str) -> list[dict]:
        nonlocal checked
        out: list[dict] = []

        # What the primary account sees. If it isn't real content, there's
        # nothing here to be protecting.
        owner = await fetch.request(url, ctx=ctx, timeout=15)
        if not is_real_content(owner.status, owner.body):
            return out
        checked += 1

        # --- 1. is a session required at all? ---
        anon = await fetch.request(url, ctx=ctx, authenticated=False, timeout=15)
        if is_real_content(anon.status, anon.body) and \
                same_resource(owner.body, anon.body):
            out.append(_base(
                "missing-authentication",
                "Authenticated content served without a session",
                Severity.high, url,
                f"`{urlparse(url).path}` returns the same content whether or not "
                f"a session is presented.\n\n"
                f"This endpoint is reachable by anyone who knows the URL. It was "
                f"found while scanning as a logged-in user, which means it's part "
                f"of the authenticated application — it just doesn't check. That "
                f"pattern usually comes from authorization being enforced in the "
                f"user interface (the link isn't shown to logged-out visitors) "
                f"rather than at the endpoint.\n\n"
                f"The response is {len(anon.body)} bytes and is not a login page, "
                f"so this is content being served rather than a redirect being "
                f"followed.",
                f"GET {url}\n"
                f"  with session:    HTTP {owner.status}, {len(owner.body)} bytes\n"
                f"  without session: HTTP {anon.status}, {len(anon.body)} bytes\n"
                f"  → same resource",
                "Enforce authorization server-side, in the handler, on every "
                "request — not in the template that decides whether to show a "
                "link.\n\n"
                "Deny by default: require an authenticated principal for every "
                "route unless it is explicitly marked public, so a new endpoint is "
                "protected by omission rather than exposed by it. Framework "
                "middleware (`@login_required`, a global auth filter, route guards) "
                "gets you that; a per-handler check does not, because the handler "
                "someone forgets is the one that leaks.\n\n"
                "Then audit sibling routes — an endpoint missing its check is "
                "rarely the only one.",
                ["CWE-306", "CWE-425"], 7.5))

        # --- 2. can another account read it? ---
        for identity in identities:
            other = await fetch.request(url, ctx=ctx, identity=identity, timeout=15)
            if not is_real_content(other.status, other.body):
                continue
            if not same_resource(owner.body, other.body):
                continue

            # Two accounts seeing an identical dashboard is correct behaviour.
            # Two accounts seeing an identical *record* is not.
            if not addresses_a_record(url):
                continue

            name = identity.get("name", "second account")
            role = identity.get("role") or "another user"
            out.append(_base(
                "idor-cross-account",
                f"Record readable by an unrelated account ({name})",
                Severity.critical, url,
                f"`{url}` returns the same record to the primary account and to "
                f"**{name}** ({role}). The URL addresses a specific resource, and "
                f"a second, unrelated account can read it.\n\n"
                f"That is insecure direct object reference: the application is "
                f"using the identifier in the URL to *find* the record, but not to "
                f"check that the caller is entitled to it. Anyone with an account "
                f"can enumerate identifiers and read every record of this type — "
                f"which for most applications means every customer's data.\n\n"
                f"**Verify before reporting.** Confirm the two accounts genuinely "
                f"have no relationship (not the same organisation, not shared "
                f"access), and open the response to check it contains the first "
                f"account's data rather than a generic page that happens to be the "
                f"same size. This finding is worth a lot when it's real and costs "
                f"you credibility with a triage team when it isn't.",
                f"GET {url}\n"
                f"  as primary account: HTTP {owner.status}, {len(owner.body)} bytes\n"
                f"  as {name}:          HTTP {other.status}, {len(other.body)} bytes\n"
                f"  → identical resource returned to both",
                "Authorize on the object, not on the route. Every lookup that "
                "takes an identifier from the request must be constrained by the "
                "caller's identity in the same query:\n\n"
                "  # wrong — finds the record, then trusts the URL\n"
                "  order = Order.get(request.args['id'])\n\n"
                "  # right — a record the caller doesn't own is simply not found\n"
                "  order = Order.get(id=request.args['id'], owner=current_user)\n\n"
                "Doing it in the query rather than as a check afterwards means the "
                "failure mode is a 404, and means nobody can forget the check on a "
                "new endpoint that reuses the same repository method.\n\n"
                "Sequential integer identifiers make enumeration trivial; UUIDs "
                "raise the cost but are not the fix — an unguessable identifier is "
                "still a valid identifier once it leaks. Fix the authorization, "
                "then consider the identifiers.\n\n"
                "Add an automated test that fetches one account's resource as "
                "another account and asserts 403/404. This bug class returns "
                "whenever someone adds an endpoint.",
                ["CWE-639", "CWE-284", "CWE-863"], 8.1))
            break   # one identity is enough to prove it

        return out

    # Records first: they're where the valuable finding is, and the cap should
    # be spent on them rather than on the marketing pages that sort first
    # alphabetically.
    ordered = sorted(set(targets), key=lambda u: (not addresses_a_record(u), u))

    results = await fetch.gather_limited(
        [examine(u) for u in ordered[:80]], limit=4)
    for group in results:
        findings += group or []

    if log:
        idor = [f for f in findings if f["rule_id"] == "idor-cross-account"]
        await log("info",
                  f"[authz] {checked} authenticated endpoint(s) compared across "
                  f"{1 + len(identities)} session(s) → {len(findings)} issue(s)",
                  "authz")
        if not identities:
            await log("info",
                      "[authz] only one account configured, so cross-account access "
                      "was not tested. Add a second identity under Credentials — it "
                      "is the only way to detect IDOR, and no single-session scanner "
                      "can do it.", "authz")
        if idor:
            await log("error",
                      f"[authz] {len(idor)} record(s) readable by an unrelated "
                      f"account — verify the two accounts are genuinely unrelated, "
                      f"then report as IDOR", "authz")
    return findings
