"""Deterministic attack surface mapping.

Before the LLM gets involved, classify what was actually discovered. This is
the reliable half of the analysis: no model, no hallucination, just pattern
recognition over the URLs, parameters and status codes recon turned up.

The categories are chosen for what they imply about *manual* testing:

  auth            — where authentication logic lives; bypasses and reset flaws
  api             — machine endpoints, usually weaker access control than UI
  admin           — privilege boundaries worth probing
  upload          — file handling: type confusion, path traversal, stored XSS
  payment         — money movement; logic flaws here are the highest-value class
  user-object     — per-user resources: the natural home of IDORs
  export          — data egress paths, often missing per-record authorization
  webhook         — inbound callbacks, frequently unauthenticated
  redirect-ssrf   — parameters that take a URL; open redirect and SSRF
  idor-candidate  — identifiers in the path that can be incremented or swapped
  debug           — non-production surface exposed by accident

Each carries the reasoning for *why* it matters, so the UI can explain itself
without another model call.
"""

from __future__ import annotations

import re
from collections import defaultdict
from urllib.parse import parse_qs, urlparse

# category -> (path signals, why it matters, likely vuln classes)
CATEGORIES: dict[str, tuple[list[str], str, list[str]]] = {
    "auth": (
        ["login", "signin", "sign-in", "register", "signup", "sign-up", "password",
         "reset", "forgot", "oauth", "sso", "saml", "token", "session", "logout",
         "verify", "confirm", "2fa", "mfa", "otp", "auth"],
        "Authentication logic is where the highest-impact bypasses live. Password "
        "reset flows in particular are a classic source of account takeover — token "
        "predictability, host header injection, tokens that don't expire or aren't "
        "bound to the requesting user.",
        ["auth-bypass", "account-takeover", "business-logic"],
    ),
    "api": (
        ["/api/", "/v1/", "/v2/", "/v3/", "/rest/", "graphql", "/rpc", ".json",
         "/swagger", "/openapi"],
        "API endpoints routinely enforce weaker access control than the UI they "
        "serve, because developers assume only their own frontend calls them. "
        "Check whether every object-level permission the UI enforces is also "
        "enforced server-side.",
        ["broken-access-control", "IDOR", "mass-assignment"],
    ),
    "admin": (
        ["admin", "dashboard", "manage", "console", "backoffice", "internal",
         "staff", "moderator", "control", "panel"],
        "Privilege boundaries. Worth testing whether a normal account can reach "
        "these routes directly, whether the check is client-side only, and whether "
        "admin-only API endpoints verify role server-side.",
        ["broken-access-control", "privilege-escalation"],
    ),
    "upload": (
        ["upload", "attachment", "file", "import", "media", "avatar", "photo",
         "document", "attach"],
        "File handling. Look at what validation exists on type and extension, "
        "where files are stored and whether they're served from the same origin, "
        "and whether filenames are used in paths.",
        ["file-upload", "path-traversal", "stored-xss"],
    ),
    "payment": (
        ["pay", "checkout", "billing", "subscription", "order", "cart", "invoice",
         "refund", "coupon", "discount", "promo", "price", "plan", "upgrade"],
        "Money movement — the highest-value logic flaw category and the least "
        "detectable by scanners. Look for client-controlled prices or quantities, "
        "negative values, coupon stacking, race conditions on redemption, and "
        "state transitions that skip payment confirmation.",
        ["business-logic", "race-condition", "price-manipulation"],
    ),
    "user-object": (
        ["/user/", "/users/", "/account", "/profile", "/settings", "/me", "/member",
         "/customer", "/team", "/org", "/workspace", "/tenant"],
        "Per-user resources — the natural home of IDOR and tenant isolation "
        "failures. Compare responses for the same resource across two accounts you "
        "control; that's the single highest-yield manual test there is.",
        ["IDOR", "broken-access-control", "tenant-isolation"],
    ),
    "export": (
        ["export", "download", "report", "backup", "csv", "pdf", "xlsx", "print",
         "receipt", "statement"],
        "Data egress. These often authorize the action but not the specific "
        "records returned, so changing an ID or date range yields other users' data.",
        ["IDOR", "info-disclosure", "broken-access-control"],
    ),
    "webhook": (
        ["webhook", "callback", "hook", "notify", "event", "ipn"],
        "Inbound callbacks are frequently unauthenticated because they're assumed "
        "to be called only by a trusted third party. Check whether signature "
        "verification exists and whether it's actually enforced.",
        ["auth-bypass", "ssrf", "business-logic"],
    ),
    "debug": (
        ["debug", "/test", "/dev", "staging", "actuator", "phpinfo", "trace",
         "status", "health", "metrics", "config"],
        "Non-production surface exposed by accident. Often leaks configuration, "
        "internal hostnames, environment variables, or offers functionality that "
        "was never meant to face users.",
        ["info-disclosure", "misconfiguration"],
    ),
    "search": (
        ["search", "query", "filter", "lookup", "find", "autocomplete", "suggest"],
        "Search endpoints take user input into a backend query. Beyond injection, "
        "check whether results respect per-user visibility — search is a common way "
        "to enumerate records you shouldn't see.",
        ["injection", "info-disclosure", "IDOR"],
    ),
}

# Parameter names that deserve a second look, and why.
INTERESTING_PARAMS: dict[str, tuple[str, str]] = {
    # SSRF / redirect
    "url": ("redirect-ssrf", "takes a URL — test for SSRF and open redirect"),
    "uri": ("redirect-ssrf", "takes a URI"),
    "link": ("redirect-ssrf", "takes a link"),
    "redirect": ("redirect-ssrf", "controls post-action destination"),
    "redirect_uri": ("redirect-ssrf", "OAuth redirect — check allowlist strictness"),
    "next": ("redirect-ssrf", "controls destination after an action"),
    "return": ("redirect-ssrf", "return destination"),
    "returnurl": ("redirect-ssrf", "return destination"),
    "callback": ("redirect-ssrf", "callback destination"),
    "continue": ("redirect-ssrf", "continuation destination"),
    "dest": ("redirect-ssrf", "destination parameter"),
    "target": ("redirect-ssrf", "target parameter"),
    "fetch": ("redirect-ssrf", "server-side fetch — prime SSRF candidate"),
    "proxy": ("redirect-ssrf", "proxying behaviour"),
    "image": ("redirect-ssrf", "remote image fetch — SSRF candidate"),
    "domain": ("redirect-ssrf", "host parameter"),
    # IDOR
    "id": ("idor-candidate", "object identifier — compare across two accounts"),
    "uid": ("idor-candidate", "user identifier"),
    "user_id": ("idor-candidate", "user identifier"),
    "userid": ("idor-candidate", "user identifier"),
    "account": ("idor-candidate", "account identifier"),
    "account_id": ("idor-candidate", "account identifier"),
    "order_id": ("idor-candidate", "order identifier"),
    "invoice": ("idor-candidate", "invoice identifier"),
    "doc": ("idor-candidate", "document identifier"),
    "file_id": ("idor-candidate", "file identifier"),
    "key": ("idor-candidate", "record key"),
    "ref": ("idor-candidate", "record reference"),
    # injection-adjacent
    "q": ("search", "search input"),
    "query": ("search", "search input"),
    "search": ("search", "search input"),
    "sort": ("injection", "often interpolated into a query — check ORDER BY handling"),
    "order": ("injection", "often interpolated into a query"),
    "filter": ("injection", "often interpolated into a query"),
    "where": ("injection", "often interpolated into a query"),
    "table": ("injection", "database object name in user input"),
    "column": ("injection", "database object name in user input"),
    # file
    "file": ("path-traversal", "filename in user input — check traversal handling"),
    "path": ("path-traversal", "path in user input"),
    "template": ("path-traversal", "template name — check SSTI and traversal"),
    "page": ("path-traversal", "page/include name"),
    "lang": ("path-traversal", "locale file selection"),
    "download": ("path-traversal", "download target"),
    # privilege
    "role": ("mass-assignment", "role in user input — check server-side enforcement"),
    "admin": ("mass-assignment", "privilege flag in user input"),
    "is_admin": ("mass-assignment", "privilege flag in user input"),
    "debug": ("misconfiguration", "debug toggle exposed to users"),
    "test": ("misconfiguration", "test toggle exposed to users"),
}

_NUMERIC_SEG = re.compile(r"/\d{1,12}(?=/|$)")
_UUID_SEG = re.compile(r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
_HASH_SEG = re.compile(r"/[0-9a-f]{16,}(?=/|$)", re.I)


def classify_url(url: str) -> list[str]:
    """Every category a URL belongs to (they overlap deliberately)."""
    low = url.lower()
    path = urlparse(low).path or "/"
    hits = []
    for name, (signals, _why, _classes) in CATEGORIES.items():
        if any(sig in path for sig in signals):
            hits.append(name)
    return hits


def map_surface(assets: list[dict], endpoints: list[str] | None = None) -> dict:
    """Build the full attack surface map from recon output."""
    urls: list[str] = []
    status_by_url: dict[str, int | None] = {}

    for a in assets:
        u = a.get("url") or ""
        if u:
            urls.append(u)
            status_by_url[u] = a.get("status_code")
    urls += [e for e in (endpoints or []) if e]
    urls = sorted(set(urls))

    categorised: dict[str, list[str]] = defaultdict(list)
    for u in urls:
        for cat in classify_url(u):
            categorised[cat].append(u)

    # ---- parameter inventory ----
    params: dict[str, dict] = {}
    for u in urls:
        qs = parse_qs(urlparse(u).query, keep_blank_values=True)
        for name in qs:
            key = name.lower()
            note = INTERESTING_PARAMS.get(key)
            entry = params.setdefault(key, {
                "name": name, "seen_on": [], "count": 0,
                "class": note[0] if note else None,
                "why": note[1] if note else "",
            })
            entry["count"] += 1
            if len(entry["seen_on"]) < 5:
                entry["seen_on"].append(u)

    # ---- IDOR candidates: identifiers embedded in the path ----
    idor: list[dict] = []
    for u in urls:
        path = urlparse(u).path or ""
        kind = None
        if _NUMERIC_SEG.search(path):
            kind = "sequential numeric ID"
        elif _UUID_SEG.search(path):
            kind = "UUID"
        elif _HASH_SEG.search(path):
            kind = "opaque hash"
        if kind:
            idor.append({
                "url": u,
                "kind": kind,
                "why": ("Sequential IDs can simply be incremented to reach other users' "
                        "records." if kind.startswith("sequential") else
                        "Not guessable, but still worth testing: capture a real identifier "
                        "from one account and request it while authenticated as another."),
            })

    # ---- authentication boundaries ----
    boundaries = [
        {"url": u, "status": status_by_url.get(u)}
        for u in urls if status_by_url.get(u) in (401, 403)
    ]

    # ---- assemble ----
    out_categories = []
    for name, found in sorted(categorised.items(), key=lambda kv: -len(kv[1])):
        _signals, why, classes = CATEGORIES[name]
        out_categories.append({
            "category": name,
            "why": why,
            "vuln_classes": classes,
            "count": len(found),
            "urls": sorted(set(found))[:25],
        })

    interesting = sorted(
        (p for p in params.values() if p["class"]),
        key=lambda p: -p["count"],
    )
    other = sorted(
        (p for p in params.values() if not p["class"]),
        key=lambda p: -p["count"],
    )

    return {
        "total_urls": len(urls),
        "categories": out_categories,
        "params_interesting": interesting[:40],
        "params_other": [p["name"] for p in other][:60],
        "idor_candidates": idor[:30],
        "auth_boundaries": boundaries[:30],
    }


def priority_hint(surface: dict) -> list[str]:
    """Short, deterministic observations to seed the model — and to stand alone
    if it's unavailable."""
    notes = []
    cats = {c["category"]: c["count"] for c in surface.get("categories", [])}

    if cats.get("payment"):
        notes.append(f"{cats['payment']} payment-related endpoint(s) — highest-value "
                     f"logic flaw territory")
    if cats.get("api") and cats.get("user-object"):
        notes.append("API endpoints handling per-user objects — prime IDOR ground; "
                     "compare responses across two accounts")
    if cats.get("auth"):
        notes.append(f"{cats['auth']} authentication endpoint(s) — check reset token "
                     f"binding and expiry")
    if surface.get("auth_boundaries"):
        notes.append(f"{len(surface['auth_boundaries'])} endpoint(s) returning 401/403 — "
                     f"these are the permission boundaries worth pushing on")
    if cats.get("upload"):
        notes.append("File upload present — check type validation and where files are served from")
    ssrf = [p for p in surface.get("params_interesting", []) if p["class"] == "redirect-ssrf"]
    if ssrf:
        notes.append(f"{len(ssrf)} URL-taking parameter(s) ({', '.join(p['name'] for p in ssrf[:4])}) "
                     f"— SSRF and open redirect candidates")
    if surface.get("idor_candidates"):
        seq = [i for i in surface["idor_candidates"] if i["kind"].startswith("sequential")]
        if seq:
            notes.append(f"{len(seq)} URL(s) with sequential numeric IDs — trivially enumerable")
    if cats.get("debug"):
        notes.append("Debug or non-production surface reachable")
    return notes
