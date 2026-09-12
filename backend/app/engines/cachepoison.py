"""Web cache poisoning and web cache deception.

Two different bugs that both come from the same mistake: a cache and an
application disagreeing about what identifies a response.

**Cache deception.** A cache is usually told "static file extensions are
public, store them". An application usually routes `/account/anything.css` to
the `/account` handler and returns the logged-in user's page. Put those two
rules together and the victim's private page gets stored under a URL the
attacker chose — so the attacker fetches it and reads their data. No XSS, no
CSRF, no interaction beyond getting the victim to load one link.

**Cache poisoning.** Caches key an entry on the URL and a few headers. Anything
outside that key is *unkeyed*, and if an unkeyed header still changes the
response — `X-Forwarded-Host` rewriting an absolute URL in the page, say — then
one request can overwrite the cached copy that everyone else is served.

Why this engine is careful
--------------------------
Poisoning a real cache hurts real users, and a scanner that does it by accident
is worse than the bug. So every probe here appends a unique cache-buster query
parameter. If the probe *does* land in a shared cache, it lands under a URL
that contains a random token nobody else will ever request. The evidence is
identical; the blast radius is us.

Canary values use the reserved `.invalid` TLD (RFC 2606), which can never
resolve, so a reflected value cannot become a live link to a third party.
"""

from __future__ import annotations

import secrets
from urllib.parse import urlparse, urlunparse

from ..models import Severity
from ..normalize import make_dedupe_key
from . import fetch
from .registry import EngineSpec, register

CANARY_HOST = "cache-probe.invalid"

# Headers that a front end commonly reads but a cache commonly does not key on.
# Each maps to what a reflection of it would mean.
POISON_HEADERS: list[tuple[str, str, str]] = [
    ("X-Forwarded-Host", CANARY_HOST, "absolute URLs are built from it"),
    ("X-Forwarded-Server", CANARY_HOST, "the backend trusts it as the host"),
    ("X-Host", CANARY_HOST, "a legacy host override is honoured"),
    ("X-Original-URL", f"/{CANARY_HOST}", "the routed path can be overridden"),
    ("X-Rewrite-URL", f"/{CANARY_HOST}", "the routed path can be overridden"),
]

# Suffixes that many frameworks ignore when routing but many caches treat as
# "this is a static file, cache it".
DECEPTION_SUFFIXES = [
    ("/{tok}.css", "path-suffix"),
    ("/{tok}.js", "path-suffix"),
    ("%0A{tok}.css", "encoded-newline"),
    (";{tok}.css", "path-parameter"),
    ("%3F{tok}.css", "encoded-question-mark"),
    ("%23{tok}.css", "encoded-fragment"),
]

# Header values that say a shared cache stored, or would store, this response.
_HIT_HEADERS = ("x-cache", "cf-cache-status", "x-cache-status",
                "x-drupal-cache", "x-varnish-cache", "cdn-cache",
                "x-served-by", "fastly-debug-digest")


def cache_buster() -> str:
    return secrets.token_hex(8)


def with_buster(url: str, token: str) -> str:
    """Add a unique query parameter so any cached entry is ours alone."""
    parts = urlparse(url)
    query = f"{parts.query}&cb={token}" if parts.query else f"cb={token}"
    return urlunparse(parts._replace(query=query))


def deception_urls(url: str, token: str) -> list[tuple[str, str]]:
    """(probe_url, what_it_tests). The buster rides in the query string."""
    parts = urlparse(url)
    base = urlunparse(parts._replace(query="", fragment=""))
    out = []
    for template, kind in DECEPTION_SUFFIXES:
        probe = base.rstrip("/") + template.format(tok=token)
        out.append((with_buster(probe, token), kind))
    return out


def cacheability(headers: dict[str, str]) -> tuple[bool, str]:
    """Would a shared cache store this? Returns (verdict, why).

    Read conservatively: an explicit `no-store`/`private` is believed, and
    anything else needs positive evidence — a hit header, an Age, or a
    public/max-age directive. Guessing "probably cacheable" from silence is how
    this check turns into noise.
    """
    cc = (headers.get("cache-control") or "").lower()
    if "no-store" in cc or "private" in cc:
        return False, f"Cache-Control: {cc}"

    for name in _HIT_HEADERS:
        value = (headers.get(name) or "").lower()
        if "hit" in value:
            return True, f"{name}: {headers.get(name)}"

    age = (headers.get("age") or "").strip()
    if age.isdigit() and int(age) > 0:
        return True, f"Age: {age} (served from a cache)"

    if "public" in cc:
        return True, f"Cache-Control: {cc}"

    if "max-age" in cc:
        # max-age=0 is not storage.
        for part in cc.split(","):
            part = part.strip()
            if part.startswith("max-age=") and part[8:].strip().isdigit():
                if int(part[8:].strip()) > 0:
                    return True, f"Cache-Control: {cc}"
    return False, ""


def looks_like_same_page(base: str, probe: str) -> bool:
    """Did the odd URL return the *original* page rather than a 404?

    Compares a sample from the middle of the baseline body rather than the
    whole thing: headers, nonces and CSRF tokens differ between two responses
    to the same page, so an equality test would never fire.
    """
    if not base or not probe:
        return False
    if abs(len(base) - len(probe)) > max(len(base) * 0.5, 400):
        return False
    sample = base[len(base) // 3:][:160].strip()
    return len(sample) >= 40 and sample in probe


def private_markers(body: str) -> list[str]:
    """Words suggesting the page is user-specific and worth stealing."""
    lowered = (body or "").lower()
    hits = [w for w in ("log out", "logout", "sign out", "my account",
                        "dashboard", "csrf", "authenticity_token",
                        "your profile", "account settings")
            if w in lowered]
    return hits[:4]


def analyse_reflection(header: str, value: str, why: str,
                       resp_headers: dict[str, str], body: str) -> dict | None:
    """Judge one unkeyed-header probe. Pure, so the logic is testable offline."""
    where = []
    if value.lower() in (body or "").lower():
        where.append("response body")
    for name in ("location", "content-location", "link", "refresh"):
        if value.lower() in (resp_headers.get(name) or "").lower():
            where.append(f"{name} header")
    if not where:
        return None

    cacheable, evidence = cacheability(resp_headers)
    if not cacheable:
        return None

    return {
        "rule": "cache-poison-unkeyed-header",
        "severity": Severity.high,
        "detail": (
            f"`{header}: {value}` was reflected into the {' and '.join(where)}, "
            f"and the response is stored by a shared cache ({evidence}). The "
            f"header is not part of the cache key, so a single request carrying "
            f"it can overwrite the copy served to everyone else — {why}.\n\n"
            f"Reflected into an absolute URL for a script or stylesheet, this "
            f"becomes stored XSS against every visitor until the entry expires."),
        "cache_evidence": evidence,
        "where": ", ".join(where),
    }


@register(EngineSpec(
    name="cachepoison",
    label="Testing cache behaviour",
    description="Web cache poisoning and cache deception — unkeyed headers that "
                "change a cached response, and static-looking suffixes that make "
                "a cache store a logged-in user's private page under a URL an "
                "attacker picks. Every probe is cache-busted so nothing real is "
                "poisoned.",
    phase="post_http",
    takes="urls",
    produces="findings",
    weight=5,
    limit=25,
    skip_cdn=False,   # a CDN edge is exactly where this bug lives
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
        out: list[dict] = []
        token = cache_buster()

        base = await fetch.request(with_buster(url, token), timeout=12, ctx=ctx)
        if not base.ok or base.status != 200:
            return []

        # ---- 1. unkeyed header reflection -> poisoning ----
        for header, value, why in POISON_HEADERS:
            probe_token = cache_buster()
            resp = await fetch.request(with_buster(url, probe_token),
                                       headers={header: value},
                                       timeout=12, ctx=ctx)
            if not resp.ok:
                continue
            issue = analyse_reflection(header, value, why, resp.headers, resp.body)
            if not issue:
                continue
            key = f"{host}|{issue['rule']}|{header}"
            if key in seen:
                continue
            seen.add(key)
            out.append({
                "engine": "cachepoison", "rule_id": issue["rule"],
                "name": f"Cache poisoning via unkeyed {header}",
                "severity": issue["severity"],
                "host": host, "url": url, "matched_at": url,
                "description": issue["detail"],
                "evidence": (f"Request:  {header}: {value}\n"
                             f"          (cache-busted with ?cb={probe_token})\n"
                             f"Response: HTTP {resp.status}\n"
                             f"          reflected in {issue['where']}\n"
                             f"          {issue['cache_evidence']}"),
                "remediation": (
                    "Either stop reading the header, or add it to the cache key.\n\n"
                    "  • If the application genuinely needs X-Forwarded-Host, add "
                    "`Vary: X-Forwarded-Host` so the cache stores one entry per "
                    "value.\n"
                    "  • Better, strip these headers at the edge before they reach "
                    "the origin, and build absolute URLs from configuration rather "
                    "than from a request header.\n"
                    "  • Mark anything user-specific `Cache-Control: private, no-store`."),
                "references": [
                    "https://portswigger.net/research/practical-web-cache-poisoning",
                    "https://owasp.org/www-community/attacks/Cache_Poisoning",
                ],
                "tags": ["cache", "poisoning", "unkeyed-input"],
                "cve": [], "cwe": ["CWE-444", "CWE-349"], "cvss_score": None,
                "dedupe_key": make_dedupe_key("cachepoison", issue["rule"],
                                              host, f"{url}|{header}"),
                "raw": {"header": header, "value": value,
                        "cache_evidence": issue["cache_evidence"]},
            })

        # ---- 2. static-suffix routing -> cache deception ----
        markers = private_markers(base.body)
        for probe_url, kind in deception_urls(url, token):
            resp = await fetch.request(probe_url, timeout=12, ctx=ctx)
            if not resp.ok or resp.status != 200:
                continue
            if not looks_like_same_page(base.body, resp.body):
                continue
            cacheable, evidence = cacheability(resp.headers)
            if not cacheable:
                continue

            rule = "cache-deception"
            key = f"{host}|{rule}|{kind}"
            if key in seen:
                continue
            seen.add(key)
            severity = Severity.high if markers else Severity.medium
            out.append({
                "engine": "cachepoison", "rule_id": rule,
                "name": "Web cache deception",
                "severity": severity,
                "host": host, "url": url, "matched_at": probe_url,
                "description": (
                    f"`{probe_url}` returned the same page as `{url}` and the "
                    f"response is stored by a shared cache ({evidence}). The "
                    f"application ignored the `{kind}` suffix when routing; the "
                    f"cache did not, and treated the result as a static file.\n\n"
                    + (f"The page contains {', '.join(markers)}, so it is "
                       f"user-specific — an attacker who persuades a logged-in "
                       f"victim to load this URL can then fetch the cached copy "
                       f"and read that user's data."
                       if markers else
                       "No session markers were visible on this response, so "
                       "confirm against an authenticated page before reporting: "
                       "the impact depends entirely on whether the cached copy "
                       "contains someone's private content.")),
                "evidence": (f"Original: {url} -> HTTP {base.status}\n"
                             f"Probe:    {probe_url} -> HTTP {resp.status}\n"
                             f"          same body as the original\n"
                             f"          {evidence}"
                             + (f"\nSession markers: {', '.join(markers)}"
                                if markers else "")),
                "remediation": (
                    "Make the cache and the application agree on what a URL is.\n\n"
                    "  • Cache on the response's Content-Type, not on the URL's "
                    "apparent extension.\n"
                    "  • Return 404 for paths the route does not actually define, "
                    "rather than ignoring trailing segments.\n"
                    "  • Send `Cache-Control: private, no-store` on every "
                    "authenticated response, which makes this unexploitable even "
                    "if the routing stays loose."),
                "references": [
                    "https://portswigger.net/web-security/web-cache-deception",
                    "https://owasp.org/www-project-web-security-testing-guide/",
                ],
                "tags": ["cache", "deception", "information-disclosure"],
                "cve": [], "cwe": ["CWE-524", "CWE-525"], "cvss_score": None,
                "dedupe_key": make_dedupe_key("cachepoison", rule, host,
                                              f"{url}|{kind}"),
                "raw": {"probe": probe_url, "kind": kind,
                        "cache_evidence": evidence, "markers": markers},
            })
        return out

    results = await fetch.gather_limited([check(u) for u in targets], limit=5)
    for group in results:
        findings += group or []

    if log:
        await log("info", f"[cachepoison] {len(findings)} cache issue(s) across "
                          f"{len(targets)} endpoint(s)", "cachepoison")
    return findings
