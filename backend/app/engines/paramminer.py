"""Hidden parameter discovery.

Applications accept parameters that appear nowhere in their HTML, their
JavaScript or their documentation: debug switches, admin overrides, internal
flags, arguments left behind by a removed feature. They are unlinked, so a
crawler cannot find them, and they are undocumented, so nobody has reviewed
them — which is exactly why they are worth finding. `?debug=1` and
`?admin=true` are real bugs that get paid.

Hidden parameters are also the raw material for the bug classes that pay most.
IDOR needs a parameter carrying an identifier. SSRF needs a parameter carrying
a URL. Neither is findable until you know the parameter exists.

The method is differential: establish how the page responds normally, then send
batches of candidate names with a distinctive value and watch for a response
that changes — the value reflected in the body, a different length, a different
status. A batch that changes is bisected to find which name caused it, so
several hundred candidates cost tens of requests rather than hundreds.

This is the only engine here that sends a meaningful number of requests, so it
is deep-scan only, batched, and capped.
"""

from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from .. import memory
from ..models import Severity
from ..normalize import make_dedupe_key
from . import fetch
from .registry import EngineSpec, register

CANARY = "z9q4x7t2"

# Ordered by what tends to be interesting rather than alphabetically: a capped
# run should spend its budget on the names that matter.
CANDIDATES = [
    # switches that change behaviour
    "debug", "test", "admin", "is_admin", "isAdmin", "role", "isDebug",
    "development", "dev", "verbose", "trace", "profile", "preview", "draft",
    "edit", "override", "force", "bypass", "internal", "staff", "superuser",
    "impersonate", "sudo", "as_user", "user_id", "userId", "uid", "account",
    "account_id", "customer_id", "org", "org_id", "tenant", "tenant_id",
    # things that take a location — SSRF material
    "url", "uri", "src", "source", "dest", "target", "path", "file",
    "filename", "template", "page", "document", "doc", "load", "fetch",
    "callback", "webhook", "feed", "proxy", "image", "img", "avatar",
    "download", "export", "import", "data", "input", "content",
    # output and format control
    "format", "output", "type", "mode", "view", "render", "raw", "json",
    "xml", "csv", "pretty", "callback_fn", "jsonp",
    # access and filtering
    "filter", "search", "q", "query", "sort", "order", "order_by", "group_by",
    "limit", "offset", "page_size", "per_page", "count", "fields", "include",
    "expand", "select", "where", "show_all", "all", "deleted", "archived",
    "hidden", "private", "public", "status", "state", "active", "enabled",
    "disabled", "visible", "approved", "verified", "confirmed",
    # identity and tokens
    "token", "key", "api_key", "apikey", "auth", "authorization", "session",
    "sid", "sess", "secret", "password", "passwd", "code", "otp", "hash",
    "signature", "sig", "nonce", "state_token", "csrf", "csrf_token",
    # miscellaneous but historically productive
    "cmd", "exec", "run", "action", "op", "method", "func", "function",
    "class", "module", "plugin", "theme", "lang", "locale", "country",
    "currency", "redirect_to", "next", "continue", "ref", "utm_debug",
    "cache", "nocache", "refresh", "reload", "version", "v", "id",
]

BATCH = 24


def chunk(items: list[str], size: int = BATCH) -> list[list[str]]:
    return [items[i:i + size] for i in range(0, len(items), size)]


def with_params(url: str, names: list[str], value: str = CANARY) -> str:
    parsed = urlparse(url)
    params = parse_qsl(parsed.query, keep_blank_values=True)
    params += [(n, value) for n in names]
    return urlunparse(parsed._replace(query=urlencode(params)))


def differs(base_status: int, base_len: int, base_body: str,
            status: int, length: int, body: str, canary: str = CANARY) -> str:
    """How this response differs from the baseline. "" means it doesn't.

    Reflection is the strong signal and is checked first. Length is the weak
    one and needs a threshold, because pages carry timestamps, CSRF tokens and
    rotating banners that shift the byte count on every request for reasons
    that have nothing to do with the parameter.
    """
    if canary in body and canary not in base_body:
        return "reflected"
    if status != base_status:
        return "status"
    if base_len and abs(length - base_len) > max(48, base_len * 0.03):
        return "length"
    return ""


@register(EngineSpec(
    name="paramminer",
    label="Mining for hidden parameters",
    description="Finds query parameters the application accepts but never links: "
                "debug switches, admin overrides, and the ID- and URL-carrying "
                "parameters that IDOR and SSRF testing depend on. Differential and "
                "batched, then bisected.",
    phase="post_http",
    takes="urls",
    produces="findings",
    weight=9,
    limit=12,
    default_in=("deep",),
))
async def _engine(targets: list[str], ctx: dict) -> list[dict]:
    log = ctx.get("log")
    findings: list[dict] = []
    requests_sent = 0

    # Names that paid off on earlier scans go first, and a name learned from a
    # real finding is added if the built-in list never had it. Nothing is
    # dropped, so a capped run simply spends its budget where the evidence says
    # it should. Memory can never create a finding — it only decides what gets
    # guessed, and every guess still has to survive the same differential test.
    remembered = memory.recall_params()
    candidates = memory.prioritise(CANDIDATES, remembered)
    if remembered and log:
        await log("info",
                  f"[paramminer] trying {len(remembered)} name(s) remembered "
                  f"from earlier scans first", "paramminer")

    async def mine(url: str) -> list[dict]:
        nonlocal requests_sent
        host = (urlparse(url).hostname or "").lower()

        # Baseline, twice — a page that differs from itself can't be tested
        # differentially, and quietly reporting noise as findings is worse than
        # reporting nothing.
        first = await fetch.request(url, timeout=12, ctx=ctx)
        second = await fetch.request(url, timeout=12, ctx=ctx)
        requests_sent += 2
        if not first.ok or not second.ok:
            return []
        if first.status != second.status or abs(len(first.body) - len(second.body)) > 48:
            return []

        base_status, base_body = first.status, first.body
        base_len = len(base_body)
        hits: list[tuple[str, str]] = []

        async def test(names: list[str]) -> str:
            nonlocal requests_sent
            resp = await fetch.request(with_params(url, names), timeout=12, ctx=ctx)
            requests_sent += 1
            if not resp.ok:
                return ""
            return differs(base_status, base_len, base_body,
                           resp.status, len(resp.body), resp.body)

        for group in chunk(candidates):
            if not await test(group):
                continue
            # Bisect down to the individual name.
            queue = [group]
            while queue:
                current = queue.pop()
                if len(current) == 1:
                    reason = await test(current)
                    if reason:
                        hits.append((current[0], reason))
                    continue
                mid = len(current) // 2
                for half in (current[:mid], current[mid:]):
                    if await test(half):
                        queue.append(half)

        out = []
        for name, reason in hits[:12]:
            interesting = name in {
                "debug", "admin", "is_admin", "isAdmin", "role", "internal",
                "staff", "superuser", "impersonate", "sudo", "override",
                "bypass", "force", "test", "preview"}
            urlish = name in {"url", "uri", "src", "dest", "target", "path",
                              "file", "template", "callback", "webhook",
                              "proxy", "feed", "load", "fetch", "image"}
            out.append({
                "engine": "paramminer",
                "rule_id": "hidden-parameter-privileged" if interesting
                else "hidden-parameter-url" if urlish else "hidden-parameter",
                "name": f"Undocumented parameter accepted: `{name}`",
                "severity": Severity.medium if interesting else
                Severity.low if urlish else Severity.info,
                "host": host, "url": url, "matched_at": with_params(url, [name]),
                "description": (
                    f"`{name}` changes this page's response ({reason}) but appears "
                    f"nowhere in the page or its scripts — nothing links to it, so "
                    f"nothing has been reviewing it.\n\n"
                    + ("This name is one that typically switches behaviour rather "
                       "than filtering content. If it enables a privileged view or "
                       "a debug mode for an unauthenticated request, that is a "
                       "broken access control finding on its own — test it with "
                       "values like `1`, `true` and your own user ID.\n\n"
                       if interesting else "")
                    + ("This name typically carries a location. Test it for server-"
                       "side request forgery and for path traversal: point it at an "
                       "internal address and at `../` sequences and compare the "
                       "responses.\n\n" if urlish else "")
                    + f"Detected by response {reason}: the parameter was accepted "
                      f"and acted on."),
                "evidence": f"GET {with_params(url, [name])}\n"
                            f"differs from baseline by: {reason}",
                "remediation": (
                    "Reject unexpected parameters rather than ignoring them — a "
                    "strict schema on input (pydantic, JSON Schema, strong "
                    "parameters) turns an undocumented parameter into a 400 "
                    "instead of a behaviour change.\n\n"
                    "Where a parameter is real but undocumented, either document "
                    "and test it or remove it. Debug and impersonation switches "
                    "should be compiled out of production builds, not gated by a "
                    "runtime flag."),
                "references": [
                    "https://owasp.org/www-project-web-security-testing-guide/",
                ],
                "tags": ["discovery", "parameter"], "cve": [],
                "cwe": ["CWE-233", "CWE-1230"], "cvss_score": None,
                "dedupe_key": make_dedupe_key("paramminer", f"param-{name}", host, url),
                "raw": {"param": name, "signal": reason},
            })
        return out

    results = await fetch.gather_limited([mine(u) for u in targets], limit=3)
    for group in results:
        findings += group or []

    if log:
        await log("info",
                  f"[paramminer] {requests_sent} request(s) across {len(targets)} "
                  f"page(s) → {len(findings)} hidden parameter(s)", "paramminer")
    return findings
