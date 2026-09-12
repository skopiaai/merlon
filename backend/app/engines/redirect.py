"""Open redirect detection.

An open redirect is a URL on the target's own domain that will send a visitor
anywhere the URL says. On its own, triage teams often rate it low — "the user
can see the address bar". That undersells it, because an open redirect is
rarely the whole bug; it's the component that makes other bugs work:

  * **OAuth token theft.** If a redirect_uri allowlist accepts any path on the
    domain, an open redirect on that domain forwards the authorisation code to
    an attacker. This is a full account takeover, and it is common.
  * **SSRF filter bypass.** A server-side fetcher that allowlists the target's
    own domain will happily follow a redirect off it.
  * **Phishing that survives inspection.** The link the victim checks really is
    the university's domain, with the university's certificate.

The probes cover the parser confusions that beat naive validation:
protocol-relative `//host`, backslash variants that browsers normalise to
slashes but validators don't, and userinfo (`https://trusted.com@attacker`)
which reads as the trusted host to a human and to a bad regex.

The canary is under `.invalid` (RFC 2606) and can never resolve, and redirects
are never followed — detection reads the `Location` header. So a positive
result is proved without a single packet reaching anyone else.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..models import Severity
from ..normalize import make_dedupe_key
from . import fetch
from .registry import EngineSpec, register

CANARY = "redirect-canary.invalid"

# Parameter names that carry a destination. Ordered roughly by how often they
# turn out to be unvalidated.
REDIRECT_PARAMS = (
    "url", "redirect", "redirect_uri", "redirect_url", "redirectUrl", "next",
    "return", "returnTo", "return_to", "return_url", "returnUrl", "continue",
    "dest", "destination", "goto", "go", "target", "to", "out", "view",
    "callback", "callback_url", "forward", "from", "back", "backurl", "r", "u",
    "link", "login_url", "logout_url", "checkout_url", "image_url", "path",
    "domain", "site", "page", "ref", "referrer", "success_url", "cancel_url",
)


def payloads(host: str) -> list[tuple[str, str]]:
    """(value_to_inject, what_it_tests)."""
    return [
        (f"https://{CANARY}", "absolute"),
        (f"//{CANARY}", "protocol-relative"),
        (f"/\\{CANARY}", "backslash"),
        (f"https:/\\{CANARY}", "mixed-slash"),
        (f"https://{host}@{CANARY}", "userinfo"),
        (f"https://{CANARY}%23@{host}", "fragment-confusion"),
        (f"https://{CANARY}%2f{host}", "encoded-path"),
    ]


def redirects_offsite(location: str, canary: str = CANARY) -> bool:
    """Does this Location value actually send the browser to the canary?

    The subtlety worth testing: a `Location` that stays on the target but
    carries the canary as a *query parameter* is the application echoing input,
    not redirecting to it. Treating that as a finding is the single most common
    false positive in open-redirect scanning.
    """
    if not location:
        return False
    value = location.strip()
    if canary.lower() not in value.lower():
        return False

    # Normalise the parser confusions a browser would resolve.
    probe = value.replace("\\", "/")
    if probe.lower().startswith("http:/") or probe.lower().startswith("https:/"):
        probe = re.sub(r"^https?:/+", "//", probe, flags=re.I)

    if not probe.startswith("//"):
        return False   # relative path — stays on this origin

    authority = probe[2:].split("/")[0].split("?")[0].split("#")[0]
    # userinfo: everything before the last @ is credentials, not the host
    host_part = authority.rsplit("@", 1)[-1].split(":")[0].lower()
    return host_part == canary.lower() or host_part.endswith("." + canary.lower())


def candidate_urls(url: str) -> list[tuple[str, str, str]]:
    """(url_with_payload_slot, parameter, original_value) for one URL.

    Existing parameters that look like destinations are tested first; if the
    URL has none, a small set is appended, because unlinked parameters are
    exactly the ones nobody remembered to validate.
    """
    parsed = urlparse(url)
    params = parse_qsl(parsed.query, keep_blank_values=True)
    out: list[tuple[str, str, str]] = []

    named = {k for k, _ in params}
    for key, value in params:
        if key.lower() in {p.lower() for p in REDIRECT_PARAMS}:
            out.append((url, key, value))

    if not out:
        for key in REDIRECT_PARAMS[:8]:
            if key not in named:
                out.append((url, key, ""))
    return out


def inject(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    params = [(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True)
              if k != param]
    params.append((param, value))
    return urlunparse(parsed._replace(query=urlencode(params, safe="/:@%\\")))


@register(EngineSpec(
    name="redirect",
    label="Testing for open redirects",
    description="Unvalidated redirect parameters, including the protocol-relative, "
                "backslash and userinfo bypasses. Matters most as an OAuth "
                "token-theft and SSRF-filter-bypass primitive, not on its own.",
    phase="post_http",
    takes="urls",
    produces="findings",
    weight=6,
    limit=60,
    default_in=("standard", "deep"),
    # The Location header points at our unresolvable canary. Nothing to infer.
    proves=("open-redirect",),
))
async def _engine(targets: list[str], ctx: dict) -> list[dict]:
    log = ctx.get("log")
    findings: list[dict] = []
    seen: set[str] = set()
    tested = 0

    async def check(url: str) -> list[dict]:
        nonlocal tested
        host = (urlparse(url).hostname or "").lower()
        out = []
        for base, param, _original in candidate_urls(url)[:6]:
            for value, kind in payloads(host):
                tested += 1
                probe = inject(base, param, value)
                resp = await fetch.request(probe, follow=False, timeout=10, ctx=ctx)
                if not resp.ok or resp.status not in (301, 302, 303, 307, 308):
                    continue
                location = resp.header("location")
                if not redirects_offsite(location):
                    continue

                key = f"{host}|{param}"
                if key in seen:
                    return out
                seen.add(key)

                out.append({
                    "engine": "redirect", "rule_id": "open-redirect",
                    "name": f"Open redirect via `{param}`",
                    "severity": Severity.medium,
                    "host": host, "url": probe, "matched_at": probe,
                    "description": (
                        f"The `{param}` parameter sends visitors to any address it "
                        f"is given, including addresses on other domains. The "
                        f"working payload used the **{kind}** form, which means "
                        f"{'there is no destination validation at all' if kind == 'absolute' else 'the destination check exists but can be confused by a URL a browser parses differently than the validator does'}.\n\n"
                        f"Rated medium on its own. It becomes critical when "
                        f"combined with anything that trusts this domain: an OAuth "
                        f"redirect_uri allowlist matching by domain, a server-side "
                        f"fetcher that allowlists you, or a mail filter that trusts "
                        f"your links."),
                    "evidence": (f"GET {probe}\n"
                                 f"HTTP {resp.status}\n"
                                 f"Location: {location}"),
                    "remediation": (
                        "Don't accept a URL. Accept an identifier and map it to a "
                        "destination server-side:\n\n"
                        "  DESTINATIONS = {'dashboard': '/app', 'help': '/support'}\n"
                        "  target = DESTINATIONS.get(request.args['next'], '/')\n\n"
                        "If you must accept a URL, parse it and compare the *host* "
                        "against an allowlist — never a prefix or `startswith` check, "
                        "which the payload above defeats. Reject anything whose "
                        "parsed scheme isn't http/https, and normalise backslashes "
                        "before parsing.\n\n"
                        "Then check whether your OAuth configuration allowlists "
                        "redirect URIs by domain rather than by exact URL. If it "
                        "does, this bug is an account takeover and should be "
                        "treated at that severity."),
                    "references": [
                        "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
                        "https://portswigger.net/kb/issues/00500100_open-redirection-reflected",
                    ],
                    "tags": ["redirect", "input-validation"],
                    "cve": [], "cwe": ["CWE-601"], "cvss_score": 6.1,
                    "dedupe_key": make_dedupe_key("redirect", "open-redirect", host, base),
                    "raw": {"param": param, "payload": value, "kind": kind,
                            "location": location},
                })
                return out
        return out

    results = await fetch.gather_limited([check(u) for u in targets], limit=6)
    for group in results:
        findings += group or []

    if log:
        await log("info", f"[redirect] {tested} probe(s), {len(findings)} open "
                          f"redirect(s)", "redirect")
    return findings
