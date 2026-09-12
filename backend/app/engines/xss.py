"""Reflected cross-site scripting.

Reflected XSS is a parameter whose value is written into the page without being
encoded, so an attacker's markup — a `<script>`, an `onerror=` — runs in the
victim's browser. Proving it normally means a headless browser, but the *server
side* of it is decidable without one: if the characters that start a tag or
break an attribute survive unencoded in the response, the injection point is
there. Whether a given payload then executes is a browser-and-CSP question left
to a human; the unencoded reflection is the finding.

How this stays low false-positive:

  * **Reflection-gated.** A parameter is only tested if a plain random marker
    sent through it comes back in the body. No reflection, no reflected XSS.
  * **The proof is a literal tag we injected.** The probe sends
    `PRE<xNNNN>POST`, a made-up tag that cannot occur naturally. If the response
    contains that exact `<xNNNN>` — the `<` and `>` intact — the value was
    written as markup. If it comes back `&lt;xNNNN&gt;`, it was encoded, and
    nothing is reported. A number or word appearing elsewhere proves nothing;
    only the injected tag inside its wrapper counts.
  * **The claim is only what was proven.** The report states which characters
    survived unencoded (the tag delimiters, and whether a quote did too), rather
    than asserting the exact sink context — HTML body versus an attribute we
    broke out of depends on the surrounding markup, which the payload alone
    cannot settle. Over-claiming context is how a scanner loses a triager's
    trust.

Only existing GET parameters are touched. The payload is an inert nonsense tag;
nothing scripts, navigates or changes state.
"""

from __future__ import annotations

import secrets
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..models import Severity
from ..normalize import make_dedupe_key
from . import fetch
from .registry import EngineSpec, register


def make_probe() -> dict:
    tag = "x" + secrets.token_hex(3)
    pre, post = "zq" + secrets.token_hex(2), secrets.token_hex(2) + "qz"
    return {"tag": tag, "pre": pre, "post": post}


def html_payload(p: dict) -> str:
    """A made-up tag preceded by a quote (to also probe attribute contexts),
    wrapped in random markers."""
    return f'{p["pre"]}"><{p["tag"]}>{p["post"]}'


def marker(p: dict) -> str:
    return "rfl" + p["pre"]


def reflected(body: str, mark: str) -> bool:
    return bool(body) and mark in body


def classify(body: str, p: dict) -> dict | None:
    """Decide what, if anything, survived unencoded. Pure and offline.

    The finding requires our nonsense tag to appear as real markup — the `<`
    and `>` intact. That is unambiguous HTML injection and the honest claim to
    make; the exact sink context (HTML body vs an attribute we broke out of)
    depends on the surrounding markup, which the payload alone cannot settle, so
    it is reported as *which characters survived* rather than asserted. Returns
    None when the tag was encoded or is absent.
    """
    if not body:
        return None
    raw_tag = f"<{p['tag']}>"
    if raw_tag not in body:
        return None   # encoded (&lt;tag&gt;) or absent — the app is fine

    # The tag survived. Note whether the quote also survived, which is what
    # matters for breaking out of an attribute context — reported as evidence,
    # not asserted as the context.
    quote_survived = f'"><{p["tag"]}>' in body
    survived = "< > and a double-quote" if quote_survived else "< and >"
    return {
        "severity": Severity.high,
        "survived": survived,
        "quote": quote_survived,
        "detail": f"the characters {survived} were returned unencoded, and an "
                  f"injected tag appeared as live markup",
    }


def candidate_params(url: str) -> list[tuple[str, str]]:
    return list(parse_qsl(urlparse(url).query, keep_blank_values=True))


def inject(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    pairs = [(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True)
             if k != param]
    pairs.append((param, value))
    return urlunparse(parsed._replace(query=urlencode(pairs)))


@register(EngineSpec(
    name="xss",
    label="Testing for reflected XSS",
    description="Reflected cross-site scripting decided from the server "
                "response: an inert nonsense tag is injected and reported only "
                "if it survives unencoded in the HTML. Reflection-gated, "
                "existing GET params only, nothing scripts or changes state.",
    phase="post_http",
    takes="urls",
    produces="findings",
    weight=6,
    limit=40,
    default_in=("deep",),
    # Our nonsense tag came back as live markup: the injection is shown.
    proves=("xss-reflected",),
))
async def _engine(targets: list[str], ctx: dict) -> list[dict]:
    log = ctx.get("log")
    findings: list[dict] = []
    seen: set[str] = set()

    async def check(url: str) -> list[dict]:
        host = (urlparse(url).hostname or "").lower()
        params = candidate_params(url)
        if not host or not params:
            return []
        out: list[dict] = []

        for param, _value in params:
            key = f"{host}|{param}"
            if key in seen:
                continue
            probe = make_probe()

            # 1. reflection gate
            m = marker(probe)
            base = await fetch.request(inject(url, param, m), timeout=12, ctx=ctx)
            if not base.ok or not reflected(base.body, m):
                continue

            # 2. inject the inert tag and see whether it survived unencoded
            payload = html_payload(probe)
            resp = await fetch.request(inject(url, param, payload), timeout=12, ctx=ctx)
            if not resp.ok:
                continue
            verdict = classify(resp.body, probe)
            if not verdict:
                continue

            seen.add(key)
            out.append({
                "engine": "xss", "rule_id": "xss-reflected",
                "name": "Reflected XSS (unencoded HTML injection)",
                "severity": verdict["severity"],
                "host": host, "url": url, "matched_at": inject(url, param, payload),
                "description": (
                    f"The `{param}` parameter is reflected into the response "
                    f"unencoded — {verdict['detail']}. Because an injected tag "
                    f"`<{probe['tag']}>` came back as live markup rather than "
                    f"escaped text, an attacker-supplied script or event handler "
                    f"would be written into the page and run in the victim's "
                    f"browser.\n\nAn inert nonsense tag was used to prove the "
                    f"injection point; whether a specific payload executes "
                    f"depends on the surrounding markup, the browser and any "
                    f"CSP, and is left to a human."),
                "evidence": (
                    f"Parameter: {param}\n"
                    f"Sent:      {payload}\n"
                    f"Returned:  ...<{probe['tag']}>... "
                    f"({verdict['survived']} survived unencoded)"),
                "remediation": (
                    "Contextually encode all user input on output — HTML-encode "
                    "for the HTML body, attribute-encode inside attributes, and "
                    "never place untrusted data inside a script. Use the "
                    "framework's auto-escaping templating rather than building "
                    "HTML by concatenation, and add a Content-Security-Policy as "
                    "defence in depth."),
                "references": [
                    "https://portswigger.net/web-security/cross-site-scripting/reflected",
                    "https://owasp.org/www-community/attacks/xss/",
                ],
                "tags": ["xss", "injection", "client-side"],
                "cve": [], "cwe": ["CWE-79"], "cvss_score": None,
                "dedupe_key": make_dedupe_key("xss", "reflected", host, f"{url}|{param}"),
                "raw": {"param": param, "quote_survived": verdict["quote"]},
            })
        return out

    results = await fetch.gather_limited([check(u) for u in targets], limit=5)
    for group in results:
        findings += group or []

    if log:
        await log("info", f"[xss] {len(findings)} reflected XSS across "
                          f"{len(targets)} endpoint(s)", "xss")
    return findings
