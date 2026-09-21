"""DOM-based cross-site scripting, proven by execution.

The server never sees this bug. When client-side JavaScript reads
`location.hash` — or a query parameter, or `document.referrer` — and writes it
into `innerHTML`, `document.write` or an event handler, the payload never
appears in the HTTP response at all. A fragment is not even sent to the server.
Every check in this project that reads a response body is structurally blind to
it, which is why this engine renders the page instead.

**Why executing the payload here is safe, and why it is the honest proof.**
The JavaScript runs inside *our own* throwaway headless browser. Nothing is
written to the target, no state changes, no other user is involved, and a
fragment payload never leaves the client. So unlike the reflected-XSS engine —
which must stop at "the characters survived unencoded" because it has no
browser — this one can settle the question completely: the payload either ran
or it did not.

The proof is `document.title`. Each probe carries a unique canary and sets the
title to it. After rendering, if the title is that canary, attacker-controlled
input reached a sink and executed. A page that merely echoes the payload as
text leaves the title alone, so reflection cannot produce a false positive.

If no browser is installed the engine reports nothing and says so. A missing
Chrome must never fail a scan.
"""

from __future__ import annotations

import secrets
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..models import Severity
from ..normalize import make_dedupe_key
from . import browser
from .registry import EngineSpec, register


def make_canary() -> str:
    return "mrl" + secrets.token_hex(5)


def payloads(canary: str) -> list[tuple[str, str]]:
    """(payload, the sink it is shaped for).

    Each sets document.title to the canary and does nothing else — no network
    call, no storage write, no navigation. Used to *name* the sink once
    something has fired; the scan itself sends the combined probes below.
    """
    set_title = f"document.title='{canary}'"
    return [
        (f"<img src=x onerror=\"{set_title}\">", "innerHTML (img/onerror)"),
        (f"<svg onload=\"{set_title}\">", "innerHTML (svg/onload)"),
        (f"\"><img src=x onerror=\"{set_title}\">", "attribute break-out"),
        (f"<script>{set_title}</script>", "document.write / script sink"),
        (f"javascript:{set_title}", "javascript: URL sink"),
    ]


def probe_values(canary: str) -> list[tuple[str, str]]:
    """The probes actually sent: as few page loads as will still find it.

    Each headless render costs a couple of seconds, and firing every payload at
    every vector meant twenty-one loads per host — about thirteen minutes of a
    deep scan spent almost entirely on pages with no DOM XSS at all.

    The markup payloads are concatenated into one value instead. Whichever sink
    the page has, the same canary lands in the title, so one load answers the
    question for all of them. The `javascript:` payload stays separate because
    it only works when the *whole* value becomes a URL — concatenating anything
    onto it stops it being one.

    That is two loads per vector rather than five, and the individual payloads
    are only replayed afterwards, on the rare page where something fired, to say
    which sink it was.
    """
    markup = "".join(p for p, _sink in payloads(canary)
                     if not p.startswith("javascript:"))
    js = next(p for p, _sink in payloads(canary) if p.startswith("javascript:"))
    return [(markup, "markup sink"), (js, "javascript: URL sink")]


def fragment_url(url: str, payload: str) -> str:
    """Put the payload in the fragment — never sent to the server."""
    from urllib.parse import quote
    base = url.split("#", 1)[0]
    return f"{base}#{quote(payload, safe='')}"


def param_url(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    pairs = [(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True)
             if k != param]
    pairs.append((param, payload))
    return urlunparse(parsed._replace(query=urlencode(pairs), fragment=""))


def executed(title: str, canary: str) -> bool:
    """The whole verdict: did our payload run?"""
    return bool(title) and title.strip() == canary


def candidate_params(url: str) -> list[str]:
    return [k for k, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)]


def probe_url(url: str, vector: str, param: str, value: str) -> str:
    """Place a payload on the vector being tested."""
    if vector == "fragment":
        return fragment_url(url, value)
    return param_url(url, param, value)


@register(EngineSpec(
    name="domxss",
    label="Rendering pages for DOM XSS",
    description="DOM-based XSS proven by execution in a headless browser — the "
                "class that never appears in the HTTP response and that no "
                "body-reading check can see. The payload only sets the page "
                "title, and runs solely in our own browser.",
    phase="post_http",
    takes="urls",
    produces="findings",
    weight=8,
    limit=15,
    default_in=("deep",),
    # The payload ran. There is nothing left to infer.
    proves=("domxss-executed",),
))
async def _engine(targets: list[str], ctx: dict) -> list[dict]:
    log = ctx.get("log")
    findings: list[dict] = []
    seen: set[str] = set()

    if not browser.available():
        if log:
            await log("info", "[domxss] no Chrome/Chromium available — skipping "
                              "DOM XSS (install a browser or use the container)",
                      "domxss")
        return []

    for url in targets:
        host = (urlparse(url).hostname or "").lower()
        if not host or host in seen:
            continue

        # No baseline load. The canary is random per probe, so a page cannot
        # already contain it, and nothing here compares against a "before"
        # title — the previous baseline render was a page load per host that
        # answered no question.
        hit = None

        # Fragment first — it is the commonest DOM-XSS source and never reaches
        # the server, so it is the least intrusive thing we can send.
        vectors: list[tuple[str, str]] = [("fragment", "")]
        vectors += [("param:" + p, p) for p in candidate_params(url)[:3]]

        for vector_name, param in vectors:
            if hit:
                break
            canary = make_canary()
            for value, kind in probe_values(canary):
                probe = probe_url(url, vector_name, param, value)
                r = await browser.render(probe)
                if not r.ok or not executed(r.title, canary):
                    continue

                # Something fired. Replay the individual payloads to name the
                # sink — only reached on a page that actually has the bug, so
                # the cost lands where it is worth paying.
                sink, shown, at = kind, value, probe
                narrow = make_canary()
                for one, one_sink in payloads(narrow):
                    if kind == "javascript: URL sink" and not one.startswith("javascript:"):
                        continue
                    if kind == "markup sink" and one.startswith("javascript:"):
                        continue
                    one_probe = probe_url(url, vector_name, param, one)
                    rr = await browser.render(one_probe)
                    if rr.ok and executed(rr.title, narrow):
                        sink, shown, at = one_sink, one, one_probe
                        break

                hit = {"payload": shown, "sink": sink, "probe": at,
                       "vector": vector_name, "canary": canary}
                break

        if not hit:
            continue
        seen.add(host)
        findings.append({
            "engine": "domxss", "rule_id": "domxss-executed",
            "name": "DOM-based XSS (payload executed)",
            "severity": Severity.high,
            "host": host, "url": url, "matched_at": hit["probe"],
            "description": (
                f"Client-side JavaScript on this page takes input from the "
                f"{hit['vector']} and reaches a {hit['sink']} sink without "
                f"sanitising it. A payload delivered there **executed** in a "
                f"real browser.\n\nThis never appears in the HTTP response — a "
                f"fragment is not even sent to the server — so it is invisible "
                f"to any scanner that only reads response bodies. Exploitation "
                f"needs only a crafted link; there is no server-side fix that "
                f"filters it, because the server never sees the payload."),
            "evidence": (
                f"Vector:   {hit['vector']}\n"
                f"Payload:  {hit['payload']}\n"
                f"URL:      {hit['probe']}\n"
                f"Proof:    document.title became {hit['canary']!r} after "
                f"rendering — the injected script ran.\n"
                f"(The payload only sets the page title, and executed solely in "
                f"the scanner's own headless browser.)"),
            "remediation": (
                "Never pass untrusted values to innerHTML, outerHTML, "
                "document.write or a javascript: URL. Use textContent for text, "
                "and setAttribute with an allowlist for attributes. Where markup "
                "genuinely must be built from input, sanitise it with a "
                "maintained library such as DOMPurify — and add a "
                "Content-Security-Policy that forbids inline script, which turns "
                "this class of bug from exploitable into merely broken."),
            "references": [
                "https://portswigger.net/web-security/cross-site-scripting/dom-based",
                "https://owasp.org/www-community/attacks/DOM_Based_XSS",
            ],
            "tags": ["xss", "dom", "client-side", "injection"],
            "cve": [], "cwe": ["CWE-79"], "cvss_score": None,
            "dedupe_key": make_dedupe_key("domxss", "executed", host, url),
            "raw": {"vector": hit["vector"], "sink": hit["sink"]},
        })

    if log:
        await log("info", f"[domxss] {len(findings)} DOM XSS across "
                          f"{len(targets)} page(s)", "domxss")
    return findings
