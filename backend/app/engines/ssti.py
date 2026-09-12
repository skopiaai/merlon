"""Server-side template injection.

When user input is concatenated into a server-side template instead of passed
as data, the template engine evaluates it. `{{7*7}}` coming back as `49` is the
canonical tell, and depending on the engine it escalates to file read and
remote code execution — this is one of the highest-impact web bugs there is.

Testing it safely is the whole design problem, and this engine solves it the
same way the open-redirect engine does: prove the bug without doing anything
harmful.

  * **Only arithmetic is ever evaluated.** The payload asks the template to
    multiply two random numbers. Nothing reads a file, spawns a process, or
    touches state — a positive result is proof the sink exists, and turning it
    into an exploit is left to a human.
  * **Reflection cannot cause a false positive.** The number is wrapped in two
    random markers and sent as `PRE{{a*b}}POST`. If the input is merely
    reflected, the response contains the literal `PRE{{a*b}}POST`. Only if the
    engine *evaluated* it does the response contain `PRE<product>POST`. The
    product is checked only inside that wrapper, so a page that happens to
    contain the number elsewhere proves nothing.
  * **Reflection-first, to stay quiet.** A parameter is only probed with
    template payloads if a plain marker sent through it comes back in the body.
    A parameter that never reflects cannot be the sink, so it is not hammered.

Only parameters already present on the URL are tested; no new endpoints are
invented. Values sent are arithmetic in template delimiters, so a WAF log will
show exactly what happened.
"""

from __future__ import annotations

import secrets
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..models import Severity
from ..normalize import make_dedupe_key
from . import fetch
from .registry import EngineSpec, register


def make_probe() -> dict:
    """A single-use probe: two random factors, their product, and wrappers.

    Randomised per call so the product is distinctive and cannot be a number
    already on the page, and so two runs never collide.
    """
    a = secrets.randbelow(9000) + 1000       # 1000..10999
    b = secrets.randbelow(9000) + 1000
    tag = secrets.token_hex(3)
    return {
        "a": a, "b": b, "product": a * b,
        "pre": f"ssti{tag}a", "post": f"z{tag}ssti",
    }


# Template delimiters by engine family. The expression is always a*b so the
# only capability exercised is multiplication.
_SYNTAXES = [
    ("{{{{{a}*{b}}}}}", "Jinja2 / Twig / Nunjucks"),
    ("${{{a}*{b}}}",    "JSP EL / Thymeleaf / Spring"),
    ("#{{{a}*{b}}}",    "Ruby ERB / Thymeleaf"),
    ("<%= {a}*{b} %>",  "ERB / EJS"),
    ("{a}*{b}",         "raw (baseline — must NOT evaluate)"),
    ("{{'{a}'*1}}{{{a}*{b}}}", "Jinja2 (attribute context)"),
    ("@({a}*{b})",      "Razor"),
    ("#set($x={a}*{b})$x", "Velocity"),
]


def payloads(probe: dict) -> list[tuple[str, str]]:
    """(value_to_send, engine_family). Each embeds the wrapped arithmetic."""
    out = []
    for tmpl, family in _SYNTAXES:
        if family.startswith("raw"):
            continue  # the raw form is a control, not a payload to fire
        expr = tmpl.format(a=probe["a"], b=probe["b"])
        out.append((f"{probe['pre']}{expr}{probe['post']}", family))
    return out


def reflected(body: str, marker: str) -> bool:
    """Did a plain marker sent through the parameter come back in the body?"""
    return bool(body) and marker in body


def evaluated(body: str, probe: dict) -> bool:
    """True only if the wrapped *product* is present — proof of evaluation.

    Checked strictly inside the wrapper. The product appearing anywhere else on
    the page (a price, an id) does not satisfy this.
    """
    if not body:
        return False
    needle = f"{probe['pre']}{probe['product']}{probe['post']}"
    return needle in body


def not_merely_reflected(body: str, value: str) -> bool:
    """The literal payload must be ABSENT — otherwise it was reflected, not run."""
    return value not in (body or "")


def candidate_params(url: str) -> list[tuple[str, str]]:
    """(param, original_value) for every existing query parameter."""
    parsed = urlparse(url)
    return list(parse_qsl(parsed.query, keep_blank_values=True))


def inject(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    params = [(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True)
              if k != param]
    params.append((param, value))
    return urlunparse(parsed._replace(query=urlencode(params, safe="/:@%")))


@register(EngineSpec(
    name="ssti",
    label="Testing for template injection",
    description="Server-side template injection, proven by making the template "
                "evaluate wrapped random arithmetic — nothing but multiplication "
                "is ever executed, and reflection cannot cause a false positive. "
                "Only parameters that already reflect are probed.",
    phase="post_http",
    takes="urls",
    produces="findings",
    weight=6,
    limit=40,
    default_in=("deep",),
    # The server computed arithmetic we injected — the sink is demonstrated.
    proves=("ssti-arithmetic",),
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
        for param, _orig in params:
            # 1. Reflection gate: a plain marker must come back before we probe.
            marker = "rfl" + secrets.token_hex(4)
            base = await fetch.request(inject(url, param, marker), timeout=12, ctx=ctx)
            if not base.ok or not reflected(base.body, marker):
                continue

            # 2. Fire arithmetic payloads until one evaluates.
            probe = make_probe()
            for value, family in payloads(probe):
                resp = await fetch.request(inject(url, param, value), timeout=12, ctx=ctx)
                if not resp.ok:
                    continue
                if not evaluated(resp.body, probe):
                    continue
                if not not_merely_reflected(resp.body, value):
                    continue  # belt-and-braces: the literal is present too

                key = f"{host}|{param}"
                if key in seen:
                    break
                seen.add(key)
                out.append({
                    "engine": "ssti", "rule_id": "ssti-arithmetic",
                    "name": "Server-side template injection",
                    "severity": Severity.critical,
                    "host": host, "url": url, "matched_at": inject(url, param, value),
                    "description": (
                        f"The `{param}` parameter is evaluated by a server-side "
                        f"template engine ({family}). A payload of "
                        f"`{probe['a']}*{probe['b']}` was returned as "
                        f"`{probe['product']}`, so the input is executed as a "
                        f"template expression rather than treated as data.\n\n"
                        f"Template injection of this kind commonly escalates to "
                        f"file disclosure and remote code execution, depending on "
                        f"the engine and the objects it exposes. Only arithmetic "
                        f"was evaluated here; the escalation is left to a human."),
                    "evidence": (
                        f"Parameter: {param}\n"
                        f"Sent:      {value}\n"
                        f"Returned:  {probe['pre']}{probe['product']}{probe['post']}\n"
                        f"(the arithmetic was computed server-side; the literal "
                        f"expression is absent from the response)"),
                    "remediation": (
                        "Never pass user input into a template as part of the "
                        "template source. Render templates from fixed files and "
                        "pass user data only as bound variables the engine treats "
                        "as data. Where user-supplied templates are a genuine "
                        "requirement, use a sandboxed engine and a strict "
                        "allowlist of accessible objects."),
                    "references": [
                        "https://portswigger.net/web-security/server-side-template-injection",
                        "https://owasp.org/www-project-web-security-testing-guide/",
                    ],
                    "tags": ["ssti", "injection", "rce"],
                    "cve": [], "cwe": ["CWE-1336", "CWE-94"], "cvss_score": None,
                    "dedupe_key": make_dedupe_key("ssti", "arithmetic", host, f"{url}|{param}"),
                    "raw": {"param": param, "family": family,
                            "expression": f"{probe['a']}*{probe['b']}",
                            "product": probe["product"]},
                })
                break
        return out

    results = await fetch.gather_limited([check(u) for u in targets], limit=5)
    for group in results:
        findings += group or []

    if log:
        await log("info", f"[ssti] {len(findings)} template injection(s) across "
                          f"{len(targets)} endpoint(s)", "ssti")
    return findings
