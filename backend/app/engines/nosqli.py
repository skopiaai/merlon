"""NoSQL injection.

The document-store equivalent of SQL injection, and just as common now that so
many APIs sit on MongoDB. Where a SQL app concatenates a string, a Mongo app
often passes a request parameter straight into a query object — so a parameter
that arrives as `user[$ne]=x` becomes the query `{user: {$ne: "x"}}`, which
matches every user, and the login check that meant `user == input` now means
`user != "x"`. That is authentication bypass from one crafted parameter.

The safe subset, mirroring the SQL engine:

  * **Operator injection (primary).** A parameter is resent as `param[$ne]=<random>`
    — "not equal to a random string", i.e. always true. If the response changes
    the way a widened query would (more rows, a different page, a login that now
    succeeds) and a matching always-false operator does not, the parameter feeds
    a query object. The three-way split is required, so a param the app simply
    ignores cannot register.

  * **Error-based (corroborating).** A quote or a bare `[$ne]` sometimes trips a
    driver error — a MongoError, a Mongoose CastError, a BSON complaint. Those
    strings do not occur in ordinary pages, so a match is high-confidence and
    names the stack.

No data-extraction operators, no `$where` JavaScript payloads, no writes. GET
parameters only. Detection, not exploitation.
"""

from __future__ import annotations

import secrets
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..models import Severity
from ..normalize import make_dedupe_key
from . import fetch
from .registry import EngineSpec, register

NOSQL_ERRORS: list[tuple[str, str]] = [
    ("MongoDB", "mongoerror"),
    ("MongoDB", "mongodb"),
    ("Mongoose", "casterror"),
    ("Mongoose", "cast to objectid failed"),
    ("MongoDB", "bsonerror"),
    ("MongoDB", "$where"),
    ("MongoDB", "unknown operator"),
    ("MongoDB", "e11000 duplicate key"),
    ("Node/driver", "cannot read property"),
    ("Node/driver", "cannot read properties of undefined"),
]


def dbms_from_error(body: str) -> str | None:
    low = (body or "").lower()
    for name, sig in NOSQL_ERRORS:
        if sig in low:
            return name
    return None


def similarity(a: str, b: str) -> float:
    """Coarse same-page/different-page ratio in [0,1]. Local to keep the engine
    self-contained; identical in spirit to the SQL engine's."""
    a, b = a or "", b or ""
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    len_ratio = min(len(a), len(b)) / max(len(a), len(b))
    ta, tb = set(a.split()), set(b.split())
    tok = len(ta & tb) / len(ta | tb) if (ta | tb) else 1.0
    return (len_ratio + tok) / 2


def operator_probes(param: str, rand: str) -> list[tuple[str, str, str]]:
    """(true_param_name, false_param_name, style).

    Operator injection changes the parameter *name*, not just the value:
    `param[$ne]=random` becomes {param: {$ne: "random"}}.
    """
    return [
        (f"{param}[$ne]", f"{param}[$eq]", "$ne / $eq"),
        (f"{param}[$gt]", f"{param}[$lt]", "$gt / $lt"),
    ]


def candidate_params(url: str) -> list[tuple[str, str]]:
    parsed = urlparse(url)
    return list(parse_qsl(parsed.query, keep_blank_values=True))


def _set_params(url: str, pairs: list[tuple[str, str]]) -> str:
    parsed = urlparse(url)
    return urlunparse(parsed._replace(query=urlencode(pairs)))


def with_operator(url: str, param: str, op_name: str, value: str) -> str:
    """Replace `param=...` with `param[$op]=value`, keeping other params."""
    parsed = urlparse(url)
    pairs = [(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True)
             if k != param]
    pairs.append((op_name, value))
    return _set_params(url, pairs)


def inject_value(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    pairs = [(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True)
             if k != param]
    pairs.append((param, value))
    return _set_params(url, pairs)


_SAME = 0.95
_DIFF = 0.85


@register(EngineSpec(
    name="nosqli",
    label="Testing for NoSQL injection",
    description="NoSQL (MongoDB-style) injection via operator injection "
                "(param[$ne]) on a strict true/false differential, plus driver "
                "error signatures. GET params only; no $where JavaScript, data "
                "extraction or writes are ever sent.",
    phase="post_http",
    takes="urls",
    produces="findings",
    weight=6,
    limit=40,
    default_in=("deep",),
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

        for param, value in params:
            key = f"{host}|{param}"
            if key in seen:
                continue

            # --- 1. error-based: a bare operator sometimes trips a driver error ---
            err = await fetch.request(with_operator(url, param, f"{param}[$ne]", ""),
                                      timeout=12, ctx=ctx)
            if err.ok:
                stack = dbms_from_error(err.body)
                if stack:
                    seen.add(key)
                    out.append(_finding(host, url, param, "nosqli-error", Severity.high,
                        f"Injecting a NoSQL operator into `{param}` produced a "
                        f"{stack} error, so the value reaches a query object "
                        f"unsanitised. This is NoSQL injection.",
                        f"Parameter: {param}\nSent:      {param}[$ne]=\n"
                        f"Response contained a {stack} error signature.", stack))
                    continue

            # --- 2. operator boolean differential ---
            base = await fetch.request(inject_value(url, param, value), timeout=12, ctx=ctx)
            if not base.ok:
                continue
            rand = secrets.token_hex(6)
            for op_true, op_false, style in operator_probes(param, rand):
                rt = await fetch.request(with_operator(url, param, op_true, rand),
                                         timeout=12, ctx=ctx)
                rf = await fetch.request(with_operator(url, param, op_false, rand),
                                         timeout=12, ctx=ctx)
                if not (rt.ok and rf.ok):
                    continue
                # Always-true operator should widen the result away from the
                # single-value baseline; always-false should collapse it; and
                # the two must differ. An app that ignores the operator returns
                # the baseline for all three and is not reported.
                t_vs_base = similarity(base.body, rt.body)
                f_vs_base = similarity(base.body, rf.body)
                if (t_vs_base < _DIFF and similarity(rt.body, rf.body) < _DIFF
                        and f_vs_base >= _SAME):
                    seen.add(key)
                    out.append(_finding(host, url, param, "nosqli-operator", Severity.high,
                        f"The `{param}` parameter feeds a NoSQL query object: an "
                        f"always-true operator ({style}) changed the response "
                        f"while an always-false one left it as the baseline. A "
                        f"crafted operator alters the query's matching, which on "
                        f"a login or lookup is authentication or authorisation "
                        f"bypass.",
                        f"Parameter: {param}\n"
                        f"{op_true}={rand} -> differs from baseline (sim {t_vs_base:.2f})\n"
                        f"{op_false}={rand} -> matches baseline (sim {f_vs_base:.2f})",
                        None))
                    break
        return out

    results = await fetch.gather_limited([check(u) for u in targets], limit=5)
    for group in results:
        findings += group or []

    if log:
        await log("info", f"[nosqli] {len(findings)} injection(s) across "
                          f"{len(targets)} endpoint(s)", "nosqli")
    return findings


def _finding(host, url, param, rule, sev, desc, evidence, stack) -> dict:
    raw = {"param": param}
    if stack:
        raw["stack"] = stack
    return {
        "engine": "nosqli", "rule_id": rule,
        "name": "NoSQL injection" + (f" ({stack})" if stack else " (operator)"),
        "severity": sev, "host": host, "url": url, "matched_at": url,
        "description": desc + (
            "\n\nNoSQL injection commonly means authentication bypass and "
            "unauthorised data access, and with $where JavaScript can reach "
            "code execution. Only detection payloads were sent here."),
        "evidence": evidence,
        "remediation": (
            "Cast and validate every request parameter to its expected type "
            "before it reaches a query — a field that should be a string must "
            "never be allowed to arrive as an object. Reject query operators in "
            "user input, and use the driver's typed query builders rather than "
            "passing raw request data as a query filter."),
        "references": [
            "https://portswigger.net/web-security/nosql-injection",
            "https://owasp.org/www-community/attacks/NoSQL_injection",
        ],
        "tags": ["nosqli", "injection", "database"],
        "cve": [], "cwe": ["CWE-943", "CWE-89"], "cvss_score": None,
        "dedupe_key": make_dedupe_key("nosqli", rule, host, f"{url}|{param}"),
        "raw": raw,
    }
