"""SQL injection.

The highest-value web bug with no dedicated engine here until now. Testing it
without harming the target is the design constraint, and this engine takes the
conservative subset that is safe to fire unattended:

  * **Error-based (primary).** A single quote is appended to a parameter and the
    response is checked for a database error signature — the MySQL "check the
    manual", the Postgres "unterminated quoted string", the Oracle ORA- codes.
    A real DBMS error string is unambiguous, so this is near-zero false
    positive, and it names the database. Sending a quote reads; it does not
    write.

  * **Boolean-based (corroborating).** Where no error leaks, the parameter is
    sent three ways — untouched, with a condition that is always true, and one
    always false — and injection is reported only on a clean three-way split:
    the true response matches the baseline and the false response clearly
    differs. A page that simply echoes input cannot produce that split, so
    reflection alone is not enough.

What it deliberately does not do: no stacked queries (`; DROP …` is never
sent), no time-based payloads (which tie up a database connection), no UNION
data extraction. Only existing GET parameters are touched, and the payloads are
syntactically inert for writes. Proving exploitability past this point is left
to a human with sqlmap.
"""

from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..models import Severity
from ..normalize import make_dedupe_key
from . import fetch
from .registry import EngineSpec, register

# DBMS error signatures. Each is a string that a database emits on a broken
# query and that does not occur in ordinary page text.
DB_ERRORS: list[tuple[str, str]] = [
    ("MySQL", "you have an error in your sql syntax"),
    ("MySQL", "warning: mysql"),
    ("MySQL", "mysqlsyntaxerrorexception"),
    ("MySQL", "check the manual that corresponds to your mysql"),
    ("MySQL", "com.mysql.jdbc"),
    ("PostgreSQL", "unterminated quoted string at or near"),
    ("PostgreSQL", "pg::syntaxerror"),
    ("PostgreSQL", "psqlexception"),
    ("PostgreSQL", "syntax error at or near"),
    ("Microsoft SQL Server", "unclosed quotation mark after the character string"),
    ("Microsoft SQL Server", "microsoft sql server"),
    ("Microsoft SQL Server", "system.data.sqlclient.sqlexception"),
    ("Microsoft SQL Server", "incorrect syntax near"),
    ("Oracle", "ora-00933"),
    ("Oracle", "ora-01756"),
    ("Oracle", "quoted string not properly terminated"),
    ("Oracle", "oracle error"),
    ("SQLite", "sqlite_error"),
    ("SQLite", "unrecognized token"),
    ("SQLite", "sqlite3::query"),
    ("SQLite", "sql logic error"),
]


def dbms_from_error(body: str) -> str | None:
    """Return the DBMS whose error signature appears in the body, if any."""
    low = (body or "").lower()
    for dbms, sig in DB_ERRORS:
        if sig in low:
            return dbms
    return None


def similarity(a: str, b: str) -> float:
    """A cheap length-and-content ratio in [0,1], stable enough for the split.

    Not a diff — just enough to tell "same page" from "clearly different page"
    without pulling in a dependency. Compares normalised length and a coarse
    token overlap.
    """
    a, b = a or "", b or ""
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    la, lb = len(a), len(b)
    len_ratio = min(la, lb) / max(la, lb)
    ta, tb = set(a.split()), set(b.split())
    tok = len(ta & tb) / len(ta | tb) if (ta | tb) else 1.0
    return (len_ratio + tok) / 2


def boolean_pairs(value: str) -> list[tuple[str, str, str]]:
    """(true_payload, false_payload, style) built off the parameter's value."""
    return [
        (f"{value}' AND '1'='1", f"{value}' AND '1'='2", "single-quote string"),
        (f"{value}\" AND \"1\"=\"1", f"{value}\" AND \"1\"=\"2", "double-quote string"),
        (f"{value} AND 1=1", f"{value} AND 1=2", "numeric"),
    ]


def candidate_params(url: str) -> list[tuple[str, str]]:
    parsed = urlparse(url)
    return list(parse_qsl(parsed.query, keep_blank_values=True))


def inject(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    params = [(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True)
              if k != param]
    params.append((param, value))
    return urlunparse(parsed._replace(query=urlencode(params, safe="")))


# A boolean result is only believed when the split is this clean.
_SAME = 0.95      # true-response must be at least this similar to baseline
_DIFF = 0.85      # false-response must be below this to count as "different"


@register(EngineSpec(
    name="sqli",
    label="Testing for SQL injection",
    description="SQL injection via database error signatures and a strict "
                "boolean true/false differential. GET parameters only; no "
                "stacked queries, time delays or data extraction are ever sent.",
    phase="post_http",
    takes="urls",
    produces="findings",
    weight=7,
    limit=40,
    default_in=("deep",),
    # A database returned its own error for our quote, or answered a
    # true/false pair differently. Both are demonstrations, not inferences.
    proves=("sqli-error", "sqli-boolean"),
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

            # --- 1. error-based: a single quote should not break a safe query ---
            err = await fetch.request(inject(url, param, value + "'"), timeout=12, ctx=ctx)
            if err.ok:
                dbms = dbms_from_error(err.body)
                if dbms:
                    seen.add(key)
                    out.append(_finding(host, url, param, "sqli-error", Severity.high,
                        f"Appending a single quote to `{param}` produced a "
                        f"{dbms} error, so the value is concatenated into a SQL "
                        f"query unsanitised. This is SQL injection.",
                        f"Parameter: {param}\nSent:      {value}'\n"
                        f"Response contained a {dbms} error signature.",
                        dbms=dbms))
                    continue

            # --- 2. boolean-based: only on a clean three-way split ---
            base = await fetch.request(inject(url, param, value), timeout=12, ctx=ctx)
            if not base.ok:
                continue
            for tp, fp, style in boolean_pairs(value):
                rt = await fetch.request(inject(url, param, tp), timeout=12, ctx=ctx)
                rf = await fetch.request(inject(url, param, fp), timeout=12, ctx=ctx)
                if not (rt.ok and rf.ok):
                    continue
                same = similarity(base.body, rt.body)
                diff = similarity(base.body, rf.body)
                # True must look like the baseline; false must clearly diverge;
                # and the two must differ from each other. A reflecting page
                # fails this because both payloads echo and stay similar.
                if same >= _SAME and diff < _DIFF and similarity(rt.body, rf.body) < _DIFF:
                    seen.add(key)
                    out.append(_finding(host, url, param, "sqli-boolean", Severity.high,
                        f"The `{param}` parameter is injectable by boolean "
                        f"condition ({style}): a query that is always true "
                        f"returned the original page, while an always-false one "
                        f"returned a different result. The value alters the SQL "
                        f"query's logic.",
                        f"Parameter: {param}\n"
                        f"True  ({tp}) -> matches baseline (sim {same:.2f})\n"
                        f"False ({fp}) -> differs (sim {diff:.2f})",
                        dbms=None))
                    break
        return out

    results = await fetch.gather_limited([check(u) for u in targets], limit=5)
    for group in results:
        findings += group or []

    if log:
        await log("info", f"[sqli] {len(findings)} injection(s) across "
                          f"{len(targets)} endpoint(s)", "sqli")
    return findings


def _finding(host, url, param, rule, sev, desc, evidence, dbms=None) -> dict:
    raw = {"param": param}
    if dbms:
        raw["dbms"] = dbms
    return {
        "engine": "sqli", "rule_id": rule,
        "name": "SQL injection" + (f" ({dbms})" if dbms else " (boolean-based)"),
        "severity": sev, "host": host, "url": url, "matched_at": url,
        "description": desc + (
            "\n\nSQL injection commonly escalates to reading or modifying the "
            "whole database, and sometimes to command execution. Only detection "
            "payloads were sent here; confirming impact is left to a human."),
        "evidence": evidence,
        "remediation": (
            "Use parameterised queries (prepared statements) everywhere — never "
            "build SQL by string concatenation with user input. An ORM helps "
            "only if it is not dropped for raw queries at the injectable call. "
            "Add least-privilege database accounts so an injection cannot reach "
            "beyond the data the endpoint needs."),
        "references": [
            "https://portswigger.net/web-security/sql-injection",
            "https://owasp.org/www-community/attacks/SQL_Injection",
        ],
        "tags": ["sqli", "injection", "database"],
        "cve": [], "cwe": ["CWE-89"], "cvss_score": None,
        "dedupe_key": make_dedupe_key("sqli", rule, host, f"{url}|{param}"),
        "raw": raw,
    }
