"""SQL injection detection, offline.

The two load-bearing properties: an error signature is proof (dbms_from_error),
and the boolean path only fires on a clean three-way split so a page that merely
echoes input is never reported.
"""

from app.engines import fetch
from app.engines import sqli as Q
from app.models import Severity

from .conftest import run_coroutine

# ---------------------------------------------------------------- error signatures

def test_dbms_error_recognised():
    assert Q.dbms_from_error("You have an error in your SQL syntax; check the manual") == "MySQL"
    assert Q.dbms_from_error("ERROR: unterminated quoted string at or near \"'\"") == "PostgreSQL"
    assert Q.dbms_from_error("Unclosed quotation mark after the character string") == "Microsoft SQL Server"
    assert Q.dbms_from_error("ORA-00933: SQL command not properly ended") == "Oracle"
    assert Q.dbms_from_error("SQLITE_ERROR: unrecognized token") == "SQLite"


def test_ordinary_page_is_not_an_error():
    assert Q.dbms_from_error("<html>Welcome. Your order shipped.</html>") is None
    assert Q.dbms_from_error("") is None


# ---------------------------------------------------------------- similarity

def test_similarity_bounds():
    assert Q.similarity("abc def", "abc def") == 1.0
    assert Q.similarity("", "something") == 0.0
    assert Q.similarity("the quick brown fox", "the quick brown fox jumps") > 0.6


def test_boolean_pairs_built_from_value():
    pairs = Q.boolean_pairs("7")
    assert any("1'='1" in t and "1'='2" in f for t, f, _ in pairs)
    assert any(t == "7 AND 1=1" and f == "7 AND 1=2" for t, f, _ in pairs)


def test_inject_and_candidates():
    assert Q.candidate_params("https://x.com/a?id=1&p=2") == [("id", "1"), ("p", "2")]
    assert Q.candidate_params("https://x.com/a") == []
    assert "id=1%27" in Q.inject("https://x.com/a?id=1", "id", "1'")


# ---------------------------------------------------------------- engine behaviour

def _fake(mode, vuln_param="id"):
    """mode: 'error' emits a DBMS error on a quote; 'boolean' splits true/false;
    'echo' merely reflects (must not be flagged); 'clean' is static."""
    from urllib.parse import parse_qsl, urlparse

    async def _req(url, **kw):
        q = dict(parse_qsl(urlparse(url).query, keep_blank_values=True))
        v = q.get(vuln_param, "")
        if mode == "error":
            if v.endswith("'"):
                return fetch.Resp(url=url, status=200,
                    body="<html>You have an error in your SQL syntax near ''</html>")
            return fetch.Resp(url=url, status=200, body="<html>ok row 1</html>")
        if mode == "boolean":
            if "1'='1" in v or v.endswith("1=1"):
                return fetch.Resp(url=url, status=200, body="<html>ok product listing rows a b c d e</html>")
            if "1'='2" in v or v.endswith("1=2"):
                return fetch.Resp(url=url, status=200, body="<html>no results found</html>")
            if v.endswith("'") or v.endswith('"'):
                return fetch.Resp(url=url, status=200, body="<html>malformed weird page zzz</html>")
            return fetch.Resp(url=url, status=200, body="<html>ok product listing rows a b c d e</html>")
        if mode == "echo":
            return fetch.Resp(url=url, status=200, body=f"<html>you searched for {v}</html>")
        return fetch.Resp(url=url, status=200, body="<html>static page</html>")
    return _req


def test_error_based_detected(monkeypatch):
    monkeypatch.setattr(fetch, "request", _fake("error"))
    out = run_coroutine(Q._engine(["https://x.com/p?id=1"], {}))
    assert len(out) == 1
    assert out[0]["rule_id"] == "sqli-error"
    assert out[0]["raw"]["dbms"] == "MySQL"
    assert out[0]["severity"] is Severity.high


def test_boolean_based_detected(monkeypatch):
    monkeypatch.setattr(fetch, "request", _fake("boolean"))
    out = run_coroutine(Q._engine(["https://x.com/p?id=1"], {}))
    assert len(out) == 1
    assert out[0]["rule_id"] == "sqli-boolean"


def test_reflecting_page_is_not_flagged(monkeypatch):
    monkeypatch.setattr(fetch, "request", _fake("echo"))
    out = run_coroutine(Q._engine(["https://x.com/p?q=hello"], {}))
    assert out == [], "an echoing page must not be reported as SQLi"


def test_clean_page_is_not_flagged(monkeypatch):
    monkeypatch.setattr(fetch, "request", _fake("clean"))
    out = run_coroutine(Q._engine(["https://x.com/p?id=1"], {}))
    assert out == []


def test_no_params_no_work(monkeypatch):
    monkeypatch.setattr(fetch, "request", _fake("error"))
    assert run_coroutine(Q._engine(["https://x.com/nopath"], {})) == []


def test_engine_registered():
    from app.engines import registry
    registry.discover()
    spec = registry.get("sqli")
    assert spec is not None and spec.phase == "post_http"
    assert "deep" in spec.default_in
