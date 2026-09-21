"""NoSQL injection detection, offline.

Same discipline as the SQL engine: an error signature is proof, and the
operator differential fires only on a clean three-way split so an app that
ignores the injected operator is never reported.
"""

from app.engines import fetch
from app.engines import nosqli as N
from app.models import Severity

from .conftest import run_coroutine


def test_error_signatures():
    assert N.dbms_from_error("MongoError: unknown operator: $foo") == "MongoDB"
    assert N.dbms_from_error("CastError: Cast to ObjectId failed for value") == "Mongoose"
    assert N.dbms_from_error("TypeError: Cannot read property 'x' of undefined") == "Node/driver"
    assert N.dbms_from_error("<html>welcome back</html>") is None


def test_operator_probes_change_the_param_name():
    probes = N.operator_probes("user")
    assert ("user[$ne]", "user[$eq]", "$ne / $eq") in probes


def test_with_operator_builds_bracket_syntax():
    out = N.with_operator("https://x.com/l?user=bob&x=1", "user", "user[$ne]", "rnd")
    assert "user%5B%24ne%5D=rnd" in out or "user[$ne]=rnd" in out
    assert "x=1" in out and "user=bob" not in out


def test_candidate_params():
    assert N.candidate_params("https://x.com/l?user=a&pw=b") == [("user", "a"), ("pw", "b")]
    assert N.candidate_params("https://x.com/l") == []


def _fake(mode, vuln="user"):
    from urllib.parse import parse_qsl, urlparse

    async def _req(url, **kw):
        keys = [k for k, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)]
        has_ne = f"{vuln}[$ne]" in keys
        has_eq = f"{vuln}[$eq]" in keys
        has_gt = f"{vuln}[$gt]" in keys
        has_lt = f"{vuln}[$lt]" in keys
        if mode == "error" and has_ne:
            return fetch.Resp(url=url, status=200, body="MongoError: unknown operator")
        if mode == "operator":
            if has_ne or has_gt:   # always-true operators widen the result
                return fetch.Resp(url=url, status=200,
                    body="<html>dashboard: alpha beta gamma delta epsilon secret</html>")
            if has_eq or has_lt:   # always-false collapse to baseline (login page)
                return fetch.Resp(url=url, status=200, body="<html>please log in</html>")
            return fetch.Resp(url=url, status=200, body="<html>please log in</html>")  # baseline
        if mode == "ignore":       # app ignores the operator entirely
            return fetch.Resp(url=url, status=200, body="<html>please log in</html>")
        return fetch.Resp(url=url, status=200, body="<html>static</html>")
    return _req


def test_error_based_detected(monkeypatch):
    monkeypatch.setattr(fetch, "request", _fake("error"))
    out = run_coroutine(N._engine(["https://x.com/l?user=bob"], {}))
    assert len(out) == 1 and out[0]["rule_id"] == "nosqli-error"
    assert out[0]["raw"]["stack"] == "MongoDB"
    assert out[0]["severity"] is Severity.high


def test_operator_based_detected(monkeypatch):
    monkeypatch.setattr(fetch, "request", _fake("operator"))
    out = run_coroutine(N._engine(["https://x.com/l?user=bob"], {}))
    assert len(out) == 1 and out[0]["rule_id"] == "nosqli-operator"


def test_app_that_ignores_operator_is_not_flagged(monkeypatch):
    monkeypatch.setattr(fetch, "request", _fake("ignore"))
    out = run_coroutine(N._engine(["https://x.com/l?user=bob"], {}))
    assert out == [], "an app ignoring the operator must not be reported"


def test_no_params(monkeypatch):
    monkeypatch.setattr(fetch, "request", _fake("error"))
    assert run_coroutine(N._engine(["https://x.com/nopath"], {})) == []


def test_engine_registered():
    from app.engines import registry
    registry.discover()
    spec = registry.get("nosqli")
    assert spec is not None and "deep" in spec.default_in
