"""Server-side template injection, offline.

The load-bearing test is test_reflection_alone_does_not_fire: an endpoint that
echoes the payload verbatim (the common case) must never be reported, because
the number is only accepted inside its random wrapper and a reflected payload
shows the literal expression, not the product.
"""

from app.engines import fetch
from app.engines import ssti as S
from app.models import Severity

from .conftest import run_coroutine


def test_make_probe_is_consistent():
    p = S.make_probe()
    assert p["product"] == p["a"] * p["b"]
    assert p["pre"] and p["post"] and p["pre"] != p["post"]


def test_payloads_embed_the_wrapped_expression():
    p = {"a": 31, "b": 37, "product": 1147, "pre": "PRE", "post": "POST"}
    vals = S.payloads(p)
    assert vals, "no payloads generated"
    for value, family in vals:
        assert value.startswith("PRE") and value.endswith("POST")
        assert "31*37" in value
        assert not family.startswith("raw")   # the control is never fired


def test_evaluated_needs_the_product_in_the_wrapper():
    p = {"a": 31, "b": 37, "product": 1147, "pre": "PRE", "post": "POST"}
    assert S.evaluated("...PRE1147POST...", p) is True
    # product present but not wrapped -> not proof
    assert S.evaluated("the price is 1147 dollars", p) is False
    # wrapper present but expression not evaluated (reflected)
    assert S.evaluated("PRE31*37POST", p) is False
    assert S.evaluated("", p) is False


def test_not_merely_reflected():
    assert S.not_merely_reflected("clean page", "PRE31*37POST") is True
    assert S.not_merely_reflected("...PRE31*37POST...", "PRE31*37POST") is False


def test_reflected_gate():
    assert S.reflected("...rflABCD...", "rflABCD") is True
    assert S.reflected("nothing here", "rflABCD") is False


def test_candidate_params_reads_existing_only():
    params = S.candidate_params("https://x.com/p?a=1&b=2")
    assert ("a", "1") in params and ("b", "2") in params
    assert S.candidate_params("https://x.com/p") == []


def test_inject_replaces_one_param():
    out = S.inject("https://x.com/p?a=1&b=2", "a", "PAYLOAD")
    assert "a=PAYLOAD" in out and "b=2" in out


# ---------------------------------------------------------------- engine behaviour

def _fake_fetch(vuln_param=None, probe_capture=None):
    """A fetch that evaluates arithmetic only for vuln_param, else reflects."""
    from urllib.parse import parse_qsl, urlparse

    async def _req(url, **kw):
        q = dict(parse_qsl(urlparse(url).query, keep_blank_values=True))
        # find the injected param value (the last non-baseline marker)
        body_parts = []
        for k, v in q.items():
            if k == vuln_param and v.startswith("ssti"):
                # emulate a template engine: strip the delimiters, compute a*b,
                # keep the random wrapper. Payloads look like PRE{{a*b}}POST.
                import re
                m = re.search(r"(ssti[0-9a-f]+a).*?(\d+)\*(\d+).*?(z[0-9a-f]+ssti)", v)
                if m:
                    pre, a, b, post = m.group(1), int(m.group(2)), int(m.group(3)), m.group(4)
                    body_parts.append(f"{pre}{a*b}{post}")
                    continue
            body_parts.append(v)   # everything else is reflected verbatim
        return fetch.Resp(url=url, status=200, body=" ".join(body_parts))
    return _req


def test_vulnerable_param_is_detected(monkeypatch):
    monkeypatch.setattr(fetch, "request", _fake_fetch(vuln_param="name"))
    out = run_coroutine(S._engine(["https://x.com/p?name=hi&safe=1"], {}))
    assert len(out) == 1
    assert out[0]["rule_id"] == "ssti-arithmetic"
    assert out[0]["severity"] is Severity.critical
    assert out[0]["raw"]["param"] == "name"


def test_reflection_alone_does_not_fire(monkeypatch):
    # vuln_param=None: every param merely reflects its input, never evaluates.
    monkeypatch.setattr(fetch, "request", _fake_fetch(vuln_param=None))
    out = run_coroutine(S._engine(["https://x.com/p?name=hi&q=1"], {}))
    assert out == [], "a reflecting endpoint must not be reported as SSTI"


def test_no_params_no_work(monkeypatch):
    monkeypatch.setattr(fetch, "request", _fake_fetch(vuln_param="name"))
    out = run_coroutine(S._engine(["https://x.com/nopath"], {}))
    assert out == []


def test_engine_registered():
    from app.engines import registry
    registry.discover()
    spec = registry.get("ssti")
    assert spec is not None and spec.phase == "post_http"
    assert "deep" in spec.default_in
