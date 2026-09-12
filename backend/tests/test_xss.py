"""Reflected XSS detection, offline.

The load-bearing property is test_encoded_reflection_is_not_flagged: an app that
HTML-encodes the payload (the correct behaviour) must never be reported, because
the finding requires the injected tag to survive as raw markup.
"""

from app.engines import fetch
from app.engines import xss as X
from app.models import Severity

from .conftest import run_coroutine


def test_probe_and_payload_shape():
    p = X.make_probe()
    pl = X.html_payload(p)
    assert f'<{p["tag"]}>' in pl and '">' in pl
    assert p["tag"].startswith("x")


def test_classify_raw_html_injection():
    p = {"tag": "xabc", "pre": "zq11", "post": "22qz"}
    v = X.classify("<html>hi <xabc> there</html>", p)
    assert v and v["quote"] is False and v["severity"] is Severity.high


def test_classify_reports_surviving_quote():
    p = {"tag": "xabc", "pre": "zq11", "post": "22qz"}
    v = X.classify('<input value="zq11"><xabc>22qz">', p)
    assert v and v["quote"] is True


def test_classify_encoded_is_safe():
    p = {"tag": "xabc", "pre": "zq11", "post": "22qz"}
    assert X.classify("<html>&lt;xabc&gt;</html>", p) is None


def test_classify_absent_is_safe():
    p = {"tag": "xabc", "pre": "zq11", "post": "22qz"}
    assert X.classify("<html>nothing injected</html>", p) is None
    assert X.classify("", p) is None


def _fake(mode, vuln="q"):
    from urllib.parse import parse_qsl, urlparse

    async def _req(url, **kw):
        q = dict(parse_qsl(urlparse(url).query, keep_blank_values=True))
        v = q.get(vuln, "")
        if mode == "vuln":
            return fetch.Resp(url=url, status=200, body=f"<html>results for {v}</html>")
        if mode == "encoded":
            enc = v.replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
            return fetch.Resp(url=url, status=200, body=f"<html>results for {enc}</html>")
        if mode == "noreflect":
            return fetch.Resp(url=url, status=200, body="<html>static, no echo</html>")
        return fetch.Resp(url=url, status=200, body="<html>x</html>")
    return _req


def test_unencoded_reflection_detected(monkeypatch):
    monkeypatch.setattr(fetch, "request", _fake("vuln"))
    out = run_coroutine(X._engine(["https://x.com/s?q=hi"], {}))
    assert len(out) == 1
    assert out[0]["rule_id"].startswith("xss-reflected")
    assert out[0]["severity"] is Severity.high


def test_encoded_reflection_is_not_flagged(monkeypatch):
    monkeypatch.setattr(fetch, "request", _fake("encoded"))
    out = run_coroutine(X._engine(["https://x.com/s?q=hi"], {}))
    assert out == [], "an app that encodes output must not be reported"


def test_no_reflection_no_finding(monkeypatch):
    monkeypatch.setattr(fetch, "request", _fake("noreflect"))
    out = run_coroutine(X._engine(["https://x.com/s?q=hi"], {}))
    assert out == []


def test_no_params(monkeypatch):
    monkeypatch.setattr(fetch, "request", _fake("vuln"))
    assert run_coroutine(X._engine(["https://x.com/nopath"], {})) == []


def test_engine_registered():
    from app.engines import registry
    registry.discover()
    spec = registry.get("xss")
    assert spec is not None and "deep" in spec.default_in
