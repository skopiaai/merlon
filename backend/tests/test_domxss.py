"""DOM XSS, and the headless browser layer under it.

The properties that matter: the verdict is execution (not reflection), a
missing browser degrades to silence rather than an error, and the payloads only
ever touch document.title.
"""

from app.engines import browser
from app.engines import domxss as D
from app.models import Severity

from .conftest import run_coroutine

# ---------------------------------------------------------------- payloads

def test_payloads_only_set_the_title():
    c = "mrlCANARY"
    for payload, sink in D.payloads(c):
        assert c in payload
        assert "document.title" in payload
        assert sink
        # nothing that reaches the network, storage, or navigates away
        for forbidden in ("fetch(", "XMLHttpRequest", "localStorage",
                          "document.cookie", "location.href=", "window.open"):
            assert forbidden not in payload


def test_canaries_are_unique():
    assert D.make_canary() != D.make_canary()


def test_executed_requires_exact_canary():
    assert D.executed("mrlABC", "mrlABC") is True
    assert D.executed("  mrlABC  ", "mrlABC") is True
    assert D.executed("safe title", "mrlABC") is False
    assert D.executed("", "mrlABC") is False


def test_fragment_url_keeps_payload_client_side():
    u = D.fragment_url("https://x.com/p?a=1", "<img src=x>")
    assert u.startswith("https://x.com/p?a=1#")
    assert "<img" not in u          # percent-encoded, not raw
    assert "%3c" in u.lower()          # the < was encoded


def test_param_url_replaces_one_param():
    u = D.param_url("https://x.com/p?a=1&b=2", "a", "PAY")
    assert "a=PAY" in u and "b=2" in u


def test_candidate_params():
    assert D.candidate_params("https://x.com/p?a=1&b=2") == ["a", "b"]
    assert D.candidate_params("https://x.com/p") == []


# ---------------------------------------------------------------- browser layer

def test_render_title_parsing():
    r = browser.Render(url="u", dom="<html><head><title> hello </title></head></html>", ok=True)
    assert r.title == "hello"
    assert browser.Render(url="u", dom="<html></html>", ok=True).title == ""
    assert browser.Render(url="u").title == ""


def test_argv_is_isolated_and_bounded():
    argv = browser._argv("/bin/chrome", "https://x.com", "/tmp/prof", None, 20)
    joined = " ".join(argv)
    assert "--headless=new" in joined
    assert "--user-data-dir=/tmp/prof" in joined   # throwaway profile
    assert "--incognito" in joined
    assert "--disable-extensions" in joined
    assert "--virtual-time-budget=20000" in joined
    assert "--dump-dom" in joined
    assert argv[-1] == "https://x.com"             # URL last, never a flag slot


def test_argv_screenshot_mode():
    argv = browser._argv("/bin/chrome", "https://x.com", "/tmp/p", "/tmp/a.png", 20)
    assert "--screenshot=/tmp/a.png" in argv
    assert "--dump-dom" not in argv


def test_render_without_a_browser_is_graceful(monkeypatch):
    monkeypatch.setattr(browser, "binary", lambda: None)
    r = run_coroutine(browser.render("https://x.com"))
    assert r.ok is False and "no Chrome" in r.error


# ---------------------------------------------------------------- engine

def test_engine_skips_silently_without_a_browser(monkeypatch):
    monkeypatch.setattr(browser, "available", lambda: False)
    logged = []

    async def log(level, msg, stage=None):
        logged.append(msg)

    out = run_coroutine(D._engine(["https://x.com/p"], {"log": log}))
    assert out == [], "a missing browser must never fail a scan"
    assert any("skipping" in m for m in logged)


def _fake_render(execute_on_fragment=True):
    async def _r(url, **kw):
        if "#" in url and execute_on_fragment:
            frag = url.split("#", 1)[1]
            # emulate a sink: if a canary is present in the payload, it "ran"
            import re
            from urllib.parse import unquote
            m = re.search(r"document\.title='(mrl[0-9a-f]+)'", unquote(frag))
            if m:
                return browser.Render(url=url, ok=True,
                                      dom=f"<html><head><title>{m.group(1)}</title></head></html>")
        return browser.Render(url=url, ok=True,
                              dom="<html><head><title>safe title</title></head></html>")
    return _r


def test_executed_payload_is_reported(monkeypatch):
    monkeypatch.setattr(browser, "available", lambda: True)
    monkeypatch.setattr(browser, "render", _fake_render(True))
    out = run_coroutine(D._engine(["https://x.com/p"], {}))
    assert len(out) == 1
    assert out[0]["rule_id"] == "domxss-executed"
    assert out[0]["severity"] is Severity.high
    assert out[0]["raw"]["vector"] == "fragment"


def test_page_without_a_sink_is_not_reported(monkeypatch):
    monkeypatch.setattr(browser, "available", lambda: True)
    monkeypatch.setattr(browser, "render", _fake_render(False))
    out = run_coroutine(D._engine(["https://x.com/p"], {}))
    assert out == [], "a page that never executes the payload is not DOM XSS"


def test_engine_registered_and_proves():
    from app.engines import registry
    registry.discover()
    spec = registry.get("domxss")
    assert spec is not None and "deep" in spec.default_in
    assert "domxss-executed" in spec.proves


def test_proof_tier_recognises_it():
    from app import verify
    assert verify.is_proven_rule("domxss", "domxss-executed") is True


# ---------------------------------------------------------------- render budget

def test_probe_values_collapse_the_markup_payloads():
    """One value carries every markup sink, so one load answers for all of them."""
    probes = D.probe_values("mrlCANARY")
    assert len(probes) == 2, "markup sinks combined, javascript: kept separate"
    markup, js = probes[0][0], probes[1][0]
    assert "<img" in markup and "<svg" in markup and "<script" in markup
    assert "mrlCANARY" in markup
    # javascript: only works when the WHOLE value is the URL, so it must not
    # have anything concatenated onto it.
    assert js.startswith("javascript:")
    assert "<img" not in js


def test_a_clean_host_costs_two_loads_per_vector(monkeypatch):
    """The regression this guards: it used to be five, plus a wasted baseline.

    Twenty-one loads per host is about thirteen minutes of a deep scan spent on
    pages that mostly have no DOM XSS at all.
    """
    monkeypatch.setattr(browser, "available", lambda: True)
    loads = []

    async def counting_render(url, **kw):
        loads.append(url)
        return browser.Render(url=url, ok=True,
                              dom="<html><head><title>safe</title></head></html>")

    monkeypatch.setattr(browser, "render", counting_render)
    # one fragment vector + two params = 3 vectors
    out = run_coroutine(D._engine(["https://x.com/p?a=1&b=2"], {}))
    assert out == []
    assert len(loads) == 3 * 2, f"expected 6 loads for a clean host, got {len(loads)}"


def test_no_baseline_load_is_made(monkeypatch):
    """Every load must carry a payload; a bare page load answered no question."""
    monkeypatch.setattr(browser, "available", lambda: True)
    loads = []

    async def counting_render(url, **kw):
        loads.append(url)
        return browser.Render(url=url, ok=True, dom="<title>safe</title>")

    monkeypatch.setattr(browser, "render", counting_render)
    run_coroutine(D._engine(["https://x.com/p"], {}))
    assert loads, "no loads at all"
    for u in loads:
        assert "#" in u or "=" in u, f"{u} looks like a payload-free baseline load"


def test_a_hit_names_the_specific_sink(monkeypatch):
    """On a hit the individual payloads are replayed to identify the sink."""
    monkeypatch.setattr(browser, "available", lambda: True)

    async def svg_only_render(url, **kw):
        import re
        from urllib.parse import unquote
        dec = unquote(url)
        # this page only executes the svg/onload form
        m = re.search(r"<svg onload=\"document\.title='(mrl[0-9a-f]+)'\">", dec)
        if m:
            return browser.Render(url=url, ok=True,
                                  dom=f"<title>{m.group(1)}</title>")
        return browser.Render(url=url, ok=True, dom="<title>safe</title>")

    monkeypatch.setattr(browser, "render", svg_only_render)
    out = run_coroutine(D._engine(["https://x.com/p"], {}))
    assert len(out) == 1
    assert out[0]["raw"]["sink"] == "innerHTML (svg/onload)", \
        "the combined probe fired, so the narrowing pass must name the real sink"


def test_probe_url_routes_by_vector():
    frag = D.probe_url("https://x.com/p?a=1", "fragment", "", "PAY")
    assert "#" in frag and "a=1" in frag
    par = D.probe_url("https://x.com/p?a=1&b=2", "param:a", "a", "PAY")
    assert "a=PAY" in par and "b=2" in par and "#" not in par
