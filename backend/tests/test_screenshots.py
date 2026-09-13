"""Screenshot capture for visual triage."""

from pathlib import Path

from app.engines import browser
from app.engines import screenshots as S

from .conftest import run_coroutine


def test_safe_name_is_filesystem_safe_and_unique():
    a = S.safe_name("https://ex.ample.com/path?q=1")
    b = S.safe_name("https://ex.ample.com/other?q=2")
    assert a.endswith(".png") and b.endswith(".png")
    assert a != b, "different URLs must not collide"
    assert "/" not in a and "?" not in a and ":" not in a


def test_safe_name_separates_ports():
    assert S.safe_name("https://h.com:8443/") != S.safe_name("https://h.com/")
    assert "8443" in S.safe_name("https://h.com:8443/")


def test_safe_name_cannot_escape_its_directory():
    """The property that actually matters: the file lands inside out_dir."""
    out = Path("/tmp/shots")
    for hostile in ("https://../../etc/passwd", "https://a/..%2f..%2fx",
                    "https://../", "https://%2e%2e/x"):
        name = S.safe_name(hostile)
        assert "/" not in name and "\\" not in name
        assert not name.startswith(".")
        resolved = (out / name).resolve()
        assert resolved.parent == out.resolve(), f"{hostile} escaped to {resolved}"


def test_skips_without_a_browser(monkeypatch):
    monkeypatch.setattr(browser, "available", lambda: False)
    logged = []

    async def log(level, msg, stage=None):
        logged.append(msg)

    assert run_coroutine(S._engine(["https://x.com"], {"log": log})) == []
    assert any("skipping" in m for m in logged)


def test_one_shot_per_host(tmp_path, monkeypatch):
    monkeypatch.setattr(browser, "available", lambda: True)
    monkeypatch.setattr(S, "shot_dir", lambda sid: Path(tmp_path))
    rendered = []

    async def fake_render(url, **kw):
        rendered.append(url)
        Path(kw["screenshot"]).write_bytes(b"\x89PNG fake")
        return browser.Render(url=url, ok=True, screenshot=kw["screenshot"])

    monkeypatch.setattr(browser, "render", fake_render)
    out = run_coroutine(S._engine(
        ["https://a.com/1", "https://a.com/2", "https://b.com/1"], {}))
    assert out == [], "screenshots are context, not findings"
    assert len(rendered) == 2, "one shot per host, not per URL"
    assert len(list(Path(tmp_path).glob("*.png"))) == 2


def test_failed_render_is_not_counted(tmp_path, monkeypatch):
    monkeypatch.setattr(browser, "available", lambda: True)
    monkeypatch.setattr(S, "shot_dir", lambda sid: Path(tmp_path))

    async def fake_render(url, **kw):
        return browser.Render(url=url, ok=False, error="boom")

    monkeypatch.setattr(browser, "render", fake_render)
    assert run_coroutine(S._engine(["https://a.com/"], {})) == []


def test_engine_registered_and_produces_no_findings():
    from app.engines import registry
    registry.discover()
    spec = registry.get("screenshots")
    assert spec is not None and "deep" in spec.default_in
    assert spec.proves == (), "a screenshot is not a proof of anything"
