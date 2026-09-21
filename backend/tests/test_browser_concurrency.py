"""The global cap on Chrome processes.

Page loads are latency-bound, so running hosts together is most of the win in
the browser engines. The thing that must not break while doing it: the number of
Chrome processes alive at once is bounded *across the whole scan*, not per
engine — domxss and screenshots run in the same phase, and a per-engine limit
would multiply into a swapping scan box.
"""

import asyncio

from app.engines import browser
from app.engines import domxss as D
from app.engines import screenshots as S

from .conftest import run_coroutine


class _Tracker:
    """Counts how many renders are in flight at once."""

    def __init__(self, delay=0.02, dom="<title>safe</title>"):
        self.live = 0
        self.peak = 0
        self.total = 0
        self.delay = delay
        self.dom = dom

    async def render(self, url, **kw):
        self.live += 1
        self.peak = max(self.peak, self.live)
        self.total += 1
        try:
            await asyncio.sleep(self.delay)
            if kw.get("screenshot"):
                with open(kw["screenshot"], "wb") as fh:
                    fh.write(b"\x89PNG stub")
                return browser.Render(url=url, ok=True, screenshot=kw["screenshot"])
            return browser.Render(url=url, ok=True, dom=self.dom)
        finally:
            self.live -= 1


def test_semaphore_is_rebuilt_per_event_loop():
    """A primitive bound to a closed loop is a hang waiting to happen."""
    first = run_coroutine(_get_sem())
    second = run_coroutine(_get_sem())
    assert first is not second, "each loop must get its own semaphore"


async def _get_sem():
    return browser._semaphore()


def test_render_never_exceeds_the_cap(monkeypatch):
    """The real guard: the cap is enforced inside browser.render itself."""
    monkeypatch.setattr(browser, "MAX_BROWSERS", 2)
    monkeypatch.setattr(browser, "_slots", None)
    monkeypatch.setattr(browser, "_slots_loop", None)
    monkeypatch.setattr(browser, "binary", lambda: "/bin/true")

    live = {"now": 0, "peak": 0}

    class _Proc:
        async def communicate(self):
            live["now"] += 1
            live["peak"] = max(live["peak"], live["now"])
            await asyncio.sleep(0.02)
            live["now"] -= 1
            return (b"<title>t</title>", b"")

    async def fake_exec(*a, **kw):
        return _Proc()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

    async def drive():
        await asyncio.gather(*(browser.render(f"https://x.com/{i}")
                               for i in range(10)))
    run_coroutine(drive())
    assert live["peak"] <= 2, f"cap of 2 exceeded: {live['peak']} at once"


def test_domxss_examines_hosts_concurrently(monkeypatch):
    monkeypatch.setattr(browser, "available", lambda: True)
    tracker = _Tracker()
    monkeypatch.setattr(browser, "render", tracker.render)

    urls = [f"https://h{i}.com/p" for i in range(6)]
    out = run_coroutine(D._engine(urls, {}))
    assert out == []
    assert tracker.peak > 1, "hosts were still examined one at a time"


def test_screenshots_capture_concurrently(tmp_path, monkeypatch):
    monkeypatch.setattr(browser, "available", lambda: True)
    monkeypatch.setattr(S, "shot_dir", lambda sid: tmp_path)
    tracker = _Tracker()
    monkeypatch.setattr(browser, "render", tracker.render)

    urls = [f"https://h{i}.com/" for i in range(6)]
    assert run_coroutine(S._engine(urls, {})) == []
    assert tracker.peak > 1, "screenshots were still captured one at a time"
    assert len(list(tmp_path.glob("*.png"))) == 6


def test_one_finding_per_host_survives_concurrency(monkeypatch):
    """Parallel hosts must not produce duplicates for the same host."""
    monkeypatch.setattr(browser, "available", lambda: True)

    async def always_fires(url, **kw):
        import re
        from urllib.parse import unquote
        m = re.search(r"document\.title='(mrl[0-9a-f]+)'", unquote(url))
        return browser.Render(url=url, ok=True,
                              dom=f"<title>{m.group(1) if m else 'safe'}</title>")

    monkeypatch.setattr(browser, "render", always_fires)
    # same host, three different pages
    out = run_coroutine(D._engine(
        ["https://one.com/a", "https://one.com/b", "https://one.com/c"], {}))
    assert len(out) == 1, "one host must yield one finding, not one per page"


def test_a_failing_host_does_not_sink_the_others(monkeypatch):
    """gather(return_exceptions=True): one bad page must not lose the rest."""
    monkeypatch.setattr(browser, "available", lambda: True)

    async def explode_on_one(url, **kw):
        if "boom.com" in url:
            raise RuntimeError("chrome died")
        import re
        from urllib.parse import unquote
        m = re.search(r"document\.title='(mrl[0-9a-f]+)'", unquote(url))
        return browser.Render(url=url, ok=True,
                              dom=f"<title>{m.group(1) if m else 'safe'}</title>")

    monkeypatch.setattr(browser, "render", explode_on_one)
    out = run_coroutine(D._engine(["https://boom.com/p", "https://fine.com/p"], {}))
    assert len(out) == 1 and out[0]["host"] == "fine.com"


def test_cap_default_is_sane():
    assert browser.MAX_BROWSERS >= 1
