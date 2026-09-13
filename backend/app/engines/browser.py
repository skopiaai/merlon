"""Headless Chrome, for the things a plain HTTP fetch cannot see.

Two whole classes of work need a browser and nothing else will do:

  * **DOM-based bugs.** When client-side JavaScript takes `location.hash` and
    writes it into `innerHTML`, the server never sees the payload and the
    response body never contains it. curl is blind to this by construction.
  * **Visual triage.** A screenshot of a hundred hosts is how a human finds the
    forgotten staging box in ten seconds.

Chrome is driven by its command line rather than a driver library, for the same
reasons `fetch.py` drives curl: no extra dependency, and a hung page is a dead
subprocess instead of a wedged task. `--dump-dom` prints the DOM *after*
JavaScript has run, which is exactly the artefact these checks need.

**Degrading gracefully is a requirement, not a nicety.** Merlon runs on
machines that may not have a browser, and a missing Chrome must never fail a
scan — `available()` returns False, engines skip, and everything else proceeds.
The container ships Chromium so this is normally present; outside it, whatever
Chrome is installed is used.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import tempfile
from dataclasses import dataclass

# Where a browser is normally found, in the order we prefer it. The container
# installs `chromium`; the macOS path is for running outside Docker.
_CANDIDATES = (
    "chromium",
    "chromium-browser",
    "google-chrome",
    "google-chrome-stable",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
)

# A page that has not settled in this long is not going to.
DEFAULT_TIMEOUT = 20

# A rendered DOM larger than this tells us nothing extra and costs memory in
# every engine holding one.
MAX_DOM = 3 * 1024 * 1024


@dataclass
class Render:
    """One headless page load."""
    url: str
    dom: str = ""
    ok: bool = False
    error: str = ""
    screenshot: str = ""      # path, when one was requested

    @property
    def title(self) -> str:
        """The rendered <title>, which is how a DOM-XSS proof is read back."""
        low = self.dom.lower()
        start = low.find("<title")
        if start == -1:
            return ""
        gt = low.find(">", start)
        end = low.find("</title>", gt)
        if gt == -1 or end == -1:
            return ""
        return self.dom[gt + 1:end].strip()


def binary() -> str | None:
    """Path to a usable Chrome/Chromium, or None."""
    override = os.getenv("MERLON_CHROME")
    if override:
        return override if os.path.exists(override) or shutil.which(override) else None
    for name in _CANDIDATES:
        if os.path.isabs(name):
            if os.path.exists(name):
                return name
        else:
            found = shutil.which(name)
            if found:
                return found
    return None


def available() -> bool:
    return binary() is not None


def _argv(chrome: str, url: str, profile: str, screenshot: str | None,
          timeout: int) -> list[str]:
    """The command line. Every flag here is either isolation or determinism."""
    argv = [
        chrome,
        "--headless=new",
        "--disable-gpu",
        # Containers run as a user without the kernel namespaces Chrome's
        # sandbox wants. The page is untrusted, so this is a real trade — it is
        # mitigated by the throwaway profile, no extensions, and the fact that
        # the process is killed after `timeout` seconds regardless.
        "--no-sandbox",
        "--disable-dev-shm-usage",
        f"--user-data-dir={profile}",     # throwaway: no cookies persist
        "--incognito",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-extensions",
        "--disable-background-networking",
        "--disable-sync",
        "--mute-audio",
        "--hide-scrollbars",
        "--ignore-certificate-errors",    # same posture as curl's -k
        f"--virtual-time-budget={timeout * 1000}",
        "--window-size=1280,900",
    ]
    if screenshot:
        argv.append(f"--screenshot={screenshot}")
    else:
        argv.append("--dump-dom")
    argv.append(url)
    return argv


async def render(url: str, *, timeout: int = DEFAULT_TIMEOUT,
                 screenshot: str | None = None) -> Render:
    """Load a URL in headless Chrome. Never raises — failure comes back as ok=False."""
    chrome = binary()
    if not chrome:
        return Render(url=url, error="no Chrome/Chromium available")

    profile = tempfile.mkdtemp(prefix="merlon-chrome-")
    try:
        argv = _argv(chrome, url, profile, screenshot, timeout)
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL)
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 10)
        except (asyncio.TimeoutError, OSError) as exc:
            return Render(url=url, error=f"render failed: {exc}")
        except Exception as exc:  # noqa: BLE001 — a bad page must not kill a scan
            return Render(url=url, error=f"render failed: {exc}")

        if screenshot:
            ok = os.path.exists(screenshot) and os.path.getsize(screenshot) > 0
            return Render(url=url, ok=ok, screenshot=screenshot if ok else "",
                          error="" if ok else "no screenshot produced")

        dom = (out or b"")[:MAX_DOM].decode("utf-8", "replace")
        return Render(url=url, dom=dom, ok=bool(dom.strip()))
    finally:
        shutil.rmtree(profile, ignore_errors=True)
