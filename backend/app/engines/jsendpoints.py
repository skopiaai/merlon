"""API endpoint extraction from JavaScript.

A single-page application ships its entire API surface to the browser. The
routes are all there in the bundle — including the ones the UI only calls for
admin users, the ones behind a feature flag, and the ones left over from a
feature that was removed from the interface but not from the server.

A crawler will never find those, because nothing links to them. Reading the
bundle does, and those endpoints are disproportionately where broken access
control lives: nobody hardens a route they think is invisible.
"""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urljoin, urlparse

from .registry import EngineSpec, register

SCRIPT_SRC = re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"']", re.I)

# Paths in quotes. Deliberately conservative: matching every string that starts
# with a slash produces mountains of noise from CSS selectors and regexes.
PATH_PATTERNS = [
    # "/api/v1/users", '/admin/settings'
    re.compile(r"[\"'](/(?:api|v\d|rest|graphql|admin|internal|auth|oauth|user|account|"
               r"upload|download|export|report|webhook|callback|payment|order|invoice)"
               r"[a-zA-Z0-9_\-/.{}:$]*)[\"']"),
    # fetch("/something"), axios.get('/something')
    re.compile(r"(?:fetch|axios\.\w+|\.open)\s*\(\s*[\"'](/[a-zA-Z0-9_\-/.{}:$]{2,80})[\"']"),
    # url: "/something"
    re.compile(r"(?:url|endpoint|path|route|uri)\s*:\s*[\"'](/[a-zA-Z0-9_\-/.{}:$]{2,80})[\"']"),
    # Absolute API URLs
    re.compile(r"[\"'](https?://[a-z0-9.\-]+/(?:api|v\d|graphql)[a-zA-Z0-9_\-/.{}:$]*)[\"']", re.I),
]

# Obvious non-endpoints that slip through.
NOISE = re.compile(
    r"\.(?:png|jpe?g|gif|svg|ico|css|woff2?|ttf|eot|map|mp4|webm)$"
    r"|^/(?:\*|#|%|\$|\.|\s)"
    r"|[<>\\]",
    re.I)


async def _get(url: str, timeout: int = 20) -> str:
    try:
        proc = await asyncio.create_subprocess_exec(
            "curl", "-sS", "-L", "--max-time", str(timeout), "--max-redirs", "3", url,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 5)
    except (asyncio.TimeoutError, OSError):
        return ""
    return out.decode("utf-8", "replace")


def extract_paths(js: str) -> set[str]:
    """Endpoint paths found in a JavaScript source. Pure and testable."""
    found: set[str] = set()
    for pattern in PATH_PATTERNS:
        for match in pattern.findall(js or ""):
            path = match.strip()
            if len(path) < 3 or len(path) > 200:
                continue
            if NOISE.search(path):
                continue
            found.add(path)
    return found


def to_urls(paths: set[str], base: str) -> list[str]:
    """Resolve extracted paths against the page they came from, keeping only
    same-origin results — a third party's API is not this target's surface."""
    origin = urlparse(base)
    host = (origin.hostname or "").lower()
    out: set[str] = set()

    for path in paths:
        if path.startswith("http"):
            if (urlparse(path).hostname or "").lower().endswith(host):
                out.add(path)
            continue
        # Template placeholders can't be requested as-is; keep the prefix,
        # which is still a real endpoint worth probing.
        clean = re.split(r"[{$:]", path)[0].rstrip("/") or "/"
        out.add(urljoin(f"{origin.scheme}://{origin.netloc}", clean))
    return sorted(out)


@register(EngineSpec(
    name="jsendpoints",
    label="Extracting API routes from JavaScript",
    description="Reads the site's own bundles for API paths. Finds admin and "
                "feature-flagged routes the interface never links to — "
                "disproportionately where broken access control lives.",
    phase="post_http",
    takes="urls",
    produces="urls",
    weight=7,
    limit=10,
    default_in=("standard", "deep"),
))
async def _engine(targets: list[str], ctx: dict) -> list[str]:
    log = ctx.get("log")
    seen_scripts: set[str] = set()
    paths: set[str] = set()
    out: list[str] = []

    for page in targets:
        html = await _get(page)
        if not html:
            continue
        host = (urlparse(page).hostname or "").lower()

        # Inline scripts count too.
        found = extract_paths(html)

        scripts = [urljoin(page, src) for src in SCRIPT_SRC.findall(html)]
        scripts = [s for s in scripts
                   if (urlparse(s).hostname or "").lower().endswith(host)]

        for script in scripts[:15]:
            if script in seen_scripts:
                continue
            seen_scripts.add(script)
            body = await _get(script)
            if body:
                found |= extract_paths(body)

        paths |= found
        out += to_urls(found, page)

    result = sorted(set(out))
    if log:
        await log("info",
                  f"[jsendpoints] {len(paths)} path(s) in {len(seen_scripts)} bundle(s) "
                  f"→ {len(result)} URL(s) to test", "jsendpoints")
        admin = [p for p in paths if re.search(r"admin|internal|debug|private", p, re.I)]
        if admin:
            await log("warn",
                      f"[jsendpoints] {len(admin)} route(s) look privileged — worth "
                      f"checking whether a normal account can reach them: "
                      f"{', '.join(sorted(admin)[:4])}", "jsendpoints")
    return result
