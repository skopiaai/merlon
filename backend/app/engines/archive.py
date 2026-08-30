"""Historical URL discovery from the Wayback Machine.

A crawler only sees what the site links to today. The archive sees what it
linked to for the last twenty years — and old endpoints are frequently still
live, unmaintained, and running code nobody has looked at since.

This is one of the highest-yield techniques in bug bounty precisely because
nobody defends it: teams harden what's on the current sitemap, not the admin
panel from a 2018 redesign that still answers.

It also recovers **parameter names**, which is what turns a URL list into an
IDOR/SSRF hunting list. Passive: the requests go to archive.org, not the target.
"""

from __future__ import annotations

import asyncio
from urllib.parse import urlparse

from .registry import EngineSpec, register

CDX = ("https://web.archive.org/cdx/search/cdx"
       "?url=*.{domain}/*&output=text&fl=original&collapse=urlkey"
       "&filter=!statuscode:404&limit={limit}")

# Static assets dominate archive results and are almost never interesting.
BORING_EXT = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp4", ".webm", ".mp3", ".avi", ".mov",
)

# Extensions worth surfacing on their own — an archived .sql or .bak that is
# still served is a finding in itself.
INTERESTING_EXT = (
    ".sql", ".bak", ".backup", ".old", ".zip", ".tar", ".gz", ".7z", ".rar",
    ".env", ".config", ".conf", ".ini", ".yml", ".yaml", ".log", ".xml",
    ".json", ".db", ".sqlite", ".pem", ".key", ".pfx",
)


async def _fetch(url: str, timeout: int = 60) -> str:
    try:
        proc = await asyncio.create_subprocess_exec(
            "curl", "-sS", "-L", "--max-time", str(timeout),
            "-H", "User-Agent: Mozilla/5.0 (security research)", url,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 10)
    except (asyncio.TimeoutError, OSError):
        return ""
    return out.decode("utf-8", "replace")


def filter_urls(raw: str, apex: str, cap: int = 3000) -> list[str]:
    """Clean an archive response into URLs worth probing.

    Pure function. Deduplicates by path+parameter-names rather than by full
    URL, because /item?id=1 and /item?id=999 are the same endpoint and keeping
    both just makes the list longer without widening the surface.
    """
    apex = apex.lower().lstrip(".")
    seen_shape: set[str] = set()
    out: list[str] = []

    for line in (raw or "").splitlines():
        url = line.strip()
        if not url or "://" not in url:
            continue
        try:
            p = urlparse(url)
        except ValueError:
            continue
        host = (p.hostname or "").lower()
        if not host or not (host == apex or host.endswith("." + apex)):
            continue

        path = p.path or "/"
        if path.lower().endswith(BORING_EXT):
            continue

        params = tuple(sorted(
            kv.split("=")[0] for kv in (p.query or "").split("&") if kv))
        shape = f"{host}{path}?{','.join(params)}"
        if shape in seen_shape:
            continue
        seen_shape.add(shape)

        out.append(url)
        if len(out) >= cap:
            break
    return out


def interesting(urls: list[str]) -> list[str]:
    """Archived URLs that would be a finding if they still resolve."""
    return [u for u in urls
            if (urlparse(u).path or "").lower().endswith(INTERESTING_EXT)][:100]


@register(EngineSpec(
    name="archive",
    label="Recovering historical URLs",
    description="Pulls every URL the Wayback Machine ever recorded for the domain. "
                "Surfaces dead-but-live endpoints, forgotten admin paths and old "
                "parameter names. Passive — requests go to archive.org.",
    phase="early",
    takes="seeds",
    produces="urls",
    weight=8,
    limit=3,
    default_in=("standard", "deep"),
))
async def _engine(targets: list[str], ctx: dict) -> list[str]:
    log = ctx.get("log")
    found: list[str] = []

    for apex in targets:
        if apex.replace(".", "").isdigit():
            continue
        if log:
            await log("info", f"[archive] querying the Wayback Machine for {apex}",
                      "archive")
        body = await _fetch(CDX.format(domain=apex, limit=20000))
        if not body:
            if log:
                await log("warn", "[archive] archive.org unreachable — skipping",
                          "archive")
            continue

        urls = filter_urls(body, apex)
        found += urls
        notable = interesting(urls)
        if log:
            await log("info", f"[archive] {len(urls)} distinct endpoint shape(s) "
                              f"recovered for {apex}", "archive")
            if notable:
                await log("warn",
                          f"[archive] {len(notable)} archived URL(s) point at backups "
                          f"or config files — check whether they still resolve: "
                          f"{', '.join(notable[:3])}", "archive")

    return sorted(set(found))
