"""Certificate transparency log discovery.

Every publicly trusted TLS certificate is logged, permanently and publicly, by
design. That makes CT logs the single richest source of hostnames — they show
names that were never in DNS enumeration results, never linked from anywhere,
and in many cases were never meant to be public at all: staging environments,
internal admin panels, forgotten pilot deployments, systems from an
acquisition nobody documented.

It's also entirely passive. Querying crt.sh sends not one packet to the target.

The wildcard note matters: a certificate for *.example.com tells you the
wildcard exists but not which hosts use it, so those entries are dropped rather
than fed forward as if they were real hosts.
"""

from __future__ import annotations

import asyncio
import json
import re

from .registry import EngineSpec, register

CRTSH = "https://crt.sh/?q=%25.{domain}&output=json"

# CT entries can contain several names separated by newlines, plus wildcards
# and the occasional malformed value.
_HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9\-_.]{0,253}[a-z0-9])?$", re.I)


async def _fetch(url: str, timeout: int = 45) -> str:
    try:
        proc = await asyncio.create_subprocess_exec(
            "curl", "-sS", "-L", "--max-time", str(timeout),
            "-H", "User-Agent: Mozilla/5.0 (security research)", url,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 10)
    except (asyncio.TimeoutError, OSError):
        return ""
    return out.decode("utf-8", "replace")


def parse_crtsh(body: str, apex: str) -> list[str]:
    """Extract hostnames from a crt.sh JSON response.

    Pure function — the parsing is the part worth testing, and it can be tested
    without touching the network.
    """
    try:
        entries = json.loads(body or "[]")
    except json.JSONDecodeError:
        return []
    if not isinstance(entries, list):
        return []

    apex = apex.lower().lstrip(".")
    found: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        blob = "\n".join(str(entry.get(k, "")) for k in ("name_value", "common_name"))
        for raw in blob.split("\n"):
            name = raw.strip().lower().rstrip(".")
            if not name:
                continue
            # A wildcard proves the wildcard exists, not that any given host
            # does. Feeding "*.example.com" forward would be meaningless.
            if name.startswith("*."):
                continue
            if not _HOST_RE.match(name):
                continue
            if name == apex or name.endswith("." + apex):
                found.add(name)
    return sorted(found)


@register(EngineSpec(
    name="ctlogs",
    label="Searching certificate transparency logs",
    description="Queries public CT logs for every certificate ever issued for the "
                "domain. Finds staging, internal and forgotten hosts that DNS "
                "enumeration never sees. Completely passive.",
    phase="early",
    takes="seeds",
    produces="hosts",
    weight=5,
    limit=3,
    default_in=("standard", "deep"),
))
async def _engine(targets: list[str], ctx: dict) -> list[str]:
    log = ctx.get("log")
    found: set[str] = set()

    for apex in targets:
        if apex.replace(".", "").isdigit():
            continue  # CT logs are indexed by name, not address
        if log:
            await log("info", f"[ctlogs] querying certificate transparency for {apex}",
                      "ctlogs")
        body = await _fetch(CRTSH.format(domain=apex))
        if not body:
            if log:
                await log("warn", "[ctlogs] crt.sh unreachable or rate-limited — "
                                  "skipping this source", "ctlogs")
            continue
        names = parse_crtsh(body, apex)
        found.update(names)
        if log:
            await log("info", f"[ctlogs] {len(names)} name(s) in certificates for {apex}",
                      "ctlogs")

    return sorted(found)
