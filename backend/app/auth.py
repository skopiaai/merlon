"""Authenticated scanning support.

The single largest coverage gain available. Logged out, a scanner sees the
marketing site. Logged in, it sees the application — which is where the data,
the privileged functions, and the interesting bugs are.

Two things matter for this to be useful rather than misleading:

1. **Verify the session before scanning.** A stale cookie means every stage
   runs against the logged-out view while the UI claims otherwise. We check
   first and say so plainly if it isn't working.

2. **Never send credentials off-scope.** Auth headers go only to hosts that
   pass the engagement's scope check — sending a session cookie to a
   third-party host discovered during enumeration would be a real incident.
"""

from __future__ import annotations

import asyncio
import shutil
from urllib.parse import urlparse

from .scope import check as scope_check


def header_args(headers: dict, prefix: str = "-H") -> list[str]:
    """Render headers as repeated CLI flags for the ProjectDiscovery tools."""
    argv: list[str] = []
    for key, value in (headers or {}).items():
        if not key or value is None:
            continue
        argv += [prefix, f"{key}: {value}"]
    return argv


def scoped_headers(url: str, headers: dict, allow: list[str], deny: list[str]) -> dict:
    """Return the auth headers only if this URL is in scope.

    Called before any request that would carry credentials. Enumeration
    routinely turns up hosts that aren't yours; sending a session cookie to one
    would leak the session to a third party.
    """
    if not headers:
        return {}
    host = urlparse(url).hostname or url
    return dict(headers) if scope_check(host, allow, deny).allowed else {}


async def verify_session(check_url: str, check_string: str, headers: dict,
                         *, log=None) -> tuple[bool, str]:
    """Confirm the credentials actually produce an authenticated session.

    Returns (ok, human-readable reason). Uses curl, which is already in the
    image, so this adds no dependency.
    """
    if not headers:
        return False, "no credentials configured"
    if not check_url:
        return True, "no verification URL set — proceeding without checking"
    if not shutil.which("curl"):
        return True, "curl unavailable — cannot verify, proceeding"

    argv = ["curl", "-sS", "-L", "--max-time", "20", "-o", "-", "-w", "\n%{http_code}"]
    for key, value in headers.items():
        argv += ["-H", f"{key}: {value}"]
    argv.append(check_url)

    try:
        proc = await asyncio.create_subprocess_exec(
            *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
    except (asyncio.TimeoutError, OSError):
        return False, f"could not reach {check_url}"

    body = out.decode("utf-8", "replace")
    status = body.rsplit("\n", 1)[-1].strip()

    if status.startswith("3") or status in ("401", "403"):
        return False, (f"{check_url} returned HTTP {status} — the session looks "
                       f"expired or the credentials are wrong")

    if check_string:
        if check_string in body:
            return True, f"session verified — found {check_string!r} at {check_url}"
        return False, (f"{check_url} returned HTTP {status} but {check_string!r} was not "
                       f"present — you are probably seeing the logged-out page")

    return True, f"{check_url} returned HTTP {status} (no check string configured)"


async def verify_identities(identities: list[dict], *, log=None) -> list[dict]:
    """Check each additional account, returning only the ones that work.

    Dropping a dead identity rather than carrying it is the important part. An
    expired second session produces results that look like a clean bill of
    health: "account B could not read account A's data" reads identically
    whether B was stopped by authorization or was simply logged out. Silence
    from a broken tool is indistinguishable from silence from a secure
    application, so the broken tool has to remove itself.
    """
    live: list[dict] = []
    for index, identity in enumerate(identities or []):
        name = identity.get("name") or f"identity-{index + 1}"
        headers = identity.get("headers") or {}
        if not headers:
            if log:
                await log("warn", f"identity {name!r} has no credentials — skipped",
                          "seed")
            continue

        ok, reason = await verify_session(
            identity.get("check_url", ""), identity.get("check_string", ""), headers)
        if log:
            await log("info" if ok else "warn",
                      f"identity {name!r}: {reason}", "seed")
        if ok:
            live.append({**identity, "name": name})
    return live


def identity_summary(identities: list[dict]) -> str:
    """One line for the report, with no credential material in it."""
    if not identities:
        return "single session"
    names = ", ".join(f"{i.get('name')} ({i.get('role') or 'unspecified role'})"
                      for i in identities)
    return f"{len(identities)} additional identity(ies): {names}"


def describe(headers: dict) -> str:
    """Summarise configured auth without echoing secrets into logs or reports."""
    if not headers:
        return "unauthenticated"
    names = []
    for key, value in headers.items():
        v = str(value)
        names.append(f"{key} ({len(v)} chars, ends …{v[-4:]})" if len(v) > 8 else key)
    return "authenticated via " + ", ".join(names)
