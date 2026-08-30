"""Recon engines: subfinder (passive DNS), naabu (ports), httpx (live web).

Each returns plain dicts; the orchestrator handles scope filtering and
persistence. Keeping these pure makes them trivially unit-testable.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import tempfile

from ..auth import header_args as _auth_args
from .base import LogFn, stream_jsonl

# Profiles tune noise vs. coverage. `passive` never touches the target.
PROFILES = {
    # Sprint trades coverage for latency: high rate, no port scanning, and
    # nuclei restricted to the two severities that are worth interrupting
    # someone for. Used when being first to report matters more than being
    # thorough — a new program, or a scope list published at the start of a
    # competition.
    "sprint":   {"ports": None,       "rate": 150, "conc": 25, "nuclei_sev": "critical,high"},
    "passive":  {"ports": None,       "rate": 20,  "conc": 5,  "nuclei_sev": "medium,high,critical"},
    "standard": {"ports": "top-100",  "rate": 60,  "conc": 15, "nuclei_sev": "low,medium,high,critical"},
    "thorough": {"ports": "top-1000", "rate": 120, "conc": 25, "nuclei_sev": "info,low,medium,high,critical"},
}


async def subfinder(domains: list[str], *, log: LogFn | None = None) -> list[str]:
    """Passive subdomain enumeration. No packets hit the target."""
    if not domains:
        return []
    argv = ["subfinder", "-silent", "-json", "-all", "-duc"]
    for d in domains:
        argv += ["-d", d]

    hosts: list[str] = []
    async for rec in stream_jsonl(argv, engine="subfinder", log=log, timeout=900):
        host = rec.get("host") or rec.get("input")
        if host:
            hosts.append(host.lower())
    return sorted(set(hosts))


async def permute(known: list[str], apex: list[str], *, rate: int = 60,
                  cap: int = 20_000, log: LogFn | None = None) -> list[str]:
    """Generate and resolve subdomain permutations.

    Passive enumeration only finds names someone has already published. The
    biggest single gap versus BBOT and reconFTW was that we stopped there —
    permutation finds the hosts nobody indexed: dev-api, api-staging, api2,
    internal-portal.

    alterx builds candidates from the names already discovered (so the patterns
    match how this organisation actually names things), then dnsx resolves them.
    Only names that resolve are kept, so nothing invented reaches a later stage.
    """
    if not known and not apex:
        return []
    if not shutil.which("alterx") or not shutil.which("dnsx"):
        if log:
            await log("warn", "[permute] alterx or dnsx unavailable — skipping "
                              "permutation; passive results only", "permute")
        return []

    seed = sorted(set(known) | set(apex))
    if log:
        await log("info", f"[permute] generating candidates from {len(seed)} known name(s)",
                  "permute")

    # --- generate ---
    fd, seed_path = tempfile.mkstemp(prefix="alterx_seed_", suffix=".txt")
    with os.fdopen(fd, "w") as fh:
        fh.write("\n".join(seed) + "\n")
    try:
        proc = await asyncio.create_subprocess_exec(
            "alterx", "-silent", "-l", seed_path,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
    except (asyncio.TimeoutError, OSError):
        return []
    finally:
        try:
            os.unlink(seed_path)
        except OSError:
            pass

    candidates = [c for c in out.decode("utf-8", "replace").split()
                  if c and c not in set(seed)]
    if not candidates:
        return []

    # A permutation list can run to millions. Cap it, or resolution becomes the
    # longest stage in the scan for very little extra yield.
    truncated = len(candidates) > cap
    candidates = candidates[:cap]
    if log:
        await log("info",
                  f"[permute] resolving {len(candidates)} candidate(s)"
                  f"{' (capped)' if truncated else ''}", "permute")

    # --- resolve: only names that actually exist survive ---
    resolved: list[str] = []
    argv = ["dnsx", "-silent", "-json", "-a", "-resp",
            "-retry", "1", "-t", str(max(rate, 50))]
    async for rec in stream_jsonl(argv, engine="permute", input_lines=candidates,
                                  input_flag="-l", log=log, timeout=1800):
        host = (rec.get("host") or "").lower()
        if host and rec.get("a"):
            resolved.append(host)

    found = sorted(set(resolved) - set(seed))
    if log:
        await log("info", f"[permute] {len(found)} new host(s) that passive "
                          f"enumeration missed", "permute")
    return found


async def naabu(hosts: list[str], *, ports: str = "top-100", rate: int = 60,
                log: LogFn | None = None) -> list[dict]:
    """TCP connect scan. Connect mode (-s c) avoids needing root/CAP_NET_RAW."""
    if not hosts or not ports:
        return []
    argv = ["naabu", "-silent", "-json", "-s", "c", "-rate", str(rate), "-retries", "1"]
    if ports == "top-100":
        argv += ["-top-ports", "100"]
    elif ports == "top-1000":
        argv += ["-top-ports", "1000"]
    else:
        argv += ["-p", ports]

    out = []
    async for rec in stream_jsonl(argv, engine="naabu", input_lines=hosts,
                                  input_flag="-list", log=log, timeout=1800):
        out.append({
            "host": (rec.get("host") or rec.get("ip") or "").lower(),
            "ip": rec.get("ip", ""),
            "port": rec.get("port"),
        })
    return out


async def httpx(targets: list[str], *, concurrency: int = 15, rate: int = 60,
                auth_headers: dict | None = None,
                log: LogFn | None = None) -> list[dict]:
    """Probe for live HTTP services and fingerprint them."""
    if not targets:
        return []
    argv = [
        "httpx", "-silent", "-json", "-no-color",
        "-status-code", "-title", "-tech-detect", "-web-server",
        "-include-response-header",   # needed for the header/cookie audit
        "-follow-redirects", "-max-redirects", "3",
        "-threads", str(concurrency), "-rate-limit", str(rate),
        "-timeout", "10", "-retries", "1",
    ]
    argv += _auth_args(auth_headers)

    out = []
    async for rec in stream_jsonl(argv, engine="httpx", input_lines=targets,
                                  input_flag="-list", log=log, timeout=1800):
        out.append({
            "host": (rec.get("host") or rec.get("input") or "").lower(),
            "url": rec.get("url", ""),
            "ip": rec.get("host", "") if rec.get("a") is None else (rec.get("a") or [""])[0],
            "port": int(rec["port"]) if str(rec.get("port", "")).isdigit() else None,
            "status_code": rec.get("status_code"),
            "title": rec.get("title", "") or "",
            "tech": rec.get("tech", []) or [],
            "webserver": rec.get("webserver", "") or "",
            # httpx has used both keys across versions.
            "headers": rec.get("header") or rec.get("response_headers") or {},
            "raw": rec,
        })
    return out


async def katana(urls: list[str], *, concurrency: int = 10, depth: int = 2,
                 auth_headers: dict | None = None,
                 log: LogFn | None = None) -> list[str]:
    """Crawl for endpoints. Feeds nuclei better coverage than roots alone."""
    if not urls:
        return []
    argv = [
        "katana", "-silent", "-jsonl", "-no-color",
        "-depth", str(depth), "-concurrency", str(concurrency),
        "-rate-limit", "50", "-timeout", "10",
        "-strategy", "breadth-first", "-known-files", "all",
    ]
    argv += _auth_args(auth_headers)

    found: list[str] = []
    async for rec in stream_jsonl(argv, engine="katana", input_lines=urls,
                                  input_flag="-list", log=log, timeout=1800):
        endpoint = rec.get("endpoint") or (rec.get("request") or {}).get("endpoint")
        if endpoint:
            found.append(endpoint)
    return sorted(set(found))
