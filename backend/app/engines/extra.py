"""Additional engines beyond the core recon path.

Each returns plain dicts. Scope filtering and persistence stay in the
orchestrator so these remain independently testable.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil

from .base import LogFn, stream_jsonl

# The SecLists tarball extracts as Discovery/Web-Content/… — the earlier paths
# here were missing that "Discovery" level, so ffuf silently skipped every run.
WORDLIST_DIRS = [
    "/opt/wordlists/Discovery/Web-Content/raft-medium-directories.txt",
    "/opt/wordlists/Discovery/Web-Content/common.txt",
    "/opt/wordlists/Discovery/Web-Content/directory-list-2.3-small.txt",
    "/opt/wordlists/Web-Content/raft-medium-directories.txt",
    "/opt/wordlists/Web-Content/common.txt",
    "/opt/wordlists/common.txt",
]


def find_wordlist() -> str | None:
    """First existing candidate, else any .txt under /opt/wordlists."""
    for path in WORDLIST_DIRS:
        if os.path.exists(path):
            return path
    for root, _dirs, files in os.walk("/opt/wordlists"):
        for name in ("common.txt", "raft-medium-directories.txt"):
            if name in files:
                return os.path.join(root, name)
    return None


async def dnsx(hosts: list[str], *, log: LogFn | None = None) -> list[dict]:
    """Resolve DNS records. CNAME chains are what reveal subdomain takeovers."""
    if not hosts:
        return []
    argv = ["dnsx", "-silent", "-json", "-a", "-aaaa", "-cname", "-resp",
            "-retry", "2"]
    out = []
    async for rec in stream_jsonl(argv, engine="dnsx", input_lines=hosts,
                                  input_flag="-l", log=log, timeout=900):
        out.append({
            "host": (rec.get("host") or "").lower(),
            "a": rec.get("a") or [],
            "cname": rec.get("cname") or [],
            "raw": rec,
        })
    return out


async def tlsx(targets: list[str], *, log: LogFn | None = None) -> list[dict]:
    """Inspect TLS: expiry, self-signed, hostname mismatch, weak versions."""
    if not targets:
        return []
    argv = ["tlsx", "-silent", "-json", "-expired", "-self-signed", "-mismatched",
            "-untrusted", "-tls-version", "-cipher", "-c", "10"]
    out = []
    async for rec in stream_jsonl(argv, engine="tlsx", input_lines=targets,
                                  input_flag="-l", log=log, timeout=1200):
        out.append(rec)
    return out


async def cdncheck(hosts: list[str], *, log: LogFn | None = None) -> dict[str, str]:
    """Map host -> CDN/WAF provider.

    Worth knowing before you interpret results: a host behind Cloudflare that
    returns nothing may be well protected rather than well configured.
    """
    if not hosts or not shutil.which("cdncheck"):
        return {}
    argv = ["cdncheck", "-silent", "-json", "-resp"]
    found: dict[str, str] = {}
    async for rec in stream_jsonl(argv, engine="cdncheck", input_lines=hosts,
                                  input_flag="-i", log=log, timeout=600):
        host = (rec.get("input") or rec.get("host") or "").lower()
        provider = rec.get("cdn_name") or rec.get("waf_name") or rec.get("cloud_name")
        if host and provider:
            found[host] = provider
    return found


async def nmap(targets: list[str], *, top_ports: int = 200, log: LogFn | None = None) -> list[dict]:
    """Service and version detection.

    naabu answers "is this port open"; nmap answers "what is actually
    listening and what version" — which is what turns an open port into an
    actionable finding.
    """
    if not targets or not shutil.which("nmap"):
        return []

    out_path = "/tmp/nmap_scan.xml"
    argv = [
        "nmap", "-sV", "--version-intensity", "5",
        "--top-ports", str(top_ports),
        "-T3",                       # polite timing; -T4/-T5 trips rate limits
        "--open", "-Pn", "-n",
        "-oX", out_path,
        *targets,
    ]
    if log:
        await log("info", f"[nmap] scanning {len(targets)} host(s)", "nmap")

    proc = await asyncio.create_subprocess_exec(
        *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    try:
        async with asyncio.timeout(3600):
            await proc.communicate()
    except TimeoutError:
        proc.kill()
        await proc.wait()
        if log:
            await log("warn", "[nmap] timed out", "nmap")
        return []

    if not os.path.exists(out_path):
        return []

    # Stdlib XML parser; nmap output is trusted local input.
    import xml.etree.ElementTree as ET

    services = []
    try:
        root = ET.parse(out_path).getroot()
    except ET.ParseError:
        return []

    for host_el in root.findall("host"):
        addr_el = host_el.find("address")
        ip = addr_el.get("addr", "") if addr_el is not None else ""
        names = [h.get("name", "") for h in host_el.findall("hostnames/hostname")]
        hostname = names[0] if names else ip

        for port_el in host_el.findall("ports/port"):
            state = port_el.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port_el.find("service")
            services.append({
                "host": hostname.lower(),
                "ip": ip,
                "port": int(port_el.get("portid", 0)),
                "protocol": port_el.get("protocol", "tcp"),
                "service": svc.get("name", "") if svc is not None else "",
                "product": svc.get("product", "") if svc is not None else "",
                "version": svc.get("version", "") if svc is not None else "",
                "extrainfo": svc.get("extrainfo", "") if svc is not None else "",
            })

    os.remove(out_path)
    return services


async def ffuf(url: str, *, rate: int = 40, log: LogFn | None = None) -> list[dict]:
    """Content discovery — find paths that aren't linked from anywhere.

    Deliberately rate-limited and capped: this is the noisiest thing the
    pipeline does, and an unbounded run against someone's production box is
    how you get your IP banned from a bounty program.
    """
    wordlist = find_wordlist()
    if not wordlist or not shutil.which("ffuf"):
        if log:
            await log("warn", "[ffuf] no wordlist found under /opt/wordlists — skipping", "ffuf")
        return []
    if log:
        await log("info", f"[ffuf] using {wordlist}", "ffuf")

    out_path = "/tmp/ffuf.json"
    argv = [
        "ffuf", "-u", f"{url.rstrip('/')}/FUZZ", "-w", wordlist,
        "-mc", "200,201,204,301,302,307,401,403,405",
        "-fc", "404",
        "-rate", str(rate), "-t", "20", "-timeout", "8",
        "-o", out_path, "-of", "json", "-s",
    ]
    proc = await asyncio.create_subprocess_exec(
        *argv, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL
    )
    try:
        async with asyncio.timeout(900):
            await proc.wait()
    except TimeoutError:
        proc.kill()
        await proc.wait()

    if not os.path.exists(out_path):
        return []
    try:
        with open(out_path) as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, OSError):
        return []
    finally:
        os.remove(out_path)

    return [
        {"url": r.get("url", ""), "status": r.get("status"), "length": r.get("length")}
        for r in data.get("results", [])
    ][:500]


async def wafw00f(url: str, *, log: LogFn | None = None) -> str | None:
    """Identify a WAF, so 'no findings' can be read correctly."""
    if not shutil.which("wafw00f"):
        return None
    proc = await asyncio.create_subprocess_exec(
        "wafw00f", "-a", "-o", "-", "-f", "json", url,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        async with asyncio.timeout(120):
            out, _ = await proc.communicate()
    except TimeoutError:
        proc.kill()
        await proc.wait()
        return None
    try:
        data = json.loads(out.decode("utf-8", "replace") or "[]")
        if isinstance(data, list) and data:
            return data[0].get("firewall") or None
    except json.JSONDecodeError:
        pass
    return None
