"""Run the recon a Hack The Box machine needs, and turn it into an Observation.

`htb.py` holds the knowledge and the reasoning; this runs the tools. The split
matters because the reasoning is testable without a network and the tools are
not — every rule in `htb.py` has a unit test, while this module is a thin,
boring wrapper whose job is to not lie about what it found.

Only tools that are actually in the image get executed: nmap, httpx, nuclei,
ffuf, curl. The playbooks in `htb.py` mention netexec, evil-winrm, impacket and
so on — those are commands for *you* to run from your own attack box, printed
with the target already substituted. Pretending to run a tool that isn't
installed, and reporting nothing found, is worse than saying "run this".
"""

from __future__ import annotations

import asyncio
import re
import shutil
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

from . import htb

FAST_TIMEOUT = 240      # the quick pass — should feel immediate
FULL_TIMEOUT = 900      # all 65535 ports

# HTB's lab ranges. Not a security control — it is a "did you mean to do that"
# check, because 10.0.0.0/8 is also where most corporate networks live and an
# accidental nmap of your employer's subnet is a bad afternoon.
HTB_RANGES = ("10.10.10.", "10.10.11.", "10.129.", "10.10.14.")


@dataclass
class ScanOutcome:
    host: str
    ok: bool = False
    detail: str = ""
    ports: list[dict] = field(default_factory=list)
    os_guess: str = ""
    hostnames: list[str] = field(default_factory=list)
    raw: str = ""
    seconds: float = 0.0


def looks_like_htb(host: str) -> bool:
    return any(host.startswith(p) for p in HTB_RANGES)


def range_warning(host: str) -> str:
    """Empty string when the target is a recognised HTB address."""
    if looks_like_htb(host):
        return ""
    if host.startswith(("10.", "192.168.", "172.16.", "172.17.", "172.18.")):
        return (f"{host} is a private address but not in HTB's usual lab ranges "
                f"(10.10.10.x, 10.10.11.x, 10.129.x). If this is your own lab "
                f"that is fine — if it is a network you do not own, stop.")
    return (f"{host} is not a private address at all. HTB machines are only "
            f"reachable over the VPN on 10.x. Check the target.")


async def _run(argv: list[str], timeout: int) -> tuple[int, str]:
    """Run a tool. Never raises; a missing binary is a result, not an error."""
    if not shutil.which(argv[0]):
        return 127, f"{argv[0]} is not installed in this image"
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT)
    except OSError as exc:
        return 1, str(exc)
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return 124, f"timed out after {timeout}s"
    return proc.returncode or 0, out.decode("utf-8", "replace")


def parse_nmap_xml(xml_text: str) -> tuple[list[dict], str, list[str]]:
    """Pull ports, OS guess and hostnames out of nmap's XML.

    XML rather than screen-scraping the human output: the text format changes
    between versions and silently loses the version column when it is long,
    which is exactly the field the playbooks key on.
    """
    ports: list[dict] = []
    os_guess = ""
    hostnames: list[str] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return ports, os_guess, hostnames

    for host in root.iter("host"):
        for hn in host.iter("hostname"):
            name = hn.get("name")
            if name and name not in hostnames:
                hostnames.append(name)
        for match in host.iter("osmatch"):
            os_guess = os_guess or match.get("name", "")
        for port in host.iter("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            entry = {
                "port": int(port.get("portid", 0) or 0),
                "proto": port.get("protocol", "tcp"),
                "service": (svc.get("name") if svc is not None else "") or "",
                "product": (svc.get("product") if svc is not None else "") or "",
                "version": (svc.get("version") if svc is not None else "") or "",
            }
            scripts = [s.get("output", "") for s in port.iter("script")]
            if scripts:
                entry["scripts"] = "\n".join(x for x in scripts if x)[:4000]
            ports.append(entry)

    # A hostname in an nmap script result — commonly the SMB or TLS name — is
    # frequently the vhost the web application actually wants, so it is worth
    # more than the reverse-DNS name.
    for p in ports:
        for m in re.findall(r"[Dd]omain[_ ]?[Nn]ame:\s*([A-Za-z0-9.\-]+)",
                            p.get("scripts", "")):
            if m not in hostnames:
                hostnames.append(m)
        for m in re.findall(r"commonName=([A-Za-z0-9.\-]+)", p.get("scripts", "")):
            if m not in hostnames:
                hostnames.append(m)

    ports.sort(key=lambda p: p["port"])
    return ports, os_guess, hostnames


async def quick_scan(host: str) -> ScanOutcome:
    """Top ports with service detection — the first 60 seconds of any box."""
    import time
    started = time.time()
    out = ScanOutcome(host=host)
    code, text = await _run(
        ["nmap", "-Pn", "-sV", "-sC", "--top-ports", "1000",
         "--min-rate", "2000", "-T4", "-oX", "-", host],
        FAST_TIMEOUT)
    out.raw = text[:200_000]
    out.seconds = round(time.time() - started, 1)
    if code == 127:
        out.detail = text
        return out
    out.ports, out.os_guess, out.hostnames = parse_nmap_xml(text)
    out.ok = bool(out.ports) or code == 0
    out.detail = (f"{len(out.ports)} open port(s)" if out.ports
                  else "no open ports in the top 1000 — run the full sweep")
    return out


async def full_scan(host: str) -> ScanOutcome:
    """All 65535 ports. The step people skip and then lose two hours to."""
    import time
    started = time.time()
    out = ScanOutcome(host=host)
    code, text = await _run(
        ["nmap", "-Pn", "-p-", "--min-rate", "5000", "-T4", "-oX", "-", host],
        FULL_TIMEOUT)
    out.raw = text[:200_000]
    out.seconds = round(time.time() - started, 1)
    if code == 127:
        out.detail = text
        return out
    out.ports, out.os_guess, out.hostnames = parse_nmap_xml(text)
    out.ok = code == 0 or bool(out.ports)
    out.detail = f"{len(out.ports)} open port(s) across all 65535"
    return out


async def deep_scan(host: str, ports: list[int]) -> ScanOutcome:
    """Version and default scripts against a known port list."""
    import time
    started = time.time()
    out = ScanOutcome(host=host)
    if not ports:
        out.detail = "no ports to scan"
        return out
    plist = ",".join(str(p) for p in sorted(set(ports))[:200])
    code, text = await _run(
        ["nmap", "-Pn", "-sV", "-sC", "-p", plist, "-oX", "-", host],
        FULL_TIMEOUT)
    out.raw = text[:200_000]
    out.seconds = round(time.time() - started, 1)
    if code == 127:
        out.detail = text
        return out
    out.ports, out.os_guess, out.hostnames = parse_nmap_xml(text)
    out.ok = bool(out.ports)
    out.detail = f"version-scanned {len(out.ports)} port(s)"
    return out


def observation_from(host: str, outcome: ScanOutcome, *,
                     creds: list[dict] | None = None,
                     has_shell: bool = False, shell_user: str = "",
                     is_root: bool = False, user_flag: bool = False,
                     root_flag: bool = False,
                     difficulty: str = "easy") -> htb.Observation:
    return htb.Observation(
        host=host,
        os_guess=outcome.os_guess,
        ports=outcome.ports,
        hostnames=outcome.hostnames,
        creds=creds or [],
        has_shell=has_shell,
        shell_user=shell_user,
        is_root=is_root,
        user_flag=user_flag,
        root_flag=root_flag,
        difficulty=difficulty,
    )


async def recon(host: str, *, full: bool = True,
                difficulty: str = "easy") -> dict:
    """The whole opening sequence, then the ranked next steps.

    Runs the quick pass first and returns its findings even if the full sweep
    later fails or times out — a partial answer now beats a complete answer in
    fifteen minutes, and on a box you can act on the quick pass immediately.
    """
    warning = range_warning(host)
    quick = await quick_scan(host)

    merged = {p["port"]: p for p in quick.ports}
    full_detail = ""
    if full:
        allports = await full_scan(host)
        full_detail = allports.detail
        extra = [p["port"] for p in allports.ports if p["port"] not in merged]
        for p in allports.ports:
            merged.setdefault(p["port"], p)
        if extra:
            deep = await deep_scan(host, extra)
            for p in deep.ports:
                merged[p["port"]] = p

    outcome = ScanOutcome(
        host=host, ok=bool(merged),
        ports=sorted(merged.values(), key=lambda p: p["port"]),
        os_guess=quick.os_guess,
        hostnames=quick.hostnames,
        detail=quick.detail,
        seconds=quick.seconds,
    )

    obs = observation_from(host, outcome, difficulty=difficulty)
    actions = htb.next_actions(obs)

    return {
        "host": host,
        "warning": warning,
        "ports": outcome.ports,
        "os_guess": outcome.os_guess,
        "hostnames": outcome.hostnames,
        "phase": htb.current_phase(obs),
        "actions": actions,
        "quick_detail": quick.detail,
        "full_detail": full_detail,
        "seconds": outcome.seconds,
        "hosts_file": (
            f"{host} {outcome.hostnames[0]}" if outcome.hostnames else ""),
    }
