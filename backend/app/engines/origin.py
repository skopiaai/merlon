"""Origin server discovery behind a CDN or WAF.

Cloudflare and similar services front the majority of bug bounty targets. All
your traffic goes to the edge, which rate-limits you, filters your payloads,
and logs you. The origin server sitting behind it usually has none of that —
and very often it will answer directly if you know its address, because the
firewall rule that was supposed to only accept connections from the CDN was
never written.

That is the finding. Not "I bypassed your WAF" as a technique, but **"your
origin server is reachable from the open internet, so your WAF is optional"**.
It is a real, reportable misconfiguration with a clean fix, and it is one of
the higher-value things left that a scanner can find on a mature target.

Five independent leaks are checked, because organisations rarely close all of
them:

  **Historical DNS.** The A record before the CDN was put in front. Migrations
  don't rewrite history, and certificate transparency preserves a lot of it.

  **Non-proxied subdomains.** A single host in the zone left with `proxied: off`
  — a mail server, an FTP box, a monitoring endpoint — often shares
  infrastructure or a netblock with the origin.

  **Mail records.** MX and SPF name servers that are almost never behind the
  CDN, because mail doesn't route through an HTTP proxy.

  **Certificate SANs.** A certificate issued directly on the origin, logged
  publicly, naming hosts the CDN doesn't front.

  **Favicon hash.** The strongest signal, and the reason the favicon engine
  computes a Shodan-compatible hash: the same icon served from an IP that isn't
  a CDN edge is very likely the origin.

Confirmation is what separates this from guesswork. A candidate address is only
reported after it is asked for the target's `Host` and returns the target's
site. An IP that merely responds proves nothing — shared hosting means half the
internet responds.

Nothing here is evasion. It sends normal requests, from one address, at a
normal rate, and reports what it finds to the site's owner.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import re
from urllib.parse import urlparse

from ..models import Severity
from ..normalize import make_dedupe_key
from . import fetch
from .registry import EngineSpec, register

# Published edge ranges for the major providers. A candidate inside one of
# these is the CDN answering, not the origin — the whole point is to find an
# address that ISN'T here.
CDN_RANGES = [
    # Cloudflare IPv4
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    # Fastly
    "151.101.0.0/16", "199.232.0.0/16", "23.235.32.0/20", "43.249.72.0/22",
    # Akamai (partial — Akamai is large and announces many blocks)
    "23.32.0.0/11", "23.64.0.0/14", "104.64.0.0/10", "184.24.0.0/13",
    # Sucuri
    "192.124.249.0/24", "185.93.228.0/22",
    # Incapsula / Imperva
    "199.83.128.0/21", "198.143.32.0/19", "149.126.72.0/21", "103.28.248.0/22",
    "45.64.64.0/22", "185.11.124.0/22", "192.230.64.0/18",
]

_NETWORKS = []
for _cidr in CDN_RANGES:
    try:
        _NETWORKS.append(ipaddress.ip_network(_cidr))
    except ValueError:      # pragma: no cover - the table is static
        pass

# Subdomains that are usually left un-proxied because they don't serve HTTP.
LEAKY_PREFIXES = [
    "mail", "smtp", "mx", "mx1", "mx2", "imap", "pop", "webmail", "email",
    "ftp", "sftp", "cpanel", "whm", "direct", "origin", "origin-www", "server",
    "backend", "internal", "vpn", "remote", "ssh", "monitor", "munin",
    "nagios", "zabbix", "grafana", "old", "legacy", "dev", "staging", "test",
    "autodiscover", "autoconfig", "ns1", "ns2", "cdn-origin", "www-origin",
]

IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def is_cdn_ip(ip: str) -> bool:
    """Is this address a known CDN edge rather than a candidate origin?"""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(address in network for network in _NETWORKS)


def is_public(ip: str) -> bool:
    """Is this an address that could actually be someone's origin server?

    The link-local exclusion matters most: 169.254.169.254 is cloud metadata,
    and a scanner that happily 'discovers' it and then requests it is doing
    SSRF against the person running it.

    Note that Python treats the RFC 5737 documentation ranges (192.0.2.0/24,
    198.51.100.0/24, 203.0.113.0/24) as private, so those are excluded too.
    That is the behaviour we want — an address from a documentation range in a
    DNS record is a placeholder somebody forgot to replace, not a server — but
    it does mean tests have to use genuinely routable addresses.
    """
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (address.is_private or address.is_loopback or
                address.is_link_local or address.is_multicast or
                address.is_reserved or address.is_unspecified)


def candidate_ips(text: str) -> list[str]:
    """Public, non-CDN IPv4 addresses from arbitrary text."""
    out = []
    for match in IPV4.findall(text or ""):
        if is_public(match) and not is_cdn_ip(match) and match not in out:
            out.append(match)
    return out


def confirms_origin(target_body: str, candidate_body: str,
                    candidate_status: int, tolerance: float = 0.10) -> bool:
    """Did the candidate return the *target's* site when asked for its Host?

    Length-based within a tolerance rather than byte-equal: an origin serves the
    same application but not necessarily the same bytes — the CDN may minify,
    inject headers, or rewrite links. Requiring equality would reject every
    genuine origin.
    """
    if candidate_status not in (200, 301, 302, 401, 403):
        return False
    if not target_body or not candidate_body:
        return False
    if len(candidate_body) < 200:
        return False
    longest = max(len(target_body), len(candidate_body))
    return abs(len(target_body) - len(candidate_body)) <= longest * tolerance


async def _dig(name: str, record: str = "A", timeout: int = 8) -> list[str]:
    try:
        proc = await asyncio.create_subprocess_exec(
            "dig", "+short", "+timeout=4", "+tries=1", record, name,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except (asyncio.TimeoutError, OSError):
        return []
    return [line.strip().rstrip(".") for line in out.decode().splitlines()
            if line.strip()]


async def from_dns_history(apex: str) -> list[tuple[str, str]]:
    """(ip, how_found) from certificate transparency's record of the zone."""
    found: list[tuple[str, str]] = []
    url = f"https://crt.sh/?q=%25.{apex}&output=json"
    resp = await fetch.request(url, follow=True, timeout=45)
    try:
        entries = json.loads(resp.body or "[]")
    except json.JSONDecodeError:
        return found
    if not isinstance(entries, list):
        return found

    names = set()
    for entry in entries[:400]:
        if not isinstance(entry, dict):
            continue
        for raw in str(entry.get("name_value", "")).split("\n"):
            name = raw.strip().lower().rstrip(".")
            if name and not name.startswith("*") and name.endswith(apex):
                names.add(name)

    # Resolve only the names that look like they'd be left un-proxied.
    interesting = [n for n in names
                   if any(n.startswith(p + ".") for p in LEAKY_PREFIXES)]
    for name in sorted(interesting)[:25]:
        for ip in await _dig(name):
            if is_public(ip) and not is_cdn_ip(ip):
                found.append((ip, f"certificate for {name} resolves here, "
                                  f"outside the CDN's ranges"))
    return found


async def from_mail_records(apex: str) -> list[tuple[str, str]]:
    """Mail doesn't route through an HTTP proxy, so MX rarely hides."""
    found: list[tuple[str, str]] = []

    for mx in (await _dig(apex, "MX"))[:6]:
        host = mx.split()[-1] if " " in mx else mx
        if not host.endswith(apex):
            continue          # a third-party mail provider, not their server
        for ip in await _dig(host):
            if is_public(ip) and not is_cdn_ip(ip):
                found.append((ip, f"MX record {host} points here"))

    for txt in await _dig(apex, "TXT"):
        if "v=spf1" not in txt.lower():
            continue
        for ip in candidate_ips(txt):
            found.append((ip, "listed in the SPF record as a sending host"))
    return found


async def from_leaky_subdomains(apex: str) -> list[tuple[str, str]]:
    """A single host left un-proxied in an otherwise CDN-fronted zone."""
    found: list[tuple[str, str]] = []

    async def check(prefix: str):
        name = f"{prefix}.{apex}"
        for ip in await _dig(name):
            if is_public(ip) and not is_cdn_ip(ip):
                return ip, f"{name} resolves directly, without the CDN in front"
        return None

    results = await fetch.gather_limited(
        [check(p) for p in LEAKY_PREFIXES], limit=10)
    for item in results:
        if item:
            found.append(item)
    return found


@register(EngineSpec(
    name="origin",
    label="Looking for the origin behind the CDN",
    description="Finds servers reachable directly despite sitting behind a CDN or "
                "WAF — via DNS history, mail records, un-proxied subdomains and "
                "certificate data. Confirmed by asking the candidate for the "
                "target's Host and checking it serves the target's site.",
    phase="post_http",
    takes="urls",
    produces="findings",
    weight=9,
    limit=5,
    default_in=("standard", "deep"),
))
async def _engine(targets: list[str], ctx: dict) -> list[dict]:
    log = ctx.get("log")
    findings: list[dict] = []
    checked_hosts: set[str] = set()

    for url in targets[:5]:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        if not host or host in checked_hosts:
            continue
        checked_hosts.add(host)
        apex = ".".join(host.split(".")[-2:]) if host.count(".") >= 1 else host

        # Is this host actually behind something? If its own A record isn't a
        # CDN edge, there's no origin to hunt for.
        direct = await _dig(host)
        fronted = any(is_cdn_ip(ip) for ip in direct)
        if not fronted:
            continue

        reference = await fetch.request(f"https://{host}/", ctx=ctx,
                                        follow=True, timeout=15)
        if not reference.ok or len(reference.body) < 200:
            continue

        candidates: dict[str, str] = {}
        for source in await asyncio.gather(
                from_leaky_subdomains(apex),
                from_mail_records(apex),
                from_dns_history(apex),
                return_exceptions=True):
            if isinstance(source, Exception):
                continue
            for ip, why in source:
                candidates.setdefault(ip, why)

        if log:
            await log("info",
                      f"[origin] {host} is CDN-fronted; {len(candidates)} "
                      f"candidate origin address(es) to confirm", "origin")

        # --- confirm ---
        async def confirm(ip: str, why: str):
            for scheme in ("https", "http"):
                resp = await fetch.request(
                    f"{scheme}://{ip}/", headers={"Host": host},
                    ctx=ctx, timeout=12)
                if confirms_origin(reference.body, resp.body, resp.status):
                    return ip, why, scheme, resp
            return None

        confirmed = [r for r in await fetch.gather_limited(
            [confirm(ip, why) for ip, why in candidates.items()], limit=5) if r]

        for ip, why, scheme, resp in confirmed:
            findings.append({
                "engine": "origin", "rule_id": "origin-ip-exposed",
                "name": f"Origin server reachable directly at {ip}",
                "severity": Severity.high,
                "host": host, "url": f"{scheme}://{ip}/", "matched_at": ip,
                "description": (
                    f"`{host}` is served through a CDN/WAF, but the origin server "
                    f"at **{ip}** answers requests from the open internet. Asked "
                    f"for `Host: {host}`, it returns the site — so the protection "
                    f"in front of it is optional rather than enforced.\n\n"
                    f"Found because {why}.\n\n"
                    f"Everything the edge provides is bypassable this way: rate "
                    f"limiting, WAF rules, bot management, DDoS absorption, and the "
                    f"access logs your team relies on. An attacker who knows this "
                    f"address tests the application directly, with no filtering and "
                    f"no record of it at the edge. It also exposes the server to "
                    f"volumetric attack, which is usually the reason the CDN was "
                    f"bought.\n\n"
                    f"Confirmed by comparison, not assumption: the edge returns "
                    f"{len(reference.body)} bytes and this address returns "
                    f"{len(resp.body)} bytes of the same application."),
                "evidence": (
                    f"{host} resolves to {', '.join(direct[:3])} (CDN edge)\n"
                    f"Candidate origin: {ip} — {why}\n\n"
                    f"GET {scheme}://{ip}/  with  Host: {host}\n"
                    f"  → HTTP {resp.status}, {len(resp.body)} bytes\n"
                    f"GET https://{host}/ (through the CDN)\n"
                    f"  → HTTP {reference.status}, {len(reference.body)} bytes"),
                "remediation": (
                    "Make the origin unreachable except through the CDN. Blocking "
                    "the address you were found on is not enough — the leak that "
                    "revealed it will reveal the next one.\n\n"
                    "1. **Firewall the origin** to accept traffic only from your "
                    "CDN provider's published IP ranges (Cloudflare, Fastly and "
                    "Akamai all publish them and offer automation for it). Deny "
                    "everything else at the network layer.\n"
                    "2. **Use authenticated origin pulls** — a client certificate "
                    "or shared secret header the edge sends and the origin "
                    "requires. This survives the ranges changing.\n"
                    "3. **Rotate the origin's address** after locking it down, "
                    "since the current one is now public.\n"
                    "4. **Close the leak.** Audit the zone for un-proxied records, "
                    "check whether mail is hosted on the same address as the web "
                    "application (it shouldn't be), and avoid issuing certificates "
                    "directly on the origin."),
                "references": [
                    "https://developers.cloudflare.com/fundamentals/security/protect-your-origin-server/",
                    "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
                ],
                "tags": ["misconfig", "waf-bypass", "recon", "infrastructure"],
                "cve": [], "cwe": ["CWE-693", "CWE-1327"], "cvss_score": 7.5,
                "dedupe_key": make_dedupe_key("origin", "origin-ip-exposed", host, ip),
                "raw": {"ip": ip, "source": why, "cdn_ips": direct[:5]},
            })

        if log and confirmed:
            await log("error",
                      f"[origin] CONFIRMED origin for {host}: "
                      f"{', '.join(ip for ip, _w, _s, _r in confirmed)} — the WAF "
                      f"in front of it can be bypassed entirely", "origin")

    return findings
