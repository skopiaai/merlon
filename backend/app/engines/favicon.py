"""Favicon fingerprinting.

A favicon is a strong identity signal for one reason: nobody changes it. When
an organisation deploys Jenkins, Grafana, a router admin page or a vendor
appliance, the default icon ships with it and stays. So the hash of that icon
identifies the software behind a host that otherwise reveals nothing — no
version banner, no distinctive path, no title.

It also identifies *the organisation's own* icon, which is the useful direction
for widening surface: search the hash across the internet and you find the
hosts that belong to them but were never in DNS under their domain — shadow IT,
staging on a different registrar, an acquisition's infrastructure.

The hash is MurmurHash3 over the base64 of the icon bytes, which is the
convention Shodan uses, so the number produced here can be pasted straight into
`http.favicon.hash:` there. It's implemented inline rather than pulled in as a
dependency: it's forty lines, and the exact variant matters more than the
convenience.
"""

from __future__ import annotations

import base64
import re
from urllib.parse import urljoin, urlparse

from ..models import Severity
from ..normalize import make_dedupe_key
from . import fetch
from .registry import EngineSpec, register

ICON_LINK = re.compile(
    r"<link[^>]+rel=[\"'][^\"']*icon[^\"']*[\"'][^>]*>", re.I)
HREF = re.compile(r"href=[\"']([^\"']+)[\"']", re.I)


def murmur3_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 x86 32-bit, returned signed — the mmh3.hash() convention."""
    c1, c2 = 0xCC9E2D51, 0x1B873593
    length = len(data)
    h1 = seed
    rounded = length & ~0x03

    for i in range(0, rounded, 4):
        k1 = (data[i] | (data[i + 1] << 8) | (data[i + 2] << 16) | (data[i + 3] << 24))
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF

    k1 = 0
    tail = length & 0x03
    if tail == 3:
        k1 ^= data[rounded + 2] << 16
    if tail >= 2:
        k1 ^= data[rounded + 1] << 8
    if tail >= 1:
        k1 ^= data[rounded]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16
    return h1 - 0x100000000 if h1 & 0x80000000 else h1


def favicon_hash(icon: bytes) -> int:
    """Shodan-compatible favicon hash: murmur3 over base64 with line breaks."""
    return murmur3_32(base64.encodebytes(icon))


# Hashes of default icons for software that shouldn't normally face the
# internet. A match isn't a vulnerability by itself — it's a strong hint about
# what to test next, and several of these have a default-credentials history.
KNOWN: dict[int, tuple[str, Severity, str]] = {
    81586312: ("Jenkins", Severity.medium,
               "Jenkins exposes build configuration and, if the script console is "
               "reachable, code execution on the build server"),
    -1277814690: ("Jenkins", Severity.medium, "a Jenkins instance"),
    1278323681: ("Grafana", Severity.low,
                 "Grafana — check for anonymous dashboard access and the default "
                 "admin/admin credentials"),
    -1499940355: ("Kibana", Severity.medium,
                  "Kibana, which typically fronts an Elasticsearch cluster holding "
                  "logs and often personal data"),
    -297069493: ("phpMyAdmin", Severity.high,
                 "phpMyAdmin — a database administration interface facing the "
                 "internet"),
    1594377337: ("GitLab", Severity.low, "a GitLab instance"),
    -1957062814: ("Zabbix", Severity.medium, "Zabbix monitoring"),
    1099097618: ("pfSense", Severity.high, "a pfSense firewall administration page"),
    -1922044295: ("Cisco device", Severity.medium, "a Cisco management interface"),
    708578229: ("Fortinet", Severity.medium, "a Fortinet appliance login"),
    -335242539: ("VMware vSphere", Severity.medium, "a vSphere management interface"),
    743365239: ("Citrix", Severity.medium, "a Citrix gateway"),
    -1255464424: ("Apache Tomcat", Severity.medium,
                  "a Tomcat default page — check /manager/html for default credentials"),
    -1350437236: ("Jira", Severity.low, "a Jira instance"),
    999357577: ("Confluence", Severity.low, "a Confluence instance"),
    1912812576: ("RabbitMQ", Severity.medium, "a RabbitMQ management console"),
    -1723752240: ("MinIO", Severity.medium, "a MinIO object storage console"),
    116323821: ("Portainer", Severity.high,
                "Portainer — container management, which usually means control of "
                "the Docker host"),
    -1231681109: ("Traefik", Severity.low, "a Traefik dashboard"),
    1485257654: ("Webmin", Severity.high, "Webmin server administration"),
    -1121298052: ("Ruckus/router admin", Severity.medium, "a network device admin page"),
}


def icon_urls(html: str, page: str) -> list[str]:
    """Icon URLs declared by a page, plus the conventional /favicon.ico."""
    out = []
    for tag in ICON_LINK.findall(html or ""):
        m = HREF.search(tag)
        if m:
            out.append(urljoin(page, m.group(1)))
    parsed = urlparse(page)
    out.append(f"{parsed.scheme}://{parsed.netloc}/favicon.ico")
    seen, unique = set(), []
    for url in out:
        if url not in seen:
            seen.add(url)
            unique.append(url)
    return unique


@register(EngineSpec(
    name="favicon",
    label="Fingerprinting by favicon",
    description="Hashes each site's favicon the way Shodan does. Default icons "
                "identify the software behind hosts that give nothing else away, "
                "and the organisation's own icon hash finds their infrastructure "
                "hosted outside their domain.",
    phase="post_http",
    takes="urls",
    produces="findings",
    weight=3,
    limit=25,
    default_in=("standard", "deep"),
))
async def _engine(targets: list[str], ctx: dict) -> list[dict]:
    log = ctx.get("log")
    findings: list[dict] = []
    hashes: dict[int, list[str]] = {}

    for origin in fetch.origins(targets)[:25]:
        host = (urlparse(origin).hostname or "").lower()
        page = await fetch.request(origin, follow=True, timeout=12, ctx=ctx)
        if not page.ok:
            continue

        for url in icon_urls(page.body, origin)[:3]:
            icon = await fetch.request(url, binary=True, follow=True, timeout=12, ctx=ctx)
            if icon.status != 200 or len(icon.raw) < 60:
                continue
            value = favicon_hash(icon.raw)
            hashes.setdefault(value, []).append(host)

            known = KNOWN.get(value)
            findings.append({
                "engine": "favicon",
                "rule_id": "favicon-known-software" if known else "favicon-hash",
                "name": (f"Favicon identifies {known[0]}" if known
                         else "Favicon fingerprint"),
                "severity": known[1] if known else Severity.info,
                "host": host, "url": url, "matched_at": url,
                "description": (
                    (f"The favicon is the default icon shipped with **{known[0]}**, "
                     f"so this host is {known[2]}.\n\n"
                     f"That is a fingerprint, not a vulnerability — but software of "
                     f"this kind facing the internet is usually unintentional, and "
                     f"it tells you exactly which default credentials and known "
                     f"CVEs to check.\n\n" if known else
                     "Recorded so this host can be correlated with others.\n\n")
                    + f"Shodan search for the same icon anywhere on the internet:\n"
                      f"    http.favicon.hash:{value}\n\n"
                      f"Run that against your own icon and you find hosts that "
                      f"belong to the organisation but were never in its DNS — "
                      f"shadow IT, forgotten staging, infrastructure from an "
                      f"acquisition. That is often the widest single step "
                      f"available in external reconnaissance."),
                "evidence": f"{url} → {len(icon.raw)} bytes, murmur3 = {value}",
                "remediation": (
                    "For a default icon on administrative software: the icon isn't "
                    "the problem, the exposure is. Put the interface behind VPN or "
                    "an authenticating proxy rather than relying on the URL being "
                    "unknown.\n\n"
                    "Replacing the icon to defeat fingerprinting is not worth doing "
                    "— it delays identification by minutes and makes your own asset "
                    "inventory harder."
                    if known else
                    "No action needed — this is reconnaissance context rather than "
                    "a defect."),
                "references": ["https://www.shodan.io/search/filters"],
                "tags": ["fingerprint", "recon"], "cve": [], "cwe": [],
                "cvss_score": None,
                "dedupe_key": make_dedupe_key("favicon", f"favicon-{value}", host, origin),
                "raw": {"hash": value, "software": known[0] if known else None},
            })
            break   # one icon per origin

    if log:
        shared = {h: hs for h, hs in hashes.items() if len(hs) > 1}
        await log("info", f"[favicon] {len(hashes)} distinct icon(s) across "
                          f"{len(targets)} target(s)", "favicon")
        for value, hosts in list(shared.items())[:3]:
            await log("info",
                      f"[favicon] hash {value} is shared by {len(hosts)} hosts "
                      f"— same platform or same deployment: "
                      f"{', '.join(hosts[:5])}", "favicon")
    return findings
