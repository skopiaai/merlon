"""Virtual host discovery.

One IP address usually serves many sites. Which one you get depends entirely on
the `Host` header you send, and the server does not care whether that name has
a DNS record — it only matches it against its own configuration.

So there is a category of application that is running, reachable, and invisible
to every DNS-based enumeration: the internal admin panel or staging copy that
was configured on the same web server as the public site and then removed from
public DNS, or never put there. Subdomain enumeration cannot find it, because
there is nothing to enumerate. Sending the name in a `Host` header does.

This is one of the few remaining techniques that regularly finds something on a
target that has already been scanned by everyone else, precisely because it
doesn't start from DNS.

The names tried are all subdomains of the engagement's own domains, so the
scope guard applies exactly as it does everywhere else — nothing here can reach
another organisation's site sharing the same shared-hosting IP.
"""

from __future__ import annotations

import asyncio
from urllib.parse import urlparse

from ..models import Severity
from ..normalize import make_dedupe_key
from . import fetch
from .registry import EngineSpec, register

# Names that, when they exist as a vhost but not in public DNS, are worth
# knowing about. Weighted towards the internal and the forgotten.
NAMES = [
    "admin", "administrator", "internal", "intranet", "staging", "stage",
    "dev", "development", "test", "testing", "uat", "qa", "preprod",
    "pre-prod", "beta", "demo", "sandbox", "old", "legacy", "backup", "bak",
    "new", "temp", "tmp", "private", "secure", "portal", "dashboard",
    "panel", "console", "manage", "management", "cpanel", "webmail", "mail",
    "smtp", "vpn", "remote", "git", "gitlab", "jenkins", "ci", "build",
    "jira", "confluence", "wiki", "docs", "grafana", "kibana", "monitor",
    "monitoring", "metrics", "status", "api", "api-internal", "internal-api",
    "v1", "v2", "mobile", "m", "app", "apps", "static", "cdn", "assets",
    "files", "upload", "uploads", "download", "downloads", "db", "database",
    "phpmyadmin", "adminer", "sql", "redis", "elastic", "search", "auth",
    "sso", "login", "account", "accounts", "billing", "payment", "payments",
    "invoice", "report", "reports", "analytics", "stats", "log", "logs",
]

RANDOM_HOST = "zz9-nonexistent-vhost-4471"


async def resolve_ip(host: str, timeout: int = 8) -> str:
    try:
        proc = await asyncio.create_subprocess_exec(
            "dig", "+short", "+timeout=5", "+tries=1", "A", host,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except (asyncio.TimeoutError, OSError):
        return ""
    for line in out.decode().splitlines():
        line = line.strip()
        if line and line[0].isdigit() and line.count(".") == 3:
            return line
    return ""


def is_distinct(base_status: int, base_len: int, status: int, length: int,
                tolerance: int = 64) -> bool:
    """Is this response meaningfully different from the catch-all?

    Almost every candidate returns the default site. Only a response that
    differs from that default is a distinct virtual host, and the comparison
    has to tolerate the small per-request variation that dynamic pages produce.
    """
    if status == 0:
        return False
    if status != base_status:
        return True
    return abs(length - base_len) > max(tolerance, base_len * 0.05)


@register(EngineSpec(
    name="vhosts",
    label="Probing for hidden virtual hosts",
    description="Sends candidate names in the Host header to the target's own IP. "
                "Finds applications served by the same web server but absent from "
                "public DNS — which subdomain enumeration structurally cannot see.",
    phase="post_http",
    takes="hosts",
    produces="findings",
    weight=8,
    limit=8,
    skip_cdn=True,
    default_in=("deep",),
))
async def _engine(targets: list[str], ctx: dict) -> list[dict]:
    log = ctx.get("log")
    findings: list[dict] = []
    seen_ips: set[str] = set()

    for host in targets[:8]:
        apex = ".".join(host.split(".")[-2:]) if host.count(".") >= 1 else host
        ip = await resolve_ip(host)
        if not ip or ip in seen_ips:
            continue
        seen_ips.add(ip)

        # Establish the catch-all: what does this server return for a Host it
        # has never heard of? Everything is compared against that.
        for scheme in ("https", "http"):
            base = await fetch.request(
                f"{scheme}://{ip}/",
                headers={"Host": f"{RANDOM_HOST}.{apex}"}, timeout=10, ctx=ctx)
            if base.ok:
                break
        if not base.ok:
            continue

        base_status, base_len = base.status, len(base.body)

        async def probe(name: str):
            vhost = f"{name}.{apex}"
            resp = await fetch.request(f"{scheme}://{ip}/",
                                       headers={"Host": vhost}, timeout=10, ctx=ctx)
            if not is_distinct(base_status, base_len, resp.status, len(resp.body)):
                return None
            return vhost, resp

        results = await fetch.gather_limited(
            [probe(n) for n in NAMES], limit=8)

        hits = [r for r in results if r]
        # If nearly everything looks distinct, the server is answering
        # unpredictably and the comparison is worthless. Report nothing rather
        # than a hundred false positives.
        if len(hits) > len(NAMES) // 3:
            if log:
                await log("warn",
                          f"[vhosts] {ip} responds differently to almost every "
                          f"Host — results discarded as unreliable", "vhosts")
            continue

        for vhost, resp in hits:
            resolved = await resolve_ip(vhost)
            findings.append({
                "engine": "vhosts", "rule_id": "hidden-vhost",
                "name": f"Virtual host served without DNS: {vhost}",
                "severity": Severity.medium if not resolved else Severity.info,
                "host": vhost, "url": f"{scheme}://{ip}/", "matched_at": vhost,
                "description": (
                    f"The web server at {ip} serves a distinct site for "
                    f"`Host: {vhost}`"
                    + (", and that name has no public DNS record.\n\n"
                       "An application reachable this way is usually one somebody "
                       "believes is private — it was taken out of DNS, or never put "
                       "in, and the server configuration was left in place. It is "
                       "fully reachable by anyone who guesses the name, and it is "
                       "typically less patched and less monitored than the public "
                       "site because nobody counts it as exposed.\n\n"
                       if not resolved else
                       f", and the name resolves to {resolved}.\n\n")
                    + f"Detected by comparison: an unknown Host returns "
                      f"HTTP {base_status} at {base_len} bytes, this one returns "
                      f"HTTP {resp.status} at {len(resp.body)} bytes."),
                "evidence": (f"GET {scheme}://{ip}/  Host: {RANDOM_HOST}.{apex}\n"
                             f"  → HTTP {base_status}, {base_len} bytes (catch-all)\n"
                             f"GET {scheme}://{ip}/  Host: {vhost}\n"
                             f"  → HTTP {resp.status}, {len(resp.body)} bytes"),
                "remediation": (
                    "Removing the DNS record does not take an application offline — "
                    "the server still serves it to anyone who sends the name.\n\n"
                    "  • If the application should be internal, bind it to an "
                    "internal interface or put it behind VPN. Don't rely on the "
                    "hostname being unknown.\n"
                    "  • If it is decommissioned, remove the server block, not just "
                    "the DNS entry.\n"
                    "  • Configure a default server block that returns 444/404 for "
                    "unrecognised Host values, so unconfigured names can't fall "
                    "through to a real application."),
                "references": [
                    "https://owasp.org/www-project-web-security-testing-guide/",
                ],
                "tags": ["discovery", "misconfig", "shadow-it"], "cve": [],
                "cwe": ["CWE-200"], "cvss_score": None,
                "dedupe_key": make_dedupe_key("vhosts", "hidden-vhost", vhost, ip),
                "raw": {"ip": ip, "vhost": vhost, "resolves": bool(resolved)},
            })

    if log:
        hidden = [f for f in findings if not f["raw"]["resolves"]]
        await log("info",
                  f"[vhosts] {len(seen_ips)} IP(s) probed, {len(findings)} virtual "
                  f"host(s), {len(hidden)} with no DNS record", "vhosts")
    return findings
