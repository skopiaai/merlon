"""Client-side supply chain.

Supply chain attacks stopped being isolated typosquatting incidents and became
systematic campaigns. In 2026 the Shai-Hulud worm propagated through roughly 800
npm packages by stealing maintainer tokens and republishing trojanised versions
under the next namespace automatically; Axios was compromised through a
maintainer account takeover; dozens of `@redhat-cloud-services` packages went
the same way. The pattern is consistent — compromise the trust relationship
rather than the code.

A web scanner cannot audit somebody's build pipeline from the outside. What it
*can* see is the part of the supply chain that executes in the visitor's
browser, and that part is both large and largely unguarded:

  **Dangling script hosts.** A `<script src>` pointing at a domain that no
  longer resolves. This is the most severe thing in this file and it is
  routinely missed. Whoever registers that domain gets arbitrary JavaScript
  execution on every page of the site — reading the DOM, the session, form
  input, everything. It is a subdomain takeover with a worse payoff, and it
  happens because a marketing tag or an analytics vendor was decommissioned and
  the script tag stayed.

  **Third-party scripts without Subresource Integrity.** An external script
  with no `integrity=` attribute is a standing agreement to execute whatever
  that host serves, forever. When a CDN or an npm package is compromised — which
  is now a regular event rather than an incident — SRI is the difference
  between "the attacker's code ran on our site" and "the browser refused to run
  it."

  **Known-vulnerable libraries.** Version strings visible in the loaded
  JavaScript, checked against versions with published vulnerabilities.

The severity ordering here is deliberate and not obvious: a dangling host is
critical, missing SRI on a well-known CDN is low, and missing SRI on an obscure
one is medium. The risk is not "third-party code" in the abstract — it is how
plausible it is that this particular host gets compromised or taken over.
"""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urljoin, urlparse

from ..models import Severity
from ..normalize import make_dedupe_key
from . import fetch
from .registry import EngineSpec, register

SCRIPT_TAG = re.compile(r"<script\b[^>]*\bsrc\s*=\s*[\"']([^\"']+)[\"'][^>]*>",
                        re.I)
LINK_TAG = re.compile(
    r"<link\b[^>]*\brel\s*=\s*[\"']stylesheet[\"'][^>]*\bhref\s*=\s*[\"']([^\"']+)[\"'][^>]*>",
    re.I)
HAS_INTEGRITY = re.compile(r"\bintegrity\s*=\s*[\"']sha(?:256|384|512)-", re.I)
HAS_CROSSORIGIN = re.compile(r"\bcrossorigin\s*=", re.I)

# Hosts where a compromise would be an industry-wide event and which have
# correspondingly serious operational security. Missing SRI here is still a
# gap, but it is not the same risk as an unmaintained tag server.
MAJOR_CDNS = re.compile(
    r"(?:^|\.)(?:cdnjs\.cloudflare\.com|ajax\.googleapis\.com|"
    r"cdn\.jsdelivr\.net|unpkg\.com|code\.jquery\.com|stackpath\.bootstrapcdn\.com|"
    r"maxcdn\.bootstrapcdn\.com|cdn\.skypack\.dev|esm\.sh|"
    r"fonts\.googleapis\.com|fonts\.gstatic\.com|"
    r"www\.googletagmanager\.com|www\.google-analytics\.com)$", re.I)

# Library version fingerprints. Deliberately short — this is a signal that
# something old is loaded, not a substitute for a dependency scanner with a
# real advisory database.
LIBRARY_VERSION = re.compile(
    r"/(jquery|angular|angularjs|react|vue|lodash|moment|bootstrap|"
    r"handlebars|underscore|backbone|ember|dojo|prototype|mootools|"
    r"knockout|d3|axios)"
    r"[-.@/]v?(\d+\.\d+(?:\.\d+)?)", re.I)

# Versions with well-known published vulnerabilities. A floor, not a database:
# anything at or below these has documented issues.
VULNERABLE_BELOW = {
    "jquery": (3, 5, 0),        # XSS in htmlPrefilter / jQuery.htmlPrefilter
    "angularjs": (1, 8, 0),     # end of life, multiple sandbox escapes
    "angular": (1, 8, 0),
    "lodash": (4, 17, 21),      # prototype pollution
    "handlebars": (4, 7, 7),    # prototype pollution / RCE in templates
    "moment": (2, 29, 4),       # path traversal in locale loading
    "bootstrap": (3, 4, 1),     # XSS in data-target
    "underscore": (1, 12, 1),   # arbitrary code execution in template
    "axios": (1, 6, 0),         # SSRF / CSRF token leakage
    "d3": (3, 5, 17),
    "prototype": (1, 7, 3),
    "mootools": (1, 6, 0),
}


def external_scripts(html: str, page_url: str) -> list[tuple[str, str, bool]]:
    """(absolute_url, raw_tag, has_integrity) for every off-origin script.

    Same-origin scripts are excluded: SRI on your own assets is defence in
    depth, but the supply chain question is about code you don't control.
    """
    origin_host = (urlparse(page_url).hostname or "").lower()
    out: list[tuple[str, str, bool]] = []

    for pattern in (SCRIPT_TAG, LINK_TAG):
        for match in pattern.finditer(html or ""):
            src = match.group(1).strip()
            if src.startswith("data:") or not src:
                continue
            absolute = urljoin(page_url, src)
            host = (urlparse(absolute).hostname or "").lower()
            if not host or host == origin_host:
                continue
            out.append((absolute, match.group(0), bool(HAS_INTEGRITY.search(match.group(0)))))
    return out


def script_hosts(scripts: list[tuple[str, str, bool]]) -> list[str]:
    hosts = {(urlparse(url).hostname or "").lower() for url, _tag, _sri in scripts}
    return sorted(h for h in hosts if h)


def parse_version(text: str) -> tuple[str, tuple[int, ...]] | None:
    """(library, version tuple) from a script URL, if recognisable."""
    match = LIBRARY_VERSION.search(text or "")
    if not match:
        return None
    name = match.group(1).lower()
    parts = tuple(int(p) for p in match.group(2).split("."))
    return name, parts


def is_outdated(library: str, version: tuple[int, ...]) -> bool:
    floor = VULNERABLE_BELOW.get(library.lower())
    if not floor:
        return False
    padded = tuple(list(version) + [0] * (3 - len(version)))[:3]
    return padded < floor


async def resolves(host: str, timeout: int = 8) -> bool:
    """Does this hostname resolve at all?

    A `<script src>` pointing at a name with no DNS record is the finding. The
    check has to be careful about its own failure modes — a DNS timeout inside
    a container is not evidence that a domain is unregistered — so a lookup
    that errors is treated as "resolves" rather than reported.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            "dig", "+short", "+timeout=4", "+tries=2", "A", host,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except (asyncio.TimeoutError, OSError):
        return True
    if out.decode().strip():
        return True

    # No A record. Check for a CNAME before concluding — a name that is only a
    # CNAME to something dead is still dangling, but a name behind a CNAME that
    # resolves is fine.
    try:
        proc = await asyncio.create_subprocess_exec(
            "dig", "+short", "+timeout=4", "+tries=1", "CNAME", host,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except (asyncio.TimeoutError, OSError):
        return True
    return bool(out.decode().strip())


@register(EngineSpec(
    name="supplychain",
    label="Auditing third-party scripts",
    description="Client-side supply chain: scripts loaded from hosts that no "
                "longer resolve (arbitrary JS execution for whoever registers "
                "them), third-party code without Subresource Integrity, and "
                "known-vulnerable library versions.",
    phase="post_http",
    takes="urls",
    produces="findings",
    weight=6,
    limit=12,
    default_in=("standard", "deep"),
))
async def _engine(targets: list[str], ctx: dict) -> list[dict]:
    log = ctx.get("log")
    findings: list[dict] = []
    seen_hosts: set[str] = set()
    seen_rules: set[str] = set()

    for origin in fetch.origins(targets)[:8]:
        page_host = (urlparse(origin).hostname or "").lower()
        page = await fetch.request(origin, ctx=ctx, follow=True, timeout=15)
        if not page.ok or not page.body:
            continue

        scripts = external_scripts(page.body, origin)
        if not scripts:
            continue

        # --- 1. dangling script hosts ---
        hosts = [h for h in script_hosts(scripts) if h not in seen_hosts]
        seen_hosts.update(hosts)

        async def check_host(host: str):
            return host, await resolves(host)

        for host, alive in await fetch.gather_limited(
                [check_host(h) for h in hosts], limit=8) or []:
            if alive:
                continue
            broken = [u for u, _t, _s in scripts
                      if (urlparse(u).hostname or "").lower() == host]
            findings.append({
                "engine": "supplychain", "rule_id": "dangling-script-host",
                "name": f"Script loaded from a domain that no longer resolves: {host}",
                "severity": Severity.critical,
                "host": page_host, "url": origin, "matched_at": broken[0] if broken else host,
                "description": (
                    f"`{origin}` loads JavaScript from **{host}**, and that "
                    f"hostname has no DNS record.\n\n"
                    f"Whoever registers or takes over that name gets arbitrary "
                    f"JavaScript execution on every page that includes the tag — "
                    f"with full access to the DOM, the session, anything typed "
                    f"into a form, and the ability to rewrite the page entirely. "
                    f"No vulnerability in your application is required. The only "
                    f"cost to the attacker is a domain registration.\n\n"
                    f"This usually happens the same way every time: an analytics "
                    f"vendor, a chat widget or a marketing tag is decommissioned, "
                    f"the account lapses, and the script tag stays in a template "
                    f"nobody has read in three years. Today the browser silently "
                    f"fails to load it and nothing looks wrong.\n\n"
                    f"**Verify the domain is genuinely unregistered before "
                    f"reporting it as claimable** — a WHOIS lookup settles it. A "
                    f"name that is registered but has no A record is still a "
                    f"broken dependency, just not an immediate takeover."),
                "evidence": f"Page: {origin}\n"
                            + "\n".join(f"  <script src=\"{u}\">" for u in broken[:5])
                            + f"\n\n{host} — no A record, no CNAME",
                "remediation": (
                    "1. **Remove the script tag.** That closes it immediately and "
                    "costs nothing, since the script isn't loading anyway.\n"
                    "2. If the dependency is still needed, self-host the file or "
                    "move to a maintained provider.\n"
                    "3. **Register the domain defensively** if it is genuinely "
                    "available and you cannot deploy quickly — it is far cheaper "
                    "than the incident.\n"
                    "4. Add a Content Security Policy with an explicit `script-src` "
                    "allowlist. A CSP would have prevented this from being "
                    "exploitable even with the tag in place.\n"
                    "5. Audit every template for other third-party tags and check "
                    "each one still belongs to who you think it does."),
                "references": [
                    "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
                ],
                "tags": ["supply-chain", "takeover", "critical-compromise"],
                "cve": [], "cwe": ["CWE-1104", "CWE-829"], "cvss_score": 9.0,
                "dedupe_key": make_dedupe_key("supplychain", "dangling-script",
                                              page_host, host),
                "raw": {"script_host": host, "scripts": broken[:10]},
            })

        # --- 2. missing subresource integrity ---
        unprotected = [(u, t) for u, t, sri in scripts if not sri]
        if unprotected:
            risky = [(u, t) for u, t in unprotected
                     if not MAJOR_CDNS.search(urlparse(u).hostname or "")]
            severity = Severity.medium if risky else Severity.low
            key = f"sri-{page_host}"
            if key not in seen_rules:
                seen_rules.add(key)
                findings.append({
                    "engine": "supplychain", "rule_id": "missing-sri",
                    "name": f"{len(unprotected)} third-party script(s) without "
                            f"Subresource Integrity",
                    "severity": severity,
                    "host": page_host, "url": origin, "matched_at": origin,
                    "description": (
                        f"`{origin}` loads {len(unprotected)} script(s) or "
                        f"stylesheet(s) from other origins with no `integrity` "
                        f"attribute. The browser will execute whatever those hosts "
                        f"return, whenever they return it.\n\n"
                        + (f"**{len(risky)} of them are not on a major CDN**, which "
                           f"is where the real risk sits: "
                           f"{', '.join(sorted({(urlparse(u).hostname or '') for u, _t in risky})[:5])}. "
                           f"A small vendor's tag server is a far more plausible "
                           f"compromise than jsDelivr, and it is the kind of "
                           f"dependency nobody is monitoring.\n\n"
                           if risky else
                           "All of them are on well-known CDNs, so this is defence "
                           "in depth rather than an urgent exposure.\n\n")
                        + "Supply chain compromise stopped being rare. In 2026 a "
                          "self-propagating worm moved through hundreds of npm "
                          "packages by stealing maintainer tokens, and widely-used "
                          "libraries were trojanised through account takeover. When "
                          "that happens to something you load, SRI is the "
                          "difference between the attacker's code running on your "
                          "site and the browser refusing to execute it."),
                    "evidence": "\n".join(t[:200] for _u, t in unprotected[:6]),
                    "remediation": (
                        "Add an integrity hash and `crossorigin` to every "
                        "third-party tag:\n\n"
                        "  <script src=\"https://cdn.example.com/lib.js\"\n"
                        "          integrity=\"sha384-…\"\n"
                        "          crossorigin=\"anonymous\"></script>\n\n"
                        "Generate the hash with:\n"
                        "  `curl -s <url> | openssl dgst -sha384 -binary | openssl base64 -A`\n\n"
                        "SRI pins a specific file, so a provider that ships updates "
                        "at a floating URL will break — pin the version in the URL "
                        "too, which you want anyway.\n\n"
                        "For anything you can self-host, self-host it. That removes "
                        "the dependency rather than verifying it, and eliminates "
                        "the privacy exposure of every visitor's IP going to a "
                        "third party as a side effect.\n\n"
                        "Then add a Content Security Policy with "
                        "`require-sri-for script style` so a future tag added "
                        "without a hash is rejected rather than silently trusted."),
                    "references": [
                        "https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity",
                        "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
                    ],
                    "tags": ["supply-chain", "integrity"],
                    "cve": [], "cwe": ["CWE-353", "CWE-829"], "cvss_score": None,
                    "dedupe_key": make_dedupe_key("supplychain", "missing-sri",
                                                  page_host, origin),
                    "raw": {"count": len(unprotected),
                            "off_cdn": [u for u, _t in risky][:20]},
                })

        # --- 3. known-vulnerable library versions ---
        for url, _tag, _sri in scripts:
            parsed = parse_version(url)
            if not parsed:
                continue
            library, version = parsed
            if not is_outdated(library, version):
                continue
            key = f"{page_host}-{library}"
            if key in seen_rules:
                continue
            seen_rules.add(key)

            floor = VULNERABLE_BELOW[library]
            findings.append({
                "engine": "supplychain", "rule_id": "outdated-js-library",
                "name": f"Outdated library with known vulnerabilities: "
                        f"{library} {'.'.join(str(v) for v in version)}",
                "severity": Severity.medium,
                "host": page_host, "url": url, "matched_at": url,
                "description": (
                    f"`{origin}` loads **{library} "
                    f"{'.'.join(str(v) for v in version)}**, which is below "
                    f"{'.'.join(str(v) for v in floor)} — the first version "
                    f"without publicly documented vulnerabilities in this "
                    f"library.\n\n"
                    f"Whether this is exploitable depends entirely on how the "
                    f"library is used. Most of these are prototype pollution or "
                    f"XSS sinks that need attacker-controlled input reaching a "
                    f"specific function, so confirm the path before assigning a "
                    f"severity — an old jQuery on a static marketing page is not "
                    f"the same finding as an old jQuery handling user input.\n\n"
                    f"What it reliably tells you is that this dependency is not "
                    f"being tracked, which usually means the others aren't "
                    f"either."),
                "evidence": f"Loaded from {url}\n"
                            f"Detected: {library} "
                            f"{'.'.join(str(v) for v in version)}",
                "remediation": (
                    f"Upgrade {library} to at least "
                    f"{'.'.join(str(v) for v in floor)}, or later if a newer "
                    f"major release is available.\n\n"
                    "More usefully: put a dependency scanner in CI so this is "
                    "caught at build time rather than by someone scanning the "
                    "live site. `npm audit`, Dependabot, Renovate or Trivy all "
                    "do this, and any of them beats finding out this way."),
                "references": [
                    "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
                ],
                "tags": ["supply-chain", "outdated", "cve"],
                "cve": [], "cwe": ["CWE-1104", "CWE-937"], "cvss_score": None,
                "dedupe_key": make_dedupe_key("supplychain", f"outdated-{library}",
                                              page_host, origin),
                "raw": {"library": library,
                        "version": ".".join(str(v) for v in version)},
            })

    if log:
        dangling = sum(1 for f in findings
                       if f["rule_id"] == "dangling-script-host")
        await log("info", f"[supplychain] {len(findings)} finding(s)", "supplychain")
        if dangling:
            await log("error",
                      f"[supplychain] {dangling} script host(s) no longer resolve "
                      f"— whoever registers them executes JavaScript on every "
                      f"page", "supplychain")
    return findings
