"""Paths the site declares but never links.

robots.txt is the classic example: it exists to tell crawlers what *not* to
index, which means it is a curated list of the paths the owner considers
sensitive. Sitemaps list pages that may not be reachable through navigation.
`.well-known` carries security contacts, and its absence is itself worth
reporting to an organisation that wants vulnerability reports.

All of it is one request each, published deliberately, and read by every
crawler on the internet — about as passive as active testing gets.
"""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urljoin, urlparse

from ..models import Severity
from ..normalize import make_dedupe_key
from .registry import EngineSpec, register

DECLARED_FILES = [
    "/robots.txt",
    "/sitemap.xml",
    "/sitemap_index.xml",
    "/.well-known/security.txt",
    "/security.txt",
    "/.well-known/change-password",
    "/humans.txt",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    "/.well-known/openid-configuration",
    "/.well-known/assetlinks.json",
    "/.well-known/apple-app-site-association",
]

DISALLOW = re.compile(r"^\s*(?:dis)?allow\s*:\s*(\S+)", re.I | re.M)
SITEMAP_IN_ROBOTS = re.compile(r"^\s*sitemap\s*:\s*(\S+)", re.I | re.M)
SITEMAP_LOC = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.I)

# A Disallow entry naming one of these is the owner telling you where the
# interesting things are.
SENSITIVE_HINT = re.compile(
    r"admin|internal|private|backup|config|secret|token|api|debug|test|staging|"
    r"upload|export|dump|db|sql|log|panel|console|manage|cgi|phpmyadmin", re.I)


async def _get(url: str, timeout: int = 12) -> tuple[int, str]:
    try:
        proc = await asyncio.create_subprocess_exec(
            "curl", "-sS", "-L", "--max-time", str(timeout), "--max-redirs", "2",
            "-o", "-", "-w", "\n---CODE---%{http_code}", url,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 5)
    except (asyncio.TimeoutError, OSError):
        return 0, ""
    text = out.decode("utf-8", "replace")
    if "\n---CODE---" not in text:
        return 0, text
    body, code = text.rsplit("\n---CODE---", 1)
    return (int(code.strip()) if code.strip().isdigit() else 0), body


def parse_robots(body: str, base: str) -> tuple[list[str], list[str], list[str]]:
    """Returns (paths, sitemaps, sensitive_paths)."""
    paths, sensitive = [], []
    for rule in DISALLOW.findall(body or ""):
        path = rule.strip()
        if not path or path in ("/", "*"):
            continue
        path = path.replace("*", "").split("$")[0]
        if not path.startswith("/"):
            continue
        url = urljoin(base, path)
        paths.append(url)
        if SENSITIVE_HINT.search(path):
            sensitive.append(path)
    sitemaps = [s.strip() for s in SITEMAP_IN_ROBOTS.findall(body or "")]
    return sorted(set(paths)), sorted(set(sitemaps)), sorted(set(sensitive))


def parse_sitemap(body: str, apex: str, cap: int = 2000) -> list[str]:
    out: set[str] = set()
    for loc in SITEMAP_LOC.findall(body or ""):
        host = (urlparse(loc).hostname or "").lower()
        if host and (host == apex or host.endswith("." + apex)):
            out.add(loc.strip())
        if len(out) >= cap:
            break
    return sorted(out)


@register(EngineSpec(
    name="wellknown",
    label="Reading declared paths",
    description="robots.txt, sitemaps, security.txt and .well-known. robots.txt in "
                "particular is a curated list of what the owner considers sensitive.",
    phase="post_http",
    takes="urls",
    produces="urls",
    weight=4,
    limit=6,
    default_in=("quick", "standard", "deep"),
))
async def _engine(targets: list[str], ctx: dict) -> list[str]:
    log = ctx.get("log")
    discovered: set[str] = set()
    origins = sorted({f"{urlparse(u).scheme}://{urlparse(u).netloc}"
                      for u in targets if urlparse(u).netloc})

    for origin in origins[:6]:
        apex = (urlparse(origin).hostname or "").lower()

        for path in DECLARED_FILES:
            status, body = await _get(urljoin(origin, path))
            if status != 200 or not body.strip():
                continue
            discovered.add(urljoin(origin, path))

            if path == "/robots.txt":
                paths, sitemaps, sensitive = parse_robots(body, origin)
                discovered.update(paths)
                for sm in sitemaps[:5]:
                    _s, sm_body = await _get(sm)
                    discovered.update(parse_sitemap(sm_body, apex))
                if sensitive and log:
                    await log("warn",
                              f"[wellknown] robots.txt on {apex} names "
                              f"{len(sensitive)} sensitive-looking path(s) — the owner "
                              f"is telling you where to look: "
                              f"{', '.join(sensitive[:5])}", "wellknown")

            elif "sitemap" in path:
                discovered.update(parse_sitemap(body, apex))

    result = sorted(discovered)
    if log:
        await log("info", f"[wellknown] {len(result)} declared path(s) across "
                          f"{len(origins[:6])} origin(s)", "wellknown")
    return result


# ---------------------------------------------------------------------------
# A second engine in the same file: the *absence* of security.txt is a finding
# in its own right, and it belongs next to the code that looks for it.

@register(EngineSpec(
    name="securitytxt",
    label="Checking for a security contact",
    description="RFC 9116 security.txt. Its absence means a researcher who finds a "
                "vulnerability has no documented way to report it.",
    phase="post_http",
    takes="urls",
    produces="findings",
    weight=2,
    limit=3,
    default_in=("standard", "deep"),
))
async def _securitytxt(targets: list[str], ctx: dict) -> list[dict]:
    findings: list[dict] = []
    origins = sorted({f"{urlparse(u).scheme}://{urlparse(u).netloc}"
                      for u in targets if urlparse(u).netloc})[:3]

    for origin in origins:
        host = (urlparse(origin).hostname or "").lower()
        found = False
        for path in ("/.well-known/security.txt", "/security.txt"):
            status, body = await _get(urljoin(origin, path))
            if status == 200 and "contact" in (body or "").lower():
                found = True
                break
        if found:
            continue

        findings.append({
            "engine": "wellknown",
            "rule_id": "missing-security-txt",
            "name": "No security.txt contact published",
            "severity": Severity.info,
            "host": host,
            "url": urljoin(origin, "/.well-known/security.txt"),
            "matched_at": urljoin(origin, "/.well-known/security.txt"),
            "description": (
                "There's no security.txt, so a researcher who finds a vulnerability "
                "has no documented way to report it. In practice that means reports "
                "go to a generic support inbox and get treated as spam, or don't get "
                "sent at all — which is how organisations end up learning about "
                "issues from an attacker rather than a researcher."
            ),
            "evidence": f"No file at {origin}/.well-known/security.txt or /security.txt",
            "remediation": (
                "Publish /.well-known/security.txt per RFC 9116, with at minimum:\n"
                "  Contact: mailto:security@yourdomain\n"
                "  Expires: <a date within 12 months>\n"
                "  Preferred-Languages: en\n"
                "Add Policy: and Acknowledgments: URLs if you have them."
            ),
            "references": ["https://securitytxt.org/", "https://www.rfc-editor.org/rfc/rfc9116"],
            "tags": ["disclosure", "process"],
            "cve": [], "cwe": [], "cvss_score": None,
            "dedupe_key": make_dedupe_key("wellknown", "missing-security-txt", host, origin),
            "raw": {},
        })
    return findings
