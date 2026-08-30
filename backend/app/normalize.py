"""Map engine-specific output into the unified Finding shape.

This module is the reason a second or third engine is cheap to add: write
one `from_<engine>` function and the whole triage/dedupe/report pipeline
works on it unchanged.
"""

from __future__ import annotations

import hashlib
import re
from urllib.parse import urlparse, urlunparse

from .models import Severity

_SEV_MAP = {
    "info": Severity.info, "informational": Severity.info, "unknown": Severity.info,
    "low": Severity.low,
    "medium": Severity.medium, "moderate": Severity.medium,
    "high": Severity.high,
    "critical": Severity.critical,
}

# Strip volatile path segments so /user/1234/profile and /user/9999/profile
# collapse into one finding instead of two hundred.
_VOLATILE = [
    (re.compile(r"/\d{2,}(?=/|$)"), "/{id}"),
    (re.compile(r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I), "/{uuid}"),
    (re.compile(r"/[0-9a-f]{32,}", re.I), "/{hash}"),
]


def parse_severity(value: str | None) -> Severity:
    return _SEV_MAP.get((value or "info").strip().lower(), Severity.info)


def canonical_url(url: str) -> str:
    """Normalize a URL for dedupe purposes: drop query, collapse volatile IDs."""
    if not url:
        return ""
    try:
        p = urlparse(url)
    except ValueError:
        return url
    path = p.path or "/"
    for pattern, repl in _VOLATILE:
        path = pattern.sub(repl, path)
    return urlunparse((p.scheme, p.netloc.lower(), path, "", "", ""))


def make_dedupe_key(engine: str, rule_id: str, host: str, url: str) -> str:
    """Stable identity for a finding.

    Deliberately excludes severity and evidence: the same issue re-detected
    with slightly different evidence should update, not duplicate.
    """
    basis = f"{engine}|{rule_id}|{host.lower()}|{canonical_url(url)}"
    return hashlib.sha256(basis.encode()).hexdigest()[:32]


def from_nuclei(rec: dict) -> dict:
    """Nuclei JSONL record -> unified finding dict."""
    info = rec.get("info", {}) or {}
    classification = info.get("classification", {}) or {}

    host = (rec.get("host") or "").lower()
    if "://" in host:
        host = urlparse(host).hostname or host
    host = host.split(":")[0]

    url = rec.get("matched-at") or rec.get("host") or ""
    rule_id = rec.get("template-id", "") or ""

    evidence_parts = []
    if rec.get("extracted-results"):
        evidence_parts.append("Extracted: " + ", ".join(map(str, rec["extracted-results"])))
    if rec.get("matcher-name"):
        evidence_parts.append(f"Matcher: {rec['matcher-name']}")
    if rec.get("request"):
        evidence_parts.append("--- request ---\n" + str(rec["request"])[:2000])
    if rec.get("response"):
        evidence_parts.append("--- response (truncated) ---\n" + str(rec["response"])[:2000])

    cvss = classification.get("cvss-score")
    try:
        cvss = float(cvss) if cvss is not None else None
    except (TypeError, ValueError):
        cvss = None

    return {
        "engine": "nuclei",
        "rule_id": rule_id,
        "name": info.get("name") or rule_id or "Unnamed nuclei match",
        "severity": parse_severity(info.get("severity")),
        "host": host,
        "url": url,
        "matched_at": rec.get("matched-at", "") or "",
        "description": (info.get("description") or "").strip(),
        "evidence": "\n\n".join(evidence_parts)[:8000],
        "remediation": (info.get("remediation") or "").strip(),
        "references": info.get("reference") or [],
        "tags": info.get("tags") or [],
        "cve": [c for c in (classification.get("cve-id") or []) if c],
        "cwe": [c for c in (classification.get("cwe-id") or []) if c],
        "cvss_score": cvss,
        "dedupe_key": make_dedupe_key("nuclei", rule_id, host, url),
        "raw": rec,
    }


def from_tlsx(rec: dict) -> dict | None:
    """tlsx record -> finding, only when something is actually wrong."""
    host = (rec.get("host") or "").lower()
    port = rec.get("port", "443")
    url = f"https://{host}:{port}"

    problems: list[tuple[str, str, Severity, str]] = []
    if rec.get("expired"):
        problems.append(("tls-expired", "Expired TLS certificate", Severity.high,
                         "The certificate has passed its expiry date. Visitors get a browser "
                         "warning, and many API clients will refuse to connect at all."))
    if rec.get("self_signed"):
        problems.append(("tls-self-signed", "Self-signed TLS certificate", Severity.medium,
                         "The certificate isn't signed by a trusted authority, so clients "
                         "can't distinguish it from an attacker's certificate."))
    if rec.get("mismatched"):
        problems.append(("tls-mismatch", "TLS certificate hostname mismatch", Severity.medium,
                         "The certificate doesn't cover the hostname it's served on."))
    if rec.get("untrusted"):
        problems.append(("tls-untrusted", "Untrusted TLS certificate chain", Severity.medium,
                         "The chain doesn't resolve to a trusted root — usually a missing "
                         "intermediate certificate."))

    version = (rec.get("tls_version") or "").lower()
    if version in ("tls10", "tls11", "ssl30"):
        problems.append((f"tls-old-{version}", f"Outdated protocol in use: {version.upper()}",
                         Severity.medium,
                         "This protocol version has known weaknesses and is deprecated. "
                         "Modern clients are dropping support for it."))

    if not problems:
        return None

    rule_id, name, sev, desc = max(problems, key=lambda p: p[2].rank)
    extra = [p[1] for p in problems if p[0] != rule_id]

    return {
        "engine": "tlsx",
        "rule_id": rule_id,
        "name": name,
        "severity": sev,
        "host": host,
        "url": url,
        "matched_at": url,
        "description": desc + (f"\n\nAlso detected: {', '.join(extra)}." if extra else ""),
        "evidence": f"Issuer: {rec.get('issuer_dn', 'unknown')}\n"
                    f"Subject: {rec.get('subject_dn', 'unknown')}\n"
                    f"Not after: {rec.get('not_after', 'unknown')}\n"
                    f"Version: {rec.get('tls_version', 'unknown')}  "
                    f"Cipher: {rec.get('cipher', 'unknown')}",
        "remediation": "Reissue or renew the certificate through your CA (Let's Encrypt "
                       "automates this), serve the full chain including intermediates, and "
                       "disable TLS 1.0/1.1 in your server configuration.",
        "references": ["https://ssl-config.mozilla.org/"],
        "tags": ["tls", "certificate"],
        "cve": [], "cwe": ["CWE-295"], "cvss_score": None,
        "dedupe_key": make_dedupe_key("tlsx", rule_id, host, url),
        "raw": rec,
    }


# Services that shouldn't normally face the internet. Value is the severity.
_RISKY_SERVICES = {
    "mysql": Severity.high, "postgresql": Severity.high, "mongodb": Severity.critical,
    "redis": Severity.critical, "elasticsearch": Severity.high, "memcached": Severity.high,
    "ms-sql-s": Severity.high, "oracle-tns": Severity.high, "cassandra": Severity.high,
    "rdp": Severity.high, "ms-wbt-server": Severity.high, "vnc": Severity.high,
    "telnet": Severity.high, "ftp": Severity.medium, "smb": Severity.high,
    "microsoft-ds": Severity.high, "netbios-ssn": Severity.medium, "rpcbind": Severity.medium,
    "docker": Severity.critical, "kubernetes": Severity.high,
}


def from_nmap_service(svc: dict) -> dict | None:
    """nmap service -> finding, when the service itself is the problem."""
    name = (svc.get("service") or "").lower()
    port = svc.get("port")
    host = svc.get("host", "")
    product = " ".join(filter(None, [svc.get("product", ""), svc.get("version", "")])).strip()

    sev = _RISKY_SERVICES.get(name)
    if sev is None:
        return None

    rule_id = f"exposed-service-{name}"
    return {
        "engine": "nmap",
        "rule_id": rule_id,
        "name": f"{name} reachable from the internet on port {port}",
        "severity": sev,
        "host": host,
        "url": f"{host}:{port}",
        "matched_at": f"{host}:{port}",
        "description": (
            f"A {name} service{f' ({product})' if product else ''} is accepting connections "
            f"on port {port}. Databases and remote-access services are meant to sit on a "
            f"private network — exposing them means the only thing between an attacker and "
            f"your data is that service's own authentication, which is frequently misconfigured "
            f"or absent by default."
        ),
        "evidence": f"nmap: {port}/{svc.get('protocol', 'tcp')} {name} {product} "
                    f"{svc.get('extrainfo', '')}".strip(),
        "remediation": (
            f"Bind {name} to localhost or a private interface, and put a firewall rule in "
            f"front of it. If remote access is genuinely required, use a VPN or SSH tunnel "
            f"rather than exposing the port. Confirm authentication is enabled and not using "
            f"default credentials."
        ),
        "references": [],
        "tags": ["exposure", "network", name],
        "cve": [], "cwe": ["CWE-284"], "cvss_score": None,
        "dedupe_key": make_dedupe_key("nmap", rule_id, host, f"{host}:{port}"),
        "raw": svc,
    }


def from_dnsx_takeover(rec: dict) -> dict | None:
    """Dangling CNAME -> possible subdomain takeover.

    Flagged as a lead for manual verification, not a confirmed finding: the
    CNAME target must actually be claimable, which needs a human to check.
    """
    cnames = rec.get("cname") or []
    if not cnames or rec.get("a"):
        return None  # resolves to an address, so not dangling

    host = rec.get("host", "")
    target = cnames[0]
    return {
        "engine": "dnsx",
        "rule_id": "dangling-cname",
        "name": f"Dangling DNS record pointing at {target}",
        "severity": Severity.medium,
        "host": host,
        "url": host,
        "matched_at": host,
        "description": (
            f"{host} has a CNAME to {target}, but that name doesn't resolve to an address. "
            f"If the service it points to can be registered by someone else, they could serve "
            f"content from your subdomain — including a convincing phishing page on your domain."
        ),
        "evidence": f"CNAME: {host} -> {target}\nNo A/AAAA record resolved.",
        "remediation": (
            f"Delete the DNS record for {host} if it's no longer needed, or reclaim the "
            f"service at {target}. Then audit your other CNAMEs for the same pattern."
        ),
        "references": ["https://owasp.org/www-project-web-security-testing-guide/"],
        "tags": ["dns", "takeover"],
        "cve": [], "cwe": ["CWE-350"], "cvss_score": None,
        "dedupe_key": make_dedupe_key("dnsx", "dangling-cname", host, host),
        "raw": rec,
    }


def from_httpx_exposure(asset: dict) -> dict | None:
    """Derive findings from httpx metadata that nuclei won't flag on its own.

    Currently: non-production status codes on what look like admin surfaces.
    This is where you add your own heuristics over time — it's the cheapest
    place to encode 'things I keep noticing manually'.
    """
    url = asset.get("url", "")
    title = (asset.get("title") or "").lower()
    status = asset.get("status_code")
    host = asset.get("host", "")

    admin_words = ("admin", "dashboard", "phpmyadmin", "jenkins", "grafana",
                   "kibana", "swagger", "actuator", "portal", "login")
    hit = next((w for w in admin_words if w in url.lower() or w in title), None)
    if not hit or status not in (200, 401, 403):
        return None

    sev = Severity.medium if status == 200 else Severity.info
    return {
        "engine": "heuristic",
        "rule_id": f"exposed-surface-{hit}",
        "name": f"Administrative surface reachable: {hit}",
        "severity": sev,
        "host": host,
        "url": url,
        "matched_at": url,
        "description": (
            f"An endpoint matching '{hit}' responded with HTTP {status}. "
            "Administrative interfaces reachable from the public internet expand "
            "attack surface even when authentication is enforced."
        ),
        "evidence": f"HTTP {status} — title: {asset.get('title', '')!r}",
        "remediation": (
            "Restrict this interface to a VPN or IP allowlist, and confirm that "
            "authentication cannot be bypassed via path traversal or alternate ports."
        ),
        "references": [],
        "tags": ["exposure", "attack-surface"],
        "cve": [],
        "cwe": ["CWE-284"],
        "cvss_score": None,
        "dedupe_key": make_dedupe_key("heuristic", f"exposed-surface-{hit}", host, url),
        "raw": asset.get("raw", {}),
    }
