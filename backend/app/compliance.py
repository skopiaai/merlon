"""Compliance control mapping.

A raw finding list isn't an audit artefact. What makes output usable to a
reviewer is traceability: this finding violates *that* control, in a standard
they're already being measured against.

GIGW 3.0 — the standard for Indian government websites — builds its security
baseline on ISO 27001, OWASP ASVS, the OWASP Top 10 and CIS Benchmarks, so
mapping to those four covers both bug bounty reporting and institutional audit
work with one table.

Mappings are keyed by rule_id prefix, then by tag, then by CWE, so a new
detection inherits sensible references without needing a table entry.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import Severity


@dataclass
class Controls:
    owasp_top10: str = ""        # OWASP Top 10 2021 category
    asvs: list[str] = field(default_factory=list)   # ASVS 4.0 requirement IDs
    iso27001: list[str] = field(default_factory=list)  # ISO/IEC 27001:2022 Annex A
    cis: list[str] = field(default_factory=list)    # CIS Controls v8
    gigw: str = ""               # GIGW 3.0 security section
    cwe: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "owasp_top10": self.owasp_top10, "asvs": self.asvs,
            "iso27001": self.iso27001, "cis": self.cis,
            "gigw": self.gigw, "cwe": self.cwe,
        }

    def is_empty(self) -> bool:
        return not (self.owasp_top10 or self.asvs or self.iso27001 or self.cis)


# ---- exact rule_id (or prefix) -> controls -------------------------------

RULE_MAP: dict[str, Controls] = {
    # transport
    "missing-hsts": Controls(
        "A02:2021 Cryptographic Failures", ["V9.1.1", "V14.4.5"],
        ["A.8.24"], ["3.10"], "Transport security", ["CWE-319"]),
    "weak-hsts": Controls(
        "A02:2021 Cryptographic Failures", ["V14.4.5"], ["A.8.24"], ["3.10"],
        "Transport security", ["CWE-319"]),
    "hsts-no-subdomains": Controls(
        "A02:2021 Cryptographic Failures", ["V14.4.5"], ["A.8.24"], ["3.10"],
        "Transport security", ["CWE-319"]),
    "no-https": Controls(
        "A02:2021 Cryptographic Failures", ["V9.1.1"], ["A.8.24"], ["3.10"],
        "Transport security", ["CWE-319"]),
    "testssl-": Controls(
        "A02:2021 Cryptographic Failures", ["V9.1.2", "V9.1.3"],
        ["A.8.24"], ["3.10"], "Transport security", ["CWE-327"]),
    "tls-": Controls(
        "A02:2021 Cryptographic Failures", ["V9.1.1"], ["A.8.24"], ["3.10"],
        "Transport security", ["CWE-295"]),

    # headers / browser controls
    "missing-csp": Controls(
        "A05:2021 Security Misconfiguration", ["V14.4.3"], ["A.8.9"], ["4.1"],
        "Application security controls", ["CWE-1021", "CWE-79"]),
    "weak-csp": Controls(
        "A05:2021 Security Misconfiguration", ["V14.4.3"], ["A.8.9"], ["4.1"],
        "Application security controls", ["CWE-79"]),
    "wildcard-csp": Controls(
        "A05:2021 Security Misconfiguration", ["V14.4.3"], ["A.8.9"], ["4.1"],
        "Application security controls", ["CWE-79"]),
    "missing-xfo": Controls(
        "A05:2021 Security Misconfiguration", ["V14.4.7"], ["A.8.9"], ["4.1"],
        "Application security controls", ["CWE-1021"]),
    "missing-nosniff": Controls(
        "A05:2021 Security Misconfiguration", ["V14.4.4"], ["A.8.9"], ["4.1"],
        "Application security controls", ["CWE-430"]),
    "missing-referrer-policy": Controls(
        "A05:2021 Security Misconfiguration", ["V14.4.6"], ["A.8.9"], ["4.1"],
        "Privacy and data protection", ["CWE-200"]),
    "missing-permissions-policy": Controls(
        "A05:2021 Security Misconfiguration", ["V14.4.1"], ["A.8.9"], ["4.1"],
        "Application security controls", ["CWE-693"]),

    # session
    "insecure-cookie": Controls(
        "A07:2021 Identification and Authentication Failures",
        ["V3.4.1", "V3.4.2", "V3.4.3"], ["A.8.5"], ["6.3"],
        "Session management", ["CWE-1004", "CWE-614"]),
    "chain-session-theft": Controls(
        "A07:2021 Identification and Authentication Failures",
        ["V3.4.1", "V14.4.3"], ["A.8.5"], ["6.3"], "Session management",
        ["CWE-1004"]),
    "chain-session-interception": Controls(
        "A02:2021 Cryptographic Failures", ["V3.4.1", "V9.1.1"],
        ["A.8.24"], ["3.10"], "Session management", ["CWE-614"]),

    # access control
    "exposed-surface": Controls(
        "A01:2021 Broken Access Control", ["V4.1.1", "V1.4.1"],
        ["A.8.3", "A.8.20"], ["3.3", "4.1"], "Access control", ["CWE-284"]),
    "exposed-service": Controls(
        "A05:2021 Security Misconfiguration", ["V1.14.4"],
        ["A.8.20", "A.8.22"], ["4.4", "13.4"], "Network security", ["CWE-284"]),
    "chain-admin-fingerprint": Controls(
        "A01:2021 Broken Access Control", ["V4.1.1"], ["A.8.3"], ["4.1"],
        "Access control", ["CWE-284"]),
    "chain-data-exposure": Controls(
        "A05:2021 Security Misconfiguration", ["V1.14.4"],
        ["A.8.20", "A.8.22"], ["4.4"], "Network security", ["CWE-284"]),

    # CORS
    "cors-wildcard": Controls(
        "A05:2021 Security Misconfiguration", ["V14.5.3"], ["A.8.9"], ["4.1"],
        "Application security controls", ["CWE-942"]),

    # disclosure
    "version-disclosure": Controls(
        "A05:2021 Security Misconfiguration", ["V14.3.3"], ["A.8.9"], ["4.1"],
        "Information disclosure", ["CWE-200"]),
    "chain-source-disclosure": Controls(
        "A01:2021 Broken Access Control", ["V14.3.2", "V1.14.3"],
        ["A.8.4", "A.8.12"], ["3.3"], "Information disclosure", ["CWE-200"]),

    # DNS / email
    "spf-": Controls(
        "A07:2021 Identification and Authentication Failures", [],
        ["A.5.14"], ["9.2"], "Email security", ["CWE-290"]),
    "dmarc-": Controls(
        "A07:2021 Identification and Authentication Failures", [],
        ["A.5.14"], ["9.2"], "Email security", ["CWE-290"]),
    "dkim-": Controls(
        "A07:2021 Identification and Authentication Failures", [],
        ["A.5.14"], ["9.2"], "Email security", ["CWE-290"]),
    "dnssec-missing": Controls(
        "A08:2021 Software and Data Integrity Failures", [],
        ["A.8.20"], ["4.9"], "DNS security", ["CWE-350"]),
    "caa-missing": Controls(
        "A05:2021 Security Misconfiguration", [], ["A.8.24"], ["3.10"],
        "PKI management", []),
    "zone-transfer": Controls(
        "A01:2021 Broken Access Control", [], ["A.8.20"], ["4.9"],
        "DNS security", ["CWE-200"]),
    "dangling-cname": Controls(
        "A05:2021 Security Misconfiguration", [], ["A.8.20"], ["4.9"],
        "DNS security", ["CWE-350"]),

    # compromise / SEO spam
    "seo-cloaking": Controls(
        "A08:2021 Software and Data Integrity Failures", ["V14.2.1", "V1.14.3"],
        ["A.8.7", "A.8.32"], ["10.1", "4.1"], "Website integrity", ["CWE-506"]),
    "seo-spam-content": Controls(
        "A08:2021 Software and Data Integrity Failures", ["V14.2.1"],
        ["A.8.7", "A.8.32"], ["10.1"], "Website integrity", ["CWE-506"]),
    "malicious-redirect": Controls(
        "A08:2021 Software and Data Integrity Failures", ["V5.1.5"],
        ["A.8.7"], ["10.1"], "Website integrity", ["CWE-601"]),
    "js-spam-redirect": Controls(
        "A08:2021 Software and Data Integrity Failures", ["V5.1.5"],
        ["A.8.7"], ["10.1"], "Website integrity", ["CWE-601"]),
    "unexpected-language": Controls(
        "A08:2021 Software and Data Integrity Failures", [], ["A.8.32"],
        ["10.1"], "Website integrity", []),

    # services
    "nse-ftp-anon": Controls(
        "A07:2021 Identification and Authentication Failures", ["V2.1.1"],
        ["A.8.5"], ["4.1"], "Access control", ["CWE-287"]),
    "nse-smb": Controls(
        "A05:2021 Security Misconfiguration", [], ["A.8.20"], ["4.1"],
        "Network security", ["CWE-757"]),
    "nse-snmp-info": Controls(
        "A07:2021 Identification and Authentication Failures", [],
        ["A.8.5"], ["4.1"], "Network security", ["CWE-1188"]),
    "nse-mongodb": Controls(
        "A01:2021 Broken Access Control", [], ["A.8.3"], ["3.3"],
        "Access control", ["CWE-306"]),
    "nse-redis": Controls(
        "A01:2021 Broken Access Control", [], ["A.8.3"], ["3.3"],
        "Access control", ["CWE-306"]),

    # subdomain takeover
    "subdomain-takeover": Controls(
        "A05:2021 Security Misconfiguration", ["V1.14.1"], ["A.8.20", "A.5.9"],
        ["4.9", "1.1"], "DNS security", ["CWE-350"]),
    "dangling-cname": Controls(
        "A05:2021 Security Misconfiguration", ["V1.14.1"], ["A.8.20"],
        ["4.9"], "DNS security", ["CWE-1104"]),

    # cross-origin policy
    "cors-": Controls(
        "A05:2021 Security Misconfiguration", ["V14.5.3", "V13.2.5"],
        ["A.8.9", "A.8.26"], ["4.1"], "Application security controls",
        ["CWE-942", "CWE-346"]),

    # redirects
    "open-redirect": Controls(
        "A01:2021 Broken Access Control", ["V5.1.5"], ["A.8.28"], ["16.11"],
        "Input validation", ["CWE-601"]),

    # methods and access control enforcement
    "dangerous-http-methods": Controls(
        "A05:2021 Security Misconfiguration", ["V14.1.1", "V14.5.1"],
        ["A.8.9"], ["4.1"], "Server hardening", ["CWE-650", "CWE-16"]),
    "access-control-bypass": Controls(
        "A01:2021 Broken Access Control", ["V4.1.1", "V4.1.3"],
        ["A.8.3", "A.5.15"], ["6.8", "3.3"], "Access control",
        ["CWE-284", "CWE-425"]),

    # API surface
    "api-spec-exposed": Controls(
        "A05:2021 Security Misconfiguration", ["V14.3.2"], ["A.8.4"], ["3.3"],
        "Information disclosure", ["CWE-200"]),
    "graphql-introspection": Controls(
        "A05:2021 Security Misconfiguration", ["V13.4.1", "V14.3.2"],
        ["A.8.9"], ["3.3"], "Information disclosure", ["CWE-200"]),
    "debug-endpoint": Controls(
        "A05:2021 Security Misconfiguration", ["V14.1.3", "V14.3.2"],
        ["A.8.9", "A.8.4"], ["4.1", "3.3"], "Configuration management",
        ["CWE-489", "CWE-200"]),

    # hidden parameters
    "hidden-parameter": Controls(
        "A04:2021 Insecure Design", ["V5.1.1", "V13.1.4"], ["A.8.26"],
        ["16.11"], "Input validation", ["CWE-233", "CWE-1230"]),

    # exposed files — after the more specific "exposed-surface"/"exposed-service"
    "exposed-": Controls(
        "A05:2021 Security Misconfiguration", ["V14.3.2", "V1.14.3"],
        ["A.8.4", "A.5.14"], ["3.3", "4.1"], "Information disclosure",
        ["CWE-530", "CWE-538", "CWE-200"]),

    # reconnaissance context
    "favicon-": Controls(
        "A05:2021 Security Misconfiguration", ["V14.3.3"], ["A.8.9"], ["1.1"],
        "Asset inventory", ["CWE-200"]),
    "hidden-vhost": Controls(
        "A05:2021 Security Misconfiguration", ["V1.14.4", "V14.1.1"],
        ["A.8.9", "A.5.9"], ["1.1", "4.1"], "Asset inventory", ["CWE-200"]),
    "asn-inventory": Controls(
        "A05:2021 Security Misconfiguration", [], ["A.5.9"], ["1.1"],
        "Asset inventory", []),

    # access control, found by comparing sessions
    "missing-authentication": Controls(
        "A01:2021 Broken Access Control", ["V4.1.1", "V4.1.3", "V1.4.1"],
        ["A.5.15", "A.8.3"], ["6.8", "3.3"], "Access control",
        ["CWE-306", "CWE-425"]),
    "idor-cross-account": Controls(
        "A01:2021 Broken Access Control", ["V4.2.1", "V4.1.3", "V13.1.4"],
        ["A.5.15", "A.8.3"], ["3.3", "6.8"], "Access control",
        ["CWE-639", "CWE-284", "CWE-863"]),

    # infrastructure exposed behind a CDN
    "origin-ip-exposed": Controls(
        "A05:2021 Security Misconfiguration", ["V1.14.1", "V14.1.1"],
        ["A.8.20", "A.8.9"], ["4.1", "13.10"], "Network security",
        ["CWE-693", "CWE-1327"]),

    # LLM-backed applications. The OWASP web Top 10 predates these, so the
    # mapping lands them in the nearest applicable web category while the GIGW
    # column names what they actually are — an audit reader needs both.
    "llm-prompt-injection": Controls(
        "A03:2021 Injection", ["V5.1.1", "V5.3.4"], ["A.8.28", "A.8.26"],
        ["16.11"], "AI system security (OWASP LLM01)", ["CWE-77", "CWE-1427"]),
    "llm-system-prompt-leak": Controls(
        "A05:2021 Security Misconfiguration", ["V14.3.2"], ["A.8.4", "A.5.14"],
        ["3.3"], "AI system security (OWASP LLM07)", ["CWE-200"]),
    "llm-unbounded-consumption": Controls(
        "A04:2021 Insecure Design", ["V13.4.1", "V11.1.4"], ["A.8.6"],
        ["13.10"], "AI system security (OWASP LLM10)", ["CWE-770"]),
    "llm-": Controls(
        "A04:2021 Insecure Design", ["V5.1.1"], ["A.8.26"], ["16.11"],
        "AI system security", ["CWE-1427"]),
}

# ---- fallback by nuclei tag ----------------------------------------------

TAG_MAP: dict[str, Controls] = {
    "sqli": Controls("A03:2021 Injection", ["V5.3.4"], ["A.8.28"], ["16.11"],
                     "Input validation", ["CWE-89"]),
    "xss": Controls("A03:2021 Injection", ["V5.3.3"], ["A.8.28"], ["16.11"],
                    "Input validation", ["CWE-79"]),
    "rce": Controls("A03:2021 Injection", ["V5.3.8"], ["A.8.28"], ["16.11"],
                    "Input validation", ["CWE-94"]),
    "lfi": Controls("A01:2021 Broken Access Control", ["V12.3.1"], ["A.8.3"],
                    ["16.11"], "Input validation", ["CWE-22"]),
    "ssrf": Controls("A10:2021 Server-Side Request Forgery", ["V12.6.1"],
                     ["A.8.28"], ["16.11"], "Input validation", ["CWE-918"]),
    "redirect": Controls("A01:2021 Broken Access Control", ["V5.1.5"],
                         ["A.8.28"], ["16.11"], "Input validation", ["CWE-601"]),
    "takeover": Controls("A05:2021 Security Misconfiguration", [], ["A.8.20"],
                         ["4.9"], "DNS security", ["CWE-350"]),
    "default-login": Controls("A07:2021 Identification and Authentication Failures",
                              ["V2.1.1"], ["A.8.5"], ["4.7"], "Access control",
                              ["CWE-1392"]),
    "auth-bypass": Controls("A07:2021 Identification and Authentication Failures",
                            ["V2.1.1"], ["A.8.5"], ["6.3"], "Access control",
                            ["CWE-287"]),
    "exposure": Controls("A01:2021 Broken Access Control", ["V14.3.2"],
                         ["A.8.4"], ["3.3"], "Information disclosure", ["CWE-200"]),
    "disclosure": Controls("A05:2021 Security Misconfiguration", ["V14.3.3"],
                           ["A.8.9"], ["3.3"], "Information disclosure", ["CWE-200"]),
    "misconfig": Controls("A05:2021 Security Misconfiguration", ["V14.1.1"],
                          ["A.8.9"], ["4.1"], "Configuration management", []),
    "config": Controls("A05:2021 Security Misconfiguration", ["V14.1.1"],
                       ["A.8.9"], ["4.1"], "Configuration management", []),
    "backup": Controls("A01:2021 Broken Access Control", ["V14.3.2"], ["A.8.4"],
                       ["3.3"], "Information disclosure", ["CWE-200"]),
    "cve": Controls("A06:2021 Vulnerable and Outdated Components", ["V14.2.1"],
                    ["A.8.8"], ["7.1"], "Patch management", []),
}

# ---- fallback by CWE ------------------------------------------------------

CWE_MAP: dict[str, str] = {
    "CWE-79": "A03:2021 Injection",
    "CWE-89": "A03:2021 Injection",
    "CWE-22": "A01:2021 Broken Access Control",
    "CWE-284": "A01:2021 Broken Access Control",
    "CWE-287": "A07:2021 Identification and Authentication Failures",
    "CWE-295": "A02:2021 Cryptographic Failures",
    "CWE-306": "A01:2021 Broken Access Control",
    "CWE-319": "A02:2021 Cryptographic Failures",
    "CWE-327": "A02:2021 Cryptographic Failures",
    "CWE-352": "A01:2021 Broken Access Control",
    "CWE-601": "A01:2021 Broken Access Control",
    "CWE-918": "A10:2021 Server-Side Request Forgery",
    "CWE-1021": "A05:2021 Security Misconfiguration",
}

# Severity floors: some control failures shouldn't be reported as trivial in an
# audit context even when technically low risk in isolation.
AUDIT_FLOOR: dict[str, Severity] = {
    "dmarc-missing": Severity.high,
    "spf-missing": Severity.medium,
    "zone-transfer": Severity.high,
}


def controls_for(finding: dict) -> Controls:
    """Best available control mapping for a finding."""
    rule_id = str(finding.get("rule_id", ""))
    tags = [str(t).lower() for t in (finding.get("tags") or [])]
    cwes = [str(c).upper() for c in (finding.get("cwe") or [])]

    # 1. exact or prefix match on rule id
    for key, ctrl in RULE_MAP.items():
        if rule_id == key or rule_id.startswith(key):
            return ctrl

    # 2. nuclei tag
    for tag in tags:
        if tag in TAG_MAP:
            return TAG_MAP[tag]

    # 3. CWE
    for cwe in cwes:
        if cwe in CWE_MAP:
            return Controls(CWE_MAP[cwe], cwe=[cwe])

    # 4. severity-based catch-all so nothing is unmapped in a report
    if finding.get("cve"):
        return TAG_MAP["cve"]
    return Controls("A05:2021 Security Misconfiguration", gigw="General security")


def enrich(finding: dict) -> dict:
    """Attach control references, in place. Safe to call twice."""
    ctrl = controls_for(finding)
    finding["compliance"] = ctrl.as_dict()

    # Merge any CWE the mapping knows about but the engine didn't set.
    existing = {str(c).upper() for c in (finding.get("cwe") or [])}
    for cwe in ctrl.cwe:
        if cwe.upper() not in existing:
            finding.setdefault("cwe", []).append(cwe)
    return finding


def coverage_matrix(findings: list) -> dict:
    """Count findings per control family, for the audit report."""
    top10: dict[str, int] = {}
    iso: dict[str, int] = {}
    gigw: dict[str, int] = {}

    for f in findings:
        comp = getattr(f, "compliance", None) or (
            f.get("compliance") if isinstance(f, dict) else None)
        if not comp:
            comp = controls_for(f if isinstance(f, dict) else {
                "rule_id": f.rule_id, "tags": f.tags, "cwe": f.cwe,
                "cve": f.cve,
            }).as_dict()
        if comp.get("owasp_top10"):
            top10[comp["owasp_top10"]] = top10.get(comp["owasp_top10"], 0) + 1
        for c in comp.get("iso27001", []):
            iso[c] = iso.get(c, 0) + 1
        if comp.get("gigw"):
            gigw[comp["gigw"]] = gigw.get(comp["gigw"], 0) + 1

    return {
        "owasp_top10": dict(sorted(top10.items(), key=lambda kv: -kv[1])),
        "iso27001": dict(sorted(iso.items(), key=lambda kv: -kv[1])),
        "gigw": dict(sorted(gigw.items(), key=lambda kv: -kv[1])),
    }


# The full OWASP Top 10 2021 list, so the report can show categories with zero
# findings too — "we looked and found nothing" is itself audit evidence.
OWASP_TOP10_ALL = [
    "A01:2021 Broken Access Control",
    "A02:2021 Cryptographic Failures",
    "A03:2021 Injection",
    "A04:2021 Insecure Design",
    "A05:2021 Security Misconfiguration",
    "A06:2021 Vulnerable and Outdated Components",
    "A07:2021 Identification and Authentication Failures",
    "A08:2021 Software and Data Integrity Failures",
    "A09:2021 Security Logging and Monitoring Failures",
    "A10:2021 Server-Side Request Forgery",
]

# Categories automated scanning cannot meaningfully assess — stated explicitly
# in the report rather than left as an implied clean result.
OWASP_NOT_TESTABLE = {
    "A04:2021 Insecure Design":
        "Requires design review and threat modelling; not assessable by scanning.",
    "A09:2021 Security Logging and Monitoring Failures":
        "Requires access to logging infrastructure; not observable externally.",
}
