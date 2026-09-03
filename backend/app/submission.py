"""Platform-native submission reports.

The last mile. A finding that reproduces, has evidence, and maps to a control
is still worth nothing until it is written in the shape the platform's triage
team reads — and every platform has a different shape.

The difference is not cosmetic. HackerOne triagers work through Summary → Steps
to Reproduce → Impact and reject reports missing reproduction steps outright.
Bugcrowd wants a VRT category up front because that is what determines the
payout band. Intigriti asks for impact separately from description. A good
finding submitted in the wrong shape gets bounced back for "more information"
and loses a week — or gets closed as informative while somebody else files the
same bug properly.

Everything here is assembled from data already captured: the verification
evidence with its request, response, hash and timestamp; the compliance
mapping; and the KEV context if the CVE is being exploited. Nothing is
invented, and there is no model in this path — a report is a rendering problem,
not a generation problem, and generated reports are what programs are currently
drowning in.

**The gate.** A finding that did not reproduce will not render as a submission.
It returns a refusal explaining why instead. That is deliberate: making it
mechanically easy to file an unreproducible finding is precisely the thing
this tool exists not to do.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import Finding, Severity

PLATFORMS = ("hackerone", "bugcrowd", "intigriti", "generic")

# CVSS 3.1 base vectors that match how each severity is usually justified.
# Offered as a starting point to edit, not as a computed score — a real vector
# depends on the specific impact and nobody should paste one they haven't read.
SUGGESTED_VECTOR = {
    Severity.critical: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    Severity.high:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    Severity.medium:   "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
    Severity.low:      "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N",
    Severity.info:     "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
}

# Bugcrowd sorts by its Vulnerability Rating Taxonomy, and the category drives
# the payout band — so getting it roughly right up front matters more than it
# looks. Mapped from our rule ids.
VRT = {
    "subdomain-takeover": "Server Security Misconfiguration > Misconfigured DNS > Subdomain Takeover",
    "idor-cross-account": "Broken Access Control > Insecure Direct Object References (IDOR)",
    "missing-authentication": "Broken Access Control > Username/Email Enumeration",
    "access-control-bypass": "Broken Access Control > Server-Side Request Forgery",
    "exposed-": "Sensitive Data Exposure > Disclosure of Known Secrets",
    "archive-leak-": "Sensitive Data Exposure > Disclosure of Known Secrets",
    "open-redirect": "Unvalidated Redirects and Forwards > Open Redirect",
    "cors-": "Server Security Misconfiguration > Misconfigured CORS",
    "dangling-script-host": "Server Security Misconfiguration > Misconfigured DNS > Subdomain Takeover",
    "origin-ip-exposed": "Server Security Misconfiguration > Origin IP Disclosure",
    "debug-endpoint": "Server Security Misconfiguration > Unsafe Cross-Origin Resource Sharing",
    "graphql-introspection": "Server Security Misconfiguration > Information Disclosure",
    "dangerous-http-methods": "Server Security Misconfiguration > Unsafe HTTP Methods",
    "seo-": "Server Security Misconfiguration > Malicious Content Injection",
    "llm-prompt-injection": "Application-Level Denial-of-Service > Excessive Resource Consumption",
    "mcp-": "Broken Authentication and Session Management > Missing Authentication",
}


@dataclass
class Report:
    platform: str
    title: str
    body: str
    ready: bool
    warning: str = ""

    def as_dict(self) -> dict:
        return {"platform": self.platform, "title": self.title,
                "body": self.body, "ready": self.ready, "warning": self.warning}


def vrt_for(rule_id: str) -> str:
    for prefix, category in VRT.items():
        if rule_id.startswith(prefix):
            return category
    return "Other"


def title_for(finding: Finding) -> str:
    """A title a triager can act on without opening the report.

    Host first, because triage queues are sorted and scanned by asset, and a
    title starting with the vulnerability class makes every report look alike.
    """
    host = finding.host or "target"
    return f"[{host}] {finding.name}"


def _steps(finding: Finding) -> list[str]:
    """Reproduction steps, from the captured evidence.

    A triager who cannot reproduce a finding in two minutes closes it. This is
    the section that decides that, and it is the section most reports get
    wrong — usually by describing what was found rather than how to see it.
    """
    verification = finding.verification or {}
    captures = [c for c in verification.get("evidence", []) if c.get("reproduced")]

    lines = []
    if captures:
        for index, capture in enumerate(captures, start=1):
            note = f"  _{capture['note']}_" if capture.get("note") else ""
            lines += [
                f"{index}. Send `{capture['method']} {capture['url']}`{note}",
                "",
                "   ```http",
                f"   HTTP {capture['status']}",
            ]
            for key, value in list(capture.get("response_headers", {}).items())[:6]:
                lines.append(f"   {key}: {value}")
            excerpt = (capture.get("excerpt") or "").strip()
            if excerpt:
                lines += ["", "   " + excerpt[:400].replace("\n", "\n   ")]
            lines += [
                "   ```",
                f"   Observed {capture.get('at', 'during the scan')} · "
                f"{capture.get('body_length', 0)} bytes · "
                f"sha256 `{str(capture.get('body_sha256', ''))[:16]}…`",
                "",
            ]
    else:
        lines += [
            f"1. Request `{finding.matched_at or finding.url or finding.host}`",
            "2. Observe the response below.",
            "",
            "```",
            (finding.evidence or "")[:1200],
            "```",
            "",
        ]
    return lines


def _impact(finding: Finding) -> str:
    """Impact, taken from the description rather than restated.

    The engines already write what an attacker does with the finding — that is
    the whole point of how they are written — so this pulls it rather than
    asking a model to produce a second, vaguer version of the same thing.
    """
    text = (finding.description or "").strip()
    if not text:
        return "_Describe what an attacker gains from this._"
    return text


def _kev_note(finding: Finding) -> list[str]:
    entries = (finding.raw or {}).get("kev") or []
    if not entries:
        return []
    lines = ["", "### Actively exploited", ""]
    for entry in entries:
        lines.append(
            f"- **{entry.get('cve')}** is on CISA's Known Exploited "
            f"Vulnerabilities catalogue"
            + (f" (added {entry['added']}" if entry.get("added") else "")
            + (f", federal remediation deadline {entry['due']})"
               if entry.get("due") else ")")
            + ("  \n  **Known to be used in ransomware campaigns.**"
               if entry.get("ransomware") else ""))
    return lines


def _footer(finding: Finding) -> list[str]:
    compliance = finding.compliance or {}
    lines = ["", "---", ""]
    if compliance.get("owasp_top10"):
        lines.append(f"**Classification:** {compliance['owasp_top10']}"
                     + (f" · CWE: {', '.join(finding.cwe)}" if finding.cwe else ""))
    if finding.references:
        lines += ["", "**References**"]
        lines += [f"- {r}" for r in finding.references[:5]]
    return lines


def render(finding: Finding, platform: str = "generic") -> Report:
    """Build a submission report, or refuse and say why."""
    platform = platform.lower()
    if platform not in PLATFORMS:
        platform = "generic"

    title = title_for(finding)

    # --- the gate ---
    if finding.verify_confidence is not None and not finding.reproduced:
        return Report(
            platform=platform, title=title, ready=False,
            warning="This finding did not reproduce on retest.",
            body=(
                "## Not ready to submit\n\n"
                f"`{finding.name}` was detected during the scan but did **not "
                f"reproduce** when re-tested afterwards.\n\n"
                "Filing it costs you more than it can pay. Programs are "
                "currently overwhelmed by machine-generated reports that don't "
                "reproduce, and acceptance rate is what determines how quickly "
                "anything else you send gets read.\n\n"
                "**Before submitting, establish which of these it is:**\n\n"
                "- The target changed between the scan and the retest — "
                "re-verify and check again.\n"
                "- The result was intermittent — reproduce it manually several "
                "times and note the conditions.\n"
                "- It was never real — close it.\n\n"
                "Re-verify from the submission queue once you can reproduce it "
                "by hand, and the report will render."))

    if finding.verify_confidence is None:
        warning = ("Not yet verified. Re-verify before submitting so the report "
                   "carries reproduction evidence.")
    elif finding.verify_confidence < 0.75:
        warning = (f"Verification confidence is "
                   f"{finding.verify_confidence:.0%} — below the bar for "
                   f"submitting unreviewed. Confirm it by hand first.")
    else:
        warning = ""

    asset = finding.url or finding.host
    severity = finding.severity.value if hasattr(finding.severity, "value") \
        else str(finding.severity)

    if platform == "hackerone":
        body = [
            "## Summary", "",
            f"{finding.name} on `{asset}`.", "",
            "## Steps To Reproduce", "",
            *_steps(finding),
            "## Impact", "",
            _impact(finding),
            *_kev_note(finding),
            "", "## Remediation", "",
            finding.remediation or "_See references._",
            "", "## Supporting Material", "",
            f"- Asset: `{asset}`",
            f"- Severity: {severity}",
            f"- Suggested CVSS vector: `{SUGGESTED_VECTOR.get(finding.severity, '')}`  ",
            "  (a starting point — adjust it to the actual impact before you submit)",
            *([f"- CWE: {', '.join(finding.cwe)}"] if finding.cwe else []),
            *_footer(finding),
        ]

    elif platform == "bugcrowd":
        body = [
            f"**VRT:** {vrt_for(finding.rule_id)}",
            f"**Severity:** {severity}", "",
            "## Description", "",
            _impact(finding),
            *_kev_note(finding),
            "", "## Steps to Reproduce", "",
            *_steps(finding),
            "## Impact", "",
            f"See description. Affected asset: `{asset}`.",
            "", "## Suggested Remediation", "",
            finding.remediation or "_See references._",
            *_footer(finding),
        ]

    elif platform == "intigriti":
        body = [
            "## Description", "",
            f"{finding.name} on `{asset}`.", "",
            _impact(finding),
            "", "## Proof of concept", "",
            *_steps(finding),
            "## Impact", "",
            "What an attacker achieves with this:", "",
            _impact(finding)[:600],
            *_kev_note(finding),
            "", "## Recommended fix", "",
            finding.remediation or "_See references._",
            *_footer(finding),
        ]

    else:
        body = [
            f"# {finding.name}", "",
            f"**Asset:** `{asset}`  ",
            f"**Severity:** {severity}",
            "", "## What this is", "",
            _impact(finding),
            *_kev_note(finding),
            "", "## How to reproduce", "",
            *_steps(finding),
            "## How to fix it", "",
            finding.remediation or "_See references._",
            *_footer(finding),
        ]

    return Report(platform=platform, title=title, ready=not warning,
                  warning=warning, body="\n".join(body).strip() + "\n")
