"""DNS and email security auditing.

These checks are cheap, fast, and produce findings on a large majority of real
domains — especially institutional ones. A domain without DMARC enforcement can
be spoofed by anyone, which for a government or university address is a
phishing platform handed over for free.

Built on `dig` (from dnsutils, already in the image) so there's no new
dependency and no library-version drift.
"""

from __future__ import annotations

import asyncio
import re

from ..models import Severity
from ..normalize import make_dedupe_key
from .registry import EngineSpec, register

# Selectors worth trying when we don't know the DKIM key name. Covers the
# common mail providers; a domain using something custom will simply show as
# "not detected", which we report as informational rather than a failure.
DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2", "k1", "mail", "dkim",
    "s1", "s2", "smtp", "zoho", "mandrill", "sendgrid", "mailgun", "amazonses",
]


async def _dig(name: str, rtype: str, *, server: str | None = None,
               timeout: float = 8.0) -> list[str]:
    """One dig query, returning answer strings. Never raises."""
    argv = ["dig", "+short", "+time=3", "+tries=2"]
    if server:
        argv.append(f"@{server}")
    argv += [name, rtype]
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except (asyncio.TimeoutError, OSError, FileNotFoundError):
        return []
    return [l.strip() for l in out.decode("utf-8", "replace").splitlines() if l.strip()]


def _txt_join(records: list[str]) -> list[str]:
    """dig returns TXT values quoted and possibly split into chunks."""
    out = []
    for rec in records:
        parts = re.findall(r'"([^"]*)"', rec)
        out.append("".join(parts) if parts else rec.strip('"'))
    return out


def _finding(rule_id, name, sev, host, desc, fix, cwe=None, tags=None, evidence=""):
    return {
        "engine": "domainsec",
        "rule_id": rule_id,
        "name": name,
        "severity": sev,
        "host": host,
        "url": host,
        "matched_at": host,
        "description": desc,
        "evidence": evidence,
        "remediation": fix,
        "references": [],
        "tags": ["dns", "email"] + (tags or []),
        "cve": [],
        "cwe": cwe or [],
        "cvss_score": None,
        "dedupe_key": make_dedupe_key("domainsec", rule_id, host, host),
        "raw": {},
    }


# ------------------------------------------------------------------ SPF

def _audit_spf(host: str, txts: list[str]) -> list[dict]:
    spf = next((t for t in txts if t.lower().startswith("v=spf1")), None)
    if not spf:
        return [_finding(
            "spf-missing", "No SPF record", Severity.medium, host,
            "There's no SPF record, so receiving mail servers have no way to know which "
            "servers are permitted to send mail for this domain. Anyone can send email "
            "claiming to be from an address at this domain and it will not fail SPF.",
            "Publish a TXT record at the domain apex listing your legitimate senders and "
            "ending in -all, e.g.\n"
            "  v=spf1 include:_spf.google.com -all\n"
            "Use -all (hard fail), not ~all, once you've confirmed the list is complete.",
            cwe=["CWE-290"], tags=["spf", "spoofing"],
        )]

    out = []
    if spf.rstrip().endswith("+all"):
        out.append(_finding(
            "spf-permissive", "SPF record permits any sender (+all)", Severity.high, host,
            "The SPF record ends in +all, which explicitly authorises every server on the "
            "internet to send mail as this domain. This is worse than having no SPF at all, "
            "because it actively vouches for forgeries.",
            "Replace +all with -all and list only your legitimate senders.",
            cwe=["CWE-290"], tags=["spf", "spoofing"], evidence=spf,
        ))
    elif spf.rstrip().endswith("?all"):
        out.append(_finding(
            "spf-neutral", "SPF policy is neutral (?all)", Severity.medium, host,
            "The record ends in ?all, meaning 'no opinion' about unlisted senders. "
            "Receivers will generally treat forged mail as acceptable.",
            "Change ?all to -all once you've verified every legitimate sender is listed.",
            cwe=["CWE-290"], tags=["spf"], evidence=spf,
        ))
    elif spf.rstrip().endswith("~all"):
        out.append(_finding(
            "spf-softfail", "SPF uses soft fail (~all)", Severity.low, host,
            "The record ends in ~all, which asks receivers to accept but mark unlisted "
            "senders. It's a reasonable position while testing, but it doesn't stop spoofing.",
            "Move to -all once you're confident the sender list is complete.",
            cwe=["CWE-290"], tags=["spf"], evidence=spf,
        ))

    # RFC 7208 caps SPF evaluation at 10 DNS-querying mechanisms.
    lookups = len(re.findall(r"\b(include|a|mx|ptr|exists|redirect)[:=]", spf, re.I))
    if lookups > 10:
        out.append(_finding(
            "spf-too-many-lookups", f"SPF exceeds the 10 DNS lookup limit ({lookups})",
            Severity.medium, host,
            "SPF evaluation is capped at 10 DNS-querying mechanisms. Beyond that, receivers "
            "return permerror and typically ignore the policy entirely — so the protection "
            "you think you have isn't being applied.",
            "Flatten or consolidate include: mechanisms to get under 10 lookups.",
            tags=["spf"], evidence=spf,
        ))
    return out


# ----------------------------------------------------------------- DMARC

def _audit_dmarc(host: str, txts: list[str]) -> list[dict]:
    dmarc = next((t for t in txts if t.lower().startswith("v=dmarc1")), None)
    if not dmarc:
        return [_finding(
            "dmarc-missing", "No DMARC record", Severity.high, host,
            "There's no DMARC policy. SPF and DKIM alone don't tell receivers what to do "
            "when a message fails — DMARC does. Without it, forged mail from this domain "
            "generally still gets delivered, which makes the domain usable as a phishing "
            "platform against your own users.",
            "Publish a TXT record at _dmarc.<domain>. Start in monitoring mode:\n"
            "  v=DMARC1; p=none; rua=mailto:dmarc@yourdomain\n"
            "Review the aggregate reports, then move to p=quarantine and finally p=reject.",
            cwe=["CWE-290"], tags=["dmarc", "spoofing", "phishing"],
        )]

    policy = re.search(r"\bp\s*=\s*(none|quarantine|reject)", dmarc, re.I)
    p = policy.group(1).lower() if policy else "none"
    out = []

    if p == "none":
        out.append(_finding(
            "dmarc-monitoring-only", "DMARC policy is monitoring only (p=none)",
            Severity.medium, host,
            "A DMARC record exists but the policy is p=none, which only requests reports. "
            "Receivers are not asked to reject or quarantine forged mail, so spoofed "
            "messages from this domain still reach inboxes.",
            "Once your aggregate reports show legitimate mail passing, move to "
            "p=quarantine and then p=reject.",
            cwe=["CWE-290"], tags=["dmarc"], evidence=dmarc,
        ))
    elif p == "quarantine":
        out.append(_finding(
            "dmarc-partial", "DMARC set to quarantine rather than reject",
            Severity.low, host,
            "Forged mail is sent to spam rather than refused. Better than nothing, but "
            "users can still retrieve and act on it.",
            "Move to p=reject once you're confident no legitimate mail is being caught.",
            tags=["dmarc"], evidence=dmarc,
        ))

    pct = re.search(r"\bpct\s*=\s*(\d+)", dmarc, re.I)
    if pct and int(pct.group(1)) < 100:
        out.append(_finding(
            "dmarc-partial-pct", f"DMARC applied to only {pct.group(1)}% of mail",
            Severity.low, host,
            "The pct tag limits how much mail the policy applies to, so most forgeries are "
            "unaffected.",
            "Remove the pct tag (or set pct=100) to apply the policy to all mail.",
            tags=["dmarc"], evidence=dmarc,
        ))

    if not re.search(r"\brua\s*=", dmarc, re.I):
        out.append(_finding(
            "dmarc-no-reporting", "DMARC has no aggregate reporting address",
            Severity.info, host,
            "Without a rua address you receive no reports, so you have no visibility into "
            "who is sending mail as your domain or whether tightening the policy is safe.",
            "Add rua=mailto:dmarc@yourdomain to the record.",
            tags=["dmarc"], evidence=dmarc,
        ))
    return out


# ------------------------------------------------------------------ main

async def audit_domain(host: str, *, log=None) -> list[dict]:
    """Full DNS and email security audit for one apex domain."""
    findings: list[dict] = []
    if log:
        await log("info", f"[domainsec] auditing DNS and email policy for {host}", "domainsec")

    # Run the independent lookups concurrently.
    txt_task = _dig(host, "TXT")
    dmarc_task = _dig(f"_dmarc.{host}", "TXT")
    caa_task = _dig(host, "CAA")
    ds_task = _dig(host, "DS")
    dnskey_task = _dig(host, "DNSKEY")
    mx_task = _dig(host, "MX")
    ns_task = _dig(host, "NS")

    txt, dmarc_txt, caa, ds, dnskey, mx, ns = await asyncio.gather(
        txt_task, dmarc_task, caa_task, ds_task, dnskey_task, mx_task, ns_task)

    txts = _txt_join(txt)
    dmarc_txts = _txt_join(dmarc_txt)

    findings += _audit_spf(host, txts)
    findings += _audit_dmarc(host, dmarc_txts)

    # ---- DKIM (best effort across common selectors) ----
    if mx:
        results = await asyncio.gather(
            *(_dig(f"{sel}._domainkey.{host}", "TXT") for sel in DKIM_SELECTORS))
        found = [DKIM_SELECTORS[i] for i, r in enumerate(results) if r]
        if not found:
            findings.append(_finding(
                "dkim-not-found", "No DKIM key found at common selectors", Severity.low, host,
                "The domain accepts mail (it has MX records) but no DKIM key was found at any "
                "of the usual selector names. Without DKIM, mail can't be cryptographically "
                "attributed to your domain, and DMARC has only SPF to rely on — which breaks "
                "whenever mail is forwarded.",
                "Enable DKIM signing with your mail provider and publish the public key. "
                "If you already use a custom selector name, this check simply didn't guess it.",
                tags=["dkim"], evidence=f"Selectors tried: {', '.join(DKIM_SELECTORS)}",
            ))

    # ---- DNSSEC ----
    if not ds and not dnskey:
        findings.append(_finding(
            "dnssec-missing", "DNSSEC not enabled", Severity.low, host,
            "The zone isn't signed, so DNS responses for this domain can't be validated. "
            "An attacker positioned to tamper with DNS — a compromised resolver, a hostile "
            "network — can redirect traffic without detection.",
            "Enable DNSSEC at your DNS provider and publish the DS record with your registrar. "
            "Most managed providers make this a single toggle.",
            cwe=["CWE-350"], tags=["dnssec"],
        ))

    # ---- CAA ----
    if not caa:
        findings.append(_finding(
            "caa-missing", "No CAA record", Severity.info, host,
            "Without a CAA record, any certificate authority may issue certificates for this "
            "domain. A CAA record restricts issuance to the CAs you actually use, limiting "
            "the damage from a mis-issuance or a compromised registrar account.",
            "Publish a CAA record, e.g.\n  yourdomain. CAA 0 issue \"letsencrypt.org\"",
            tags=["tls", "pki"],
        ))

    # ---- zone transfer ----
    # A successful AXFR hands over the entire internal DNS map. Still surprisingly
    # common on institutional infrastructure.
    for server in [n.rstrip(".") for n in ns[:3]]:
        axfr = await _dig(host, "AXFR", server=server, timeout=12)
        if len(axfr) > 3:
            findings.append(_finding(
                "zone-transfer", f"DNS zone transfer allowed from {server}",
                Severity.high, host,
                f"The nameserver {server} allowed a full zone transfer to an arbitrary client. "
                f"That returns every DNS record for the domain — internal hostnames, staging "
                f"environments, infrastructure naming — which is a complete map of the estate "
                f"handed to anyone who asks. {len(axfr)} records were returned.",
                "Restrict AXFR to your secondary nameservers only. In BIND: "
                "allow-transfer { <secondary IPs>; };",
                cwe=["CWE-200"], tags=["dns", "disclosure"],
                evidence="\n".join(axfr[:25]),
            ))
            break

    if log:
        await log("info", f"[domainsec] {len(findings)} DNS/email issue(s)", "domainsec")
    return findings


@register(EngineSpec(
    name="domainsec",
    label="Checking DNS and email policy",
    description="SPF, DKIM, DMARC policy strength, DNSSEC, CAA and zone transfer. "
                "Cheap, fast, and productive on almost every institutional domain.",
    phase="early",
    takes="seeds",
    weight=4,
    limit=5,
    default_in=("quick", "standard", "deep"),
))
async def _engine(targets: list[str], ctx: dict) -> list[dict]:
    log = ctx.get("log")
    out: list[dict] = []
    for apex in targets:
        if apex.replace(".", "").isdigit():
            continue  # bare IP has no email or DNS policy of its own
        out += await audit_domain(apex, log=log)
    return out
