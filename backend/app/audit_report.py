"""Audit-grade reporting.

What separates this from the summary report: a reviewer needs to know not just
what was found, but what was *looked for*, with what tools, at what time, and
which controls each finding maps to. Absence of evidence has to be
distinguishable from evidence of absence.

Includes an integrity block — hashes over the finding set — so a report can be
shown to be unmodified since generation.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from datetime import datetime, timezone

from sqlalchemy import select

from . import compliance
from .db import SessionLocal
from .models import Asset, Engagement, Finding, FindingStatus, Lead, Scan, Severity

SEV_ORDER = ["critical", "high", "medium", "low", "info"]

STAGE_DESCRIPTIONS = {
    "subfinder": "Passive subdomain enumeration (no traffic to target)",
    "dnsx": "DNS record resolution and dangling-CNAME detection",
    "cdncheck": "CDN and WAF provider identification",
    "domainsec": "Email authentication (SPF/DKIM/DMARC), DNSSEC, CAA, zone transfer",
    "naabu": "TCP port discovery",
    "httpx": "HTTP service probing, fingerprinting, and security header audit",
    "nmap": "Service and version identification",
    "tlsx": "TLS certificate validation",
    "tlsdeep": "Deep TLS audit: protocols, cipher suites, known vulnerabilities",
    "nse": "Service-level configuration checks (SMB signing, SNMP, FTP, datastores)",
    "ffuf": "Content discovery against a directory wordlist",
    "katana": "Application crawling and endpoint discovery",
    "nuclei": "Template-based vulnerability detection (community template set)",
    "triage": "Local AI review for false-positive reduction",
    "intel": "Attack surface mapping and manual testing lead generation",
}


def _tool_versions() -> dict[str, str]:
    """Record what actually ran. Reproducibility depends on this."""
    versions: dict[str, str] = {}
    for tool, args in [
        ("nuclei", ["-version"]), ("httpx", ["-version"]), ("subfinder", ["-version"]),
        ("naabu", ["-version"]), ("katana", ["-version"]), ("dnsx", ["-version"]),
        ("tlsx", ["-version"]), ("ffuf", ["-V"]), ("nmap", ["--version"]),
    ]:
        path = shutil.which(tool)
        if not path:
            versions[tool] = "not installed"
            continue
        try:
            out = subprocess.run([tool, *args], capture_output=True, text=True, timeout=15)
            text = (out.stdout + out.stderr).strip().splitlines()
            versions[tool] = next((l.strip() for l in text if l.strip()), "unknown")[:80]
        except Exception:  # noqa: BLE001
            versions[tool] = "unknown"
    return versions


def _integrity(findings: list[Finding]) -> dict:
    """Hash the finding set so the report can be shown to be unaltered."""
    digest = hashlib.sha256()
    per_finding = []
    for f in sorted(findings, key=lambda x: x.dedupe_key):
        blob = json.dumps({
            "rule": f.rule_id, "host": f.host, "url": f.url,
            "severity": f.severity.value, "evidence": f.evidence,
        }, sort_keys=True).encode()
        h = hashlib.sha256(blob).hexdigest()
        per_finding.append((f.dedupe_key, h))
        digest.update(h.encode())
    return {"set_hash": digest.hexdigest(), "per_finding": per_finding}


def generate(scan_id: int) -> str:
    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        if not scan:
            raise ValueError("scan not found")
        eng = db.get(Engagement, scan.engagement_id)
        findings = list(db.scalars(select(Finding).where(Finding.scan_id == scan_id)))
        assets = list(db.scalars(select(Asset).where(Asset.scan_id == scan_id)))
        leads = list(db.scalars(select(Lead).where(Lead.scan_id == scan_id)))

    live = [f for f in findings if f.status != FindingStatus.false_positive]
    live.sort(key=lambda f: (-f.severity.rank, f.host, f.name))
    counts = {s: 0 for s in SEV_ORDER}
    for f in live:
        counts[f.severity.value] += 1

    matrix = compliance.coverage_matrix(live)
    integrity = _integrity(live)
    now = datetime.now(timezone.utc)

    L: list[str] = []
    add = L.append

    # ---------------- cover ----------------
    add(f"# Security Assessment Report — {eng.name}")
    add("")
    add(f"**Report generated:** {now:%Y-%m-%d %H:%M UTC}  ")
    add(f"**Assessment reference:** SCAN-{scan.id:06d}  ")
    add(f"**Assessment type:** Automated vulnerability assessment (unauthenticated"
        f"{' and authenticated' if eng.auth_headers else ''})  ")
    add(f"**Evidence set hash (SHA-256):** `{integrity['set_hash']}`  ")
    add("")
    add("> This report documents an automated vulnerability assessment. It does not "
        "constitute a penetration test: no findings were exploited to confirm impact. "
        "Findings requiring manual verification are marked as such.")
    add("")
    add("---")
    add("")

    # ---------------- authorization ----------------
    add("## 1. Authorization and scope")
    add("")
    add("| Item | Value |")
    add("| --- | --- |")
    add(f"| Authorized by | {eng.authorized_by} |")
    add(f"| Authorization reference | {eng.authorization_ref} |")
    add(f"| Authorization recorded | {eng.authorized_at:%Y-%m-%d %H:%M UTC} |")
    add(f"| Expires | {eng.expires_at:%Y-%m-%d} |" if eng.expires_at else "| Expires | not set |")
    add(f"| Engagement type | {eng.kind} |")
    add(f"| Assessment window | {scan.started_at:%Y-%m-%d %H:%M} – "
        f"{scan.finished_at:%H:%M UTC} |" if scan.started_at and scan.finished_at
        else "| Assessment window | incomplete |")
    add("")
    add("**In scope:** " + ", ".join(f"`{r}`" for r in eng.allow_rules))
    add("")
    add("**Explicitly excluded:** " +
        (", ".join(f"`{r}`" for r in eng.deny_rules) if eng.deny_rules else "none"))
    add("")
    if scan.rejected_hosts:
        add(f"{len(scan.rejected_hosts)} discovered host(s) were filtered as out of scope "
            f"and received no traffic beyond initial enumeration.")
        add("")

    # ---------------- executive summary ----------------
    add("## 2. Executive summary")
    add("")
    total = len(live)
    crit, high = counts["critical"], counts["high"]
    if crit:
        posture = (f"**Immediate action required.** {crit} critical "
                   f"{'issue was' if crit == 1 else 'issues were'} identified that could "
                   f"permit unauthorized access to systems or data.")
    elif high:
        posture = (f"**Remediation required.** {high} high-severity "
                   f"{'issue was' if high == 1 else 'issues were'} identified representing "
                   f"significant weaknesses.")
    elif counts["medium"]:
        posture = ("**Hardening recommended.** No critical or high-severity issues were "
                   "identified. Medium-severity findings represent gaps that increase "
                   "exposure in combination with other weaknesses.")
    else:
        posture = ("**No significant issues identified** by automated assessment. See "
                   "section 7 for the limits of that statement.")
    add(posture)
    add("")
    add("| Severity | Count |")
    add("| --- | --- |")
    for s in SEV_ORDER:
        add(f"| {s.title()} | {counts[s]} |")
    add(f"| **Total** | **{total}** |")
    add("")
    fp = len(findings) - len(live)
    if fp:
        add(f"A further {fp} result(s) were assessed as false positives and are excluded "
            f"from the counts above.")
        add("")

    # ---------------- methodology ----------------
    add("## 3. Methodology")
    add("")
    add(f"Assessment profile: **{scan.profile}**. The following phases were executed:")
    add("")
    add("| Phase | Description |")
    add("| --- | --- |")
    for stage in scan.stages:
        add(f"| {stage} | {STAGE_DESCRIPTIONS.get(stage, 'â€”')} |")
    add("")
    add("**Not performed:** exploitation, denial-of-service testing, social engineering, "
        "physical security assessment, and source code review.")
    add("")
    if eng.auth_headers:
        add("Authenticated scanning was configured, so results include surface reachable "
            "only after login.")
    else:
        add("Testing was performed **unauthenticated**. Functionality behind a login was "
            "not assessed and may contain issues not reflected here.")
    add("")

    add("### Tool versions")
    add("")
    add("| Tool | Version |")
    add("| --- | --- |")
    for tool, ver in _tool_versions().items():
        add(f"| {tool} | `{ver}` |")
    add("")

    # ---------------- assets ----------------
    add("## 4. Assets assessed")
    add("")
    stats = scan.stats or {}
    add(f"- Hosts in scope: {stats.get('hosts_in_scope', len({a.host for a in assets}))}")
    add(f"- Live HTTP services: {stats.get('live_services', len(assets))}")
    if stats.get("open_ports"):
        add(f"- Open ports discovered: {stats['open_ports']}")
    if stats.get("services_identified"):
        add(f"- Services identified: {stats['services_identified']}")
    if stats.get("tech"):
        add(f"- Technologies detected: {', '.join(stats['tech'][:20])}")
    add("")
    if assets:
        add("| Host | Service | Status | Title |")
        add("| --- | --- | --- | --- |")
        for a in sorted(assets, key=lambda x: x.host)[:60]:
            title = (a.title or "").replace("|", "\\|")[:50]
            add(f"| {a.host} | {a.url or '—'} | {a.status_code or '—'} | {title} |")
        add("")

    # ---------------- control coverage ----------------
    add("## 5. Control coverage")
    add("")
    add("Findings mapped to the OWASP Top 10 (2021). Categories with no findings are "
        "listed so that coverage is explicit.")
    add("")
    add("| Category | Findings | Assessed |")
    add("| --- | --- | --- |")
    for cat in compliance.OWASP_TOP10_ALL:
        n = matrix["owasp_top10"].get(cat, 0)
        note = compliance.OWASP_NOT_TESTABLE.get(cat)
        add(f"| {cat} | {n} | {'No — ' + note if note else 'Yes'} |")
    add("")

    if matrix["iso27001"]:
        add("### ISO/IEC 27001:2022 Annex A controls implicated")
        add("")
        add("| Control | Findings |")
        add("| --- | --- |")
        for ctrl, n in matrix["iso27001"].items():
            add(f"| {ctrl} | {n} |")
        add("")

    if matrix["gigw"]:
        add("### GIGW 3.0 security areas implicated")
        add("")
        add("| Area | Findings |")
        add("| --- | --- |")
        for area, n in matrix["gigw"].items():
            add(f"| {area} | {n} |")
        add("")

    # ---------------- findings ----------------
    add("## 6. Detailed findings")
    add("")
    if not live:
        add("No findings.")
        add("")
    for idx, f in enumerate(live, 1):
        comp = f.compliance or compliance.controls_for({
            "rule_id": f.rule_id, "tags": f.tags, "cwe": f.cwe, "cve": f.cve,
        }).as_dict()
        ref = f"SCAN-{scan.id:06d}-{idx:03d}"
        add(f"### {ref} — {f.name}")
        add("")
        add("| | |")
        add("| --- | --- |")
        add(f"| **Severity** | {f.severity.value.upper()} |")
        add(f"| **Affected asset** | `{f.url or f.host}` |")
        add(f"| **Detection method** | {f.engine}"
            f"{f' (`{f.rule_id}`)' if f.rule_id else ''} |")
        add(f"| **Status** | {f.status.value.replace('_', ' ')} |")
        if comp.get("owasp_top10"):
            add(f"| **OWASP Top 10** | {comp['owasp_top10']} |")
        if comp.get("asvs"):
            add(f"| **OWASP ASVS** | {', '.join(comp['asvs'])} |")
        if comp.get("iso27001"):
            add(f"| **ISO 27001** | {', '.join(comp['iso27001'])} |")
        if comp.get("cis"):
            add(f"| **CIS Controls** | {', '.join(comp['cis'])} |")
        if comp.get("gigw"):
            add(f"| **GIGW 3.0** | {comp['gigw']} |")
        if f.cwe:
            add(f"| **CWE** | {', '.join(f.cwe)} |")
        if f.cve:
            add(f"| **CVE** | {', '.join(f.cve)} |")
        if f.cvss_score is not None:
            add(f"| **CVSS** | {f.cvss_score} |")
        if f.occurrences > 1:
            add(f"| **Occurrences** | {f.occurrences} |")
        add("")
        if f.description:
            add("**Description**")
            add("")
            add(f.description.strip())
            add("")
        if f.evidence:
            add("**Evidence**")
            add("")
            add("```")
            add(f.evidence.strip()[:1500])
            add("```")
            add("")
        if f.remediation:
            add("**Remediation**")
            add("")
            add(f.remediation.strip())
            add("")
        if f.analyst_note:
            add("**Analyst note**")
            add("")
            add(f.analyst_note.strip())
            add("")
        if f.references:
            add("**References:** " + ", ".join(f.references[:5]))
            add("")
        add("")

    # ---------------- manual testing ----------------
    add("## 7. Limitations and recommended manual testing")
    add("")
    add("Automated assessment detects known vulnerability patterns: missing controls, "
        "outdated components, exposed files, and published CVEs. It cannot assess "
        "business logic, authorization correctness, or design weaknesses, because these "
        "have no signature to match. **The absence of findings in those categories should "
        "not be read as assurance.**")
    add("")
    if leads:
        add("The following areas were identified as warranting manual review:")
        add("")
        add("| Priority | Area | Class | Status |")
        add("| --- | --- | --- | --- |")
        for l in sorted(leads, key=lambda x: {"high": 0, "medium": 1, "low": 2}
                        .get(x.priority, 1))[:30]:
            area = l.area.replace("|", "\\|")[:70]
            add(f"| {l.priority} | {area} | {l.vuln_class} | {l.status.value} |")
        add("")

    # ---------------- integrity ----------------
    add("## 8. Evidence integrity")
    add("")
    add("Each finding is hashed over its rule, asset, severity, and evidence. The set "
        "hash covers all finding hashes in sorted order. Any modification to the "
        "findings changes these values.")
    add("")
    add(f"**Set hash (SHA-256):** `{integrity['set_hash']}`")
    add("")
    add("| Finding key | SHA-256 |")
    add("| --- | --- |")
    for key, h in integrity["per_finding"][:80]:
        add(f"| `{key}` | `{h[:32]}…` |")
    add("")

    add("---")
    add("")
    add(f"*Generated {now:%Y-%m-%d %H:%M UTC}. Automated findings require verification "
        f"before remediation decisions are made. This assessment supports, and does not "
        f"replace, review by a qualified auditor.*")

    return "\n".join(L)
