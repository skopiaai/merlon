"""CISA Known Exploited Vulnerabilities.

A CVE identifier tells you a vulnerability exists. It says nothing about
whether anyone is using it. Most never are — the National Vulnerability
Database holds hundreds of thousands of entries and the overwhelming majority
have no observed exploitation ever.

The KEV catalogue is the subset with evidence of active exploitation in the
wild. That is a categorically different fact, and it should reorder everything.
A medium-severity CVE that ransomware operators are exploiting this month
matters more than a critical nobody has ever weaponised, and CVSS cannot tell
you which is which because CVSS scores the vulnerability rather than the
threat.

Two uses here:

**Prioritisation.** A finding whose CVE is in KEV is escalated and marked, so
it sorts above findings that merely score higher.

**Report weight.** "This is on CISA's actively-exploited list, with a federal
remediation deadline of <date>" is an argument a security team can take to
their management. "CVSS 7.5" is not. For an institutional or government target
that sentence is often what actually gets the fix scheduled.

The catalogue is a public JSON feed, refreshed by the updater alongside
templates. Absent or stale data degrades to "no enrichment" — never to a wrong
answer.
"""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path

from .config import ARTIFACT_DIR

KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")

KEV_FILE = Path(os.getenv("SENTINEL_KEV_FILE",
                          str(ARTIFACT_DIR.parent / "kev.json")))

CVE_ID = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)

# Loaded once and cached. The file is a few megabytes and every finding in a
# scan asks about it.
_CACHE: dict[str, dict] | None = None
_CACHE_MTIME: float = 0.0


def parse_catalog(body: str) -> dict[str, dict]:
    """CVE id -> the facts worth putting in a report."""
    try:
        doc = json.loads(body or "{}")
    except json.JSONDecodeError:
        return {}

    entries = doc.get("vulnerabilities") if isinstance(doc, dict) else None
    if not isinstance(entries, list):
        return {}

    out: dict[str, dict] = {}
    for item in entries:
        if not isinstance(item, dict):
            continue
        cve = str(item.get("cveID", "")).upper()
        if not CVE_ID.fullmatch(cve):
            continue
        out[cve] = {
            "cve": cve,
            "vendor": item.get("vendorProject", ""),
            "product": item.get("product", ""),
            "name": item.get("vulnerabilityName", ""),
            "added": item.get("dateAdded", ""),
            "due": item.get("dueDate", ""),
            "ransomware": str(item.get("knownRansomwareCampaignUse", "")).lower()
            == "known",
            "action": item.get("requiredAction", ""),
        }
    return out


def load() -> dict[str, dict]:
    """The catalogue, cached until the file changes on disk."""
    global _CACHE, _CACHE_MTIME
    try:
        mtime = KEV_FILE.stat().st_mtime
    except OSError:
        return {}
    if _CACHE is not None and mtime == _CACHE_MTIME:
        return _CACHE
    try:
        _CACHE = parse_catalog(KEV_FILE.read_text())
        _CACHE_MTIME = mtime
    except OSError:
        return {}
    return _CACHE


def lookup(cves: list[str]) -> list[dict]:
    """KEV entries for any of these CVE identifiers."""
    catalog = load()
    if not catalog:
        return []
    seen, out = set(), []
    for raw in cves or []:
        for match in CVE_ID.findall(str(raw)):
            cve = match.upper()
            if cve in seen:
                continue
            seen.add(cve)
            entry = catalog.get(cve)
            if entry:
                out.append(entry)
    return out


def escalate(severity):
    """Severity for a finding that is actively exploited.

    Bumped one level, and never above critical. Not two levels and not
    automatically critical: KEV means "someone is using this", not "this is
    catastrophic here". An informational finding on a KEV CVE is still probably
    low-impact on this particular target, and inflating it would make the flag
    worthless.

    Returns the same type it was given — findings carry a `Severity` enum on
    the way to the database and a plain string everywhere else, and handing the
    ORM a raw string for an Enum column is a runtime error rather than a
    coercion.
    """
    from .models import Severity

    ladder = ["info", "low", "medium", "high", "critical"]
    current = (severity.value if isinstance(severity, Severity)
               else str(severity).lower().replace("severity.", ""))
    if current not in ladder:
        return severity
    raised = ladder[min(ladder.index(current) + 1, len(ladder) - 1)]
    return Severity(raised) if isinstance(severity, Severity) else raised


def apply(finding: dict) -> list[dict]:
    """Enrich a finding with KEV context, in place. Returns the entries found.

    Everything goes into fields the Finding model already has — severity, tags,
    description and `raw`. No new top-level key, because the finding dict is
    passed straight to the ORM as keyword arguments and an unexpected key would
    raise rather than being ignored.

    Idempotent: the tag check makes a second call a no-op, so re-triage doesn't
    escalate a finding twice.
    """
    entries = lookup(finding.get("cve") or [])
    if not entries:
        return []

    tags = finding.setdefault("tags", [])
    if "actively-exploited" in tags:
        return entries          # already applied

    tags.append("actively-exploited")
    if any(e["ransomware"] for e in entries):
        tags.append("ransomware")

    finding["severity"] = escalate(finding.get("severity", "info"))
    finding.setdefault("raw", {})["kev"] = entries

    block = note(entries)
    if block:
        finding["description"] = (finding.get("description", "").rstrip()
                                  + "\n\n" + block)
    return entries


def note(entries: list[dict]) -> str:
    """The paragraph that goes in the report.

    Written to be quotable to someone who has to decide whether to schedule the
    fix, which is a different audience from whoever reads the technical detail.
    """
    if not entries:
        return ""

    lines = ["## Actively exploited", ""]
    for entry in entries:
        lines.append(
            f"**{entry['cve']}** — {entry['name'] or 'listed'} "
            f"({entry['vendor']} {entry['product']})".rstrip())
        lines.append(
            f"On CISA's Known Exploited Vulnerabilities catalogue since "
            f"{entry['added'] or 'an earlier date'}"
            + (f", with a federal remediation deadline of {entry['due']}"
               if entry.get("due") else "")
            + ".")
        if entry["ransomware"]:
            lines.append("**Known to be used in ransomware campaigns.**")
        if entry.get("action"):
            lines.append(f"Required action: {entry['action']}")
        lines.append("")

    lines.append(
        "This is not a severity score — it is evidence of exploitation in the "
        "wild. A vulnerability on this list is being used against real targets "
        "now, which is why it should be scheduled ahead of higher-scoring "
        "findings that nobody has ever weaponised.")
    return "\n".join(lines)


def status() -> dict:
    """For the update panel."""
    catalog = load()
    try:
        age = time.time() - KEV_FILE.stat().st_mtime
    except OSError:
        age = None
    return {
        "entries": len(catalog),
        "age_seconds": age,
        "ransomware_entries": sum(1 for e in catalog.values() if e["ransomware"]),
    }
