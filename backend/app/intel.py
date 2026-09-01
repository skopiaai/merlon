"""Attack-surface analysis and finding correlation.

This is the part that addresses the real gap between a scanner and a skilled
hunter. Scanners answer "does this target match a known-bad pattern?" Hunters
ask "given how this application is built, where is the logic likely to be
wrong?" — and that second question is where almost all bounty payouts live.

We can't automate the answer, but we can automate the *shortlist*: read the
recon inventory and produce a prioritized set of places worth a human's
attention, with the specific thing to check at each.

Two mechanisms:
  * `correlate()`  — deterministic rules that chain individually-minor
                     findings into genuinely serious attack paths.
  * `analyze()`    — the local LLM reading the whole inventory and proposing
                     where to look manually.

Both produce guidance, never exploitation steps.
"""

from __future__ import annotations

import json
from collections import defaultdict

from sqlalchemy import select

from . import llm, surface
from .db import SessionLocal
from .models import Asset, Finding, Severity
from .normalize import make_dedupe_key

# ---------------------------------------------------------------- correlation


def _chain(rule_id, name, severity, host, url, description, remediation, parts):
    return {
        "engine": "correlation",
        "rule_id": rule_id,
        "name": name,
        "severity": severity,
        "host": host,
        "url": url,
        "matched_at": url,
        "description": description,
        "evidence": "Chained from:\n" + "\n".join(f"  • {p}" for p in parts),
        "remediation": remediation,
        "references": [],
        "tags": ["correlation", "attack-chain"],
        "cve": [], "cwe": [], "cvss_score": None,
        "dedupe_key": make_dedupe_key("correlation", rule_id, host, url),
        "raw": {"components": parts},
    }


def correlate(scan_id: int) -> list[dict]:
    """Deterministic attack-path chaining.

    Individually these components are often dismissed as low severity. Chained,
    they're the difference between "hardening suggestion" and "this is how
    someone gets in" — and articulating that chain is usually what turns a
    rejected bounty report into an accepted one.
    """
    with SessionLocal() as db:
        findings = list(db.scalars(select(Finding).where(Finding.scan_id == scan_id)))
        assets = list(db.scalars(select(Asset).where(Asset.scan_id == scan_id)))

    by_host: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        by_host[f.host].append(f)

    tech_by_host: dict[str, list[str]] = defaultdict(list)
    for a in assets:
        tech_by_host[a.host] += [t.lower() for t in (a.tech or [])]

    chains: list[dict] = []

    for host, hf in by_host.items():
        rule_ids = {f.rule_id for f in hf}
        tags = {t for f in hf for t in (f.tags or [])}
        names = {f.name.lower() for f in hf}
        url = next((f.url for f in hf if f.url), host)

        # Loop variables bound as defaults. `has` is called inside this
        # iteration, so nothing is wrong today — but a closure that reads a
        # loop variable by reference is a correctness bug waiting for someone
        # to defer the call, and correlation silently attributing one host's
        # findings to another would be very hard to notice in a report.
        def has(*needles: str, rule_ids=rule_ids, names=names, tags=tags) -> bool:
            blob = " ".join(rule_ids | names | tags)
            return all(n in blob for n in needles)

        # --- source or secret exposure ---
        if has("git") and ("exposure" in tags or "config" in tags):
            chains.append(_chain(
                "chain-source-disclosure", "Source code and secrets likely exposed",
                Severity.critical, host, url,
                "An exposed version control directory was found alongside other file-exposure "
                "issues. Together these usually mean full source code is retrievable — and "
                "source almost always contains database credentials, API keys, and the logic "
                "an attacker needs to find deeper flaws quickly.",
                "Block access to .git/.svn at the web server immediately. Then treat every "
                "credential in that repository's history as compromised and rotate it — not "
                "just current values, but anything ever committed.",
                [f.name for f in hf if "git" in f.rule_id or "exposure" in (f.tags or [])],
            ))

        # --- admin surface + fingerprint ---
        admin = [f for f in hf if "admin" in f.name.lower() or "login" in f.name.lower()
                 or "exposed-surface" in f.rule_id]
        version = [f for f in hf if "version-disclosure" in f.rule_id or f.cve]
        if admin and version:
            chains.append(_chain(
                "chain-admin-fingerprint", "Admin interface exposed with identifiable version",
                Severity.high, host, url,
                "An administrative interface is publicly reachable and the software version is "
                "discoverable. That combination lets an attacker look up working exploits for "
                "your exact build rather than probing blindly — and gives them a login form to "
                "spray credentials against.",
                "Restrict the admin interface to a VPN or IP allowlist, suppress version "
                "banners, enforce multi-factor authentication, and rate-limit login attempts.",
                [f.name for f in admin + version],
            ))

        # --- session theft chain ---
        weak_cookie = [f for f in hf if "insecure-cookie" in f.rule_id]
        no_csp = [f for f in hf if f.rule_id in ("missing-csp", "weak-csp", "wildcard-csp")]
        if weak_cookie and no_csp:
            chains.append(_chain(
                "chain-session-theft", "Session cookies stealable if any XSS exists",
                Severity.high, host, url,
                "Session cookies are readable by JavaScript (no HttpOnly) and there's no "
                "Content Security Policy to stop injected script from running. Any cross-site "
                "scripting bug anywhere on this origin becomes full account takeover rather "
                "than a contained defect — there is no second line of defence.",
                "Set HttpOnly, Secure and SameSite on all session cookies, then add a Content "
                "Security Policy. Either control alone substantially reduces the impact.",
                [f.name for f in weak_cookie + no_csp],
            ))

        # --- transport chain ---
        no_hsts = [f for f in hf if f.rule_id in ("missing-hsts", "weak-hsts", "no-https")]
        cookie_no_secure = [f for f in hf if "insecure-cookie" in f.rule_id
                            and "Secure" in f.name]
        if no_hsts and cookie_no_secure:
            chains.append(_chain(
                "chain-session-interception", "Session interceptable on a hostile network",
                Severity.high, host, url,
                "Cookies lack the Secure flag and HSTS isn't enforced. An attacker on the same "
                "network as a user can force a plain-HTTP request and capture the session "
                "cookie in transit — the classic public-Wi-Fi attack, and it needs no bug in "
                "your application at all.",
                "Add Secure to every cookie and enable HSTS with a long max-age. Both are "
                "one-line changes.",
                [f.name for f in no_hsts + cookie_no_secure],
            ))

        # --- takeover chain ---
        dangling = [f for f in hf if f.rule_id == "dangling-cname"]
        if dangling:
            wildcard_cookie = any("domain=" in (f.evidence or "").lower() for f in hf)
            if wildcard_cookie:
                chains.append(_chain(
                    "chain-takeover-session", "Subdomain takeover would expose domain-wide cookies",
                    Severity.critical, host, url,
                    "A dangling DNS record means someone else may be able to claim this "
                    "subdomain. Because cookies are scoped to the parent domain, whoever "
                    "claims it can read the sessions of users on your main site.",
                    "Remove the dangling DNS record now, and scope cookies to the specific "
                    "host rather than the parent domain.",
                    [f.name for f in dangling],
                ))

        # --- database exposure + weak transport ---
        db_exposed = [f for f in hf if "exposed-service" in f.rule_id
                      and f.severity.rank >= Severity.high.rank]
        if db_exposed:
            stack = ", ".join(sorted(set(tech_by_host.get(host, []))))[:120]
            chains.append(_chain(
                "chain-data-exposure", "Datastore reachable from the internet",
                Severity.critical, host, url,
                f"A database or cache service is accepting connections from the public "
                f"internet{f' on a host running {stack}' if stack else ''}. These services "
                f"commonly ship with authentication disabled, and internet-wide scanners find "
                f"them within hours of exposure. Assume it is already being probed.",
                "Firewall the port immediately, bind the service to localhost or a private "
                "interface, enable authentication, and check its logs for connections you "
                "don't recognise.",
                [f.name for f in db_exposed],
            ))

    return chains


# ------------------------------------------------------------------- AI layer

ANALYST_SYSTEM = """You are a senior application security analyst briefing a
bug bounty hunter on where to spend their manual testing time.

You are given the reconnaissance inventory for a target the hunter is
authorized to test, plus a pre-computed attack surface map. Automated scanners
have already run — your job is to identify what they structurally CANNOT find:
business logic flaws, broken access control, IDORs, authentication weaknesses,
race conditions, and tenant-isolation gaps.

Rules:
- Be specific to THIS target. Generic advice ("test for XSS") is worthless.
  Reference the actual hostnames, paths, parameters and technologies you see.
- Prioritise ruthlessly. Five strong leads beat twenty weak ones.
- Describe WHAT to examine and WHY it's promising. Do not write exploit code,
  payloads, or step-by-step attack instructions.
- If the inventory is thin, say so rather than inventing detail.
- Reply with JSON only."""

ANALYST_PROMPT = """Reconnaissance inventory for {host}:

HOSTS AND SERVICES
{assets}

TECHNOLOGY DETECTED
{tech}

ATTACK SURFACE MAP (pre-computed, reliable)
{surface}

PARAMETERS OBSERVED
{params}

AUTOMATED FINDINGS SO FAR
{findings}

Produce a manual testing plan. Return JSON:
{{
  "summary": "2-3 sentences on the target's shape and where risk concentrates",
  "attack_surface": [
    {{
      "area": "the specific host, path, parameter or feature",
      "why": "what makes it promising, referencing what you actually see above",
      "check": "the specific thing a human should examine",
      "vuln_class": "IDOR|broken-access-control|auth-bypass|business-logic|race-condition|ssrf|injection|info-disclosure|file-upload|tenant-isolation",
      "priority": "high|medium|low"
    }}
  ],
  "blind_spots": ["what this scan could not cover, and why"],
  "notable": ["anything unusual about this target worth a second look"]
}}

Give between 4 and 8 attack_surface entries, ordered by priority."""

DEEPDIVE_SYSTEM = """You are a senior application security analyst writing a
test plan for one specific lead, for a hunter who is authorized to test the
target.

Write the plan a careful reviewer would follow: what to observe, how to tell a
real flaw from expected behaviour, and what evidence to capture so the finding
can be reported credibly.

Rules:
- No exploit code, no payloads, no step-by-step attack instructions.
- Describe observations and comparisons, not weaponisation.
- Be concrete about what "vulnerable" versus "fine" looks like here.
- Reply with JSON only."""

DEEPDIVE_PROMPT = """Target context: {host} — {tech}

LEAD
Area: {area}
Vulnerability class: {vuln_class}
Why it's promising: {why}
Initial check: {check}

Write a focused test plan. Return JSON:
{{
  "approach": "2-3 sentences on how to approach testing this specific area",
  "observe": ["concrete things to look at, 3-6 items"],
  "distinguish": "how to tell an actual flaw from expected behaviour here",
  "evidence": ["what to capture if it IS a flaw, so the report is credible"],
  "false_positive_traps": ["things that look like bugs here but usually aren't"],
  "references": ["relevant OWASP or WSTG section names"]
}}"""


def build_surface(scan_id: int) -> dict:
    """Deterministic attack surface map. Works with or without the LLM."""
    with SessionLocal() as db:
        assets = list(db.scalars(select(Asset).where(Asset.scan_id == scan_id)))

    asset_dicts = [
        {"url": a.url, "host": a.host, "status_code": a.status_code, "tech": a.tech}
        for a in assets
    ]
    endpoints = [a.url for a in assets if a.url]
    smap = surface.map_surface(asset_dicts, endpoints)
    smap["hints"] = surface.priority_hint(smap)
    return smap


def _summarize(scan_id: int, smap: dict) -> dict:
    """Compact the scan's data enough to fit a local model's context."""
    with SessionLocal() as db:
        assets = list(db.scalars(select(Asset).where(Asset.scan_id == scan_id)))
        findings = list(db.scalars(select(Finding).where(Finding.scan_id == scan_id)))

    asset_lines, tech = [], set()
    for a in assets[:50]:
        bits = [a.url or a.host]
        if a.status_code:
            bits.append(f"HTTP {a.status_code}")
        if a.title:
            bits.append(f'"{a.title[:60]}"')
        if a.tech:
            bits.append("/".join(a.tech[:5]))
        asset_lines.append("  " + " — ".join(bits))
        tech.update(a.tech or [])

    surface_lines = []
    for cat in smap.get("categories", [])[:10]:
        sample = ", ".join(cat["urls"][:4])
        surface_lines.append(f"  {cat['category']} ({cat['count']}): {sample}")
    for hint in smap.get("hints", []):
        surface_lines.append(f"  ! {hint}")
    for idor in smap.get("idor_candidates", [])[:6]:
        surface_lines.append(f"  id-in-path ({idor['kind']}): {idor['url']}")

    param_lines = [
        f"  {p['name']} [{p['class']}] — {p['why']}"
        for p in smap.get("params_interesting", [])[:20]
    ]
    if smap.get("params_other"):
        param_lines.append("  other: " + ", ".join(smap["params_other"][:25]))

    finding_lines = [
        f"  [{f.severity.value}] {f.name} @ {f.url or f.host}"
        for f in sorted(findings, key=lambda x: -x.severity.rank)[:30]
    ]

    return {
        "assets": "\n".join(asset_lines) or "  (none)",
        "tech": ", ".join(sorted(tech)[:40]) or "(none detected)",
        "surface": "\n".join(surface_lines) or "  (nothing categorised)",
        "params": "\n".join(param_lines) or "  (none observed)",
        "findings": "\n".join(finding_lines) or "  (none)",
    }


def _surface_leads(smap: dict) -> list[dict]:
    """Leads derived purely from the surface map.

    These exist so the panel is useful even with Ollama off, and so the
    highest-signal categories are never missed because a small model
    overlooked them.
    """
    leads: list[dict] = []
    priority_by_cat = {
        "payment": "high", "user-object": "high", "api": "high", "auth": "high",
        "admin": "medium", "upload": "medium", "export": "medium",
        "webhook": "medium", "debug": "medium", "search": "low",
    }
    for cat in smap.get("categories", []):
        name = cat["category"]
        leads.append({
            "area": f"{name}: {cat['count']} endpoint(s) — e.g. {cat['urls'][0]}"
                    if cat["urls"] else name,
            "why": cat["why"],
            "check": f"Review each of the {cat['count']} endpoint(s) in this category. "
                     f"Likely classes: {', '.join(cat['vuln_classes'])}.",
            "vuln_class": cat["vuln_classes"][0],
            "priority": priority_by_cat.get(name, "low"),
            "category": name,
            "source": "surface",
        })

    seq = [i for i in smap.get("idor_candidates", []) if i["kind"].startswith("sequential")]
    if seq:
        leads.append({
            "area": f"Sequential IDs in {len(seq)} path(s) — e.g. {seq[0]['url']}",
            "why": "Sequential numeric identifiers appear directly in the URL path. If the "
                   "server authorizes the action but not the specific record, incrementing "
                   "the number returns another user's data. This is the single most commonly "
                   "reported bug class in bounty programs.",
            "check": "Create two accounts. Request the same resource path as each, swapping "
                     "in the other's identifier, and compare responses. A 200 with the other "
                     "account's data is the finding.",
            "vuln_class": "IDOR",
            "priority": "high",
            "category": "idor-candidate",
            "source": "surface",
        })

    ssrf = [p for p in smap.get("params_interesting", []) if p["class"] == "redirect-ssrf"]
    if ssrf:
        names = ", ".join(p["name"] for p in ssrf[:6])
        leads.append({
            "area": f"URL-taking parameters: {names}",
            "why": "These parameters accept a URL. If the server fetches it, that's SSRF — "
                   "potentially reaching internal services or cloud metadata. If it only "
                   "redirects, it's an open redirect, which is lower severity but still "
                   "reportable and often chains into OAuth token theft.",
            "check": "Determine first whether the server fetches the URL or just redirects "
                     "the browser — the two have very different impact. Then check how strictly "
                     "the destination is validated.",
            "vuln_class": "ssrf",
            "priority": "high",
            "category": "redirect-ssrf",
            "source": "surface",
        })

    if smap.get("auth_boundaries"):
        n = len(smap["auth_boundaries"])
        leads.append({
            "area": f"{n} endpoint(s) returning 401/403",
            "why": "These are the application's stated permission boundaries. Every one is a "
                   "place where the developer intended a restriction — and therefore a place "
                   "where the restriction might be incomplete.",
            "check": "Try each with a low-privilege authenticated session, alternate HTTP "
                     "methods, and path variations. Check whether the block is enforced "
                     "server-side or only reflected in the UI.",
            "vuln_class": "broken-access-control",
            "priority": "medium",
            "category": "auth-boundary",
            "source": "surface",
        })
    return leads


async def analyze(scan_id: int, host: str, *, log=None) -> dict | None:
    """Build the surface map, then ask the model to prioritise. Advisory only."""
    smap = build_surface(scan_id)
    if not smap["total_urls"]:
        return None

    leads = _surface_leads(smap)
    result: dict = {"surface": smap, "summary": "", "blind_spots": [], "notable": []}

    if await llm.available():
        if log:
            await log("info", "analysing attack surface for manual testing leads", "intel")
        data = _summarize(scan_id, smap)
        ai = await llm.complete_json(
            ANALYST_PROMPT.format(host=host, **data),
            system=ANALYST_SYSTEM, temperature=0.3,
        )
        if ai and isinstance(ai.get("attack_surface"), list):
            valid = {"high", "medium", "low"}
            for item in ai["attack_surface"]:
                p = str(item.get("priority", "")).lower()
                item["priority"] = p if p in valid else "medium"
                item["source"] = "ai"
                item["category"] = item.get("vuln_class", "")
            leads = ai["attack_surface"][:10] + leads
            result["summary"] = ai.get("summary", "")
            result["blind_spots"] = ai.get("blind_spots", []) or []
            result["notable"] = ai.get("notable", []) or []
    elif log:
        await log("warn", "Ollama unreachable — using surface map only", "intel")

    if not result["summary"]:
        result["summary"] = (
            f"{smap['total_urls']} endpoint(s) mapped across "
            f"{len(smap['categories'])} category(ies). "
            + (smap["hints"][0] if smap["hints"] else "")
        )

    order = {"high": 0, "medium": 1, "low": 2}
    leads.sort(key=lambda i: order.get(i.get("priority", "medium"), 1))
    result["leads"] = leads[:24]
    return result


def store_intel(scan_id: int, data: dict) -> int:
    """Persist the analysis: summary on the scan, leads as trackable rows."""
    from .models import Lead, Scan

    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        if scan:
            stats = dict(scan.stats or {})
            stats["intel"] = json.loads(json.dumps({
                "summary": data.get("summary", ""),
                "blind_spots": data.get("blind_spots", []),
                "notable": data.get("notable", []),
                "surface": data.get("surface", {}),
            }))
            scan.stats = stats

        # Don't duplicate leads if analysis is re-run for the same scan.
        existing = {
            (l.area, l.vuln_class)
            for l in db.scalars(select(Lead).where(Lead.scan_id == scan_id))
        }
        added = 0
        for item in data.get("leads", []):
            key = (str(item.get("area", ""))[:2000], str(item.get("vuln_class", "")))
            if key in existing or not key[0]:
                continue
            existing.add(key)
            db.add(Lead(
                scan_id=scan_id,
                area=key[0],
                why=str(item.get("why", "")),
                check=str(item.get("check", "")),
                vuln_class=str(item.get("vuln_class", ""))[:60],
                priority=str(item.get("priority", "medium"))[:10],
                category=str(item.get("category", ""))[:40],
                source=str(item.get("source", "ai"))[:20],
            ))
            added += 1
        db.commit()
        return added


async def deep_dive(lead_id: int) -> str | None:
    """On-demand richer test plan for one lead."""
    from .models import Lead, Scan

    with SessionLocal() as db:
        lead = db.get(Lead, lead_id)
        if not lead:
            return None
        if lead.deep_dive:
            return lead.deep_dive
        scan = db.get(Scan, lead.scan_id)
        host = scan.seeds[0] if scan and scan.seeds else lead.area
        tech = ", ".join((scan.stats or {}).get("tech", [])[:12]) if scan else ""
        payload = {
            "host": host, "tech": tech or "unknown stack",
            "area": lead.area, "vuln_class": lead.vuln_class,
            "why": lead.why, "check": lead.check,
        }

    result = await llm.complete_json(
        DEEPDIVE_PROMPT.format(**payload), system=DEEPDIVE_SYSTEM, temperature=0.3,
    )
    if not result:
        return None

    lines = []
    if result.get("approach"):
        lines += ["## Approach", "", str(result["approach"]), ""]
    if result.get("observe"):
        lines += ["## What to observe", ""] + [f"- {x}" for x in result["observe"]] + [""]
    if result.get("distinguish"):
        lines += ["## Flaw vs. expected behaviour", "", str(result["distinguish"]), ""]
    if result.get("evidence"):
        lines += ["## Evidence to capture", ""] + [f"- {x}" for x in result["evidence"]] + [""]
    if result.get("false_positive_traps"):
        lines += ["## Common false positives here", ""] + \
                 [f"- {x}" for x in result["false_positive_traps"]] + [""]
    if result.get("references"):
        lines += ["## References", ""] + [f"- {x}" for x in result["references"]]

    text = "\n".join(lines).strip()
    if text:
        with SessionLocal() as db:
            lead = db.get(Lead, lead_id)
            if lead:
                lead.deep_dive = text
                db.commit()
    return text or None
