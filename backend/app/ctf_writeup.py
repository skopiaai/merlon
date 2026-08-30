"""Challenge writeup generation.

The finale is graded on "severity of vulnerabilities detected, methodology &
complexity" — so how you document a finding is worth marks independently of
finding it. Under 36-hour time pressure that's exactly the work people skip.

Produces a deterministic skeleton always, and enriches it with the local model
when available. Never invents technical detail: the model only rewrites what
the analyst already wrote in their notes.
"""

from __future__ import annotations

from . import llm
from .ctf import CATEGORIES
from .db import SessionLocal
from .models import Challenge

SYSTEM = """You are helping a security researcher turn rough working notes into
a clear, professional writeup for a competition panel.

Rules:
- Use ONLY the facts in the notes. Never invent commands, values or results.
- If the notes are thin, produce a shorter writeup rather than padding it.
- Write for a technical reviewer: precise, no marketing language.
- Structure matters more than length. Methodology is being graded.
- Reply with JSON only."""

PROMPT = """Turn these working notes into a competition writeup.

Challenge: {name}
Category: {category}
Points/severity: {points} {severity}
Description as given: {description}

Analyst's working notes:
{notes}

Impact stated by the analyst: {impact}

Return JSON:
{{
  "summary": "2-3 sentences: what the issue was and why it matters",
  "methodology": ["the ordered steps actually taken, from the notes"],
  "root_cause": "why this was possible, in technical terms",
  "impact": "what an attacker achieves — concrete, not theoretical",
  "reproduction": ["numbered steps a reviewer could follow to see it again"],
  "remediation": "how the owner should fix it",
  "notes_for_panel": "anything about complexity or originality worth highlighting"
}}"""


def _skeleton(ch: Challenge) -> str:
    cat = CATEGORIES.get(ch.category, {})
    L = [
        f"# {ch.name}",
        "",
        f"**Category:** {cat.get('label', ch.category)}  ",
        f"**Points:** {ch.points}  " if ch.points else "",
        f"**Severity:** {ch.severity}  " if ch.severity else "",
        f"**Status:** {ch.status.value}  ",
        f"**Solved by:** {ch.assignee}  " if ch.assignee else "",
        "",
        "## Summary",
        "",
        ch.description.strip() or "_(fill in: what the issue was and why it matters)_",
        "",
        "## Methodology",
        "",
    ]
    if ch.notes.strip():
        L += [ch.notes.strip(), ""]
    else:
        L += ["_(fill in: the ordered steps you took)_", ""]

    L += [
        "## Impact",
        "",
        ch.impact.strip() or "_(fill in: what an attacker achieves)_",
        "",
        "## Reproduction",
        "",
        "1. _(fill in)_",
        "",
    ]
    if ch.flag:
        L += ["## Flag", "", f"`{ch.flag}`", ""]
    if ch.artifacts:
        L += ["## Artifacts", ""] + [f"- {a}" for a in ch.artifacts] + [""]
    L += [
        "## Remediation",
        "",
        "_(fill in: how the owner should fix it)_",
        "",
    ]
    return "\n".join(x for x in L if x != "")


async def generate(challenge_id: int) -> str:
    with SessionLocal() as db:
        ch = db.get(Challenge, challenge_id)
        if not ch:
            raise ValueError("challenge not found")
        skeleton = _skeleton(ch)
        payload = {
            "name": ch.name,
            "category": CATEGORIES.get(ch.category, {}).get("label", ch.category),
            "points": ch.points or "",
            "severity": ch.severity or "",
            "description": ch.description or "(none given)",
            "notes": ch.notes.strip() or "(no notes recorded)",
            "impact": ch.impact or "(not stated)",
        }
        has_notes = bool(ch.notes.strip())

    # With no notes there's nothing to rewrite — the skeleton is the honest output.
    if not has_notes or not await llm.available():
        return skeleton

    result = await llm.complete_json(PROMPT.format(**payload), system=SYSTEM,
                                     temperature=0.2)
    if not result:
        return skeleton

    cat = CATEGORIES.get(payload["category"].lower(), {})
    L = [f"# {payload['name']}", ""]
    meta = [f"**Category:** {payload['category']}"]
    if payload["points"]:
        meta.append(f"**Points:** {payload['points']}")
    if payload["severity"]:
        meta.append(f"**Severity:** {payload['severity']}")
    L += ["  \n".join(meta), ""]

    def section(title, value, numbered=False):
        if not value:
            return
        L.extend([f"## {title}", ""])
        if isinstance(value, list):
            for i, item in enumerate(value, 1):
                L.append(f"{i}. {item}" if numbered else f"- {item}")
        else:
            L.append(str(value))
        L.append("")

    section("Summary", result.get("summary"))
    section("Methodology", result.get("methodology"), numbered=True)
    section("Root cause", result.get("root_cause"))
    section("Impact", result.get("impact"))
    section("Reproduction", result.get("reproduction"), numbered=True)
    section("Remediation", result.get("remediation"))
    section("Notes for the panel", result.get("notes_for_panel"))

    if cat.get("label"):
        L += ["---", "",
              f"*{cat['label']} challenge. Drafted locally from the analyst's notes — "
              f"verify every statement before submission.*"]

    return "\n".join(L)
