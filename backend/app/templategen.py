"""Turning a confirmed finding into a reusable nuclei template.

A finding is worth one report. A template is worth every future scan you run,
against every target, forever — and it works in anyone else's nuclei too. This
is the difference between doing the work once and keeping it.

It is also the honest answer to "how do I stay ahead". Nuclei's official
library covers what everyone already knows. The checks that find things nobody
else finds are the ones you wrote after noticing something yourself, and the
gap between noticing and having a repeatable check is usually where the value
evaporates.

Two constraints shape what this generates:

**Only findings that reproduced.** A template built from something that didn't
reproduce is a permanent false positive — it will fire on every scan and you
will eventually stop reading its output, which quietly degrades every other
result too.

**Matchers come from the captured evidence, not from a guess.** The status
code, the header, and the body string are taken from the response that was
actually recorded during verification. A template whose matcher was inferred
rather than observed is one nobody can trust.

The output is a starting point that runs, not a finished detection. Templates
generated from a single observation tend to be over-specific — matching a
hostname that only appears on this target, or a timestamp. The header comment
in every generated file says so.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from .models import Finding, Severity

# nuclei ids are lowercase, hyphenated, and have to be unique in a directory.
ID_SAFE = re.compile(r"[^a-z0-9]+")

# Body text that identifies the target rather than the vulnerability. A matcher
# containing any of these fires only on this one host, which makes the template
# useless everywhere else — and misleading, because it will look like a working
# check that simply never triggers.
TARGET_SPECIFIC = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"                  # an address
    r"|[a-z0-9-]+\.[a-z]{2,}(?:/|\b)"               # a hostname
    r"|\d{4}-\d{2}-\d{2}"                           # a date
    r"|[0-9a-f]{16,}",                              # a session id or hash
    re.I)

SEVERITY_NAMES = {
    Severity.critical: "critical", Severity.high: "high",
    Severity.medium: "medium", Severity.low: "low", Severity.info: "info",
}


def template_id(finding: Finding) -> str:
    base = f"{finding.engine}-{finding.rule_id}".lower()
    base = ID_SAFE.sub("-", base).strip("-")
    return base[:60] or "generated-check"


def path_of(url: str) -> str:
    """The request path, which is what a template is parameterised on."""
    parsed = urlparse(url or "")
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    return path


def usable_matchers(finding: Finding) -> list[dict]:
    """Matchers derived from what was actually observed.

    Returns [] when the evidence cannot support a matcher — which is a valid
    outcome and better than emitting a template that matches everything.
    """
    verification = finding.verification or {}
    captures = [c for c in verification.get("evidence", [])
                if c.get("reproduced") and c.get("status")]
    if not captures:
        return []

    primary = captures[0]
    matchers: list[dict] = []

    status = primary.get("status")
    if status and status != 404:
        matchers.append({"type": "status", "status": [status]})

    # A header that is part of the finding rather than part of the server.
    interesting_headers = {
        "access-control-allow-origin", "access-control-allow-credentials",
        "allow", "location", "server", "x-powered-by", "content-type",
    }
    for name, value in (primary.get("response_headers") or {}).items():
        if name.lower() in interesting_headers and value and len(value) < 120:
            if not TARGET_SPECIFIC.search(value):
                matchers.append({
                    "type": "word", "part": "header",
                    "words": [f"{name}: {value}"],
                })
                break

    # A distinctive body string, if the excerpt has one that isn't about this
    # particular host.
    excerpt = (primary.get("excerpt") or "").strip()
    for line in excerpt.splitlines():
        candidate = line.strip()
        if 12 <= len(candidate) <= 90 and not TARGET_SPECIFIC.search(candidate):
            matchers.append({"type": "word", "part": "body",
                             "words": [candidate], "case-insensitive": True})
            break

    return matchers


def _yaml_string(value: str) -> str:
    """Quote a scalar safely without pulling in a YAML library.

    Only used for values this module produces, all of which are short single
    lines — anything longer goes through the block-literal path below.
    """
    escaped = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _block(text: str, indent: str = "    ") -> str:
    """A YAML block scalar, for prose that contains anything at all."""
    lines = (text or "").strip().splitlines() or [""]
    return "|\n" + "\n".join(f"{indent}{line}".rstrip() for line in lines)


def generate(finding: Finding) -> tuple[str, str]:
    """(filename, yaml) for a finding. Raises ValueError if it isn't suitable."""
    if finding.verify_confidence is not None and not finding.reproduced:
        raise ValueError(
            "This finding did not reproduce on retest. A template built from it "
            "would fire on every future scan and never be right — which "
            "eventually trains you to ignore its output, and everything near it.")

    matchers = usable_matchers(finding)
    if not matchers:
        raise ValueError(
            "There is no verification evidence to build a matcher from. "
            "Re-verify the finding first: matchers inferred rather than "
            "observed produce templates nobody can trust.")

    name = template_id(finding)
    severity = SEVERITY_NAMES.get(finding.severity, "info")
    path = path_of(finding.matched_at or finding.url)

    lines = [
        "# Generated by Parapet from a verified finding.",
        "#",
        "# This runs, but it is a starting point rather than a finished check.",
        "# A template built from one observation tends to be over-specific — read",
        "# the matchers below and remove anything that describes the target",
        "# rather than the vulnerability, or it will silently match nothing",
        "# everywhere else.",
        f"# Source: {finding.host} · verified "
        f"{finding.verified_at.isoformat() if finding.verified_at else 'during scan'}",
        "",
        f"id: {name}",
        "",
        "info:",
        f"  name: {_yaml_string(finding.name)}",
        "  author: parapet",
        f"  severity: {severity}",
        f"  description: {_block(finding.description[:800], '    ')}",
    ]

    if finding.remediation:
        lines.append(f"  remediation: {_block(finding.remediation[:600], '    ')}")

    if finding.references:
        lines.append("  reference:")
        lines += [f"    - {r}" for r in finding.references[:5]]

    if finding.cwe or finding.cve:
        lines.append("  classification:")
        if finding.cwe:
            lines.append(f"    cwe-id: {','.join(finding.cwe).lower()}")
        if finding.cve:
            lines.append(f"    cve-id: {','.join(finding.cve).lower()}")

    tags = [finding.engine] + [t for t in (finding.tags or [])
                               if re.fullmatch(r"[a-z0-9\-]+", str(t))]
    lines.append(f"  tags: {','.join(dict.fromkeys(tags))[:120]}")

    lines += [
        "",
        "http:",
        "  - method: GET",
        "    path:",
        f'      - "{{{{BaseURL}}}}{path}"',
        "",
        "    matchers-condition: and",
        "    matchers:",
    ]

    for matcher in matchers:
        lines.append(f"      - type: {matcher['type']}")
        if matcher["type"] == "status":
            lines.append("        status:")
            lines += [f"          - {s}" for s in matcher["status"]]
        else:
            lines.append(f"        part: {matcher['part']}")
            lines.append("        words:")
            lines += [f"          - {_yaml_string(w)}" for w in matcher["words"]]
            if matcher.get("case-insensitive"):
                lines.append("        case-insensitive: true")

    text = "\n".join(lines) + "\n"
    validate(text)
    return f"{name}.yaml", text


def validate(text: str) -> None:
    """Parse the generated template before handing it over.

    This module builds YAML by string concatenation, which is fine for the
    narrow, known shapes it emits — but a finding's name or description is
    arbitrary text from a scanned site, and arbitrary text is exactly what
    breaks hand-built YAML. Handing someone a file that nuclei refuses to load
    wastes their time and looks like their mistake.

    So the output is parsed here, and a failure is raised as a generator bug
    rather than delivered.
    """
    try:
        import yaml
    except ImportError:      # pragma: no cover - pyyaml is in requirements
        return

    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ValueError(
            f"the generated template is not valid YAML, which is a bug in the "
            f"generator rather than anything you did: {exc}") from exc

    if not isinstance(doc, dict) or not doc.get("id") or not doc.get("http"):
        raise ValueError("the generated template parsed but is missing required "
                         "fields — generator bug")
