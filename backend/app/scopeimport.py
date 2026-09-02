"""Turning a bug bounty program's scope page into engagement rules.

The most common way to get removed from a program is not finding nothing — it
is testing something that was out of scope. Program scope is published as a
table on a web page, and the usual workflow is a human reading it and then
retyping domains into a tool, which is exactly the kind of transcription that
goes wrong quietly.

So this parses a **pasted** scope table into allow and deny rules.

Pasted, not fetched. The tool deliberately does not visit a program page and
build its own scope from what it finds there. Scope is the one piece of
configuration where being wrong is a legal problem rather than a bug, and
deriving it automatically from parsed HTML means an authorization decision made
by a regex on someone else's markup. The human reads the page, copies the
table, and confirms what came out — that step is the point, not friction to be
removed.

Three things this gets right that hand-typing usually doesn't:

**Out of scope wins.** If a host appears in both lists, it is denied. Programs
routinely publish `*.example.com` in scope and `legacy.example.com` out, and
the whole value of that pairing is that the exclusion is authoritative.

**Unscannable assets are named, not silently dropped.** Mobile app bundles,
source repositories, executables and hardware appear in scope tables constantly.
A web scanner cannot test them, and quietly discarding them leaves you thinking
you have covered the program.

**Wildcards are preserved as wildcards.** `*.example.com` becomes a wildcard
rule rather than being flattened to the apex, because flattening silently
narrows scope and you would never notice.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

# Headings and markers that flip the parser into "everything below is excluded".
OUT_MARKERS = re.compile(
    r"^\s*(?:#+\s*)?(?:out[\s\-]?of[\s\-]?scope|excluded?|not in scope|"
    r"ineligible|do not test|off[\s\-]?limits)\b", re.I)

IN_MARKERS = re.compile(
    r"^\s*(?:#+\s*)?(?:in[\s\-]?scope|scope|targets?|assets? in scope|"
    r"eligible)\b\s*:?\s*$", re.I)

# Asset kinds a web scanner cannot test. Named rather than dropped.
UNSCANNABLE = [
    (re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*){2,}$", re.I),
     "mobile app bundle identifier"),
    (re.compile(r"\.(?:apk|ipa|aab)\b", re.I), "mobile application binary"),
    (re.compile(r"(?:play\.google\.com|apps\.apple\.com|itunes\.apple\.com)", re.I),
     "app store listing"),
    (re.compile(r"github\.com/|gitlab\.com/|bitbucket\.org/", re.I),
     "source repository"),
    (re.compile(r"\.(?:exe|dmg|msi|deb|rpm|jar|bin)\b", re.I), "executable"),
    # An actual ASN identifier, not the word "ASN" sitting in a type column —
    # hence the digits. Without them, every scope table with an asset-type
    # column reported a phantom asset named "CIDR".
    (re.compile(r"^as\d{3,}$", re.I), "autonomous system number"),
]

# A hostname, optionally wildcarded.
HOST = re.compile(
    r"^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9\-_]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", re.I)

# Noise that appears in copied tables and is never an asset.
NOISE = re.compile(
    r"^\s*(?:asset|type|identifier|url|domain|severity|max|reward|bounty|"
    r"eligible|description|scope|target|notes?|created|updated|"
    r"cidr|asn|ip|ipv4|ipv6|wildcard|api|hardware|executable|other|"
    r"critical|high|medium|low|none|yes|no|n/?a|—|-+|\|+|\d+)\s*$", re.I)


@dataclass
class ParsedScope:
    allow: list[str] = field(default_factory=list)
    deny: list[str] = field(default_factory=list)
    unscannable: list[tuple[str, str]] = field(default_factory=list)
    ignored: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "allow": self.allow,
            "deny": self.deny,
            "unscannable": [{"asset": a, "kind": k} for a, k in self.unscannable],
            "ignored": self.ignored,
            "counts": {
                "allow": len(self.allow), "deny": len(self.deny),
                "unscannable": len(self.unscannable),
            },
        }


def normalise(token: str) -> str:
    """A scope line reduced to a host, wildcard or CIDR, or "" if it is none.

    Scope tables carry URLs, bare domains, wildcards, ports, paths, markdown
    pipes and backticks in roughly equal measure.

    The ordering below is load-bearing, and both orderings were wrong first
    time in the same direction — silently *narrowing* scope, which is the
    failure you never notice because the scan just covers less:

      * The wildcard has to be detected before decoration is stripped.
        Stripping `*` as punctuation turned `*.example.com` into
        `.example.com`, which matches nothing, so every wildcard asset in a
        program's scope table vanished.
      * The CIDR has to be tried before splitting on `/`, or `203.0.113.0/24`
        becomes a single address and a /24 of authorised scope shrinks to one
        host.
    """
    token = token.strip().strip("`\"'| \t").strip()
    if not token or NOISE.match(token):
        return ""

    # Markdown/table decoration and trailing commentary.
    token = re.split(r"\s{2,}|\s*\|\s*|\s+—\s+|\s+-\s+", token)[0].strip()
    token = token.rstrip(".,;")
    if not token:
        return ""

    # Before any stripping that could remove it.
    wildcard = token.startswith("*.") or token.startswith("*")
    token = token.lstrip("*").lstrip(".")
    if not token:
        return ""

    # Before splitting on "/", which would drop the prefix length.
    try:
        network = ipaddress.ip_network(token, strict=False)
        return str(network)
    except ValueError:
        pass

    if "://" in token:
        token = urlparse(token).hostname or ""
    else:
        token = token.split("/")[0]

    token = token.split(":")[0].strip().lower()
    if not token:
        return ""

    # A bare address that wasn't CIDR-shaped.
    try:
        ipaddress.ip_address(token)
        return token
    except ValueError:
        pass

    if not HOST.match(token):
        return ""
    return f"*.{token}" if wildcard else token


def classify(token: str) -> tuple[str, str]:
    """(kind, detail) — "host", "unscannable" or "ignored"."""
    raw = token.strip().strip("`\"'| \t")
    for pattern, kind in UNSCANNABLE:
        if pattern.search(raw):
            # A bundle id like com.example.app looks like a hostname to the
            # naive pattern, so check it before treating it as one.
            if kind == "mobile app bundle identifier" and normalise(raw):
                if not raw.lower().startswith(("com.", "io.", "org.", "net.")):
                    continue
            return "unscannable", kind
    return ("host", "") if normalise(raw) else ("ignored", "")


def parse(text: str, *, default_section: str = "in") -> ParsedScope:
    """Parse a pasted scope table.

    `default_section` decides where lines before any heading go. "in" is right
    for pasting an in-scope table on its own; paste both tables together and
    the headings take over.
    """
    result = ParsedScope()
    section = default_section
    seen_allow: set[str] = set()
    seen_deny: set[str] = set()

    for raw_line in (text or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue

        if OUT_MARKERS.search(line):
            section = "out"
            continue
        if IN_MARKERS.search(line):
            section = "in"
            continue

        # A table row can hold several assets; split on the usual separators
        # but not on dots or hyphens, which are part of hostnames.
        for token in re.split(r"[,;\s]+|\|", line):
            token = token.strip()
            if not token:
                continue

            kind, detail = classify(token)
            if kind == "unscannable":
                entry = (token.strip("`\"'| \t"), detail)
                if entry not in result.unscannable:
                    result.unscannable.append(entry)
                continue
            if kind == "ignored":
                if len(token) > 3 and not NOISE.match(token):
                    if token not in result.ignored:
                        result.ignored.append(token)
                continue

            host = normalise(token)
            if section == "out":
                if host not in seen_deny:
                    seen_deny.add(host)
                    result.deny.append(host)
            elif host not in seen_allow:
                seen_allow.add(host)
                result.allow.append(host)

    result.allow, result.deny = reconcile(result.allow, result.deny)
    return result


def reconcile(allow: list[str], deny: list[str]) -> tuple[list[str], list[str]]:
    """Out of scope wins.

    A host listed in both lists is denied. This is not an edge case — programs
    routinely publish `*.example.com` in scope with specific hosts excluded,
    and the exclusion is the authoritative half of that pair. Keeping a host in
    both would leave the outcome depending on evaluation order, which is not
    something an authorization decision should depend on.
    """
    denied = set(deny)
    return ([a for a in allow if a not in denied], sorted(denied))


def summarise(scope: ParsedScope) -> str:
    """What to show the operator before they accept this.

    Deliberately written as something to check rather than something to
    approve. The parser is a convenience; the human confirming it against the
    program page is the actual authorization step.
    """
    lines = []

    if scope.allow:
        lines.append(f"**{len(scope.allow)} asset(s) in scope**")
        lines += [f"  ✓ {a}" for a in scope.allow[:20]]
        if len(scope.allow) > 20:
            lines.append(f"  … {len(scope.allow) - 20} more")
    else:
        lines.append("**Nothing parsed as in scope.** Check the paste included "
                     "the asset column.")

    if scope.deny:
        lines += ["", f"**{len(scope.deny)} explicitly out of scope** "
                      f"(these win over any wildcard above)"]
        lines += [f"  ✗ {d}" for d in scope.deny[:15]]

    if scope.unscannable:
        lines += ["", f"**{len(scope.unscannable)} asset(s) this tool cannot test**"]
        lines += [f"  — {a} ({k})" for a, k in scope.unscannable[:12]]
        lines.append("  They are in the program's scope; they are simply not "
                     "web endpoints. Listed so you know what is left uncovered "
                     "rather than assuming the program is fully scanned.")

    if scope.ignored:
        lines += ["", "**Not recognised** — check whether any of these are assets:"]
        lines += [f"  ? {i}" for i in scope.ignored[:10]]

    lines += ["", "Read this against the program page before you scan. A parser "
                  "reading a pasted table is a convenience; confirming it is the "
                  "authorization step, and getting it wrong is how researchers "
                  "get removed from programs."]
    return "\n".join(lines)
