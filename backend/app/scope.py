"""Scope enforcement.

Every host that enters or leaves the scan pipeline passes through here.
Nothing is scanned unless it matches an explicit allowlist rule on an
engagement that has a recorded authorization.

Rule syntax
-----------
  example.com          exact host
  *.example.com        host and any subdomain
  10.0.0.0/24          CIDR range
  192.168.1.50         single IP

Exclusions use the same syntax and always win over allows.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlparse

_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")

# Hosts that are never scannable regardless of allowlist. Cloud metadata
# endpoints in particular can leak credentials and must never be probed.
HARD_DENY_IPS = [
    ipaddress.ip_network("169.254.0.0/16"),   # link-local / cloud metadata
    ipaddress.ip_network("127.0.0.0/8"),      # loopback
    ipaddress.ip_network("::1/128"),
]
HARD_DENY_HOSTS = {"metadata.google.internal", "localhost"}


def hard_denied(target: str) -> str:
    """Why this host may never be reached, or "" if it is permitted.

    Split out of `check()` because the redirect follower needs the *absolute*
    prohibitions without the engagement allowlist. A target legitimately in
    scope can still answer `302 Location: http://169.254.169.254/…`, and
    following that reaches the cloud metadata service from inside whatever
    network the scanner is running on. The seed was checked; the hop was not.

    RFC1918 is deliberately absent — Hack The Box lives on 10.10.10.0/24 and
    home labs on 192.168.0.0/16, and denying those would break the tool's
    actual job. Link-local and loopback are the ones that are never a target
    and always a trap.
    """
    try:
        host = normalize_host(target)
    except ScopeViolation as exc:
        return str(exc)

    if host in HARD_DENY_HOSTS:
        return f"{host} is hard-denied"

    ip = _as_ip(host)
    if ip is not None:
        for net in HARD_DENY_IPS:
            if ip.version == net.version and ip in net:
                return f"{host} is in hard-denied range {net}"
    return ""


class ScopeViolation(Exception):
    """Raised when a target fails scope validation. Never swallow this."""


def normalize_host(value: str) -> str:
    """Reduce a URL, host:port, or bare host to a lowercase hostname."""
    value = value.strip().lower()
    if not value:
        raise ScopeViolation("empty target")
    if "://" in value:
        parsed = urlparse(value)
        value = parsed.hostname or ""
    else:
        # strip a trailing :port, but not IPv6 colons
        if value.count(":") == 1:
            value = value.split(":", 1)[0]
    value = value.rstrip(".")
    if not value:
        raise ScopeViolation("could not extract a hostname")
    return value


def _as_ip(host: str):
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def _matches_rule(host: str, rule: str) -> bool:
    rule = rule.strip().lower().rstrip(".")
    if not rule:
        return False

    ip = _as_ip(host)

    # CIDR rule
    if "/" in rule:
        if ip is None:
            return False
        try:
            return ip in ipaddress.ip_network(rule, strict=False)
        except ValueError:
            return False

    # wildcard rule
    if rule.startswith("*."):
        base = rule[2:]
        return host == base or host.endswith("." + base)

    return host == rule


@dataclass
class ScopeDecision:
    host: str
    allowed: bool
    reason: str


def check(host: str, allow_rules: list[str], deny_rules: list[str]) -> ScopeDecision:
    """Pure scope decision for a single host. No side effects."""
    try:
        host = normalize_host(host)
    except ScopeViolation as exc:
        return ScopeDecision(host, False, str(exc))

    if host in HARD_DENY_HOSTS:
        return ScopeDecision(host, False, "hard-denied host")

    ip = _as_ip(host)
    if ip is not None:
        for net in HARD_DENY_IPS:
            if ip.version == net.version and ip in net:
                return ScopeDecision(host, False, f"hard-denied range {net}")

    for rule in deny_rules:
        if _matches_rule(host, rule):
            return ScopeDecision(host, False, f"excluded by rule '{rule}'")

    if not allow_rules:
        return ScopeDecision(host, False, "engagement has no allowlist rules")

    for rule in allow_rules:
        if _matches_rule(host, rule):
            return ScopeDecision(host, True, f"allowed by rule '{rule}'")

    return ScopeDecision(host, False, "not in scope")


def filter_hosts(hosts, allow_rules, deny_rules) -> tuple[list[str], list[ScopeDecision]]:
    """Split a host list into in-scope and rejected.

    Called on every stage boundary, not just at scan start. Subdomain
    enumeration in particular loves to return third-party hosts (CDN
    endpoints, SaaS CNAMEs) that are emphatically not yours to scan.
    """
    kept, rejected = [], []
    seen = set()
    for h in hosts:
        decision = check(h, allow_rules, deny_rules)
        if decision.allowed:
            if decision.host not in seen:
                seen.add(decision.host)
                kept.append(decision.host)
        else:
            rejected.append(decision)
    return kept, rejected


def validate_rule(rule: str) -> str:
    """Validate an allowlist rule at entry time so typos fail loudly."""
    rule = rule.strip().lower().rstrip(".")
    if not rule:
        raise ScopeViolation("empty rule")
    if "/" in rule:
        try:
            ipaddress.ip_network(rule, strict=False)
        except ValueError as exc:
            raise ScopeViolation(f"invalid CIDR '{rule}': {exc}") from exc
        return rule
    probe = rule[2:] if rule.startswith("*.") else rule
    if _as_ip(probe) is not None:
        return rule
    if not _HOSTNAME_RE.match(probe):
        raise ScopeViolation(f"'{rule}' is not a valid hostname, wildcard, IP, or CIDR")
    return rule
