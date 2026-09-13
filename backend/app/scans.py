"""Creating a scan from a bare target — the one implementation.

Three entry points now start a scan the same way: the HTTP quick-scan the web
UI calls, the MCP `start_scan` tool an agent calls, and the command line. Each
had begun to grow its own copy of "normalise the host, derive the scope, find
or create the engagement, apply the depth preset". Three copies of a rule about
*authorisation and scope* is precisely the code that must not drift, so it
lives here once and they all call it.

The authorisation check is part of it, deliberately. It is not the caller's
job to remember: a caller that forgets a gate leaves a hole, whereas a caller
that forgets to pass `authorized=True` just gets an exception.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import schemas, scope
from .models import Engagement, Scan


class NotAuthorized(Exception):
    """The caller did not affirm they may test this target."""


class BadTarget(Exception):
    """The target could not be read as a domain."""


def create_quick_scan(db: Session, target: str, *, authorized: bool,
                      depth: str = "standard", include_subdomains: bool = True,
                      authorized_by: str = "self-attested (owner)",
                      authorization_ref: str = "",
                      source: str = "quickscan") -> Scan:
    """Derive scope from a target, reuse or create its engagement, queue a scan.

    Returns the persisted Scan. Starting it is left to the caller, because the
    three entry points run it differently — the API and MCP hand it to the
    orchestrator's loop, the CLI awaits it directly.
    """
    if not authorized:
        raise NotAuthorized(
            "Refused: scanning a target requires confirming you own it or are "
            "permitted to test it. That record is what protects the operator.")

    try:
        host = scope.normalize_host(target)
    except scope.ScopeViolation as exc:
        raise BadTarget(f"could not read that as a domain: {exc}") from exc

    if depth not in schemas.DEPTH_PRESETS:
        raise BadTarget(
            f"unknown depth {depth!r}; choose from "
            f"{sorted(schemas.DEPTH_PRESETS)}")

    rules = [host] + ([f"*.{host}"] if include_subdomains else [])

    engagement = db.scalar(select(Engagement).where(Engagement.name == host))
    if engagement is None:
        engagement = Engagement(
            name=host,
            kind="self_owned",
            authorized_by=authorized_by,
            authorization_ref=(authorization_ref
                               or f"Self-attested ownership of {host} ({source})"),
            allow_rules=rules,
            deny_rules=[],
        )
        db.add(engagement)
        db.commit()
        db.refresh(engagement)
    elif sorted(engagement.allow_rules) != sorted(rules):
        # The subdomain choice changed since last time; the scope follows it.
        engagement.allow_rules = rules
        db.commit()

    profile, stages = schemas.DEPTH_PRESETS[depth]
    scan = Scan(engagement_id=engagement.id, seeds=[host],
                profile=profile, stages=stages)
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan
