"""Continuous monitoring and asset diffing.

The most reliable edge in bug bounty is arriving first, and the moment when
that is possible is the moment an asset appears. A subdomain that went live
this morning has not been hunted by anyone — every other researcher's last
scan predates it, and the organisation's own testing usually lags deployment.

So this watches an engagement's attack surface on a schedule and reports the
**difference**, not the state. A full scan report is a list you have already
read. A diff is three lines saying `payments-staging.target.com appeared four
hours ago`, and that is the line worth acting on.

Three things it tracks, because each has a different meaning:

  **New hosts.** Something was deployed, or a name was added to DNS. Highest
  value — it is unhunted by definition.

  **New endpoints and technology changes.** An existing host started serving
  something it wasn't. A framework version changed, an admin panel appeared, a
  login form showed up where there wasn't one.

  **Disappearances.** A host that stopped resolving is worth noticing for the
  opposite reason: a name still pointed at a decommissioned service is exactly
  the setup for a subdomain takeover.

The snapshot is deliberately cheap — hosts, URLs, status codes and detected
technology, not full findings. Diffing is a comparison over sets, so a watch
run costs one recon pass and nothing else.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy import select

from .db import SessionLocal
from .models import Asset, Engagement, Scan, ScanState


@dataclass
class Snapshot:
    """The attack surface at a point in time."""
    scan_id: int
    at: str
    hosts: set[str] = field(default_factory=set)
    urls: set[str] = field(default_factory=set)
    # host -> a compact signature of what it was serving
    signatures: dict[str, str] = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "scan_id": self.scan_id, "at": self.at,
            "hosts": sorted(self.hosts), "urls": sorted(self.urls),
            "signatures": self.signatures,
        }


@dataclass
class Diff:
    """What changed between two snapshots."""
    new_hosts: list[str] = field(default_factory=list)
    gone_hosts: list[str] = field(default_factory=list)
    new_urls: list[str] = field(default_factory=list)
    changed: list[dict] = field(default_factory=list)
    baseline_at: str = ""
    current_at: str = ""

    @property
    def interesting(self) -> bool:
        return bool(self.new_hosts or self.new_urls or self.changed
                    or self.gone_hosts)

    def as_dict(self) -> dict:
        return {
            "new_hosts": self.new_hosts, "gone_hosts": self.gone_hosts,
            "new_urls": self.new_urls, "changed": self.changed,
            "baseline_at": self.baseline_at, "current_at": self.current_at,
            "interesting": self.interesting,
            "counts": {
                "new_hosts": len(self.new_hosts),
                "gone_hosts": len(self.gone_hosts),
                "new_urls": len(self.new_urls),
                "changed": len(self.changed),
            },
        }


def signature(asset: Asset) -> str:
    """A compact description of what a host is serving.

    Status, title and technology — enough that a meaningful change shows up and
    a page whose copy was edited doesn't. Diffing full response bodies would
    fire on every deploy and every rotating CSRF token, which trains you to
    ignore the alert.
    """
    tech = ",".join(sorted(str(t) for t in (asset.tech or [])))
    return f"{asset.status_code or 0}|{(asset.title or '')[:60]}|{tech}"


def snapshot_of(scan_id: int) -> Snapshot:
    """Build a snapshot from a completed scan's stored assets."""
    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        assets = list(db.scalars(select(Asset).where(Asset.scan_id == scan_id)))

        snap = Snapshot(
            scan_id=scan_id,
            at=(scan.finished_at or scan.created_at).isoformat() if scan else "",
        )
        for asset in assets:
            if asset.host:
                snap.hosts.add(asset.host.lower())
                snap.signatures[asset.host.lower()] = signature(asset)
            if asset.url:
                snap.urls.add(asset.url)
        return snap


def diff(baseline: Snapshot, current: Snapshot) -> Diff:
    """What appeared, vanished or changed. Pure — this is the tested part."""
    result = Diff(baseline_at=baseline.at, current_at=current.at)

    result.new_hosts = sorted(current.hosts - baseline.hosts)
    result.gone_hosts = sorted(baseline.hosts - current.hosts)
    result.new_urls = sorted(current.urls - baseline.urls)

    for host in sorted(current.hosts & baseline.hosts):
        before = baseline.signatures.get(host, "")
        after = current.signatures.get(host, "")
        if before and after and before != after:
            result.changed.append({
                "host": host, "before": before, "after": after,
                "why": _explain(before, after),
            })
    return result


def _explain(before: str, after: str) -> str:
    """Say what actually changed, in words rather than two opaque strings."""
    old_status, old_title, old_tech = (before.split("|") + ["", "", ""])[:3]
    new_status, new_title, new_tech = (after.split("|") + ["", "", ""])[:3]
    notes = []

    if old_status != new_status:
        notes.append(f"HTTP {old_status} → {new_status}")
        if old_status in ("0", "404", "403") and new_status == "200":
            notes.append("something is now being served here that wasn't before")
    if old_title != new_title:
        notes.append(f"title changed to {new_title!r}")
    if old_tech != new_tech:
        added = set(filter(None, new_tech.split(","))) - set(filter(None, old_tech.split(",")))
        removed = set(filter(None, old_tech.split(","))) - set(filter(None, new_tech.split(",")))
        if added:
            notes.append(f"now running {', '.join(sorted(added))}")
        if removed:
            notes.append(f"no longer running {', '.join(sorted(removed))}")
    return "; ".join(notes) or "signature changed"


def last_two_scans(engagement_id: int) -> tuple[int | None, int | None]:
    """(baseline_scan_id, current_scan_id) — the two most recent completed scans."""
    with SessionLocal() as db:
        scans = list(db.scalars(
            select(Scan)
            .where(Scan.engagement_id == engagement_id,
                   Scan.state == ScanState.completed)
            # id as a tiebreaker: finished_at can be NULL on a row that was
            # marked completed without going through _finish, and NULLs make
            # the order undefined — which would silently compare the wrong two
            # scans rather than fail.
            .order_by(Scan.finished_at.desc(), Scan.id.desc())
            .limit(2)))
    if len(scans) < 2:
        return (None, scans[0].id if scans else None)
    return (scans[1].id, scans[0].id)


def diff_engagement(engagement_id: int) -> dict:
    """Compare an engagement's two most recent completed scans."""
    baseline_id, current_id = last_two_scans(engagement_id)
    if current_id is None:
        return {"available": False,
                "detail": "no completed scans for this engagement yet"}
    if baseline_id is None:
        return {"available": False,
                "detail": "only one completed scan — run another to see what "
                          "changed. The diff is the point; a single scan is just "
                          "a list."}

    result = diff(snapshot_of(baseline_id), snapshot_of(current_id))
    return {
        "available": True,
        "baseline_scan": baseline_id,
        "current_scan": current_id,
        **result.as_dict(),
    }


def summarise(result: Diff) -> str:
    """One paragraph for a notification or a log line."""
    if not result.interesting:
        return "No change in the attack surface since the last scan."

    parts = []
    if result.new_hosts:
        shown = ", ".join(result.new_hosts[:5])
        more = f" (+{len(result.new_hosts) - 5} more)" if len(result.new_hosts) > 5 else ""
        parts.append(
            f"**{len(result.new_hosts)} new host(s)**: {shown}{more}. These have "
            f"not been scanned before and are the highest-value thing here — a "
            f"host that appeared since your last run has not been hunted by "
            f"anyone else either.")
    if result.changed:
        parts.append(
            f"**{len(result.changed)} host(s) changed**: "
            + "; ".join(f"{c['host']} — {c['why']}" for c in result.changed[:4]))
    if result.gone_hosts:
        parts.append(
            f"**{len(result.gone_hosts)} host(s) stopped responding**: "
            f"{', '.join(result.gone_hosts[:5])}. Worth checking whether the DNS "
            f"record still exists — a name pointing at a decommissioned service "
            f"is how subdomain takeovers happen.")
    if result.new_urls:
        parts.append(f"**{len(result.new_urls)} new endpoint(s)** on existing hosts.")
    return "\n\n".join(parts)


def previously_seen(scan_id: int) -> dict[str, dict]:
    """dedupe_key -> when this finding first appeared in an earlier scan.

    A scanner run weekly reports the same thirty findings every week. Without
    this, the submission queue looks identical each time and the two entries
    that are actually new are buried in twenty-eight you already read and
    decided about.

    Only earlier scans of the *same engagement* count. The same rule firing on
    a different target is a different finding, and treating it as a duplicate
    would hide real work.
    """
    from .models import Finding

    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        if not scan:
            return {}

        earlier = list(db.scalars(
            select(Scan).where(
                Scan.engagement_id == scan.engagement_id,
                Scan.id != scan_id,
                Scan.created_at < scan.created_at,
            )))
        if not earlier:
            return {}

        history: dict[str, dict] = {}
        for previous in sorted(earlier, key=lambda s: s.created_at):
            for finding in db.scalars(
                    select(Finding).where(Finding.scan_id == previous.id)):
                # Keep the *earliest* sighting: "first seen three months ago"
                # is the useful fact, not "seen again yesterday".
                history.setdefault(finding.dedupe_key, {
                    "first_seen": (previous.finished_at
                                   or previous.created_at).isoformat(),
                    "scan_id": previous.id,
                    "status": finding.status.value,
                    "name": finding.name,
                })
        return history


def annotate_new(entries: list[dict], history: dict[str, dict]) -> list[dict]:
    """Mark queue entries as new or previously seen. Pure, so it is testable.

    Entries keep their order — this adds context, it does not re-sort. Whether
    something is new matters, but it matters less than whether it reproduces,
    and the queue's ordering already encodes that priority.
    """
    for entry in entries:
        seen = history.get(entry.get("dedupe_key", ""))
        if seen:
            entry["first_seen"] = seen["first_seen"]
            entry["previously"] = seen["status"]
            entry["is_new"] = False
        else:
            entry["is_new"] = True
    return entries


def watch_targets() -> list[dict]:
    """Engagements worth re-scanning, with when they were last looked at.

    Expired engagements are excluded — re-scanning something whose
    authorization has lapsed is exactly the mistake the engagement record
    exists to prevent, and a scheduler is precisely where it would happen
    without anyone noticing.
    """
    now = datetime.now(timezone.utc)
    out = []
    with SessionLocal() as db:
        for eng in db.scalars(select(Engagement)):
            if eng.expires_at is not None:
                expires = eng.expires_at
                if expires.tzinfo is None:
                    expires = expires.replace(tzinfo=timezone.utc)
                if expires < now:
                    continue
            last = db.scalars(
                select(Scan).where(Scan.engagement_id == eng.id,
                                   Scan.state == ScanState.completed)
                .order_by(Scan.finished_at.desc()).limit(1)).first()
            out.append({
                "engagement_id": eng.id,
                "name": eng.name,
                "last_scan_id": last.id if last else None,
                "last_scan_at": (last.finished_at.isoformat()
                                 if last and last.finished_at else None),
                "seeds": list(last.seeds) if last else [],
            })
    return out


# ---------------------------------------------------------------------------
# Findings, rather than surface
#
# The diff above answers "what appeared". This answers "what is new, and what
# went away" about the findings themselves, which is the question someone
# monitoring a programme actually asks on a Monday.
#
# The care is all in one place: **absence is not a fix.** A finding that is
# missing from the newer scan usually means it was fixed — but it also means
# exactly that if the engine which found it never ran, because the rescan was
# shallower, the engine was disabled, or the scan stopped early. Reporting
# those as "fixed" would tell someone a vulnerability is gone when nobody
# looked, which is the most damaging thing a security tool can say.
# ---------------------------------------------------------------------------

def finding_index(scan_id: int) -> dict[str, dict]:
    """Every finding in a scan, keyed by the identity it keeps across scans.

    `dedupe_key` is already the project's notion of "the same finding seen
    again" — the orchestrator uses it to bump occurrences rather than insert a
    duplicate — so it is the right key here too rather than a second one.
    """
    from .models import Finding

    with SessionLocal() as db:
        rows = db.scalars(select(Finding).where(Finding.scan_id == scan_id)).all()
        out: dict[str, dict] = {}
        for f in rows:
            key = f.dedupe_key or f"{f.engine}:{f.rule_id}:{f.host}:{f.url}"
            verification = f.verification or {}
            out[key] = {
                "dedupe_key": key,
                "engine": f.engine,
                "rule_id": f.rule_id,
                "name": f.name,
                "severity": (f.severity.value if hasattr(f.severity, "value")
                             else str(f.severity)),
                "host": f.host,
                "url": f.url,
                "tier": verification.get("tier"),
            }
        return out


def engines_that_ran(scan_id: int) -> set[str]:
    """Which engines this scan actually got through.

    Read from the stages it recorded completing, falling back to the engines
    that produced findings. Used to tell "this was fixed" apart from "nobody
    checked".
    """
    from .models import Finding

    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        ran: set[str] = set(scan.completed_stages or []) if scan else set()
        # An engine that produced a finding plainly ran, whatever the stage
        # record says — this keeps older scans, recorded before stages were
        # tracked, from looking like they ran nothing.
        ran |= {e for (e,) in db.execute(
            select(Finding.engine).where(Finding.scan_id == scan_id).distinct())}
        return ran


_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _by_severity(items: list[dict]) -> list[dict]:
    return sorted(items, key=lambda f: (_SEVERITY_ORDER.get(f["severity"], 4),
                                        f["host"], f["name"]))


def diff_findings(baseline_id: int, current_id: int) -> dict:
    """What changed between two scans' findings.

    Four buckets, because three would be a lie:

      new            present now, absent before
      fixed          present before, absent now — and the engine did run again
      still_open     present in both
      not_rechecked  present before, absent now, but the engine that found it
                     did not run this time, so nothing was actually verified
    """
    before = finding_index(baseline_id)
    after = finding_index(current_id)
    ran_now = engines_that_ran(current_id)

    new = [f for k, f in after.items() if k not in before]
    still_open = [f for k, f in after.items() if k in before]

    fixed, not_rechecked = [], []
    for key, finding in before.items():
        if key in after:
            continue
        if finding["engine"] in ran_now:
            fixed.append(finding)
        else:
            not_rechecked.append(finding)

    def counts(items: list[dict]) -> dict:
        out: dict[str, int] = {}
        for f in items:
            out[f["severity"]] = out.get(f["severity"], 0) + 1
        return out

    return {
        "baseline_scan": baseline_id,
        "current_scan": current_id,
        "new": _by_severity(new),
        "fixed": _by_severity(fixed),
        "still_open": _by_severity(still_open),
        "not_rechecked": _by_severity(not_rechecked),
        "summary": {
            "new": counts(new),
            "fixed": counts(fixed),
            "still_open": counts(still_open),
            "not_rechecked": counts(not_rechecked),
        },
    }


def diff_findings_engagement(engagement_id: int) -> dict:
    """The same, for the two most recent completed scans of an engagement."""
    baseline, current = last_two_scans(engagement_id)
    if current is None:
        return {"error": "no completed scans for this engagement"}
    if baseline is None:
        return {"error": "only one completed scan — nothing to compare against",
                "current_scan": current}
    return diff_findings(baseline, current)


def summarise_findings(result: dict) -> str:
    """One paragraph a human can read without opening the list."""
    if "error" in result:
        return result["error"]
    s = result["summary"]

    def line(label: str, bucket: str) -> str:
        counts = s[bucket]
        total = sum(counts.values())
        if not total:
            return ""
        detail = ", ".join(f"{n} {sev}" for sev, n in
                           sorted(counts.items(),
                                  key=lambda kv: _SEVERITY_ORDER.get(kv[0], 4)))
        return f"{label}: {total} ({detail})"

    parts = [p for p in (line("New", "new"), line("Fixed", "fixed"),
                         line("Still open", "still_open")) if p]
    text = " · ".join(parts) or "No change."
    stale = sum(s["not_rechecked"].values())
    if stale:
        text += (f" · {stale} finding(s) from the previous scan were not "
                 f"rechecked, because the engine that found them did not run "
                 f"this time — they are not known to be fixed.")
    return text
