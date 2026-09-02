from __future__ import annotations

import enum
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Severity(str, enum.Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"

    @property
    def rank(self) -> int:
        return ["info", "low", "medium", "high", "critical"].index(self.value)


class ScanState(str, enum.Enum):
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"


class FindingStatus(str, enum.Enum):
    new = "new"
    triaging = "triaging"
    confirmed = "confirmed"
    false_positive = "false_positive"
    accepted_risk = "accepted_risk"
    reported = "reported"
    fixed = "fixed"


class Engagement(Base):
    """A scoped, authorized piece of work. Scans hang off engagements so
    authorization is structurally impossible to skip."""
    __tablename__ = "engagements"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    kind: Mapped[str] = mapped_column(String(50), default="bug_bounty")  # bug_bounty | internal | ctf | lab

    # --- authorization record: who said yes, when, and where's the proof ---
    authorized_by: Mapped[str] = mapped_column(String(200))
    authorization_ref: Mapped[str] = mapped_column(Text)  # program URL, email subject, ticket ID
    authorized_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    allow_rules: Mapped[list] = mapped_column(JSON, default=list)
    deny_rules: Mapped[list] = mapped_column(JSON, default=list)

    # --- authenticated scanning ---
    # Most of any real application sits behind a login; without credentials a
    # scan sees a fraction of the attack surface. Stored per-engagement so the
    # authorization record and the credentials travel together.
    #
    # NOTE: these are stored in plaintext in the local SQLite file. That is
    # acceptable for a single-user offline tool and NOT acceptable if this ever
    # becomes multi-user — see docs/UPDATING.md.
    auth_headers: Mapped[dict] = mapped_column(JSON, default=dict)   # {"Cookie": "...", ...}
    auth_check_url: Mapped[str] = mapped_column(Text, default="")    # page only visible logged in
    auth_check_string: Mapped[str] = mapped_column(Text, default="") # text proving the session works

    # Additional accounts, for access-control testing. One session tells you
    # what a logged-in user can reach; two tell you whether one user can reach
    # the *other's* data, which is the bug class that pays most and the one no
    # single-session scanner can see.
    #
    # [{"name": "user-b", "role": "standard", "headers": {...},
    #   "check_url": "...", "check_string": "..."}]
    auth_identities: Mapped[list] = mapped_column(JSON, default=list)

    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    scans: Mapped[list[Scan]] = relationship(back_populates="engagement", cascade="all, delete-orphan")

    @property
    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        exp = self.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return exp < utcnow()


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagements.id", ondelete="CASCADE"))
    seeds: Mapped[list] = mapped_column(JSON, default=list)
    profile: Mapped[str] = mapped_column(String(50), default="standard")  # passive | standard | thorough
    stages: Mapped[list] = mapped_column(JSON, default=list)

    state: Mapped[ScanState] = mapped_column(Enum(ScanState), default=ScanState.queued)
    stage_current: Mapped[str] = mapped_column(String(50), default="")
    progress: Mapped[float] = mapped_column(Float, default=0.0)
    error: Mapped[str] = mapped_column(Text, default="")

    stats: Mapped[dict] = mapped_column(JSON, default=dict)
    rejected_hosts: Mapped[list] = mapped_column(JSON, default=list)

    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    engagement: Mapped[Engagement] = relationship(back_populates="scans")
    findings: Mapped[list[Finding]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    assets: Mapped[list[Asset]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class Asset(Base):
    """Something discovered during recon: a host, a live service, an endpoint."""
    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    host: Mapped[str] = mapped_column(String(255), index=True)
    url: Mapped[str] = mapped_column(Text, default="")
    ip: Mapped[str] = mapped_column(String(64), default="")
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    title: Mapped[str] = mapped_column(Text, default="")
    tech: Mapped[list] = mapped_column(JSON, default=list)
    raw: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    scan: Mapped[Scan] = relationship(back_populates="assets")


class Finding(Base):
    """The unified finding. Every engine normalizes into this shape, which is
    what makes cross-tool dedupe and a single triage queue possible."""
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("scan_id", "dedupe_key", name="uq_scan_dedupe"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))

    engine: Mapped[str] = mapped_column(String(50), index=True)
    rule_id: Mapped[str] = mapped_column(String(200), default="")   # e.g. nuclei template ID
    name: Mapped[str] = mapped_column(Text)
    severity: Mapped[Severity] = mapped_column(Enum(Severity), default=Severity.info, index=True)

    host: Mapped[str] = mapped_column(String(255), index=True)
    url: Mapped[str] = mapped_column(Text, default="")
    matched_at: Mapped[str] = mapped_column(Text, default="")

    description: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[str] = mapped_column(Text, default="")
    remediation: Mapped[str] = mapped_column(Text, default="")
    references: Mapped[list] = mapped_column(JSON, default=list)
    tags: Mapped[list] = mapped_column(JSON, default=list)
    cve: Mapped[list] = mapped_column(JSON, default=list)
    cwe: Mapped[list] = mapped_column(JSON, default=list)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Control references (OWASP Top 10 / ASVS / ISO 27001 / CIS / GIGW).
    # Populated at save time so reports are traceable to a standard.
    compliance: Mapped[dict] = mapped_column(JSON, default=dict)

    dedupe_key: Mapped[str] = mapped_column(String(200), index=True)
    occurrences: Mapped[int] = mapped_column(Integer, default=1)

    status: Mapped[FindingStatus] = mapped_column(Enum(FindingStatus), default=FindingStatus.new, index=True)
    triage_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)  # 0..1, LLM-assigned
    triage_note: Mapped[str] = mapped_column(Text, default="")
    analyst_note: Mapped[str] = mapped_column(Text, default="")

    # --- independent re-verification (app/verify.py) ---
    # Deliberately separate from triage_confidence, which is the LLM's opinion.
    # This one is computed from facts: did it reproduce, did it reproduce twice,
    # did a control request behave differently. An LLM's belief that a finding
    # is real is precisely the signal that produced the industry-wide flood of
    # unreproducible AI reports, so it is recorded and given no weight here.
    verify_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    reproduced: Mapped[bool] = mapped_column(Boolean, default=False)
    verification: Mapped[dict] = mapped_column(JSON, default=dict)  # evidence + reasons

    raw: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    scan: Mapped[Scan] = relationship(back_populates="findings")


class LeadStatus(str, enum.Enum):
    todo = "todo"
    testing = "testing"
    confirmed = "confirmed"     # found something real here
    clear = "clear"             # checked, nothing wrong
    skipped = "skipped"


class Lead(Base):
    """A manual-testing lead: somewhere worth a human's attention.

    Stored rather than rendered once, so hunting progress survives across
    sessions — you can come back tomorrow and see what you'd already checked.
    """
    __tablename__ = "leads"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)

    area: Mapped[str] = mapped_column(Text)              # the endpoint or feature
    why: Mapped[str] = mapped_column(Text, default="")   # what makes it promising
    check: Mapped[str] = mapped_column(Text, default="") # what to examine
    vuln_class: Mapped[str] = mapped_column(String(60), default="")
    priority: Mapped[str] = mapped_column(String(10), default="medium", index=True)
    source: Mapped[str] = mapped_column(String(20), default="ai")  # ai | surface

    category: Mapped[str] = mapped_column(String(40), default="")
    deep_dive: Mapped[str] = mapped_column(Text, default="")  # on-demand richer plan

    status: Mapped[LeadStatus] = mapped_column(Enum(LeadStatus), default=LeadStatus.todo, index=True)
    notes: Mapped[str] = mapped_column(Text, default="")

    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class ChallengeStatus(str, enum.Enum):
    todo = "todo"
    working = "working"
    stuck = "stuck"
    solved = "solved"
    abandoned = "abandoned"


class Challenge(Base):
    """A CTF challenge, or a finding during the 36-hour finale.

    Deliberately separate from Finding: a Finding comes from a scanner and
    carries scope and compliance metadata; a Challenge is human work being
    tracked under time pressure, with an owner and a writeup.
    """
    __tablename__ = "challenges"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(Text)
    category: Mapped[str] = mapped_column(String(40), index=True)  # web|binary|crypto|forensics|network|drone
    points: Mapped[int] = mapped_column(Integer, default=0)

    status: Mapped[ChallengeStatus] = mapped_column(
        Enum(ChallengeStatus), default=ChallengeStatus.todo, index=True)
    assignee: Mapped[str] = mapped_column(String(80), default="")

    description: Mapped[str] = mapped_column(Text, default="")
    notes: Mapped[str] = mapped_column(Text, default="")   # working notes as you go
    flag: Mapped[str] = mapped_column(Text, default="")
    writeup: Mapped[str] = mapped_column(Text, default="")
    artifacts: Mapped[list] = mapped_column(JSON, default=list)  # filenames/URLs

    # For the finale, where findings are graded rather than flag-based.
    severity: Mapped[str] = mapped_column(String(20), default="")
    impact: Mapped[str] = mapped_column(Text, default="")

    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    solved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class ScanLog(Base):
    __tablename__ = "scan_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    level: Mapped[str] = mapped_column(String(20), default="info")
    stage: Mapped[str] = mapped_column(String(50), default="")
    message: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
