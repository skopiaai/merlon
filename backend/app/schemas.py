from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .models import ChallengeStatus, FindingStatus, LeadStatus, ScanState, Severity
from .scope import ScopeViolation, validate_rule

# Core recon stages, which have data dependencies and are wired into the
# pipeline by hand. Everything else is a registered engine — see
# app/engines/registry.py — and is added here automatically.
CORE_STAGES = [
    "subfinder",   # passive subdomain enumeration
    "permute",     # alterx permutations + dnsx resolution (active)
    "dnsx",        # DNS resolution + dangling CNAME detection
    "cdncheck",    # CDN/WAF identification (context for reading results)
    "naabu",       # port discovery
    "httpx",       # live HTTP probing + fingerprinting
    "nmap",        # service/version detection
    "tlsx",        # TLS and certificate inspection
    "ffuf",        # content discovery (noisiest stage)
    "katana",      # crawling
    "nuclei",      # template-driven detection
    "triage",      # local LLM review
]


def _valid_stages() -> list[str]:
    from .engines import registry
    return CORE_STAGES + [s for s in registry.stage_names() if s not in CORE_STAGES]


VALID_STAGES = _valid_stages()



class EngagementCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    kind: str = "bug_bounty"
    authorized_by: str = Field(min_length=1, description="Person or program that granted permission")
    authorization_ref: str = Field(min_length=1, description="Program URL, email ref, or ticket ID")
    expires_at: datetime | None = None
    allow_rules: list[str] = Field(min_length=1)
    deny_rules: list[str] = []
    notes: str = ""

    @field_validator("allow_rules", "deny_rules")
    @classmethod
    def _check_rules(cls, v: list[str]) -> list[str]:
        out = []
        for rule in v:
            try:
                out.append(validate_rule(rule))
            except ScopeViolation as exc:
                raise ValueError(str(exc)) from exc
        return out


class EngagementOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    kind: str
    authorized_by: str
    authorization_ref: str
    authorized_at: datetime
    expires_at: datetime | None
    allow_rules: list[str]
    deny_rules: list[str]
    notes: str
    auth_check_url: str
    auth_check_string: str
    created_at: datetime


class ScanCreate(BaseModel):
    engagement_id: int
    seeds: list[str] = Field(min_length=1)
    profile: str = "standard"
    stages: list[str] = ["subfinder", "naabu", "httpx", "nuclei", "triage"]

    @field_validator("profile")
    @classmethod
    def _check_profile(cls, v: str) -> str:
        if v not in ("passive", "standard", "thorough"):
            raise ValueError("profile must be passive, standard, or thorough")
        return v

    @field_validator("stages")
    @classmethod
    def _check_stages(cls, v: list[str]) -> list[str]:
        bad = set(v) - set(VALID_STAGES)
        if bad:
            raise ValueError(f"unknown stage(s): {', '.join(sorted(bad))}")
        return v


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    engagement_id: int
    seeds: list[str]
    profile: str
    stages: list[str]
    state: ScanState
    stage_current: str
    progress: float
    error: str
    stats: dict
    rejected_hosts: list
    started_at: datetime | None
    finished_at: datetime | None
    created_at: datetime


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    scan_id: int
    engine: str
    rule_id: str
    name: str
    severity: Severity
    host: str
    url: str
    description: str
    evidence: str
    remediation: str
    references: list
    tags: list
    cve: list
    cwe: list
    cvss_score: float | None
    occurrences: int
    status: FindingStatus
    triage_confidence: float | None
    triage_note: str
    analyst_note: str
    created_at: datetime


class FindingUpdate(BaseModel):
    status: FindingStatus | None = None
    analyst_note: str | None = None
    severity: Severity | None = None


class AssetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    host: str
    url: str
    ip: str
    port: int | None
    status_code: int | None
    title: str
    tech: list


class ScopeCheckRequest(BaseModel):
    engagement_id: int
    hosts: list[str]


class AuthConfig(BaseModel):
    """Credentials for authenticated scanning.

    Headers rather than a login flow: paste a session cookie or bearer token
    from your browser's developer tools. That covers almost every real case
    without the tool needing to replay a login form.
    """
    headers: dict[str, str] = Field(
        default_factory=dict,
        description='e.g. {"Cookie": "session=abc123"} or {"Authorization": "Bearer …"}')
    check_url: str = Field("", description="A page only visible when logged in")
    check_string: str = Field("", description="Text on that page proving the session works")
    identities: list["Identity"] = Field(
        default_factory=list,
        description="Additional accounts, for access-control testing")

    @field_validator("headers")
    @classmethod
    def _sane_headers(cls, v: dict[str, str]) -> dict[str, str]:
        return _check_headers(v)


def _check_headers(v: dict[str, str]) -> dict[str, str]:
    """Reject header injection.

    A newline in a header value splits the request, so a pasted value
    containing one could turn an authenticated scan into a request the operator
    never intended to send. Rejected at the boundary rather than escaped later.
    """
    for key in v:
        if not key or "\n" in key or "\r" in key:
            raise ValueError(f"invalid header name: {key!r}")
    for value in v.values():
        if "\n" in str(value) or "\r" in str(value):
            raise ValueError("header values cannot contain newlines")
    return v


class Identity(BaseModel):
    """One account the scanner can act as.

    Access control is only testable with two of these. A single session tells
    you what a logged-in user sees; two tell you whether one user can reach the
    other's data — which is the difference between finding a misconfiguration
    and finding an IDOR.
    """
    name: str = Field(min_length=1, max_length=60,
                      description="A label, e.g. 'user-b' — appears in findings")
    role: str = Field("", max_length=60,
                      description="e.g. 'standard', 'admin', 'read-only'")
    headers: dict[str, str] = Field(default_factory=dict)
    check_url: str = ""
    check_string: str = ""

    @field_validator("headers")
    @classmethod
    def _sane_headers(cls, v: dict[str, str]) -> dict[str, str]:
        return _check_headers(v)


class LeadOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    scan_id: int
    area: str
    why: str
    check: str
    vuln_class: str
    priority: str
    source: str
    category: str
    deep_dive: str
    status: LeadStatus
    notes: str
    created_at: datetime


class LeadUpdate(BaseModel):
    status: LeadStatus | None = None
    notes: str | None = None
    priority: str | None = None


class ChallengeCreate(BaseModel):
    name: str = Field(min_length=1, max_length=300)
    category: str
    points: int = 0
    description: str = ""
    assignee: str = ""

    @field_validator("category")
    @classmethod
    def _known_category(cls, v: str) -> str:
        from .ctf import category_names
        if v not in category_names():
            raise ValueError(f"category must be one of: {', '.join(category_names())}")
        return v


class ChallengeUpdate(BaseModel):
    name: str | None = None
    category: str | None = None
    points: int | None = None
    status: ChallengeStatus | None = None
    assignee: str | None = None
    description: str | None = None
    notes: str | None = None
    flag: str | None = None
    writeup: str | None = None
    severity: str | None = None
    impact: str | None = None


class ChallengeOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    category: str
    points: int
    status: ChallengeStatus
    assignee: str
    description: str
    notes: str
    flag: str
    writeup: str
    artifacts: list
    severity: str
    impact: str
    created_at: datetime
    solved_at: datetime | None


class QuickScanRequest(BaseModel):
    """One-field scan entry point.

    The engagement and scope rules are derived from the target rather than
    hand-entered — but authorization is still recorded, because that record
    is the thing that protects you if anyone ever asks why you scanned a host.
    """
    target: str = Field(min_length=3, description="Domain or URL, e.g. example.com")
    depth: str = "standard"
    include_subdomains: bool = True
    authorized: bool = Field(description="Must be true — you confirm you own or may test this")
    authorized_by: str = "self-attested (owner)"
    authorization_ref: str = ""

    @field_validator("depth")
    @classmethod
    def _check_depth(cls, v: str) -> str:
        if v not in DEPTHS:
            raise ValueError(f"depth must be one of: {', '.join(DEPTHS)}")
        return v


DEPTHS = ("sprint", "quick", "standard", "deep")

# depth -> (scan profile, pipeline stages)
# Core stage order per depth. Registered engines are appended automatically
# based on the `default_in` they declare, so a new engine joins the right
# presets without editing this table.
#
# `sprint` exists for one situation: a new program drops, or a scope list is
# published, and the first valid report wins. It runs only the engines that
# find high-severity issues quickly on a single host, with nuclei restricted to
# critical and high. It is not thorough and isn't meant to be — it answers
# "is there something here worth spending an hour on?" in about two minutes.
_CORE_PRESETS: dict[str, tuple[str, list[str]]] = {
    "sprint":   ("sprint",   ["httpx", "nuclei"]),
    "quick":    ("passive",  ["httpx", "tlsx", "nuclei", "triage"]),
    "standard": ("standard", ["subfinder", "dnsx", "cdncheck", "httpx", "tlsx",
                              "nuclei", "triage"]),
    "deep":     ("thorough", ["subfinder", "permute", "dnsx", "cdncheck", "naabu", "httpx",
                              "nmap", "tlsx", "ffuf", "katana", "nuclei", "triage"]),
}

# Engines that earn their place in a sprint: each is cheap and each can produce
# something immediately reportable on its own.
_SPRINT_ENGINES = ["takeover", "exposures", "apidocs", "secrets", "cors",
                   "wellknown", "domainsec"]


def _build_presets() -> dict[str, tuple[str, list[str]]]:
    from .engines import registry
    out: dict[str, tuple[str, list[str]]] = {}
    weights = registry.weights()

    for depth, (profile, core) in _CORE_PRESETS.items():
        if depth == "sprint":
            extras = [e for e in _SPRINT_ENGINES if registry.get(e)]
        else:
            extras = [e for e in registry.defaults_for(depth) if e not in core]

        # Cheapest first. Engines run concurrently within a phase, but their
        # results are saved as each finishes — so ordering decides what appears
        # in the findings list in the first minute versus the tenth. A takeover
        # check that costs six weight units should not be queued behind a
        # parameter miner that costs nine.
        extras.sort(key=lambda name: (weights.get(name, 5), name))

        # Engine stages run after httpx, so order them just before nuclei.
        if "nuclei" in core:
            i = core.index("nuclei")
            stages = core[:i] + extras + core[i:]
        else:
            stages = core + extras
        out[depth] = (profile, stages)
    return out


DEPTH_PRESETS: dict[str, tuple[str, list[str]]] = _build_presets()


class DecodeRequest(BaseModel):
    text: str = Field(min_length=1, max_length=200_000)
    include_caesar: bool = False


class RSARequest(BaseModel):
    """Parameters as given by the challenge. Accepts decimal or 0x-prefixed hex."""
    n: str
    e: str = "65537"
    c: str = ""
    other_n: list[str] = []

    @field_validator("n", "e", "c", mode="before")
    @classmethod
    def _to_int_str(cls, v):
        if v in (None, ""):
            return ""
        s = str(v).strip().replace("_", "").replace(" ", "")
        return str(int(s, 16)) if s.lower().startswith("0x") else s
