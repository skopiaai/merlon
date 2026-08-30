"""Correlation and tech-mapping tests."""

import pytest

from app import intel
from app.db import SessionLocal, init_db
from app.engines.nuclei import ALWAYS_TAGS, tags_for
from app.models import Asset, Engagement, Finding, Scan, Severity


@pytest.fixture
def scan_id():
    init_db()
    with SessionLocal() as db:
        eng = Engagement(name="t", authorized_by="me", authorization_ref="ref",
                         allow_rules=["example.com"], deny_rules=[])
        db.add(eng); db.commit(); db.refresh(eng)
        scan = Scan(engagement_id=eng.id, seeds=["example.com"], stages=["httpx"])
        db.add(scan); db.commit(); db.refresh(scan)
        return scan.id


def add(scan_id, **kw):
    defaults = dict(
        engine="test", rule_id="r", name="n", severity=Severity.low,
        host="example.com", url="https://example.com", dedupe_key=str(id(kw)),
        tags=[], cve=[], cwe=[], references=[], evidence="", raw={},
    )
    defaults.update(kw)
    with SessionLocal() as db:
        db.add(Finding(scan_id=scan_id, **defaults))
        db.commit()


# ---------------- tech -> nuclei tags ----------------

@pytest.mark.parametrize("tech,expected", [
    (["WordPress 6.4"], "wordpress"),
    (["nginx", "PHP"], "nginx"),
    (["Jenkins"], "jenkins"),
    (["Spring Boot"], "springboot"),
    (["Next.js"], "nextjs"),
])
def test_tech_maps_to_tags(tech, expected):
    assert expected in tags_for(tech)


def test_unknown_tech_yields_no_tags():
    assert tags_for(["SomeBespokeThing"]) == []


def test_tech_matching_is_case_insensitive():
    assert tags_for(["WORDPRESS"]) == tags_for(["wordpress"])


def test_always_tags_cover_high_value_classes():
    for tag in ("rce", "sqli", "ssrf", "takeover", "default-login", "exposure"):
        assert tag in ALWAYS_TAGS


# ---------------- correlation ----------------

def test_session_theft_chain(scan_id):
    add(scan_id, rule_id="insecure-cookie-sessionid",
        name="Cookie 'sessionid': missing HttpOnly", severity=Severity.high,
        dedupe_key="a")
    add(scan_id, rule_id="missing-csp", name="No Content Security Policy",
        severity=Severity.medium, dedupe_key="b")

    chains = intel.correlate(scan_id)
    ids = {c["rule_id"] for c in chains}
    assert "chain-session-theft" in ids
    chain = next(c for c in chains if c["rule_id"] == "chain-session-theft")
    assert chain["severity"] is Severity.high
    assert "account takeover" in chain["description"]


def test_no_chain_when_only_one_component(scan_id):
    add(scan_id, rule_id="missing-csp", name="No CSP", dedupe_key="only")
    assert "chain-session-theft" not in {c["rule_id"] for c in intel.correlate(scan_id)}


def test_exposed_database_is_critical(scan_id):
    add(scan_id, rule_id="exposed-service-redis",
        name="redis reachable from the internet on port 6379",
        severity=Severity.critical, dedupe_key="db")
    chain = next(c for c in intel.correlate(scan_id) if c["rule_id"] == "chain-data-exposure")
    assert chain["severity"] is Severity.critical


def test_admin_plus_version_chain(scan_id):
    add(scan_id, rule_id="exposed-surface-admin", name="Administrative surface: admin",
        severity=Severity.medium, dedupe_key="adm")
    add(scan_id, rule_id="version-disclosure-server", name="Server header reveals exact version",
        severity=Severity.low, dedupe_key="ver")
    chain = next(c for c in intel.correlate(scan_id)
                 if c["rule_id"] == "chain-admin-fingerprint")
    assert chain["severity"] is Severity.high


def test_transport_chain(scan_id):
    add(scan_id, rule_id="missing-hsts", name="HSTS not enabled", dedupe_key="h")
    add(scan_id, rule_id="insecure-cookie-sid", name="Cookie 'sid': missing Secure",
        dedupe_key="c")
    assert "chain-session-interception" in {c["rule_id"] for c in intel.correlate(scan_id)}


def test_correlation_is_deterministic(scan_id):
    add(scan_id, rule_id="insecure-cookie-sessionid",
        name="Cookie 'sessionid': missing HttpOnly", dedupe_key="a")
    add(scan_id, rule_id="missing-csp", name="No CSP", dedupe_key="b")
    first = [c["dedupe_key"] for c in intel.correlate(scan_id)]
    second = [c["dedupe_key"] for c in intel.correlate(scan_id)]
    assert first == second


def test_clean_scan_produces_no_chains(scan_id):
    assert intel.correlate(scan_id) == []


# ---------------- inventory summarisation ----------------

def test_summary_survives_empty_scan(scan_id):
    smap = intel.build_surface(scan_id)
    data = intel._summarize(scan_id, smap)
    assert data["assets"] == "  (none)"
    assert smap["total_urls"] == 0


def test_summary_includes_assets_and_surface(scan_id):
    with SessionLocal() as db:
        db.add(Asset(scan_id=scan_id, host="api.example.com",
                     url="https://api.example.com/api/v1/users/42", status_code=200,
                     title="API", tech=["nginx"]))
        db.commit()
    smap = intel.build_surface(scan_id)
    data = intel._summarize(scan_id, smap)
    assert "api.example.com" in data["assets"]
    assert "nginx" in data["tech"]
    assert "api" in data["surface"]


def test_surface_leads_generated_without_llm(scan_id):
    """The panel must be useful even with Ollama off."""
    with SessionLocal() as db:
        for url in ("https://a.example.com/checkout/order/12",
                    "https://a.example.com/api/v1/user/7",
                    "https://a.example.com/go?url=http://x"):
            db.add(Asset(scan_id=scan_id, host="a.example.com", url=url, status_code=200))
        db.commit()

    smap = intel.build_surface(scan_id)
    leads = intel._surface_leads(smap)
    assert leads, "surface map alone should produce leads"
    classes = {l["vuln_class"] for l in leads}
    assert "IDOR" in classes or "business-logic" in classes
    assert all(l["source"] == "surface" for l in leads)
    assert all(l["priority"] in ("high", "medium", "low") for l in leads)


def test_store_intel_is_idempotent(scan_id):
    data = {"summary": "s", "leads": [
        {"area": "x", "why": "w", "check": "c", "vuln_class": "IDOR", "priority": "high"},
    ]}
    assert intel.store_intel(scan_id, data) == 1
    assert intel.store_intel(scan_id, data) == 0, "re-running must not duplicate leads"
