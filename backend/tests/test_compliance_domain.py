"""Tests for DNS/email auditing, compliance mapping and authenticated scanning."""

import pytest

from app import auth, compliance
from app.engines.domainsec import _audit_dmarc, _audit_spf, _txt_join
from app.models import Severity


# ---------------------------------------------------------------- SPF

def ids(findings):
    return {f["rule_id"] for f in findings}


def test_missing_spf_flagged():
    assert "spf-missing" in ids(_audit_spf("a.com", ["some-other-txt"]))


def test_strict_spf_is_clean():
    assert _audit_spf("a.com", ["v=spf1 include:_spf.google.com -all"]) == []


@pytest.mark.parametrize("record,rule,sev", [
    ("v=spf1 +all", "spf-permissive", Severity.high),
    ("v=spf1 ?all", "spf-neutral", Severity.medium),
    ("v=spf1 ~all", "spf-softfail", Severity.low),
])
def test_spf_policy_strength(record, rule, sev):
    found = _audit_spf("a.com", [record])
    match = next(f for f in found if f["rule_id"] == rule)
    assert match["severity"] is sev


def test_spf_lookup_limit():
    record = "v=spf1 " + " ".join(f"include:x{i}.com" for i in range(12)) + " -all"
    assert "spf-too-many-lookups" in ids(_audit_spf("a.com", [record]))


# ---------------------------------------------------------------- DMARC

def test_missing_dmarc_is_high():
    found = _audit_dmarc("a.com", [])
    assert found[0]["rule_id"] == "dmarc-missing"
    assert found[0]["severity"] is Severity.high


def test_dmarc_none_is_monitoring_only():
    found = ids(_audit_dmarc("a.com", ["v=DMARC1; p=none; rua=mailto:x@a.com"]))
    assert "dmarc-monitoring-only" in found
    assert "dmarc-missing" not in found


def test_dmarc_reject_is_clean():
    found = ids(_audit_dmarc("a.com", ["v=DMARC1; p=reject; rua=mailto:x@a.com"]))
    assert found == set()


def test_dmarc_quarantine_is_low():
    f = next(x for x in _audit_dmarc("a.com", ["v=DMARC1; p=quarantine; rua=mailto:x@a.com"])
             if x["rule_id"] == "dmarc-partial")
    assert f["severity"] is Severity.low


def test_dmarc_pct_below_100_flagged():
    found = ids(_audit_dmarc("a.com", ["v=DMARC1; p=reject; pct=20; rua=mailto:x@a.com"]))
    assert "dmarc-partial-pct" in found


def test_dmarc_without_reporting_flagged():
    assert "dmarc-no-reporting" in ids(_audit_dmarc("a.com", ["v=DMARC1; p=reject"]))


def test_txt_join_reassembles_chunked_records():
    assert _txt_join(['"v=spf1 " "include:x.com " "-all"']) == ["v=spf1 include:x.com -all"]


# ------------------------------------------------------------ compliance

def test_known_rule_maps_to_controls():
    c = compliance.controls_for({"rule_id": "missing-hsts", "tags": [], "cwe": []})
    assert c.owasp_top10.startswith("A02")
    assert "V9.1.1" in c.asvs
    assert c.iso27001 and c.gigw


def test_prefix_match_covers_generated_rule_ids():
    c = compliance.controls_for({"rule_id": "insecure-cookie-sessionid", "tags": [], "cwe": []})
    assert c.owasp_top10.startswith("A07")


def test_tag_fallback():
    c = compliance.controls_for({"rule_id": "unknown-thing", "tags": ["sqli"], "cwe": []})
    assert c.owasp_top10.startswith("A03")


def test_cwe_fallback():
    c = compliance.controls_for({"rule_id": "unknown", "tags": [], "cwe": ["CWE-918"]})
    assert c.owasp_top10.startswith("A10")


def test_nothing_is_left_unmapped():
    c = compliance.controls_for({"rule_id": "totally-unknown", "tags": [], "cwe": []})
    assert c.owasp_top10, "every finding must land in some category for the report"


def test_enrich_is_idempotent():
    f = {"rule_id": "missing-csp", "tags": [], "cwe": []}
    compliance.enrich(f)
    first = dict(f["compliance"])
    compliance.enrich(f)
    assert f["compliance"] == first
    assert len(f["cwe"]) == len(set(f["cwe"])), "no duplicate CWEs on re-enrich"


def test_coverage_matrix_counts():
    findings = [
        {"rule_id": "missing-hsts", "tags": [], "cwe": []},
        {"rule_id": "no-https", "tags": [], "cwe": []},
        {"rule_id": "missing-csp", "tags": [], "cwe": []},
    ]
    for f in findings:
        compliance.enrich(f)
    m = compliance.coverage_matrix(findings)
    assert m["owasp_top10"]["A02:2021 Cryptographic Failures"] == 2


def test_untestable_categories_declared():
    assert "A04:2021 Insecure Design" in compliance.OWASP_NOT_TESTABLE
    assert set(compliance.OWASP_NOT_TESTABLE) <= set(compliance.OWASP_TOP10_ALL)


# ------------------------------------------------------------------ auth

def test_header_args_rendering():
    assert auth.header_args({"Cookie": "a=b"}) == ["-H", "Cookie: a=b"]
    assert auth.header_args({}) == []


def test_credentials_never_leave_scope():
    """The important one: a session cookie must not reach a third-party host."""
    headers = {"Cookie": "session=secret"}
    allow, deny = ["*.example.com"], []
    assert auth.scoped_headers("https://api.example.com/x", headers, allow, deny) == headers
    assert auth.scoped_headers("https://evil.com/x", headers, allow, deny) == {}


def test_describe_does_not_leak_the_secret():
    text = auth.describe({"Cookie": "session=supersecretvalue12345"})
    assert "supersecretvalue" not in text
    assert "Cookie" in text


def test_describe_handles_no_auth():
    assert auth.describe({}) == "unauthenticated"


def test_header_injection_rejected():
    from pydantic import ValidationError

    from app.schemas import AuthConfig
    with pytest.raises(ValidationError):
        AuthConfig(headers={"Cookie": "a=b\r\nX-Evil: 1"})
    with pytest.raises(ValidationError):
        AuthConfig(headers={"Bad\nName": "x"})
