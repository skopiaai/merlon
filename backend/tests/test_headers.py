"""Header/cookie audit tests.

These encode the policy the auditor enforces, so tightening or relaxing it is
a deliberate change rather than an accident.
"""

import pytest

from app.headers import audit
from app.models import Severity


def asset(url="https://example.com", headers=None, host="example.com"):
    return {"url": url, "host": host, "headers": headers or {}}


def ids(findings):
    return {f["rule_id"] for f in findings}


def by_id(findings, rule_id):
    return next(f for f in findings if f["rule_id"] == rule_id)


def test_bare_https_response_flags_the_full_set():
    found = ids(audit(asset(headers={"Content-Type": "text/html"})))
    assert {"missing-hsts", "missing-csp", "missing-xfo", "missing-nosniff",
            "missing-referrer-policy", "missing-permissions-policy"} <= found


def test_well_configured_site_is_quiet():
    found = audit(asset(headers={
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=(), microphone=()",
        "X-Frame-Options": "DENY",
    }))
    assert found == [], f"unexpected findings: {ids(found)}"


def test_plain_http_is_high():
    f = by_id(audit(asset(url="http://example.com", headers={"Server": "nginx"})), "no-https")
    assert f["severity"] is Severity.high


def test_hsts_short_max_age_flagged():
    found = ids(audit(asset(headers={"Strict-Transport-Security": "max-age=3600"})))
    assert "weak-hsts" in found
    assert "hsts-no-subdomains" in found
    assert "missing-hsts" not in found


def test_csp_unsafe_inline_flagged():
    found = audit(asset(headers={"Content-Security-Policy": "default-src 'self' 'unsafe-inline'"}))
    assert "weak-csp" in ids(found)
    assert "missing-csp" not in ids(found)


def test_csp_frame_ancestors_satisfies_clickjacking_check():
    found = ids(audit(asset(headers={"Content-Security-Policy": "frame-ancestors 'none'"})))
    assert "missing-xfo" not in found


def test_cors_wildcard_with_credentials_is_high():
    f = by_id(audit(asset(headers={
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true",
    })), "cors-wildcard-credentials")
    assert f["severity"] is Severity.high


def test_cors_wildcard_without_credentials_is_low():
    f = by_id(audit(asset(headers={"Access-Control-Allow-Origin": "*"})), "cors-wildcard")
    assert f["severity"] is Severity.low


@pytest.mark.parametrize("header,value,flagged", [
    ("Server", "nginx/1.18.0", True),
    ("Server", "nginx", False),          # no version, no finding
    ("X-Powered-By", "PHP/8.1.2", True),
])
def test_version_disclosure(header, value, flagged):
    found = ids(audit(asset(headers={header: value})))
    assert (f"version-disclosure-{header.lower()}" in found) is flagged


def test_session_cookie_without_flags_escalates_to_high():
    found = audit(asset(headers={"Set-Cookie": ["sessionid=abc123; Path=/"]}))
    cookie = next(f for f in found if f["rule_id"].startswith("insecure-cookie"))
    assert cookie["severity"] is Severity.high
    assert "HttpOnly" in cookie["remediation"]


def test_ordinary_cookie_without_flags_is_medium():
    found = audit(asset(headers={"Set-Cookie": ["theme=dark; Path=/"]}))
    cookie = next(f for f in found if f["rule_id"].startswith("insecure-cookie"))
    assert cookie["severity"] is Severity.medium


def test_fully_flagged_cookie_passes():
    found = audit(asset(headers={
        "Set-Cookie": ["sessionid=abc; Secure; HttpOnly; SameSite=Lax; Path=/"]
    }))
    assert not [f for f in found if f["rule_id"].startswith("insecure-cookie")]


def test_header_matching_is_case_insensitive():
    found = ids(audit(asset(headers={"strict-transport-security": "max-age=31536000; includeSubDomains"})))
    assert "missing-hsts" not in found


def test_no_headers_yields_nothing():
    assert audit(asset(headers={})) == []


def test_findings_have_stable_dedupe_keys():
    a = audit(asset(headers={"Content-Type": "text/html"}))
    b = audit(asset(headers={"Content-Type": "text/html"}))
    assert [f["dedupe_key"] for f in a] == [f["dedupe_key"] for f in b]
    assert len({f["dedupe_key"] for f in a}) == len(a), "keys must be unique per finding"
