"""Cloud bucket detection and SARIF export.

Both were gaps found by comparing against reNgine, BBOT and reconFTW: they all
check cloud storage, and none of them export a standard interchange format.
"""

import pytest

from app import sarif
from app.db import SessionLocal, init_db
from app.engines.buckets import candidate_names, classify, extract_refs
from app.models import Engagement, Finding, FindingStatus, Scan, Severity

# ------------------------------------------------------------- extraction

@pytest.mark.parametrize("html,provider,name", [
    ('<img src="https://acme-assets.s3.amazonaws.com/logo.png">', "s3", "acme-assets"),
    ('<img src="https://acme-media.s3-eu-west-1.amazonaws.com/a.jpg">', "s3", "acme-media"),
    ('<script src="https://s3.amazonaws.com/acme-static/app.js">', "s3", "acme-static"),
    ('<img src="https://storage.googleapis.com/acme-bucket/x.png">', "gcs", "acme-bucket"),
    ('<a href="https://acmefiles.blob.core.windows.net/docs">', "azure", "acmefiles"),
])
def test_bucket_references_are_extracted(html, provider, name):
    assert (provider, name) in extract_refs(html)


def test_ordinary_page_references_no_buckets():
    assert extract_refs('<img src="/static/logo.png"><a href="https://example.com">') == set()


def test_candidate_names_derive_from_domain():
    names = candidate_names("www.examplecorp.com")
    assert "examplecorp" in names
    assert "examplecorp-backup" in names
    assert "examplecorp-uploads" in names


def test_candidate_names_skip_useless_domains():
    assert candidate_names("in") == []


# ---------------------------------------------------------- classification

LISTING = """<?xml version="1.0"?>
<ListBucketResult><Name>acme-assets</Name>
<Contents><Key>backup/db-2026.sql</Key></Contents>
<Contents><Key>internal/salaries.xlsx</Key></Contents>
</ListBucketResult>"""


def test_public_listing_is_high():
    f = classify("s3", "acme-assets", 200, LISTING, "acme.com")
    assert f["rule_id"] == "bucket-public-list-s3"
    assert f["severity"] is Severity.high
    assert "rotate" in f["remediation"]


def test_unclaimed_bucket_is_high():
    body = "<Error><Code>NoSuchBucket</Code></Error>"
    f = classify("s3", "acme-old", 404, body, "acme.com")
    assert f["rule_id"] == "bucket-unclaimed-s3"
    assert f["severity"] is Severity.high
    assert "globally unique" in f["description"]


def test_private_bucket_is_informational_not_alarming():
    f = classify("s3", "acme-private", 403, "<Error><Code>AccessDenied</Code></Error>",
                 "acme.com")
    assert f["severity"] is Severity.info
    assert "correct configuration" in f["description"]


def test_unrelated_response_is_not_a_finding():
    assert classify("s3", "nope", 200, "<html>hello</html>", "acme.com") is None
    assert classify("s3", "nope", 0, "", "acme.com") is None


def test_gcs_and_azure_are_classified_too():
    for provider in ("gcs", "azure"):
        f = classify(provider, "acme", 200,
                     "<ListBucketResult><Key>x</Key></ListBucketResult>", "acme.com")
        assert f and provider in f["rule_id"]


# ------------------------------------------------------------------ SARIF

@pytest.fixture
def scan_with_findings():
    init_db()
    with SessionLocal() as db:
        eng = Engagement(name="sarif-test", authorized_by="me",
                         authorization_ref="ref", allow_rules=["example.com"],
                         deny_rules=[])
        db.add(eng); db.commit(); db.refresh(eng)
        scan = Scan(engagement_id=eng.id, seeds=["example.com"],
                    stages=["httpx", "nuclei"], profile="standard")
        db.add(scan); db.commit(); db.refresh(scan)

        rows = [
            ("missing-csp", "No Content Security Policy", Severity.medium,
             FindingStatus.new),
            ("bucket-public-list-s3", "Publicly listable S3 bucket", Severity.high,
             FindingStatus.confirmed),
            ("missing-csp", "No Content Security Policy", Severity.medium,
             FindingStatus.new),   # same rule, different host -> one rule, two results
            ("noise", "A false positive", Severity.low, FindingStatus.false_positive),
        ]
        for i, (rid, name, sev, status) in enumerate(rows):
            from app import compliance
            d = {"rule_id": rid, "tags": [], "cwe": [], "cve": []}
            compliance.enrich(d)
            db.add(Finding(
                scan_id=scan.id, engine="test", rule_id=rid, name=name, severity=sev,
                host=f"h{i}.example.com", url=f"https://h{i}.example.com/",
                description="desc", remediation="fix it", evidence="ev",
                dedupe_key=f"key{i}", status=status, compliance=d["compliance"],
                references=[], tags=[], cve=[], cwe=d["cwe"]))
        db.commit()
        return scan.id


def test_sarif_has_required_top_level_fields(scan_with_findings):
    doc = sarif.generate(scan_with_findings)
    assert doc["version"] == "2.1.0"
    assert doc["$schema"].endswith("sarif-schema-2.1.0.json")
    assert len(doc["runs"]) == 1
    assert doc["runs"][0]["tool"]["driver"]["name"]


def test_false_positives_excluded_by_default(scan_with_findings):
    results = sarif.generate(scan_with_findings)["runs"][0]["results"]
    assert all(r["properties"]["status"] != "false_positive" for r in results)
    assert len(results) == 3


def test_false_positives_can_be_included(scan_with_findings):
    doc = sarif.generate(scan_with_findings, include_false_positives=True)
    assert len(doc["runs"][0]["results"]) == 4


def test_rules_are_deduplicated_and_indexed(scan_with_findings):
    run = sarif.generate(scan_with_findings)["runs"][0]
    rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    assert len(rule_ids) == len(set(rule_ids)), "rules must be unique"
    assert len(rule_ids) == 2, "two distinct rule ids across three results"
    for result in run["results"]:
        assert run["tool"]["driver"]["rules"][result["ruleIndex"]]["id"] == result["ruleId"]


def test_severity_maps_to_sarif_levels(scan_with_findings):
    run = sarif.generate(scan_with_findings)["runs"][0]
    levels = {r["ruleId"]: r["level"] for r in run["results"]}
    assert levels["bucket-public-list-s3"] == "error"
    assert levels["missing-csp"] == "warning"


def test_security_severity_is_present_for_github(scan_with_findings):
    """GitHub sorts by security-severity, not level — without it everything
    displays as medium."""
    rules = sarif.generate(scan_with_findings)["runs"][0]["tool"]["driver"]["rules"]
    for rule in rules:
        assert float(rule["properties"]["security-severity"]) > 0


def test_compliance_travels_into_sarif(scan_with_findings):
    rules = sarif.generate(scan_with_findings)["runs"][0]["tool"]["driver"]["rules"]
    for rule in rules:
        assert rule["properties"]["owasp-top10"], f"{rule['id']} lost its OWASP mapping"
    assert any(t.startswith("OWASP:") for r in rules for t in r["properties"]["tags"])


def test_fingerprints_are_stable_across_exports(scan_with_findings):
    a = sarif.generate(scan_with_findings)["runs"][0]["results"]
    b = sarif.generate(scan_with_findings)["runs"][0]["results"]
    assert [r["partialFingerprints"] for r in a] == [r["partialFingerprints"] for r in b]


def test_every_result_has_a_location(scan_with_findings):
    for r in sarif.generate(scan_with_findings)["runs"][0]["results"]:
        loc = r["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"].startswith("http")


def test_untested_categories_are_declared(scan_with_findings):
    """A consumer must not read 'no results' as 'assessed and clean'."""
    props = sarif.generate(scan_with_findings)["runs"][0]["properties"]
    assert "A04:2021 Insecure Design" in props["notAssessed"]


def test_authorization_is_recorded_in_the_export(scan_with_findings):
    props = sarif.generate(scan_with_findings)["runs"][0]["properties"]
    assert props["authorizedBy"] == "me"
    assert props["scope"] == ["example.com"]


def test_output_is_valid_json(scan_with_findings):
    import json
    json.loads(sarif.generate_json(scan_with_findings))


def test_unknown_scan_raises(scan_with_findings):
    with pytest.raises(ValueError):
        sarif.generate(999999)
