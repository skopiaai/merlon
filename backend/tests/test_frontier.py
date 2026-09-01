"""Post-quantum readiness, client-side supply chain, archived leaks, KEV.

Four things that became relevant in 2026 and share a property: **the exposure
already happened, and patching does not undo it.**

Traffic recorded today under classical key exchange is decryptable later. A
script host that lapsed is claimable now. An email address in a URL the
Internet Archive stored is public permanently. And a CVE on CISA's
actively-exploited list is not a hypothetical — someone is using it while you
read the report.

Most of the tests below are about *not* over-claiming, because each of these
classes has an obvious wrong version: flagging every RSA certificate, flagging
every third-party script, reporting every archived `?code=` as a leaked token,
or treating KEV membership as automatic criticality.
"""

import json

import pytest

from app import kev
from app.engines import registry
from app.engines.archiveleaks import group_leaks, leaks_in_url, mask
from app.engines.pqc import (negotiated_group, supports_pq_keyexchange,
                             tls_version, uses_pq_certificate)
from app.engines.supplychain import (external_scripts, is_outdated,
                                     parse_version, script_hosts)


@pytest.fixture(autouse=True)
def _loaded():
    registry.discover(force=False)


# ================================================== post-quantum readiness

PQ_HANDSHAKE = """
Connecting to 203.0.113.1
CONNECTION ESTABLISHED
Protocol  : TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Negotiated TLS1.3 group: X25519MLKEM768
Verification: OK
"""

CLASSICAL_HANDSHAKE = """
CONNECTION ESTABLISHED
Protocol  : TLSv1.3
Ciphersuite: TLS_AES_128_GCM_SHA256
Negotiated TLS1.3 group: x25519
Verification: OK
"""


def test_hybrid_key_agreement_is_recognised():
    assert supports_pq_keyexchange(PQ_HANDSHAKE)


@pytest.mark.parametrize("group", [
    "X25519MLKEM768", "SecP256r1MLKEM768", "X25519Kyber768", "MLKEM1024",
])
def test_every_deployed_hybrid_group_is_known(group):
    assert supports_pq_keyexchange(f"Negotiated TLS1.3 group: {group}")


def test_classical_key_agreement_is_not_mistaken_for_hybrid():
    assert not supports_pq_keyexchange(CLASSICAL_HANDSHAKE)
    assert not supports_pq_keyexchange("")


def test_handshake_details_are_extracted_for_the_report():
    assert negotiated_group(PQ_HANDSHAKE) == "X25519MLKEM768"
    assert tls_version(PQ_HANDSHAKE) == "TLSv1.3"


def test_a_classical_certificate_is_not_reported_as_a_defect():
    """Signatures stay classical for years and that is fine — forging one has
    to happen live, so recorded traffic doesn't help. Flagging every RSA
    certificate on the internet would be pure noise."""
    assert not uses_pq_certificate(CLASSICAL_HANDSHAKE)
    import inspect

    from app.engines import pqc
    source = inspect.getsource(pqc)
    # There must be exactly one rule for "not ready", and it must be about key
    # exchange rather than about the certificate.
    assert "pqc-not-ready" in source
    assert "pqc-certificate-weak" not in source


def test_readiness_is_reported_as_information_not_a_problem():
    spec = registry.get("pqc")
    assert spec is not None
    import inspect
    source = inspect.getsource(__import__("app.engines.pqc", fromlist=["x"]))
    assert "pqc-ready" in source, "compliance evidence belongs in the report too"


# ============================================== client-side supply chain

PAGE = """
<html><head>
  <script src="https://cdn.jsdelivr.net/npm/jquery@3.4.1/dist/jquery.min.js"></script>
  <script src="https://tags.deadvendor.test/analytics.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.10/lodash.min.js"
          integrity="sha384-abc" crossorigin="anonymous"></script>
  <script src="/local/app.js"></script>
  <link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Inter">
</head><body></body></html>
"""


def test_only_off_origin_scripts_are_considered():
    """SRI on your own assets is defence in depth; the supply chain question is
    about code you don't control."""
    scripts = external_scripts(PAGE, "https://site.example.com/")
    urls = [u for u, _t, _s in scripts]
    assert not any("/local/app.js" in u for u in urls)
    assert any("jsdelivr" in u for u in urls)


def test_stylesheets_count_too():
    scripts = external_scripts(PAGE, "https://site.example.com/")
    assert any("fonts.googleapis.com" in u for u, _t, _s in scripts)


def test_integrity_attribute_is_detected():
    scripts = external_scripts(PAGE, "https://site.example.com/")
    protected = [u for u, _t, sri in scripts if sri]
    assert len(protected) == 1
    assert "lodash" in protected[0]


def test_relative_sources_resolve_against_the_page():
    scripts = external_scripts(
        '<script src="//other.example.net/x.js"></script>',
        "https://site.example.com/page")
    assert scripts[0][0].startswith("https://other.example.net/")


def test_data_urls_are_ignored():
    assert external_scripts('<script src="data:text/javascript,void(0)"></script>',
                            "https://a.example.com/") == []


def test_script_hosts_are_deduplicated():
    hosts = script_hosts(external_scripts(PAGE, "https://site.example.com/"))
    assert len(hosts) == len(set(hosts))
    assert "tags.deadvendor.test" in hosts


# ------------------------------------------------------ library versions

@pytest.mark.parametrize("url,library,version", [
    ("https://cdn.example.com/jquery-1.11.3.min.js", "jquery", (1, 11, 3)),
    ("https://cdn.jsdelivr.net/npm/jquery@3.4.1/dist/jquery.min.js", "jquery", (3, 4, 1)),
    ("https://x.example.com/libs/lodash/4.17.10/lodash.min.js", "lodash", (4, 17, 10)),
    ("https://x.example.com/angular.1.6.9.js", "angular", (1, 6, 9)),
])
def test_library_versions_are_parsed(url, library, version):
    parsed = parse_version(url)
    assert parsed == (library, version)


def test_unversioned_scripts_are_not_guessed_at():
    assert parse_version("https://cdn.example.com/app.min.js") is None
    assert parse_version("") is None


def test_old_versions_are_flagged():
    assert is_outdated("jquery", (1, 11, 3))
    assert is_outdated("lodash", (4, 17, 10))


def test_current_versions_are_not_flagged():
    assert not is_outdated("jquery", (3, 7, 1))
    assert not is_outdated("lodash", (4, 17, 21))


def test_unknown_libraries_are_never_flagged():
    """A library with no known floor must not be reported as outdated just for
    being old."""
    assert not is_outdated("somelib", (0, 1, 0))


def test_two_part_versions_compare_correctly():
    assert is_outdated("jquery", (1, 11))
    assert not is_outdated("jquery", (3, 6))


# ==================================================== archived URL leaks

def test_email_in_a_query_parameter_is_found():
    leaks = leaks_in_url("https://a.example.com/sub?email=alice@example.com&plan=pro")
    assert ("email", "email", "alice@example.com") in leaks


def test_email_in_the_path_is_found():
    leaks = leaks_in_url("https://a.example.com/users/bob@example.com/invoice")
    assert any(kind == "email" for kind, _p, _v in leaks)


def test_a_real_token_is_found():
    url = "https://a.example.com/reset?token=a1b2c3d4e5f60718293a4b5c6d7e8f90abcd1234"
    assert any(kind == "credential" for kind, _p, _v in leaks_in_url(url))


def test_jwts_are_found():
    url = ("https://a.example.com/x?access_token="
           "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghij")
    assert any(kind == "credential" for kind, _p, _v in leaks_in_url(url))


def test_presigned_storage_urls_are_found():
    url = ("https://bucket.s3.amazonaws.com/report.pdf?X-Amz-Signature="
           "abc123def456&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE")
    assert any(kind == "presigned-url" for kind, _p, _v in leaks_in_url(url))


def test_a_short_code_is_not_reported_as_a_credential():
    """`?code=IN` is a country code. Requiring a credential-shaped value is
    what stops this engine reporting every archived URL on the internet."""
    assert leaks_in_url("https://a.example.com/x?code=IN&lang=en") == []
    assert leaks_in_url("https://a.example.com/p?key=hero&id=4") == []


def test_ordinary_urls_produce_nothing():
    assert leaks_in_url("https://a.example.com/about") == []
    assert leaks_in_url("https://a.example.com/search?q=laptop&page=2") == []
    assert leaks_in_url("") == []


def test_utm_parameters_are_not_leaks():
    assert leaks_in_url(
        "https://a.example.com/?utm_source=newsletter&utm_campaign=spring") == []


def test_leaks_group_by_class_not_by_url():
    """Three thousand URLs each carrying one customer's email is one finding
    about a broken pattern. Reporting it per-URL is what machine-generated
    noise looks like."""
    urls = [f"https://a.example.com/s?email=user{i}@example.com" for i in range(50)]
    grouped = group_leaks(urls)
    assert set(grouped) == {"email"}
    assert len(grouped["email"]) == 50


def test_repeated_values_are_counted_once():
    urls = ["https://a.example.com/s?email=same@example.com"] * 10
    assert len(group_leaks(urls)["email"]) == 1


# --------------------------------------------------------- redaction

def test_emails_are_masked():
    masked = mask("alice.smith@example.com")
    assert "alice.smith" not in masked
    assert "@example.com" in masked, "the domain is what makes it confirmable"


def test_tokens_are_masked_but_identifiable():
    masked = mask("a1b2c3d4e5f60718293a4b5c6d7e8f90")
    assert "a1b2c3d4e5f60718293a4b5c6d7e8f90" not in masked
    assert "32 chars" in masked


def test_the_report_never_contains_the_raw_value():
    import inspect

    from app.engines import archiveleaks
    source = inspect.getsource(archiveleaks)
    # Every place a value reaches evidence or raw must go through mask().
    assert "mask(value)" in source
    assert "mask(v) for" in source, "stored samples must be masked too"


# ============================================================== CISA KEV

CATALOG = json.dumps({
    "vulnerabilities": [
        {"cveID": "CVE-2021-44228", "vendorProject": "Apache",
         "product": "Log4j2", "vulnerabilityName": "Log4Shell",
         "dateAdded": "2021-12-10", "dueDate": "2021-12-24",
         "knownRansomwareCampaignUse": "Known",
         "requiredAction": "Apply updates."},
        {"cveID": "CVE-2023-1234", "vendorProject": "Example",
         "product": "Thing", "vulnerabilityName": "Example flaw",
         "dateAdded": "2023-05-01", "dueDate": "2023-05-22",
         "knownRansomwareCampaignUse": "Unknown"},
    ]
})


def test_catalog_parses():
    catalog = kev.parse_catalog(CATALOG)
    assert "CVE-2021-44228" in catalog
    assert catalog["CVE-2021-44228"]["ransomware"] is True
    assert catalog["CVE-2023-1234"]["ransomware"] is False


def test_catalog_survives_junk():
    assert kev.parse_catalog("not json") == {}
    assert kev.parse_catalog("") == {}
    assert kev.parse_catalog('{"vulnerabilities": "nope"}') == {}


def test_malformed_cve_ids_are_dropped():
    body = json.dumps({"vulnerabilities": [{"cveID": "not-a-cve"}]})
    assert kev.parse_catalog(body) == {}


def test_severity_is_raised_one_level_not_to_critical():
    """KEV means 'someone is using this', not 'this is catastrophic here'.
    Jumping everything to critical would make the flag meaningless."""
    assert kev.escalate("medium") == "high"
    assert kev.escalate("low") == "medium"
    assert kev.escalate("critical") == "critical"


def test_escalation_preserves_the_enum_type():
    """Findings carry a Severity enum into the ORM; handing it a raw string for
    an Enum column is a runtime error, not a coercion."""
    from app.models import Severity
    raised = kev.escalate(Severity.medium)
    assert isinstance(raised, Severity)
    assert raised is Severity.high


def test_unknown_severity_is_left_alone():
    assert kev.escalate("bogus") == "bogus"


def test_applying_kev_enriches_without_breaking_the_orm(monkeypatch):
    """The finding dict is passed to the model as keyword arguments, so an
    unexpected top-level key raises instead of being ignored."""
    from app.models import Finding, Severity

    monkeypatch.setattr(kev, "load", lambda: kev.parse_catalog(CATALOG))

    finding = {"severity": Severity.medium, "cve": ["CVE-2021-44228"],
               "tags": [], "description": "Something.", "raw": {}}
    entries = kev.apply(finding)

    assert entries
    assert finding["severity"] is Severity.high
    assert "actively-exploited" in finding["tags"]
    assert "ransomware" in finding["tags"]
    assert "Log4Shell" in finding["description"]
    assert finding["raw"]["kev"]

    columns = {c.name for c in Finding.__table__.columns}
    assert set(finding) <= columns | {"dedupe_key"}, \
        "kev.apply added a key the Finding model has no column for"


def test_applying_twice_does_not_escalate_twice(monkeypatch):
    from app.models import Severity
    monkeypatch.setattr(kev, "load", lambda: kev.parse_catalog(CATALOG))

    finding = {"severity": Severity.medium, "cve": ["CVE-2021-44228"],
               "tags": [], "description": "x", "raw": {}}
    kev.apply(finding)
    kev.apply(finding)
    assert finding["severity"] is Severity.high


def test_findings_without_a_known_cve_are_untouched(monkeypatch):
    from app.models import Severity
    monkeypatch.setattr(kev, "load", lambda: kev.parse_catalog(CATALOG))

    finding = {"severity": Severity.low, "cve": ["CVE-2099-9999"], "tags": [],
               "description": "x", "raw": {}}
    assert kev.apply(finding) == []
    assert finding["severity"] is Severity.low
    assert finding["tags"] == []


def test_a_missing_catalog_degrades_to_no_enrichment(monkeypatch, tmp_path):
    """Absent data must never produce a wrong answer."""
    monkeypatch.setattr(kev, "KEV_FILE", tmp_path / "absent.json")
    monkeypatch.setattr(kev, "_CACHE", None)
    assert kev.load() == {}
    assert kev.lookup(["CVE-2021-44228"]) == []


def test_the_report_note_is_written_for_a_decision_maker():
    note = kev.note(list(kev.parse_catalog(CATALOG).values()))
    assert "Actively exploited" in note
    assert "ransomware" in note.lower()
    assert "2021-12-24" in note, "the federal deadline is the persuasive part"


# ================================================ registration and mapping

NEW_ENGINES = ["pqc", "supplychain", "archiveleaks"]


@pytest.mark.parametrize("name", NEW_ENGINES)
def test_engine_is_registered_and_wired(name):
    from app.schemas import DEPTH_PRESETS, VALID_STAGES
    spec = registry.get(name)
    assert spec is not None, f"{name} did not register"
    assert name in VALID_STAGES
    for depth in spec.default_in:
        assert name in DEPTH_PRESETS[depth][1]


@pytest.mark.parametrize("rule", [
    "pqc-not-ready", "pqc-ready", "dangling-script-host", "missing-sri",
    "outdated-js-library", "archive-leak-email", "archive-leak-credential",
    "archive-leak-national-id",
])
def test_new_rules_map_to_a_real_control(rule):
    from app import compliance
    controls = compliance.controls_for({"rule_id": rule, "tags": [], "cwe": []})
    assert controls.owasp_top10
    assert controls.gigw != "General security", f"{rule} hit the catch-all"


def test_archive_leaks_run_in_the_quick_preset():
    """Passive, fast, and among the highest-yield checks available — it reads a
    third-party index and never touches the target."""
    from app.schemas import DEPTH_PRESETS
    assert "archiveleaks" in DEPTH_PRESETS["quick"][1]
