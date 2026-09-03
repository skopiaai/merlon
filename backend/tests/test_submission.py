"""Submission reports and generated templates.

The last mile, and the place where a tool can most easily do harm to the person
using it. Making it one click to file an unreproducible finding would undo
every safeguard in the verification layer — acceptance rate is what decides how
fast anything else you send gets read, and programs are currently drowning in
machine-generated reports that don't reproduce.

So the tests here are mostly about refusal: a report that won't render, a
template that won't generate, and a matcher that won't be invented.
"""

import pytest

from app import submission, templategen
from app.models import Finding, Severity

VERIFICATION = {
    "confidence": 0.88,
    "reproduced": True,
    "reasons": ["reproduced: HTTP 200 at 2026-09-01T10:00:00+00:00"],
    "evidence": [{
        "method": "GET", "url": "https://app.example.com/.env",
        "status": 200,
        "request_headers": {},
        "response_headers": {"server": "nginx", "content-type": "text/plain"},
        "body_sha256": "a" * 64, "body_length": 412,
        "excerpt": "APP_KEY=[redacted]\nDB_HOST=db.internal",
        "at": "2026-09-01T10:00:00+00:00", "reproduced": True, "note": "",
    }],
}


def make(**overrides) -> Finding:
    """A finding as it exists after verification."""
    defaults = dict(
        id=1, scan_id=1, engine="exposures", rule_id="exposed-.env",
        name="Exposed file: /.env", severity=Severity.critical,
        host="app.example.com", url="https://app.example.com/.env",
        matched_at="https://app.example.com/.env",
        description="An environment file is downloadable without authentication.",
        evidence="GET /.env -> 200", remediation="Remove it and rotate every key.",
        references=["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"],
        tags=["exposure", "config"], cve=[], cwe=["CWE-530"], cvss_score=None,
        compliance={"owasp_top10": "A05:2021 Security Misconfiguration"},
        dedupe_key="k", occurrences=1,
        verify_confidence=0.88, reproduced=True, verification=VERIFICATION,
        verified_at=None, raw={},
    )
    defaults.update(overrides)
    return Finding(**defaults)


# ================================================== the refusal that matters

def test_a_finding_that_did_not_reproduce_will_not_render():
    """One click to file an unreproducible finding would undo the whole
    verification layer."""
    report = submission.render(make(reproduced=False, verify_confidence=0.2))
    assert report.ready is False
    assert "did not reproduce" in report.warning.lower()
    assert "Not ready to submit" in report.body


def test_the_refusal_says_what_to_do_next():
    body = submission.render(make(reproduced=False, verify_confidence=0.2)).body
    for expected in ("target changed", "intermittent", "never real"):
        assert expected in body, f"the refusal should name the {expected!r} case"


def test_an_unverified_finding_renders_with_a_warning():
    """Not refused — you may have verified it by hand. But not silent."""
    report = submission.render(make(verify_confidence=None, verification={}))
    assert report.ready is False
    assert "not yet verified" in report.warning.lower()
    assert report.body, "the report should still render so it can be edited"


def test_a_low_confidence_finding_warns_but_renders():
    report = submission.render(make(verify_confidence=0.5))
    assert report.ready is False
    assert "%" in report.warning


def test_a_verified_finding_is_ready():
    report = submission.render(make())
    assert report.ready is True
    assert report.warning == ""


# ============================================== the shape each platform wants

@pytest.mark.parametrize("platform,required", [
    ("hackerone", ["## Summary", "## Steps To Reproduce", "## Impact"]),
    ("bugcrowd", ["**VRT:**", "## Steps to Reproduce", "## Description"]),
    ("intigriti", ["## Description", "## Proof of concept", "## Impact"]),
    ("generic", ["## How to reproduce", "## How to fix it"]),
])
def test_each_platform_gets_its_own_sections(platform, required):
    """A good finding in the wrong shape gets bounced for 'more information'
    and loses a week."""
    body = submission.render(make(), platform).body
    for heading in required:
        assert heading in body, f"{platform} report missing {heading!r}"


def test_an_unknown_platform_falls_back_rather_than_failing():
    report = submission.render(make(), "somewhere-else")
    assert report.platform == "generic"
    assert report.body


def test_bugcrowd_gets_a_vrt_category():
    """VRT drives the payout band, so it belongs at the top."""
    body = submission.render(make(), "bugcrowd").body
    assert "Sensitive Data Exposure" in body


def test_vrt_falls_back_for_unmapped_rules():
    assert submission.vrt_for("something-nobody-mapped") == "Other"


def test_title_leads_with_the_asset():
    """Triage queues are scanned by asset. A title starting with the class
    makes every report look the same."""
    assert submission.title_for(make()).startswith("[app.example.com]")


# ================================================ evidence, not invention

def test_reproduction_steps_come_from_captured_evidence():
    body = submission.render(make(), "hackerone").body
    assert "GET https://app.example.com/.env" in body
    assert "HTTP 200" in body
    assert "2026-09-01" in body
    assert "sha256" in body


def test_steps_fall_back_to_raw_evidence_when_unverified():
    body = submission.render(make(verify_confidence=None, verification={})).body
    assert "GET /.env -> 200" in body


def test_no_model_is_involved():
    """A report is a rendering problem. Generated reports are what programs are
    currently drowning in.

    Checked by import rather than by substring — the first version of this test
    searched for "llm" and matched the `llm-prompt-injection` VRT key, which is
    a mapping table entry rather than a call.
    """
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(submission))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)

    assert "llm" not in imported, "the submission path must not call a model"
    assert not any(m in imported for m in ("openai", "anthropic", "httpx"))


def test_kev_context_is_included_when_present():
    finding = make(raw={"kev": [{"cve": "CVE-2021-44228", "added": "2021-12-10",
                                 "due": "2021-12-24", "ransomware": True}]})
    body = submission.render(finding, "hackerone").body
    assert "CVE-2021-44228" in body
    assert "ransomware" in body.lower()
    assert "2021-12-24" in body


def test_kev_section_is_absent_otherwise():
    assert "Actively exploited" not in submission.render(make()).body


def test_the_suggested_cvss_vector_is_marked_as_a_starting_point():
    """Pasting a vector you haven't read is how a report gets its severity
    argued down."""
    body = submission.render(make(), "hackerone").body
    assert "CVSS:3.1" in body
    assert "starting point" in body


def test_report_serialises_for_the_api():
    import json
    json.dumps(submission.render(make(), "hackerone").as_dict())


# ==================================================== template generation

def test_a_template_is_generated_from_a_verified_finding():
    name, yaml_text = templategen.generate(make())
    assert name.endswith(".yaml")
    assert "id: exposures-exposed-env" in yaml_text
    assert "severity: critical" in yaml_text


def test_the_generated_template_is_valid_yaml():
    import yaml
    _name, text = templategen.generate(make())
    doc = yaml.safe_load(text)
    assert doc["id"]
    assert doc["info"]["name"]
    assert doc["http"][0]["matchers"]


@pytest.mark.parametrize("hostile_name", [
    'Exposed file: "quoted"',
    "Exposed: value: with: colons",
    "Exposed file: #hash and | pipe",
    "Exposed\\backslash and 'single quotes'",
    "Exposed {braces} [brackets] & ampersand",
    "Exposed *asterisk and >angle",
])
def test_arbitrary_finding_text_still_produces_valid_yaml(hostile_name):
    """A finding's name and description are arbitrary text from a scanned
    site, and arbitrary text is exactly what breaks hand-built YAML. Handing
    someone a file nuclei refuses to load wastes their time and looks like
    their mistake."""
    import yaml
    _name, text = templategen.generate(make(name=hostile_name))
    doc = yaml.safe_load(text)
    assert doc["info"]["name"] == hostile_name


def test_a_multiline_description_survives():
    description = "Line one.\n\nLine two: with a colon.\n  - and a list item"
    import yaml
    _name, text = templategen.generate(make(description=description))
    assert yaml.safe_load(text)["info"]["description"]


def test_malformed_output_is_raised_rather_than_delivered():
    """If the generator ever emits something unparseable, that is its bug and
    the user should never receive the file."""
    with pytest.raises(ValueError, match="not valid YAML|missing required"):
        templategen.validate("id: x\n  bad: [unclosed\n")


def test_validation_rejects_a_template_missing_its_essentials():
    with pytest.raises(ValueError, match="missing required"):
        templategen.validate("info:\n  name: only info\n")


def test_the_template_carries_the_observed_status():
    _name, text = templategen.generate(make())
    assert "- 200" in text


def test_the_template_path_comes_from_the_finding():
    _name, text = templategen.generate(make())
    assert "{{BaseURL}}/.env" in text


def test_a_template_is_refused_for_an_unreproduced_finding():
    """It would fire on every future scan and never be right, which eventually
    trains you to ignore its output — and everything near it."""
    with pytest.raises(ValueError, match="did not reproduce"):
        templategen.generate(make(reproduced=False, verify_confidence=0.1))


def test_a_template_is_refused_without_evidence():
    with pytest.raises(ValueError, match="no verification evidence"):
        templategen.generate(make(verification={}, verify_confidence=None))


def test_matchers_are_never_invented():
    assert templategen.usable_matchers(make(verification={})) == []


def test_target_specific_strings_are_kept_out_of_matchers():
    """A matcher containing this target's hostname looks like a working check
    and silently matches nothing anywhere else."""
    verification = {
        "evidence": [{
            "reproduced": True, "status": 200,
            "response_headers": {"server": "nginx"},
            "excerpt": "Welcome to app.example.com dashboard\nGeneric error page",
            "body_length": 100, "body_sha256": "b" * 64, "at": "x",
            "method": "GET", "url": "https://app.example.com/",
        }]
    }
    matchers = templategen.usable_matchers(make(verification=verification))
    body_words = [w for m in matchers if m.get("part") == "body"
                  for w in m.get("words", [])]
    assert not any("app.example.com" in w for w in body_words)


def test_dates_and_hashes_are_kept_out_of_matchers():
    verification = {
        "evidence": [{
            "reproduced": True, "status": 200, "response_headers": {},
            "excerpt": "Generated on 2026-09-01\nsession a1b2c3d4e5f60718293a4b5c",
            "body_length": 50, "body_sha256": "c" * 64, "at": "x",
            "method": "GET", "url": "https://a.example.com/",
        }]
    }
    matchers = templategen.usable_matchers(make(verification=verification))
    words = [w for m in matchers for w in m.get("words", [])]
    assert not any("2026-09-01" in w for w in words)
    assert not any("a1b2c3d4e5f6" in w for w in words)


def test_the_template_warns_that_it_is_a_starting_point():
    """Templates from a single observation tend to be over-specific, and the
    person running it later has no way to know that unless the file says so."""
    _name, text = templategen.generate(make())
    assert "starting point" in text
    assert "over-specific" in text


def test_template_ids_are_filename_safe():
    finding = make(rule_id="exposed-/.git/config", engine="exposures")
    name, _text = templategen.generate(finding)
    assert "/" not in name
    assert name.replace(".yaml", "").replace("-", "").isalnum()


def test_tags_exclude_anything_that_is_not_a_tag():
    finding = make(tags=["exposure", "Critical Compromise!", "config"])
    _name, text = templategen.generate(finding)
    tag_line = next(ln for ln in text.splitlines() if ln.startswith("  tags:"))
    assert "Critical Compromise!" not in tag_line
    assert "exposure" in tag_line
