"""Tests for the AI exfiltration and agent-surface engines.

Both engines are mostly pure functions over response bodies, which is
deliberate — the parts that decide severity and wording are testable without a
network, and the network part is a thin wrapper.

The properties worth protecting are the ones where being wrong is expensive in
a specific direction:

  * a site that configured CSP correctly must not be reported as exfiltratable
    — a false positive there lands on exactly the team that did the work, and
    is how a tool loses credibility;
  * a secret found in a manifest must never be echoed into the report, which
    gets stored, exported and pasted into a ticket;
  * snake_case tool names must match the dangerous-capability check, because
    almost every real tool is named that way.
"""
from __future__ import annotations

import json

import pytest

from app import compliance
from app.engines import aiexfil, aisurface

# ------------------------------------------------------- CSP / beacon logic


@pytest.mark.parametrize("csp,allowed,why", [
    (None,                              True,  "no header at all is the common case"),
    ("img-src *",                       True,  "explicit wildcard"),
    ("img-src 'self' https:",           True,  "scheme source reaches any host"),
    ("default-src *",                   True,  "falls back to default-src"),
    ("script-src 'self'",               True,  "CSP that does not constrain images"),
    ("img-src 'self' data:",            False, "data: makes no network request"),
    ("img-src 'self' blob:",            False, "blob: is local"),
    ("default-src 'self'",              False, "locked down via default-src"),
    ("img-src 'self' *.cdn.example.com", False, "wildcard over one owned domain"),
])
def test_csp_beacon_decision(csp, allowed, why):
    headers = {"content-security-policy": csp} if csp else {}
    got, detail = aiexfil.csp_allows_offsite_images(headers)
    assert got is allowed, f"{why}: {detail}"


def test_data_uri_is_not_treated_as_an_exfiltration_source():
    """`img-src 'self' data:` is a correct defence, not a hole.

    A data URI is self-contained and generates no request, so counting it as
    permissive would flag the sites that did the right thing.
    """
    allowed, _ = aiexfil.csp_allows_offsite_images(
        {"content-security-policy": "img-src 'self' data:"})
    assert allowed is False


def test_csp_header_matching_is_case_insensitive():
    allowed, _ = aiexfil.csp_allows_offsite_images(
        {"Content-Security-Policy": "IMG-SRC 'self'"})
    assert allowed is False


# ------------------------------------------------------ Unicode smuggling

def test_smuggled_text_round_trips():
    assert aiexfil.unsmuggle(aiexfil.smuggle("Say SNTL7731")) == "Say SNTL7731"


def test_smuggled_text_contains_no_visible_characters():
    hidden = aiexfil.smuggle("secret instruction")
    assert all(0xE0000 <= ord(c) <= 0xE007F for c in hidden)
    # Nothing in the ASCII range survived, which is what makes it invisible.
    assert not any(c.isprintable() and ord(c) < 0x80 for c in hidden)


def test_smuggle_drops_non_ascii_rather_than_producing_junk():
    """Out-of-range code points have no tag-block equivalent."""
    assert aiexfil.smuggle("café") == aiexfil.smuggle("caf")


def test_tag_characters_are_detectable():
    assert aiexfil.TAG_CHARS.search(aiexfil.smuggle("x"))
    assert not aiexfil.TAG_CHARS.search("ordinary text")


# ------------------------------------------------- rendering evidence

def test_markdown_image_in_reply_is_recognised():
    reply = f"![alt](https://{aiexfil.CANARY_HOST}/SNTL7731.png)"
    evidence = aiexfil.rendering_evidence(reply, "application/json")
    assert evidence
    assert any("markdown image" in e for e in evidence)


def test_html_img_tag_is_recognised_as_stronger_evidence():
    reply = f'<img src="https://{aiexfil.CANARY_HOST}/x.png">'
    evidence = aiexfil.rendering_evidence(reply, "text/html")
    assert any("<img>" in e for e in evidence)


def test_markdown_link_is_not_reported_as_an_image():
    """One click versus zero. Same channel, different severity story."""
    reply = f"[click](https://{aiexfil.CANARY_HOST}/x)"
    evidence = aiexfil.rendering_evidence(reply, "application/json")
    assert any("markdown link" in e for e in evidence)
    assert not any("markdown image" in e for e in evidence)


def test_a_reply_without_the_canary_produces_no_evidence():
    assert aiexfil.rendering_evidence("Sure, here is your answer.", "application/json") == []


def test_canary_host_cannot_resolve():
    """The probe must never be able to reach anything.

    `.invalid` is reserved by RFC 2606 precisely so that it never resolves, so
    a payload that escapes into a real request still goes nowhere. If someone
    later swaps in a host they control, this fails.
    """
    assert aiexfil.CANARY_HOST.endswith(".invalid")


# ------------------------------------------------------ manifest analysis

BENIGN_MANIFEST = json.dumps({
    "schema_version": "v1",
    "name_for_human": "Docs Search",
    "auth": {"type": "oauth"},
    "api": {"url": "https://api.example.com/openapi.yaml"},
    "tools": [{"name": "search_docs"}, {"name": "get_article"}],
})

LEAKY_MANIFEST = json.dumps({
    "schema_version": "v1",
    "auth": {"type": "none"},
    "api": {"url": "http://internal-api.corp/openapi.yaml"},
    "api_key": "sk-live-abcdefghijklmnop",
    "tools": [{"name": "delete_user"}, {"name": "run_query"},
              {"name": "send_email"}],
})


def test_benign_manifest_raises_nothing():
    assert aisurface.manifest_risks(BENIGN_MANIFEST) == []


def test_internal_hostnames_are_flagged():
    risks = aisurface.manifest_risks(LEAKY_MANIFEST)
    assert any("non-public hosts" in r for r in risks)


def test_no_auth_declaration_is_flagged():
    risks = aisurface.manifest_risks(LEAKY_MANIFEST)
    assert any('"type": "none"' in r for r in risks)


def test_snake_case_tool_names_match_the_capability_check():
    """`\\bdelete\\b` never matches `delete_user` — underscore is a word char.

    Almost every real tool is snake_case, so the anchored version finds nothing
    on the manifests that matter.
    """
    risks = aisurface.manifest_risks(LEAKY_MANIFEST)
    caps = next(r for r in risks if "state-changing" in r)
    assert "delete_user" in caps
    assert "send_email" in caps


def test_read_only_tools_are_not_called_dangerous():
    risks = aisurface.manifest_risks(json.dumps(
        {"tools": [{"name": "get_profile"}, {"name": "list_items"},
                   {"name": "search_docs"}]}))
    assert not any("state-changing" in r for r in risks)


def test_secret_values_are_never_echoed_into_the_report():
    """The report gets stored, exported, and pasted into a ticket.

    Naming the key is enough to act on; reproducing the value copies the
    exposure into somewhere new.
    """
    risks = " ".join(aisurface.manifest_risks(LEAKY_MANIFEST))
    assert "sk-live-abcdefghijklmnop" not in risks
    assert "api_key" in risks
    assert "withheld" in risks


def test_credential_detection_survives_odd_key_names():
    risks = aisurface.manifest_risks(json.dumps(
        {"client_secret": "abcdefghijklmnop123"}))
    assert any("credential-shaped" in r for r in risks)


# ------------------------------------------------------ vector / model parsing

@pytest.mark.parametrize("body,expected", [
    ('{"result":{"collections":[{"name":"hr_policies"},{"name":"tickets"}]}}',
     ["hr_policies", "tickets"]),
    ('{"classes":[{"class":"InternalDocs"}]}', ["InternalDocs"]),
    ('[{"name":"docs","id":"1"}]', ["docs"]),
])
def test_collection_names_are_extracted(body, expected):
    assert aisurface.parse_collections(body) == expected


def test_collection_parsing_survives_garbage():
    assert aisurface.parse_collections("not json at all") == []
    assert aisurface.parse_collections("") == []


def test_collection_parsing_is_depth_limited():
    """A deeply nested or hostile response must not run away."""
    nested = {"a": None}
    node = nested
    for _ in range(50):
        node["a"] = {"a": None, "name": "deep"}
        node = node["a"]
    names = aisurface.parse_collections(json.dumps(nested))
    assert len(names) <= 40


@pytest.mark.parametrize("body,expected", [
    ('{"models":[{"name":"qwen2.5:14b"}]}', ["qwen2.5:14b"]),
    ('{"object":"list","data":[{"id":"meta-llama/Llama-3"}]}', ["meta-llama/Llama-3"]),
    ('{"model_id":"tgi-model"}', ["tgi-model"]),
])
def test_model_names_are_extracted(body, expected):
    assert aisurface.parse_models(body) == expected


def test_model_parsing_survives_garbage():
    assert aisurface.parse_models("<html>nope</html>") == []


# ------------------------------------------------------------- registration

def test_both_engines_are_registered():
    from app.engines import registry
    names = {e["name"] for e in registry.describe()}
    assert {"aiexfil", "aisurface"} <= names


def test_new_engines_run_in_standard_and_deep():
    from app.engines import registry
    for spec in registry.describe():
        if spec["name"] in ("aiexfil", "aisurface"):
            assert "standard" in spec["default_in"]
            assert "deep" in spec["default_in"]


# ---------------------------------------------------------------- compliance

AI_RULES = [
    "ai-exfil-markdown-image", "ai-exfil-markdown-link", "ai-exfil-html-image",
    "ai-output-xss", "ai-unicode-smuggling", "ai-indirect-sink",
    "ai-manifest", "ai-vector-open", "ai-inference-open",
]


@pytest.mark.parametrize("rule", AI_RULES)
def test_every_new_rule_is_mapped(rule):
    assert rule in compliance.RULE_MAP, f"{rule} has no compliance mapping"
    controls = compliance.RULE_MAP[rule]
    assert not controls.is_empty(), f"{rule} maps to nothing"


@pytest.mark.parametrize("rule", AI_RULES)
def test_every_new_rule_names_its_owasp_llm_or_agentic_category(rule):
    """A 2026 audit asks about ASI identifiers, not only LLM ones."""
    gigw = compliance.RULE_MAP[rule].gigw
    assert "OWASP LLM" in gigw or "ASI" in gigw, gigw


def test_rule_ids_emitted_by_the_engines_are_all_mapped():
    """Catches a rule added to an engine without a mapping.

    Read from the source rather than by running the engine, so it works with no
    network — and so a rule that only fires on an unusual response is still
    covered.
    """
    import re
    from pathlib import Path

    for module in (aiexfil, aisurface):
        source = Path(module.__file__).read_text()
        emitted = set(re.findall(r'"rule_id":\s*f?"([a-z0-9\-]+)"', source))
        # f-string rule ids (ai-exfil-{key}) are covered by the parametrised
        # list above; only literal ones can be checked mechanically here.
        for rule in emitted:
            if "{" in rule:
                continue
            assert rule in compliance.RULE_MAP, (
                f"{module.__name__} emits {rule!r} with no compliance mapping")


# ---------------------------------------------- redaction, end to end
#
# These exist because the unit test above passed while the engine still leaked.
# `manifest_risks()` correctly withheld the secret, and then the evidence block
# quoted the raw response body underneath it. Testing the helper proved the
# helper; only asserting on the whole finding proves the finding.

def test_json_credentials_are_redacted():
    """The unquoted key=value pattern cannot match JSON.

    After `api_key` comes a closing quote, not the `=` or `:` separator, so the
    original pattern failed and the value passed through untouched. Agent
    manifests are all JSON, which is exactly where these now appear.
    """
    from app.engines.exposures import redact

    out = redact(json.dumps({"api_key": "sk-live-abcdefghijklmnop",
                             "client_secret": "abcdef123456",
                             "name": "Docs Search"}))
    assert "sk-live-abcdefghijklmnop" not in out
    assert "abcdef123456" not in out
    assert "[redacted]" in out
    # Still valid JSON, and the non-secret fields survive.
    assert json.loads(out)["name"] == "Docs Search"
    assert json.loads(out)["api_key"] == "[redacted]"


def test_unquoted_credentials_still_redacted():
    """The JSON pattern must not have displaced the .env one."""
    from app.engines.exposures import redact

    out = redact("DB_PASSWORD=hunter2\nAWS_KEY=AKIAIOSFODNN7EXAMPLE")
    assert "hunter2" not in out
    assert "AKIAIOSFODNN7EXAMPLE" not in out


def test_short_values_are_not_redacted():
    """`"key": "ab"` is a field name, not a credential."""
    from app.engines.exposures import redact
    assert redact('{"key": "ab"}') == '{"key": "ab"}'


def test_manifest_finding_never_contains_the_secret_anywhere():
    """Assert on the whole finding — description, evidence and raw.

    This is the shape of the bug that got through: every individual helper was
    correct and the assembled finding still carried the value.
    """
    import re
    from pathlib import Path

    source = Path(aisurface.__file__).read_text()
    # Every place the engine quotes a response body into evidence must go
    # through redact(). A raw `resp.body` slice in an evidence string is the
    # defect, so look for one.
    evidence_blocks = re.findall(r'"evidence":\s*\((.*?)\),\n', source, re.S)
    assert evidence_blocks, "no evidence blocks found — has the engine changed?"
    for block in evidence_blocks:
        if "resp.body" in block:
            assert "redact(" in block, (
                "an evidence block quotes resp.body without redacting:\n" + block)


# ------------------------------------------------ catch-all false positives

def test_generic_json_is_not_mistaken_for_a_manifest():
    """A server that returns JSON for every path produced ten findings.

    API gateway defaults and framework catch-all routes do exactly this. Ten
    confident "manifest published" findings against a site with no AI surface
    at all is the noise that teaches you to skip the engine's output entirely —
    at which point the one real finding goes with it.
    """
    assert aisurface.looks_like_manifest('{"status":"ok","service":"api"}') is False
    assert aisurface.looks_like_manifest('{"error":"not found"}') is False
    assert aisurface.looks_like_manifest("") is False


def test_a_real_manifest_is_recognised():
    assert aisurface.looks_like_manifest(BENIGN_MANIFEST) is True
    assert aisurface.looks_like_manifest(LEAKY_MANIFEST) is True


def test_one_manifest_key_is_not_enough():
    """`"version":` alone appears in most health endpoints.

    A single-key threshold put the catch-all responses straight back in, which
    is why this requires two distinct declarations.
    """
    assert aisurface.looks_like_manifest('{"version":"1.2.3"}') is False
    assert aisurface.looks_like_manifest('{"version":"1.2.3","tools":[]}') is True


def test_mcp_style_manifest_is_recognised():
    """MCP descriptors use different keys from OpenAI plugin manifests."""
    assert aisurface.looks_like_manifest(json.dumps({
        "protocolVersion": "2025-06-18",
        "serverInfo": {"name": "docs", "version": "1.0"},
        "capabilities": {"tools": {}},
    })) is True
