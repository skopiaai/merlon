"""AI-assisted JavaScript analysis.

This is the only engine that lets a model decide anything, so it is the one
place where the tool's central claim could quietly stop being true. Almost
every test here is about containing the model rather than using it.

The pattern being enforced: the model explores, deterministic code verifies.
Skipping the second half is precisely what got AI-generated vulnerability
reports banned by major programs in 2026, and a scanner that ships model output
straight into a report is indistinguishable from the tools that caused it.
"""

import pytest

from app.engines import registry
from app.engines.jsintel import (
    claim_is_grounded,
    extract_regions,
    is_vendor,
    severity_of,
    usable_claims,
)
from app.models import Severity

BUNDLE = """
function loadUser(){ return fetch('/api/me').then(r=>r.json()); }

function renderNav(user){
  if (user.role === 'admin') { showAdminPanel(); }
  const token = localStorage.getItem('auth_token');
  if (featureFlags['beta_billing']) { mountBilling(); }
}

function canDelete(user, doc){ return user.isAdmin || doc.owner === user.id; }

function render(html){ document.getElementById('out').innerHTML = html; }
"""


@pytest.fixture(autouse=True)
def _loaded():
    registry.discover(force=False)


# ============================================ what the model is allowed to see

def test_decision_points_are_extracted():
    reasons = {reason for reason, _code in extract_regions(BUNDLE)}
    assert reasons, "nothing extracted from a bundle full of auth logic"
    assert any("role" in r or "privilege" in r or "permission" in r
               for r in reasons)


def test_extracted_regions_are_verbatim_source():
    """Excerpts have to be exact, because grounding a claim later depends on
    comparing the model's snippet against this same text."""
    for _reason, code in extract_regions(BUNDLE):
        assert code in BUNDLE


def test_vendor_runtime_is_skipped():
    """A megabyte of framework internals would consume the model's context and
    produce confident nonsense about code it half-saw."""
    assert is_vendor("__webpack_require__.d = function(){}")
    assert is_vendor("/*! For license information please see vendor.js */")
    assert not is_vendor("if (user.role === 'admin') { showAdminPanel(); }")


def test_extraction_is_capped():
    """A model given a hundred excerpts answers about none of them well."""
    big = BUNDLE * 200
    assert len(extract_regions(big, cap=6)) <= 6


def test_empty_and_boring_sources_yield_nothing():
    assert extract_regions("") == []
    assert extract_regions("const a = 1 + 2; console.log(a);") == []


# ================================================ the hallucination safeguard

def test_a_claim_citing_real_code_is_kept():
    claim = {"title": "Client-side admin gate",
             "snippet": "if (user.role === 'admin') { showAdminPanel(); }"}
    assert claim_is_grounded(claim, BUNDLE)


def test_a_claim_citing_invented_code_is_rejected():
    """The core safeguard. Models produce plausible code when asked about code,
    and a confidently wrong finding is worse than no finding."""
    claim = {"title": "Hardcoded admin password",
             "snippet": "const ADMIN_PASSWORD = 'hunter2';"}
    assert not claim_is_grounded(claim, BUNDLE)


def test_reflowed_minified_code_still_counts_as_grounded():
    """Models reformat minified JavaScript in their output. That is not
    evidence of invention, so whitespace is normalised before comparing."""
    claim = {"snippet": "if (user.role === 'admin') {\n    showAdminPanel();\n}"}
    assert claim_is_grounded(claim, BUNDLE)


def test_a_trivially_short_snippet_is_not_evidence():
    """'return' appears in every file. A snippet has to be specific enough to
    point at something."""
    assert not claim_is_grounded({"snippet": "return"}, BUNDLE)
    assert not claim_is_grounded({"snippet": ""}, BUNDLE)


def test_ungrounded_claims_are_counted_not_silently_dropped():
    response = {"findings": [
        {"title": "real", "snippet": "if (user.role === 'admin') { showAdminPanel(); }"},
        {"title": "invented", "snippet": "eval(atob(window.__payload));"},
        {"title": "also invented", "snippet": "const KEY='sk_live_abcdefghijkl';"},
    ]}
    kept, rejected = usable_claims(response, BUNDLE)
    assert len(kept) == 1
    assert rejected == 2, "rejections must be counted so the log can report them"


def test_claims_without_a_title_are_rejected():
    kept, rejected = usable_claims(
        {"findings": [{"snippet": "if (user.role === 'admin') { showAdminPanel(); }"}]},
        BUNDLE)
    assert kept == [] and rejected == 1


def test_malformed_model_output_yields_nothing():
    """Every one of these is a real thing small models do."""
    assert usable_claims(None, BUNDLE) == ([], 0)
    assert usable_claims({}, BUNDLE) == ([], 0)
    assert usable_claims({"findings": "not a list"}, BUNDLE) == ([], 0)
    assert usable_claims({"findings": ["a string"]}, BUNDLE)[0] == []


def test_an_empty_answer_is_a_valid_answer():
    """The prompt says so explicitly. A model that finds nothing and says
    nothing is behaving correctly."""
    assert usable_claims({"findings": []}, BUNDLE) == ([], 0)


# ==================================================== containing the severity

def test_model_severity_is_capped_at_medium():
    """Everything here is a hypothesis about server behaviour inferred from
    client code. Letting a model hand out criticals for reading a bundle is how
    a tool stops being trusted."""
    assert severity_of({"severity": "high"}) is Severity.medium
    assert severity_of({"severity": "critical"}) is Severity.low  # unknown → low


def test_lower_severities_pass_through():
    assert severity_of({"severity": "low"}) is Severity.low
    assert severity_of({"severity": "info"}) is Severity.info


def test_missing_severity_defaults_low():
    assert severity_of({}) is Severity.low


# ================================================ containing the whole engine

def test_leads_can_never_reach_the_submit_queue():
    """A reproduction check can confirm the file is still there. It cannot
    confirm the server is missing a check — so this engine's findings are held
    for review by construction, not by scoring."""
    from app.verify import ALWAYS_REVIEW
    assert "jsintel" in ALWAYS_REVIEW


def test_engine_is_deep_only():
    """It reads whole bundles and calls a model per file. That does not belong
    in a two-minute sprint."""
    from app.schemas import DEPTH_PRESETS
    spec = registry.get("jsintel")
    assert spec is not None
    assert spec.default_in == ("deep",)
    assert "jsintel" not in DEPTH_PRESETS["sprint"][1]
    assert "jsintel" not in DEPTH_PRESETS["quick"][1]


def test_engine_degrades_without_a_model(monkeypatch):
    """No Ollama means no findings and an explanation — never a crash, and
    never a guess."""
    from app import llm

    from .conftest import run_coroutine

    async def unavailable():
        return False

    monkeypatch.setattr(llm, "available", unavailable)

    logged = []

    async def log(level, message, stage=""):
        logged.append(message)

    spec = registry.get("jsintel")
    result = run_coroutine(spec.run(["https://a.example.com/"], {"log": log}))
    assert result == []
    assert any("no local model" in m for m in logged)


def test_findings_are_tagged_for_review():
    import inspect

    from app.engines import jsintel
    source = inspect.getsource(jsintel)
    assert "needs-review" in source
    assert "ai-assisted" in source


def test_the_prompt_forbids_speculation():
    """The system prompt is part of the safety design, not decoration."""
    from app.engines.jsintel import SYSTEM
    lowered = SYSTEM.lower()
    assert "verbatim" in lowered
    assert "never speculate" in lowered
    assert "empty" in lowered, "an empty answer must be permitted explicitly"


def test_findings_map_to_a_control():
    from app import compliance
    controls = compliance.controls_for(
        {"rule_id": "js-logic-lead", "tags": [], "cwe": []})
    assert controls.owasp_top10.startswith("A01")
    assert controls.gigw != "General security"
