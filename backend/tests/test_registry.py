"""Engine registry tests.

The registry's whole promise is that adding a detection costs one file. These
tests hold that promise: a registered engine must appear in the valid stage
list, get a progress weight, land in the right depth presets, and have its
findings mapped to a compliance control — all without anyone editing the
orchestrator, schemas or the UI.
"""

import pytest

from app import compliance
from app.engines import registry
from app.engines.secrets import scan_text
from app.models import Severity
from app.schemas import CORE_STAGES, DEPTH_PRESETS, VALID_STAGES


@pytest.fixture(autouse=True)
def _loaded():
    registry.discover(force=False)


# ------------------------------------------------------------- discovery

def test_engines_are_discovered():
    names = registry.stage_names()
    for expected in ("domainsec", "seospam", "tlsdeep", "nse", "secrets"):
        assert expected in names, f"{expected} did not register"


def test_every_engine_is_fully_described():
    for spec in registry.all_engines().values():
        assert spec.label, f"{spec.name} has no UI label"
        assert spec.description, f"{spec.name} has no description"
        assert spec.run is not None, f"{spec.name} has no run function"
        assert spec.weight > 0
        assert spec.phase in ("early", "post_http")
        assert spec.takes in ("seeds", "hosts", "urls", "assets")


def test_duplicate_registration_is_rejected():
    from app.engines.registry import EngineSpec, register
    with pytest.raises(ValueError, match="already registered"):
        @register(EngineSpec(name="seospam", label="dupe"))
        async def _dupe(targets, ctx):
            return []


# --------------------------------------------- wiring happens for free

def test_registered_engines_are_valid_stages():
    for name in registry.stage_names():
        assert name in VALID_STAGES, f"{name} is registered but not an accepted stage"


def test_core_stages_are_not_duplicated():
    assert len(VALID_STAGES) == len(set(VALID_STAGES))
    for core in CORE_STAGES:
        assert core in VALID_STAGES


def test_engines_land_in_their_declared_presets():
    for spec in registry.all_engines().values():
        for depth in spec.default_in:
            _profile, stages = DEPTH_PRESETS[depth]
            assert spec.name in stages, \
                f"{spec.name} declares default_in={spec.default_in} but is missing " \
                f"from the {depth} preset"


def test_engines_do_not_appear_in_presets_they_did_not_ask_for():
    for spec in registry.all_engines().values():
        for depth in ("quick", "standard", "deep"):
            if depth in spec.default_in:
                continue
            assert spec.name not in DEPTH_PRESETS[depth][1]


def test_engine_stages_run_before_nuclei():
    """Engines feed nuclei's target list, so ordering matters."""
    for depth, (_p, stages) in DEPTH_PRESETS.items():
        if "nuclei" not in stages:
            continue
        n = stages.index("nuclei")
        for spec in registry.all_engines().values():
            if spec.name in stages:
                assert stages.index(spec.name) < n, \
                    f"{spec.name} runs after nuclei in the {depth} preset"


def test_every_engine_has_a_progress_weight():
    weights = registry.weights()
    for name in registry.stage_names():
        assert weights.get(name, 0) > 0


def test_orchestrator_picks_up_registry_weights():
    from app.orchestrator import ScanRunner
    runner = ScanRunner(1)
    runner._plan(["httpx", "secrets", "nuclei", "triage"])
    assert "secrets" in runner._stage_plan
    i = runner._stage_plan.index("secrets")
    assert runner._weights[i] == registry.get("secrets").weight


def test_phase_filtering():
    stages = ["domainsec", "seospam", "nuclei"]
    early = {s.name for s in registry.for_phase("early", stages)}
    post = {s.name for s in registry.for_phase("post_http", stages)}
    assert early == {"domainsec"}
    assert "seospam" in post
    assert "nuclei" not in early | post, "core stages must not be treated as engines"


def test_unrequested_engines_are_not_run():
    assert registry.for_phase("post_http", ["httpx"]) == []


def test_describe_is_serialisable():
    import json
    json.dumps(registry.describe())


# ------------------------------------- the new engine, as a worked example

# Assembled rather than written out. A literal Stripe-shaped key in the
# source trips the secret scanners our own users run over this repository,
# including GitHub's push protection. The value is fake either way.
_STRIPE_KEY = "sk_" + "live_" + "0123456789abcdefghijklmnop"

SECRETS_JS = """
var cfg = {
  awsKey: "AKIAIOSFODNN7EXAMPLE",
  stripe: "__STRIPE_KEY__",
};
//# sourceMappingURL=main.js.map
""".replace("__STRIPE_KEY__", _STRIPE_KEY)


def test_new_engine_detects_credentials():
    found = scan_text(SECRETS_JS, "example.com", "https://example.com/main.js")
    rules = {f["rule_id"] for f in found}
    assert "secret-aws-access-key" in rules
    assert "secret-stripe-live-key" in rules
    assert "sourcemap-exposed" in rules


def test_credentials_are_rated_critical():
    found = scan_text(SECRETS_JS, "example.com", "https://example.com/main.js")
    aws = next(f for f in found if f["rule_id"] == "secret-aws-access-key")
    assert aws["severity"] is Severity.critical


def test_secret_values_are_redacted_in_evidence():
    """A vulnerability report shouldn't itself leak the credential."""
    found = scan_text(SECRETS_JS, "example.com", "https://example.com/main.js")
    for f in found:
        assert "AKIAIOSFODNN7EXAMPLE" not in f["evidence"]
        assert _STRIPE_KEY not in f["evidence"]


def test_clean_javascript_produces_nothing():
    assert scan_text("function add(a,b){return a+b}", "a.com", "https://a.com/x.js") == []


def test_new_engine_findings_map_to_a_control():
    """The compliance layer must cover a brand-new engine with no table entry."""
    for f in scan_text(SECRETS_JS, "example.com", "https://example.com/main.js"):
        controls = compliance.controls_for(f)
        assert controls.owasp_top10, f"{f['rule_id']} has no OWASP category"


def test_new_engine_needed_no_orchestrator_changes():
    """Regression guard for the architecture itself."""
    import inspect

    from app import orchestrator
    source = inspect.getsource(orchestrator)
    for engine in ("secrets", "seospam", "domainsec", "tlsdeep", "nse"):
        assert f"engines.{engine}" not in source and f"{engine}." not in source.replace(
            f'"{engine}"', ""), \
            f"orchestrator references {engine} directly — the registry should handle it"
