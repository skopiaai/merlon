"""Time-to-first-finding, and keeping detection content current.

Two things this file protects.

**Speed.** Not total runtime — time until something reportable appears. A scan
that finds a critical in three minutes and finishes in forty beats one that
finds the same critical at minute thirty-eight, and in a bug bounty the second
one is worth nothing because someone else already filed it. The tests here hold
the ordering decisions that produce that: urgent severities in their own nuclei
pass, cheap engines before expensive ones, and a sprint preset that does the
minimum that can still find something.

**Freshness.** Templates are the scanner. The updater's state handling has to
survive a missing file, a corrupt file and a half-finished run, because the
failure mode is silent — a stale copy scans perfectly and just doesn't find
what it doesn't know about.
"""

import json
import time

import pytest

from app.engines import registry
from .conftest import run_coroutine
from app.engines.nuclei import split_severities
from app.engines.recon import PROFILES
from app.schemas import DEPTH_PRESETS, DEPTHS, VALID_STAGES


@pytest.fixture(autouse=True)
def _loaded():
    registry.discover(force=False)


# ------------------------------------------------- urgent findings come first

def test_urgent_severities_are_split_out():
    urgent, rest = split_severities("info,low,medium,high,critical")
    assert urgent == "high,critical" or set(urgent.split(",")) == {"high", "critical"}
    assert "info" in rest and "critical" not in rest


def test_split_preserves_every_requested_severity():
    """Splitting must not silently drop a severity the caller asked for."""
    wanted = "info,low,medium,high,critical"
    urgent, rest = split_severities(wanted)
    combined = set(urgent.split(",")) | set(rest.split(","))
    assert combined == set(wanted.split(","))


def test_split_handles_urgent_only():
    urgent, rest = split_severities("critical,high")
    assert set(urgent.split(",")) == {"critical", "high"}
    assert rest == ""


def test_split_handles_no_urgent():
    urgent, rest = split_severities("info,low")
    assert urgent == ""
    assert set(rest.split(",")) == {"info", "low"}


def test_split_survives_empty_input():
    assert split_severities("") == ("", "")


# ------------------------------------------------------------ sprint preset

def test_sprint_is_a_valid_depth():
    assert "sprint" in DEPTHS
    assert "sprint" in DEPTH_PRESETS


def test_sprint_uses_its_own_profile():
    profile, _stages = DEPTH_PRESETS["sprint"]
    assert profile == "sprint"
    assert PROFILES["sprint"]["nuclei_sev"] == "critical,high"


def test_sprint_does_not_port_scan():
    """Port scanning is the single slowest thing here and finds nothing a
    sprint can act on."""
    assert PROFILES["sprint"]["ports"] is None
    _p, stages = DEPTH_PRESETS["sprint"]
    for slow in ("naabu", "nmap", "ffuf", "katana", "permute", "paramminer",
                 "vhosts", "authbypass", "netblock"):
        assert slow not in stages, f"{slow} does not belong in a sprint"


def test_sprint_still_runs_the_engines_that_pay():
    _p, stages = DEPTH_PRESETS["sprint"]
    for essential in ("takeover", "exposures", "apidocs", "secrets"):
        assert essential in stages


def test_sprint_skips_ai_triage():
    """Triage is a local LLM pass over the results — valuable, but it runs
    after everything and adds minutes to a run whose point is speed."""
    _p, stages = DEPTH_PRESETS["sprint"]
    assert "triage" not in stages


def test_every_sprint_stage_is_valid():
    _p, stages = DEPTH_PRESETS["sprint"]
    assert set(stages) <= set(VALID_STAGES)


def test_each_depth_costs_more_than_the_one_below_it():
    """Stage *count* is the wrong measure — a sprint can run more engines than
    a quick scan and still finish sooner, because the engines it runs are cheap
    and the stages it drops (port scanning, fuzzing, crawling) are not. So this
    compares the orchestrator's own cost estimate, which is what drives the
    progress bar and is the closest thing to predicted runtime."""
    from app.orchestrator import ScanRunner

    def cost(depth: str) -> int:
        runner = ScanRunner(1)
        runner._plan(DEPTH_PRESETS[depth][1])
        return runner._total_weight

    assert cost("sprint") < cost("quick") < cost("standard") < cost("deep")


# --------------------------------------------------- cheap engines run first

@pytest.mark.parametrize("depth", ["standard", "deep"])
def test_engines_are_ordered_cheapest_first(depth):
    """Engines finish independently and save as they go, so order decides what
    is on screen in minute one versus minute ten."""
    _p, stages = DEPTH_PRESETS[depth]
    weights = registry.weights()
    engine_weights = [weights[s] for s in stages if s in weights]
    assert engine_weights == sorted(engine_weights), \
        f"{depth} runs an expensive engine before a cheap one"


def test_ordering_did_not_break_the_nuclei_dependency():
    """Engines feed nuclei's target list — reordering must not put one after."""
    for depth, (_p, stages) in DEPTH_PRESETS.items():
        if "nuclei" not in stages:
            continue
        n = stages.index("nuclei")
        for name in registry.stage_names():
            if name in stages:
                assert stages.index(name) < n, \
                    f"{name} runs after nuclei in {depth}"


# ------------------------------------------------------------------ updater

def test_status_reports_never_updated_as_stale(tmp_path, monkeypatch):
    from app import updater
    monkeypatch.setattr(updater, "STATE_FILE", tmp_path / "state.json")
    monkeypatch.setattr(updater, "TEMPLATE_DIR", tmp_path / "templates")
    status = updater.status()
    assert status["stale"] is True
    assert status["last_run"] is None


def test_status_reports_fresh_after_a_run(tmp_path, monkeypatch):
    from app import updater
    state_file = tmp_path / "state.json"
    monkeypatch.setattr(updater, "STATE_FILE", state_file)
    monkeypatch.setattr(updater, "TEMPLATE_DIR", tmp_path / "templates")
    updater.save_state({"last_run": time.time(), "running": False, "sources": []})
    assert updater.status()["stale"] is False


def test_content_older_than_a_day_is_stale(tmp_path, monkeypatch):
    from app import updater
    monkeypatch.setattr(updater, "STATE_FILE", tmp_path / "state.json")
    monkeypatch.setattr(updater, "TEMPLATE_DIR", tmp_path / "templates")
    updater.save_state({"last_run": time.time() - 90_000, "running": False,
                        "sources": []})
    assert updater.status()["stale"] is True


def test_corrupt_state_file_does_not_crash(tmp_path, monkeypatch):
    """The failure mode has to be 'looks stale', never 'app won't start'."""
    from app import updater
    state_file = tmp_path / "state.json"
    state_file.write_text("{ this is not json")
    monkeypatch.setattr(updater, "STATE_FILE", state_file)
    monkeypatch.setattr(updater, "TEMPLATE_DIR", tmp_path / "templates")
    assert updater.status()["stale"] is True


def test_missing_template_dir_is_not_an_error(tmp_path, monkeypatch):
    from app import updater
    monkeypatch.setattr(updater, "STATE_FILE", tmp_path / "state.json")
    monkeypatch.setattr(updater, "TEMPLATE_DIR", tmp_path / "nope")
    assert updater.status()["template_dirs"] == []
    assert updater.extra_template_paths() == []


def test_synced_repos_become_template_paths(tmp_path, monkeypatch):
    from app import updater
    templates = tmp_path / "templates"
    (templates / "fuzzing-templates").mkdir(parents=True)
    (templates / "kenzer").mkdir()
    (templates / "takeover-fingerprints.json").write_text("[]")
    monkeypatch.setattr(updater, "TEMPLATE_DIR", templates)

    paths = updater.extra_template_paths()
    assert len(paths) == 2, "only directories are template roots"
    assert not any(p.endswith(".json") for p in paths)


def test_template_counting(tmp_path):
    from app import updater
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "one.yaml").write_text("id: one")
    (tmp_path / "a" / "two.yml").write_text("id: two")
    (tmp_path / "a" / "readme.md").write_text("not a template")
    assert updater.count_templates(tmp_path) == 2


def test_community_repositories_are_distinct_and_https():
    from app import updater
    names = [n for n, _u in updater.COMMUNITY_REPOS]
    assert len(names) == len(set(names)), "two repos would clone to one directory"
    for _name, url in updater.COMMUNITY_REPOS:
        assert url.startswith("https://"), "no unauthenticated git:// or ssh remotes"


def test_a_second_update_is_refused_while_one_runs(tmp_path, monkeypatch):
    from app import updater
    monkeypatch.setattr(updater, "STATE_FILE", tmp_path / "state.json")
    monkeypatch.setattr(updater, "TEMPLATE_DIR", tmp_path / "templates")
    updater.save_state({"last_run": None, "running": True, "sources": []})

    result = run_coroutine(updater.run_all())
    assert "already running" in result.get("detail", "")


def test_source_results_serialise(tmp_path, monkeypatch):
    """The UI reads this straight off the API — it has to be JSON."""
    from dataclasses import asdict

    from app import updater
    monkeypatch.setattr(updater, "STATE_FILE", tmp_path / "state.json")
    monkeypatch.setattr(updater, "TEMPLATE_DIR", tmp_path / "templates")
    result = updater.SourceResult(name="x", kind="templates", ok=True, items=5)
    json.dumps(asdict(result))
    updater.save_state({"last_run": time.time(), "running": False,
                        "sources": [asdict(result)]})
    json.dumps(updater.status())


# ------------------------------------------------------------------ the API

def test_update_status_endpoint():
    from fastapi.testclient import TestClient

    from app.main import app
    with TestClient(app) as client:
        response = client.get("/api/system/update")
        assert response.status_code == 200
        body = response.json()
        assert "stale" in body and "sources" in body and "auto_daily" in body


def test_sprint_depth_is_accepted_by_the_api_schema():
    from app.schemas import QuickScanRequest
    request = QuickScanRequest(target="example.com", depth="sprint", authorized=True)
    assert request.depth == "sprint"


def test_unknown_depth_is_still_rejected():
    from pydantic import ValidationError

    from app.schemas import QuickScanRequest
    with pytest.raises(ValidationError):
        QuickScanRequest(target="example.com", depth="ludicrous", authorized=True)
