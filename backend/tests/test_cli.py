"""The headless CLI, and the severity gate the GitHub Action depends on.

The gate lives here rather than in the workflow because logic inside a YAML
file is logic nobody can test — and a build gate that silently stops gating is
worse than no gate at all.
"""

import json

import pytest

from app import cli


def f(severity, tier=None):
    return {"severity": severity, "tier": tier}


# ---------------------------------------------------------------- the gate

def test_severity_is_ordered_not_matched():
    findings = [f("critical"), f("high"), f("medium"), f("low"), f("info")]
    assert cli.count_breaching(findings, "critical") == 1
    assert cli.count_breaching(findings, "high") == 2      # critical + high
    assert cli.count_breaching(findings, "medium") == 3
    assert cli.count_breaching(findings, "info") == 5


def test_never_gates_nothing():
    assert cli.count_breaching([f("critical")], "never") == 0


def test_a_typo_does_not_disable_the_gate():
    """An unknown threshold must fall back to 'high', never to passing."""
    assert cli.count_breaching([f("critical"), f("high")], "hgih") == 2
    assert cli.count_breaching([f("low")], "nonsense") == 0


def test_only_proven_ignores_inferred_findings():
    findings = [f("critical", "proven"), f("critical", "reproduced"),
                f("high", None)]
    assert cli.count_breaching(findings, "high") == 3
    assert cli.count_breaching(findings, "high", only_proven=True) == 1


def test_missing_severity_is_treated_as_info():
    assert cli.count_breaching([{}], "info") == 1
    assert cli.count_breaching([{}], "critical") == 0


def test_empty_is_zero():
    assert cli.count_breaching([], "info") == 0


# ---------------------------------------------------------------- parser

def test_parser_requires_target():
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["scan"])


def test_parser_defaults():
    a = cli.build_parser().parse_args(["scan", "--target", "x.com"])
    assert a.authorized is False      # must be opted into explicitly
    assert a.depth == "standard"
    assert a.fail_on is None          # no gate unless asked for
    assert a.only_proven is False


def test_parser_accepts_the_gate_flags():
    a = cli.build_parser().parse_args(
        ["scan", "--target", "x.com", "--authorized",
         "--fail-on", "critical", "--only-proven"])
    assert a.authorized and a.fail_on == "critical" and a.only_proven


# ---------------------------------------------------------------- refusals

def test_scan_refuses_without_authorization(tmp_path, capsys):
    rc = cli.main(["scan", "--target", "example.com",
                   "--json", str(tmp_path / "r.json")])
    assert rc == 2
    assert "Refused" in capsys.readouterr().err
    assert not (tmp_path / "r.json").exists(), "no report for a refused scan"


def test_scan_refuses_an_unreadable_target(capsys):
    rc = cli.main(["scan", "--target", "..", "--authorized"])
    assert rc == 2
    assert "could not read that as a domain" in capsys.readouterr().err


# ---------------------------------------------------------------- report

def test_report_is_written_and_gates(tmp_path, monkeypatch, capsys):
    """Drive cmd_scan with the pipeline stubbed out, so this stays offline."""
    from app.db import SessionLocal, init_db
    from app.models import Finding, Severity
    init_db()

    async def fake_run(scan_id, *, verify):
        with SessionLocal() as db:
            db.add(Finding(scan_id=scan_id, engine="sqli", rule_id="sqli-error",
                           name="SQL injection", severity=Severity.critical,
                           host="ex.com", dedupe_key=f"k{scan_id}",
                           verification={"tier": "proven", "confidence": 1.0,
                                         "submittable": True}))
            db.commit()

    monkeypatch.setattr(cli, "_run_scan", fake_run)
    out = tmp_path / "r.json"

    rc = cli.main(["scan", "--target", "example.com", "--authorized",
                   "--json", str(out), "--fail-on", "high"])
    report = json.loads(out.read_text())
    assert report["target"] == "example.com"
    assert len(report["findings"]) == 1
    hit = report["findings"][0]
    assert hit["tier"] == "proven" and hit["severity"] == "critical"
    assert rc == 1, "a critical finding must fail a --fail-on high gate"

    # ...and the same scan gates clean when nothing is asked of it.
    rc = cli.main(["scan", "--target", "example.com", "--authorized",
                   "--json", str(out)])
    assert rc == 0, "without --fail-on the CLI reports but never fails"
