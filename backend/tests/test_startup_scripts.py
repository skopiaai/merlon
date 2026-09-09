"""Guards against the failure mode where the launcher exits without saying why.

`start.sh` once printed "checking Docker…" and returned to the prompt. No error,
no exit message, nothing in a log. The cause was `set -e` plus a bare
`run_timeout 15 docker info` whose status was read on the *next* line — but
under `set -e` a failing untested command ends the script immediately, so the
`case $?` that handled "Docker isn't running" never ran. Every branch of that
handler was dead code the moment Docker was stopped, which is precisely when it
was needed.

Two shapes cause this, and both are easy to reintroduce because both look
correct:

  1. `cmd` followed by `case $?` / `if [ $? ... ]` — the status is consumed too
     late; the shell has already exited.
  2. `[ test ] && action` as a whole statement — when the test is false the
     statement's status is 1, so `set -e` treats a false condition as a fatal
     error. The second instance in start.sh sat on the *default* configuration
     path, meaning the common case was the broken one.

These tests read the scripts as text rather than running them, so they work in
CI with no Docker daemon present.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = sorted(
    p for p in ROOT.glob("*.sh")
) + sorted(ROOT.glob("backend/*.sh"))


def _lines(path: Path) -> list[tuple[int, str]]:
    """Numbered, comment-free, blank-free lines."""
    out = []
    for n, raw in enumerate(path.read_text().splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        out.append((n, line))
    return out


def _errexit(path: Path) -> bool:
    return bool(re.search(r"^\s*set\s+-[a-z]*e", path.read_text(), re.M))


def test_scripts_exist():
    assert SCRIPTS, "no shell scripts found — has the launcher moved?"
    assert any(p.name == "start.sh" for p in SCRIPTS)


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_syntax_is_valid(script: Path):
    """A script that cannot parse fails at line 1 with a message nobody reads."""
    r = subprocess.run(
        ["bash", "-n", str(script)], capture_output=True, text=True, timeout=30
    )
    assert r.returncode == 0, f"{script.name} does not parse:\n{r.stderr}"


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_no_deferred_status_check_under_errexit(script: Path):
    """`$?` is meaningless after a bare command when `set -e` is on.

    By the time the next line runs the shell has already exited, so any handler
    keyed off `$?` is unreachable exactly when it matters. The fix is to mark
    the command as tested — `cmd || status=$?`, or wrap it in `if` — which also
    exempts it from `set -e`.
    """
    if not _errexit(script):
        return

    lines = _lines(script)
    offenders = []
    for i, (n, line) in enumerate(lines):
        if not re.search(r"\$\?", line):
            continue
        # `foo || status=$?` and `status=$(...)` capture correctly.
        if "||" in line or line.lstrip().startswith(("trap ", "#")):
            continue
        prev = lines[i - 1][1] if i else ""
        # The previous statement must have been *tested* — part of an if/while
        # condition, or joined with && / || — otherwise set -e already killed us.
        tested = (
            prev.startswith(("if ", "while ", "until ", "elif "))
            or "||" in prev
            or "&&" in prev
            or prev.endswith(("then", "do", "{", "(", "fi", "esac", "done"))
            or prev.startswith(("local ", "return", "exit"))
            or "=" in prev.split()[0] if prev.split() else False
        )
        if not tested:
            offenders.append(f"{script.name}:{n}: reads $? after untested `{prev}`")

    assert not offenders, (
        "status read after a command that `set -e` would have already exited on:\n"
        + "\n".join(offenders)
    )


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_no_trailing_and_and_statement_under_errexit(script: Path):
    """`[ test ] && action` is safe mid-script but not in two positions.

    It is worth being exact here, because the obvious reading of `set -e` is
    wrong and it is easy to "fix" code that was never broken. A failing command
    inside an `&&` list is explicitly exempt from `set -e`, so a bare

        [ -n "$MAYBE" ] && echo hi

    in the middle of a script does *not* exit when the test is false — verified,
    not assumed. Two positions do bite, because there the list's status stops
    being discarded and becomes something else's status:

      * the last statement of a **function** — the function returns the test's
        status, and a plain function call is not exempt, so `set -e` kills the
        script at the *call site*, which is nowhere near the code at fault;
      * the last statement of the **script** — the script then exits non-zero
        after doing everything correctly, which breaks any caller (CI, a
        wrapper, `&&` in the user's own shell) that checks the status.

    An `if` block has neither problem and reads no worse.
    """
    if not _errexit(script):
        return

    lines = _lines(script)
    offenders = []
    for i, (n, line) in enumerate(lines):
        if "&&" not in line or "||" in line:
            continue
        if line.startswith(("if ", "while ", "until ", "elif ", "trap ")):
            continue
        if re.search(r"&&\s*(break|continue|return|exit)\b", line):
            continue
        # The hazard is a *test* on the left, whose falseness is routine.
        left = line.split("&&")[0].strip()
        if not re.match(r"^(\[\[?\s|test\s|!\s)", left):
            continue

        nxt = lines[i + 1][1] if i + 1 < len(lines) else None
        if nxt is None:
            offenders.append(
                f"{script.name}:{n}: last line of the script — a false test "
                f"makes a successful run exit non-zero: `{line}`"
            )
        elif nxt == "}":
            offenders.append(
                f"{script.name}:{n}: last statement of a function — a false "
                f"test aborts the script at the call site: `{line}`"
            )

    assert not offenders, (
        "`[ test ] && action` in a position where its status escapes; "
        "use an if block:\n" + "\n".join(offenders)
    )


def test_start_reports_unexpected_exits():
    """The launcher must never fail silently again.

    A trap on ERR turns "returned to the prompt with no output" — the single
    least debuggable failure a user can hit — into a line number and a status.
    """
    text = (ROOT / "start.sh").read_text()
    # The handler body spans several lines, so the signal `ERR` is not on the
    # same line as `trap` — match across the statement rather than line by line.
    assert re.search(r"\btrap\b[\s\S]{0,800}?\bERR\b", text), (
        "start.sh has no ERR trap; an unexpected exit would be silent again"
    )


def test_start_handles_docker_being_stopped():
    """Docker stopped is the most likely state on a first run, not an edge case."""
    text = (ROOT / "start.sh").read_text()
    assert "docker_status=$?" in text or "|| docker_status" in text, (
        "the Docker probe's status is not captured in a set -e-safe way"
    )
    assert "open -a Docker" in text, "the auto-start-Docker branch has gone missing"
