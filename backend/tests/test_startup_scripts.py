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


# ------------------------------------------------- rename: container names
#
# `container_name:` is a global Docker name, not project-scoped. Pinning the
# compose project name did not change it, so the first upgrade run collided
# with the containers the previous name had created:
#
#   Conflict. The container name "/bbwebapp-backend" is already in use
#
# Renaming them is only half the fix — the old containers still hold ports 8000
# and 5173, so start.sh has to remove them. These tests keep the two lists in
# agreement, because a container renamed in compose but not added to the
# cleanup list reintroduces the same failure for the next person upgrading.

def _compose() -> dict:
    import yaml
    return yaml.safe_load((ROOT / "docker-compose.yml").read_text())


def test_compose_pins_the_project_name():
    """Without this the project name comes from the checkout directory, so two
    people with differently-named folders get differently-named volumes."""
    assert _compose().get("name") == "merlon"


# Every name this project has shipped under, newest first. `start.sh` must
# clean up all of them: the containers from the *previous* generation are the
# ones actually running on a machine that upgraded last time, and those are
# what hold ports 8000 and 5173.
PREVIOUS_GENERATIONS = ["parapet", "bbwebapp"]


def test_container_names_carry_the_current_brand():
    for service, spec in _compose()["services"].items():
        name = spec.get("container_name")
        if name:
            assert name.startswith("merlon-"), (
                f"service {service} still uses the pre-rename container name {name!r}")


def test_startup_removes_every_pre_rename_container():
    """Each renamed container must appear in start.sh's cleanup list."""
    import re

    start = (ROOT / "start.sh").read_text()
    match = re.search(r'LEGACY_CONTAINERS="([^"]+)"', start)
    assert match, "start.sh no longer declares LEGACY_CONTAINERS"
    listed = set(match.group(1).split())

    expected = {
        spec["container_name"].replace("merlon-", old + "-")
        for spec in _compose()["services"].values()
        if spec.get("container_name")
        for old in PREVIOUS_GENERATIONS
    }
    missing = expected - listed
    assert not missing, (
        f"these containers were renamed but are not cleaned up on upgrade: "
        f"{sorted(missing)} — the next person to upgrade hits a name conflict")


def test_diagnose_still_finds_a_pre_rename_install():
    """Otherwise the first thing an upgrading user is told is 'no container'.

    Which is both wrong and the opposite of useful, given they are running
    diagnose.sh precisely because the upgrade did not work.
    """
    text = (ROOT / "diagnose.sh").read_text()
    assert "merlon-backend" in text
    for old in PREVIOUS_GENERATIONS:
        assert f"{old}-backend" in text, f"no fallback to the {old} container name"


def test_favicon_matches_the_react_logo():
    """Two copies of the same artwork, so they can drift.

    The favicon is a standalone file (index.html cannot import a component) and
    the header uses the React one. A logo redesign that updates only the tab
    icon, or only the header, is the kind of thing nobody notices for months.
    """
    import re

    logo = (ROOT / "frontend" / "src" / "Logo.tsx").read_text()
    favicon = (ROOT / "frontend" / "public" / "favicon.svg").read_text()

    paths = re.findall(r'd="(M[^"]+)"', logo)
    assert paths, "no paths found in Logo.tsx — has the mark changed shape?"
    for d in paths:
        assert d in favicon, (
            f"favicon.svg is missing a path from Logo.tsx: {d[:40]}… "
            f"— the two copies of the mark have drifted apart")

def test_shell_scripts_are_forced_to_lf_for_windows_checkouts():
    """Without this, the backend container does not start on Windows.

    backend/entrypoint.sh is COPY'd into the image and is the container's CMD.
    Git on Windows defaults to core.autocrlf=true and rewrites LF to CRLF on
    checkout, so Docker copies in a file whose shebang ends `\r`. The container
    then exits with

        exec /usr/local/bin/entrypoint.sh: no such file or directory

    naming a file that is plainly present. Nothing about that message points at
    line endings, which is what makes it expensive.

    .gitattributes pins these to LF regardless of platform. This asserts the
    rule covers every shell script and the Dockerfiles, so adding a new one
    outside the pattern is caught here rather than by a Windows user.
    """
    import subprocess

    attrs = ROOT / ".gitattributes"
    assert attrs.exists(), ".gitattributes is missing — Windows checkouts will "\
                           "get CRLF and the backend container will not start"

    targets = [str(p.relative_to(ROOT)) for p in SCRIPTS]
    targets += ["backend/Dockerfile", "docker-compose.yml"]

    result = subprocess.run(
        ["git", "check-attr", "eol", "--"] + targets,
        cwd=ROOT, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr

    for line in result.stdout.strip().splitlines():
        # `git check-attr eol -- <path>` prints "<path>: eol: <value>".
        path, _attr, value = line.rsplit(": ", 2)
        assert value == "lf", (
            f"{path} is not pinned to LF (got {value!r}); a Windows checkout "
            f"would give it CRLF")


def test_powershell_launcher_exists_for_windows():
    """start.sh is bash. Windows users need something that runs without WSL."""
    ps1 = ROOT / "start.ps1"
    assert ps1.exists(), "no PowerShell launcher — Windows needs WSL without it"
    text = ps1.read_text(encoding="utf-8")
    assert "docker compose up" in text, "start.ps1 never brings the stack up"
    assert "Docker.DockerDesktop" in text, "start.ps1 cannot install Docker"
