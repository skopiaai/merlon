"""Keeping the detection content current.

A vulnerability scanner is mostly a database with a scheduler attached. The
code here changes monthly; the *content* — nuclei templates, takeover
fingerprints, wordlists — changes daily, and a template published this morning
finds bugs this afternoon that yesterday's copy walks straight past.

For bug bounty that gap is the whole game. When a new CVE template lands,
everyone with an up-to-date copy scans for it within hours, and the first valid
report is the one that gets paid. Running week-old templates means arriving
after that window has closed.

So this module updates four kinds of thing:

  templates    the official nuclei set, plus community repositories that carry
               checks the official set doesn't
  fingerprints subdomain takeover service signatures
  wordlists    content discovery lists
  tools        the scanner binaries themselves

Each source updates independently and a failure is contained: a community
repository that's been deleted or renamed costs you that repository, not the
update run. Every result is recorded with a timestamp so the UI can show what
is current and what is stale, because "I ran the update button at some point"
is not the same as knowing.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from . import config
from .config import ARTIFACT_DIR

STATE_FILE = Path(config.env("UPDATE_STATE",
                            str(ARTIFACT_DIR.parent / "update-state.json")))
TEMPLATE_DIR = Path(config.env("TEMPLATE_DIR", "/data/templates"))

# Content is considered stale after this long. Chosen to match how fast the
# nuclei template repository actually moves — it takes several commits a day.
STALE_AFTER = 24 * 3600


@dataclass
class SourceResult:
    name: str
    kind: str                 # templates | fingerprints | wordlists | tools
    ok: bool = False
    detail: str = ""
    items: int = 0            # templates added, fingerprints parsed, etc.
    seconds: float = 0.0
    at: float = field(default_factory=time.time)

    # "This source could not update, and that is fine" is a different state
    # from "this source failed". Pinned binaries inside the container are the
    # main case: they are refreshed when the image is rebuilt, so an in-place
    # self-update being unavailable changes nothing about detection coverage.
    # Collapsing the two made the panel report "2 sources unavailable" for a
    # system that was completely current, which trains you to ignore it — and
    # then you also ignore the one that matters.
    skipped: bool = False


@dataclass
class UpdateRun:
    started_at: float = field(default_factory=time.time)
    finished_at: float = 0.0
    running: bool = False
    sources: list[dict] = field(default_factory=list)

    @property
    def ok_count(self) -> int:
        return sum(1 for s in self.sources if s.get("ok"))


# Community template repositories. The official set is handled by nuclei's own
# updater; these are the ones bug bounty hunters maintain, which is where
# checks for very recent disclosures tend to appear first.
#
# Each is cloned shallow into its own directory, so a repository that turns out
# to be noisy can be removed by deleting one folder — and one that disappears
# upstream just fails its own line in the report.
COMMUNITY_REPOS: list[tuple[str, str]] = [
    ("fuzzing-templates", "https://github.com/projectdiscovery/fuzzing-templates.git"),
    ("nuclei-bb", "https://github.com/coffinxp/nuclei-templates.git"),
    ("kenzer", "https://github.com/ARPSyndicate/kenzer-templates.git"),
    # Renamed upstream: geeknik/nuclei-templates is now a 404 and the repo
    # lives at the-nuclei-templates. Verified 226 templates at time of change.
    ("geeknik", "https://github.com/geeknik/the-nuclei-templates.git"),
    ("cent", "https://github.com/xm1k3/cent.git"),
]

TAKEOVER_FINGERPRINTS = (
    "https://raw.githubusercontent.com/EdOverflow/can-i-take-over-xyz/master/"
    "fingerprints.json"
)


# --------------------------------------------------------------- state

def load_state() -> dict:
    try:
        return json.loads(STATE_FILE.read_text())
    except (OSError, json.JSONDecodeError):
        return {"last_run": None, "running": False, "sources": []}


def save_state(state: dict) -> None:
    try:
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        STATE_FILE.write_text(json.dumps(state, indent=2))
    except OSError:
        pass


def status() -> dict:
    """What the UI shows: what's current, what's stale, when it last ran."""
    from . import kev

    state = load_state()
    last = state.get("last_run")
    age = (time.time() - last) if last else None
    return {
        # Surfaced separately from the source list because it changes how
        # findings are prioritised rather than what gets detected — an empty
        # catalogue means CVE findings sort purely by score, which is worth
        # knowing before a scan rather than after.
        "kev": kev.status(),
        "last_run": last,
        "age_seconds": age,
        "stale": age is None or age > STALE_AFTER,
        "running": bool(state.get("running")),
        "sources": state.get("sources", []),
        "template_dirs": sorted(p.name for p in TEMPLATE_DIR.glob("*")
                                if p.is_dir()) if TEMPLATE_DIR.exists() else [],
        "auto_daily": config.env("AUTO_UPDATE", "1") != "0",
    }


def extra_template_paths() -> list[str]:
    """Community template directories to pass to nuclei with -t.

    Read at scan time rather than cached, so a repository added by an update
    run is in play for the very next scan without a restart.
    """
    if not TEMPLATE_DIR.exists():
        return []
    return [str(p) for p in sorted(TEMPLATE_DIR.glob("*")) if p.is_dir()]


# --------------------------------------------------------------- helpers

async def _run(argv: list[str], timeout: int = 900) -> tuple[int, str]:
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        return 124, f"timed out after {timeout}s"
    except OSError as exc:
        return 127, str(exc)
    return proc.returncode or 0, out.decode("utf-8", "replace").strip()


def count_templates(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(1 for _ in path.rglob("*.yaml")) + sum(1 for _ in path.rglob("*.yml"))


# --------------------------------------------------------------- sources

async def update_nuclei_templates() -> SourceResult:
    started = time.time()
    result = SourceResult(name="nuclei-templates (official)", kind="templates")
    if not shutil.which("nuclei"):
        result.detail = "nuclei is not installed"
        return result

    code, out = await _run(["nuclei", "-update-templates", "-silent"], timeout=900)
    home = Path(os.path.expanduser("~")) / "nuclei-templates"
    result.ok = code == 0
    result.items = count_templates(home)
    result.detail = (out or "already current")[-400:]
    result.seconds = round(time.time() - started, 1)
    return result


async def update_community_repo(name: str, url: str) -> SourceResult:
    started = time.time()
    result = SourceResult(name=f"{name} templates", kind="templates")
    if not shutil.which("git"):
        result.detail = "git is not installed"
        return result

    TEMPLATE_DIR.mkdir(parents=True, exist_ok=True)
    dest = TEMPLATE_DIR / name

    if (dest / ".git").exists():
        code, out = await _run(
            ["git", "-C", str(dest), "pull", "--ff-only", "--depth", "1"], timeout=600)
    else:
        code, out = await _run(
            ["git", "clone", "--depth", "1", "--single-branch", url, str(dest)],
            timeout=900)

    result.ok = code == 0 and dest.exists()
    result.items = count_templates(dest)
    result.detail = (out or "")[-300:] if not result.ok else \
        f"{result.items} template(s)"
    result.seconds = round(time.time() - started, 1)
    return result


async def update_takeover_fingerprints() -> SourceResult:
    """Refresh subdomain takeover signatures from the community list.

    Written to disk rather than merged into the engine's built-in table: the
    built-ins are the tested baseline and stay authoritative, and anything new
    from upstream is additive. A bad upstream commit can't silently disable a
    detection that way.
    """
    started = time.time()
    result = SourceResult(name="takeover fingerprints", kind="fingerprints")
    code, out = await _run(
        ["curl", "-sS", "-L", "--max-time", "60", TAKEOVER_FINGERPRINTS], timeout=90)
    if code != 0 or not out.strip():
        result.detail = "could not fetch fingerprints"
        result.seconds = round(time.time() - started, 1)
        return result

    try:
        entries = json.loads(out)
    except json.JSONDecodeError:
        result.detail = "upstream returned something that isn't JSON"
        result.seconds = round(time.time() - started, 1)
        return result

    if not isinstance(entries, list):
        result.detail = "unexpected format"
        return result

    path = TEMPLATE_DIR / "takeover-fingerprints.json"
    try:
        TEMPLATE_DIR.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(entries, indent=1))
    except OSError as exc:
        result.detail = str(exc)
        return result

    vulnerable = sum(1 for e in entries if isinstance(e, dict) and e.get("vulnerable"))
    result.ok = True
    result.items = len(entries)
    result.detail = f"{len(entries)} service(s), {vulnerable} currently claimable"
    result.seconds = round(time.time() - started, 1)
    return result


async def update_tool(binary: str) -> SourceResult:
    """Self-update a ProjectDiscovery binary.

    These ship an `-update` flag that replaces the binary in place. Worth doing
    because detection logic lives in the tools too — httpx's technology
    fingerprints and cdncheck's provider ranges both change.
    """
    started = time.time()
    result = SourceResult(name=binary, kind="tools")
    path = shutil.which(binary)
    if not path:
        result.skipped = True
        result.detail = "not installed in this image"
        return result

    code, out = await _run([binary, "-update", "-silent"], timeout=600)
    text = (out or "").strip()
    low = text.lower()
    result.seconds = round(time.time() - started, 1)

    if code == 0:
        result.ok = True
        result.detail = text[-200:] or "current"
        return result

    # Non-zero covers several situations that are not failures. Classify them,
    # because the difference decides whether the user should act.
    #
    #  - "latest version" — nothing to do; the tool said so and then exited
    #    non-zero anyway, which several ProjectDiscovery releases do.
    #  - version unknown — a binary built with `go install` carries no release
    #    version, so the updater cannot compare and refuses. Expected here:
    #    the Dockerfile builds some tools from source on purpose.
    #  - read-only or permission — the binary lives in an image layer. Nothing
    #    to fix; `docker compose build --pull` is how these get updated.
    benign = (
        "latest version" in low
        or ("already" in low and "date" in low)
        or "up to date" in low
        or "no updates" in low
    )
    unwritable = any(k in low for k in
                     ("permission denied", "read-only", "read only", "text file busy"))
    unversioned = any(k in low for k in
                      ("could not determine", "unable to determine", "version not found",
                       "no version", "devel"))

    if benign:
        result.ok = True
        result.detail = text[-200:] or "already current"
    elif unwritable or unversioned:
        result.skipped = True
        result.detail = (
            f"pinned by the container image — rebuild to update ({text[-120:]})"
            if text else "pinned by the container image — rebuild to update")
    else:
        result.detail = text[-200:] or f"exited {code} with no output"
    return result


async def update_kev() -> SourceResult:
    """Refresh CISA's Known Exploited Vulnerabilities catalogue.

    Small, changes weekly, and reorders how every CVE finding gets prioritised —
    the cheapest high-value thing in this list.
    """
    started = time.time()
    result = SourceResult(name="CISA KEV catalogue", kind="fingerprints")

    from . import kev
    code, out = await _run(
        ["curl", "-sS", "-L", "--max-time", "90", kev.KEV_URL], timeout=120)
    if code != 0 or not out.strip():
        result.detail = "could not fetch the catalogue"
        result.seconds = round(time.time() - started, 1)
        return result

    entries = kev.parse_catalog(out)
    if not entries:
        result.detail = "upstream returned something unparseable"
        return result

    try:
        kev.KEV_FILE.parent.mkdir(parents=True, exist_ok=True)
        kev.KEV_FILE.write_text(out)
    except OSError as exc:
        result.detail = str(exc)
        return result

    ransomware = sum(1 for e in entries.values() if e["ransomware"])
    result.ok = True
    result.items = len(entries)
    result.detail = (f"{len(entries)} actively exploited CVEs, "
                     f"{ransomware} used in ransomware")
    result.seconds = round(time.time() - started, 1)
    return result


async def update_wordlists() -> SourceResult:
    """Refresh SecLists if it was installed as a git checkout.

    The tarball install is deliberately not re-downloaded here — it's hundreds
    of megabytes and changes slowly, so pulling it on a daily schedule costs a
    lot of bandwidth for very little new content.
    """
    started = time.time()
    result = SourceResult(name="SecLists wordlists", kind="wordlists")
    path = Path("/opt/wordlists")
    if not (path / ".git").exists():
        result.ok = True
        result.detail = "installed from a release archive — no daily update needed"
        result.items = sum(1 for _ in path.rglob("*.txt")) if path.exists() else 0
        return result

    code, out = await _run(["git", "-C", str(path), "pull", "--ff-only"], timeout=900)
    result.ok = code == 0
    result.detail = (out or "")[-200:]
    result.items = sum(1 for _ in path.rglob("*.txt"))
    result.seconds = round(time.time() - started, 1)
    return result


# --------------------------------------------------------------- the run

async def run_all(*, include_tools: bool = True,
                  include_community: bool = True,
                  log=None) -> dict:
    """Update everything. Returns the same shape `status()` does."""
    state = load_state()
    if state.get("running"):
        return {**status(), "detail": "an update is already running"}

    state["running"] = True
    save_state(state)

    async def note(message: str) -> None:
        if log:
            await log("info", message, "update")

    results: list[SourceResult] = []
    started = time.time()

    try:
        await note("updating official nuclei templates…")
        results.append(await update_nuclei_templates())

        if include_community:
            await note(f"updating {len(COMMUNITY_REPOS)} community template repos…")
            # Concurrent: these are independent network fetches and running
            # them in series turns a 40-second job into four minutes.
            results += list(await asyncio.gather(
                *(update_community_repo(name, url) for name, url in COMMUNITY_REPOS)))

        await note("refreshing takeover fingerprints and the KEV catalogue…")
        results += list(await asyncio.gather(
            update_takeover_fingerprints(), update_kev()))

        await note("checking wordlists…")
        results.append(await update_wordlists())

        if include_tools:
            await note("self-updating scanner binaries…")
            results += list(await asyncio.gather(
                *(update_tool(b) for b in
                  ("httpx", "subfinder", "dnsx", "cdncheck", "katana", "naabu",
                   "tlsx", "nuclei"))))

        total_templates = sum(r.items for r in results if r.kind == "templates")
        await note(f"update complete — {sum(1 for r in results if r.ok)}/"
                   f"{len(results)} source(s) current, "
                   f"{total_templates} templates available")
    finally:
        state = {
            "last_run": time.time(),
            "running": False,
            "duration": round(time.time() - started, 1),
            "sources": [asdict(r) for r in results],
        }
        save_state(state)

    return status()


async def daily(interval: int = 24 * 3600) -> None:
    """Background loop — keeps content fresh without anyone pressing anything.

    Runs shortly after startup if the content is already stale, then every
    `interval`. A failure is logged and the loop continues; an update problem
    must never stop the application.
    """
    import logging
    logger = logging.getLogger(__name__)

    if config.env("AUTO_UPDATE", "1") == "0":
        logger.info("automatic content updates are disabled")
        return

    await asyncio.sleep(90)   # let the app finish starting first
    while True:
        try:
            if status()["stale"]:
                logger.info("detection content is stale — updating")
                await run_all()
            else:
                logger.info("detection content is current")
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            logger.warning("scheduled update failed: %s", exc)
        await asyncio.sleep(interval)
