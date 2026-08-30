"""Artifact auto-analysis.

In a Jeopardy CTF almost every challenge starts the same way: here is a file,
find the flag. The first ten minutes are always the same commands in the same
order, and under time pressure people forget one. This runs the whole chain
automatically, in parallel, and puts flag candidates at the top.

Design rules:
  * Every step is best-effort. A missing tool degrades that step, never the run.
  * Everything is read-only against the artifact; nothing is executed.
  * Output is capped — a 500 MB strings dump helps nobody.
"""

from __future__ import annotations

import asyncio
import math
import os
import re
import shutil
import tempfile
from dataclasses import dataclass, field

MAX_OUTPUT = 20_000        # per step, characters kept
STEP_TIMEOUT = 90          # seconds per tool

# Flag formats worth hunting. The event's own prefix is unknown until the day,
# so the generic brace pattern catches anything shaped like a flag.
FLAG_PATTERNS = [
    r"\bflag\{[^}\n]{1,200}\}",
    r"\bFLAG\{[^}\n]{1,200}\}",
    r"\bCTF\{[^}\n]{1,200}\}",
    r"\bTCQ\{[^}\n]{1,200}\}",
    r"\b[A-Za-z][A-Za-z0-9_]{1,15}\{[A-Za-z0-9_@!\-\.\$#%\+/= ]{4,200}\}",
]


@dataclass
class Step:
    name: str
    tool: str
    ok: bool
    output: str = ""
    note: str = ""


@dataclass
class Report:
    filename: str
    size: int
    filetype: str = ""
    category_hint: str = ""
    entropy: float = 0.0
    steps: list[Step] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    extracted: list[str] = field(default_factory=list)
    summary: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "filename": self.filename, "size": self.size, "filetype": self.filetype,
            "category_hint": self.category_hint, "entropy": round(self.entropy, 2),
            "flags": self.flags, "extracted": self.extracted, "summary": self.summary,
            "steps": [vars(s) for s in self.steps],
        }


# ------------------------------------------------------------------ helpers

async def _run(name: str, argv: list[str], *, cwd: str | None = None,
               note: str = "") -> Step:
    """Run one tool. Never raises."""
    tool = argv[0]
    if not shutil.which(tool):
        return Step(name, tool, False, note=f"{tool} not installed in this image")
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv, cwd=cwd,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=STEP_TIMEOUT)
    except asyncio.TimeoutError:
        return Step(name, tool, False, note=f"timed out after {STEP_TIMEOUT}s")
    except OSError as exc:
        return Step(name, tool, False, note=str(exc))

    text = out.decode("utf-8", "replace")
    truncated = len(text) > MAX_OUTPUT
    return Step(name, tool, True, text[:MAX_OUTPUT],
                note=(note + (" · output truncated" if truncated else "")).strip(" ·"))


def find_flags(text: str) -> list[str]:
    found: list[str] = []
    for pattern in FLAG_PATTERNS:
        for m in re.findall(pattern, text or ""):
            if m not in found:
                found.append(m)
    return found[:40]


def shannon_entropy(data: bytes) -> float:
    """High entropy means compressed or encrypted — worth knowing early."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def guess_category(filetype: str, name: str) -> str:
    low = (filetype + " " + name).lower()
    if any(k in low for k in ("pcap", "tcpdump", "capture")):
        return "network"
    if any(k in low for k in ("elf", "pe32", "executable", "mach-o", "shared object")):
        return "binary"
    if any(k in low for k in ("image", "png", "jpeg", "gif", "bmp", "tiff", "wav",
                              "audio", "video", "mp4", "zip", "archive", "7-zip",
                              "rar", "tar", "gzip", "pdf")):
        return "forensics"
    if any(k in low for k in ("tlog", "mavlink", ".bin", "dataflash")):
        return "drone"
    if any(k in low for k in ("ascii", "text", "utf-8", "json", "pem", "certificate")):
        return "crypto"
    return "forensics"


# ------------------------------------------------------------------ chains

async def _universal(path: str) -> list[Step]:
    """Run on everything, regardless of type."""
    return list(await asyncio.gather(
        _run("File type", ["file", "-b", path]),
        _run("Readable strings", ["strings", "-n", "6", path],
             note="printable runs of 6+ characters"),
        _run("Metadata", ["exiftool", path]),
        _run("Embedded files", ["binwalk", path],
             note="signatures found inside the file"),
    ))


async def _image_chain(path: str, workdir: str) -> list[Step]:
    steps = list(await asyncio.gather(
        _run("PNG structure", ["pngcheck", "-v", path]),
        _run("LSB stego (zsteg)", ["zsteg", "-a", path]),
        # An empty passphrase is the common case; a wrong guess just fails.
        _run("steghide (blank passphrase)",
             ["steghide", "extract", "-sf", path, "-p", "", "-xf",
              os.path.join(workdir, "steghide_out")]),
    ))
    out = os.path.join(workdir, "steghide_out")
    if os.path.exists(out):
        with open(out, "rb") as fh:
            steps.append(Step("steghide payload", "steghide", True,
                              fh.read(MAX_OUTPUT).decode("utf-8", "replace"),
                              "extracted with an empty passphrase"))
    return steps


async def _binary_chain(path: str) -> list[Step]:
    return list(await asyncio.gather(
        _run("Mitigations", ["pwn", "checksec", path]),
        _run("Symbols", ["readelf", "-s", path]),
        _run("Dynamic imports", ["objdump", "-T", path]),
        _run("Sections", ["readelf", "-S", path]),
    ))


async def _pcap_chain(path: str, workdir: str) -> list[Step]:
    objects = os.path.join(workdir, "http_objects")
    os.makedirs(objects, exist_ok=True)
    steps = list(await asyncio.gather(
        _run("Protocol hierarchy", ["tshark", "-r", path, "-q", "-z", "io,phs"]),
        _run("Conversations", ["tshark", "-r", path, "-q", "-z", "conv,tcp"]),
        _run("Cleartext credentials",
             ["tshark", "-r", path, "-Y",
              "http.authorization || ftp.request.command == \"PASS\" || telnet"],
             note="HTTP auth, FTP passwords, telnet"),
        _run("ICS protocols",
             ["tshark", "-r", path, "-Y", "modbus || s7comm || dnp3 || bacapp"],
             note="industrial control traffic"),
        _run("Extract HTTP objects",
             ["tshark", "-r", path, "--export-objects", f"http,{objects}"]),
    ))
    if os.path.isdir(objects):
        names = os.listdir(objects)[:40]
        if names:
            steps.append(Step("Files carried in HTTP", "tshark", True,
                              "\n".join(names), f"{len(names)} object(s) extracted"))
    return steps


async def _archive_chain(path: str) -> list[Step]:
    return list(await asyncio.gather(
        _run("Archive contents", ["7z", "l", path]),
    ))


async def _telemetry_chain(path: str) -> list[Step]:
    return list(await asyncio.gather(
        _run("MAVLink messages",
             ["python3", "-m", "pymavlink.tools.mavlogdump", path],
             note="decoded telemetry"),
        _run("Status text only",
             ["python3", "-m", "pymavlink.tools.mavlogdump",
              "--types", "STATUSTEXT", path],
             note="flags often hide in STATUSTEXT"),
    ))


async def _carve(path: str, workdir: str) -> tuple[Step, list[str]]:
    """binwalk extraction, reported separately because it produces files."""
    out = os.path.join(workdir, "carved")
    os.makedirs(out, exist_ok=True)
    step = await _run("Carve embedded files",
                      ["binwalk", "-e", "--run-as=root", "-C", out, path])
    found: list[str] = []
    for root, _dirs, files in os.walk(out):
        for f in files:
            rel = os.path.relpath(os.path.join(root, f), out)
            found.append(rel)
    return step, sorted(found)[:60]


# ------------------------------------------------------------------- driver

async def analyze(path: str, original_name: str = "") -> Report:
    name = original_name or os.path.basename(path)
    size = os.path.getsize(path)
    report = Report(filename=name, size=size)

    with open(path, "rb") as fh:
        head = fh.read(4_000_000)
    report.entropy = shannon_entropy(head)

    ftype = await _run("File type", ["file", "-b", path])
    report.filetype = (ftype.output or "unknown").strip().splitlines()[0][:200] \
        if ftype.ok else "unknown"
    report.category_hint = guess_category(report.filetype, name)

    workdir = tempfile.mkdtemp(prefix="analyze_")
    try:
        steps = await _universal(path)

        low = (report.filetype + " " + name).lower()
        if any(k in low for k in ("image", "png", "jpeg", "gif", "bmp", "wav")):
            steps += await _image_chain(path, workdir)
        if any(k in low for k in ("elf", "executable", "pe32", "mach-o", "shared object")):
            steps += await _binary_chain(path)
        if any(k in low for k in ("pcap", "capture")):
            steps += await _pcap_chain(path, workdir)
        if any(k in low for k in ("zip", "7-zip", "rar", "tar", "gzip", "archive")):
            steps += await _archive_chain(path)
        if name.lower().endswith((".tlog", ".bin", ".log")) or "mavlink" in low:
            steps += await _telemetry_chain(path)

        carve_step, extracted = await _carve(path, workdir)
        steps.append(carve_step)
        report.extracted = extracted

        # Flags can appear in any tool's output, in the raw bytes, or inside a
        # carved file — so search all three.
        haystack = "\n".join(s.output for s in steps if s.output)
        haystack += "\n" + head.decode("utf-8", "replace")
        for root, _dirs, files in os.walk(workdir):
            for f in files[:200]:
                try:
                    with open(os.path.join(root, f), "rb") as fh:
                        haystack += "\n" + fh.read(400_000).decode("utf-8", "replace")
                except OSError:
                    continue

        report.flags = find_flags(haystack)
        report.steps = steps
        report.summary = _summarize(report)
        return report
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def _summarize(r: Report) -> list[str]:
    notes: list[str] = []
    if r.flags:
        notes.append(f"{len(r.flags)} flag-shaped string(s) found — check these first")
    if r.entropy > 7.5:
        notes.append(f"Very high entropy ({r.entropy:.2f}/8) — encrypted, compressed "
                     f"or packed rather than plain data")
    elif r.entropy < 1.5 and r.size > 1000:
        notes.append(f"Unusually low entropy ({r.entropy:.2f}/8) — heavily repetitive data")
    if r.extracted:
        notes.append(f"{len(r.extracted)} file(s) carved out of this one — "
                     f"analyse those next")

    for s in r.steps:
        if not s.ok:
            continue
        low = s.output.lower()
        if s.name == "Embedded files" and "zip archive" in low:
            notes.append("A ZIP archive is embedded inside this file")
        if s.name == "PNG structure" and "additional data after iend" in low:
            notes.append("Data appended after the PNG end marker — a classic hiding spot")
        if s.name == "Mitigations":
            if "no canary" in low:
                notes.append("Binary has no stack canary")
            if "nx disabled" in low or "nx unknown" in low:
                notes.append("Binary has NX disabled — stack may be executable")
            if "no pie" in low:
                notes.append("Binary is not PIE — fixed load address")
        if s.name == "Cleartext credentials" and s.output.strip():
            notes.append("Cleartext credentials present in the capture")
        if s.name == "ICS protocols" and s.output.strip():
            notes.append("Industrial control protocol traffic present")
        if s.name == "Metadata" and re.search(r"comment\s*:", low):
            notes.append("A comment field is set in the metadata — read it")

    missing = [s.tool for s in r.steps if not s.ok and "not installed" in s.note]
    if missing:
        notes.append("Tools unavailable in this image: " + ", ".join(sorted(set(missing))))
    return notes
