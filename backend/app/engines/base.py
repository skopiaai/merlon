"""Async subprocess plumbing shared by every engine wrapper.

Design notes
------------
* Engines are external binaries. We never reimplement detection logic.
* Everything runs through `run_jsonl`, which streams NDJSON off stdout so
  the UI sees results while the scan is still going.
* stderr is captured separately and surfaced as log lines, because these
  tools put progress info there and it's the first thing you want when a
  scan mysteriously returns nothing.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import tempfile
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field

LogFn = Callable[[str, str], Awaitable[None]]  # (level, message) -> None

# asyncio's StreamReader defaults to a 64 KiB line limit and raises
# "Separator is found, but chunk is longer than limit" past it. Nuclei emits
# one JSON object per finding *including the full request and response*, so a
# single line routinely exceeds that. 16 MiB is generous enough that only a
# genuinely pathological response trips it.
STREAM_LIMIT = 16 * 1024 * 1024


class EngineError(RuntimeError):
    pass


@dataclass
class EngineResult:
    records: list[dict] = field(default_factory=list)
    returncode: int = 0
    stderr_tail: list[str] = field(default_factory=list)


def require_binary(name: str) -> str:
    path = shutil.which(name)
    if not path:
        raise EngineError(
            f"'{name}' is not installed in the backend container. "
            f"Rebuild with `docker compose build backend`."
        )
    return path


# Nuclei's -stats output, e.g.
# "[0:01:20] | Templates: 9312 | Hosts: 6 | RPS: 84 | Matched: 3 | Errors: 1 | Requests: 6721/58203 (11%)"
_PROGRESS_RE = re.compile(r"Requests:\s*([\d,]+)/([\d,]+)\s*\((\d+)%\)")


async def _drain_stderr(stream, log: LogFn | None, tail: list[str], engine: str):
    while True:
        try:
            raw = await stream.readline()
        except (ValueError, asyncio.LimitOverrunError):
            continue  # over-long stderr line; readline already drained it
        if not raw:
            break
        line = raw.decode("utf-8", "replace").rstrip()
        if not line:
            continue
        tail.append(line)
        del tail[:-40]  # keep only the last 40 lines
        if not log:
            continue

        # Surface progress at info level so it shows in the plain-language view;
        # everything else stays behind the "show technical log" toggle.
        match = _PROGRESS_RE.search(line)
        if match:
            done, total, pct = match.groups()
            await log("info", f"[{engine}] {pct}% — {done} of {total} checks run")
        else:
            await log("debug", f"[{engine}] {line}")


async def stream_jsonl(
    argv: list[str],
    *,
    engine: str,
    input_lines: list[str] | None = None,
    input_flag: str = "-list",
    log: LogFn | None = None,
    timeout: float = 3600.0,
) -> AsyncIterator[dict]:
    """Run a tool and yield each stdout line parsed as JSON.

    Target lists go to a real temp file rather than through stdin. These tools
    take a file *path* and open() it themselves — pointing them at /dev/stdin
    fails with ENXIO ("no such device or address") when stdin is a pipe, which
    it always is under asyncio. A temp file is unambiguous and works for every
    tool regardless of how it reads input.
    """
    require_binary(argv[0])

    tmp_path: str | None = None
    if input_lines is not None:
        if not input_lines:
            return
        fd, tmp_path = tempfile.mkstemp(prefix=f"{engine}_targets_", suffix=".txt")
        with os.fdopen(fd, "w") as fh:
            fh.write("\n".join(input_lines) + "\n")
        argv = [*argv, input_flag, tmp_path]

    if log:
        await log("info", f"[{engine}] exec: {' '.join(argv)}")

    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        limit=STREAM_LIMIT,
    )

    tail: list[str] = []
    err_task = asyncio.create_task(_drain_stderr(proc.stderr, log, tail, engine))

    try:
        async with asyncio.timeout(timeout):
            oversized = 0
            while True:
                try:
                    raw = await proc.stdout.readline()
                except (ValueError, asyncio.LimitOverrunError):
                    # One finding with an enormous response body. readline()
                    # has already drained it, so skip this record rather than
                    # failing the whole scan over a single result.
                    oversized += 1
                    continue
                if not raw:
                    break
                line = raw.decode("utf-8", "replace").strip()
                if not line or not line.startswith("{"):
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue
            if oversized and log:
                await log("warn", f"[{engine}] skipped {oversized} oversized record(s)")
            await proc.wait()
    except TimeoutError:
        proc.kill()
        await proc.wait()
        raise EngineError(f"[{engine}] exceeded {timeout:.0f}s timeout") from None
    except asyncio.CancelledError:
        proc.kill()
        await proc.wait()
        raise
    finally:
        err_task.cancel()
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    # Exit code 1 with no output is normal for "found nothing" in some tools,
    # so only treat a non-zero code as fatal if stderr looks like a real error.
    if proc.returncode not in (0, None):
        joined = " ".join(tail).lower()
        if any(k in joined for k in ("could not", "failed to", "no such", "invalid", "panic")):
            raise EngineError(f"[{engine}] exited {proc.returncode}: {tail[-1] if tail else 'no detail'}")


async def collect_jsonl(argv: list[str], **kw) -> list[dict]:
    return [rec async for rec in stream_jsonl(argv, **kw)]
