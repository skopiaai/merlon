"""Screenshots of every live host, for visual triage.

Reading a hundred HTTP titles tells you very little. Looking at a hundred
thumbnails finds the forgotten staging box, the default install page and the
exposed admin panel in about ten seconds, which is why every serious recon
framework has this and why its absence was the one gap this project's own
comparison table admitted to.

This produces no findings on purpose. A screenshot is not a vulnerability — it
is context attached to an asset, so it is written to the artifact directory and
recorded on the asset row rather than pushed into the findings queue where it
would only add noise.

Like every browser-backed engine here it degrades to nothing when Chromium is
absent, because a missing browser must never fail a scan.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from urllib.parse import urlparse

from ..config import ARTIFACT_DIR
from . import browser
from .registry import EngineSpec, register

# One shot per host is the point — a gallery of fifty pages from one site is
# noise, and the interesting thing is always "what is this host".
MAX_SHOTS = 60


def safe_name(url: str) -> str:
    """A filesystem-safe, collision-resistant name for a URL.

    The host is kept readable so a human can scan the directory, and a short
    hash of the full URL is appended so two ports or schemes on the same host
    do not overwrite each other.
    """
    parsed = urlparse(url)
    host = re.sub(r"[^A-Za-z0-9._-]", "_", parsed.hostname or "unknown")[:60]
    # A hostname of ".." is legal to parse and would produce a filename made of
    # dots. It cannot traverse — there is no separator left — but a file called
    # "..-abc.png" confuses tooling and reads like a bug. Collapse dot runs and
    # never start or end on one.
    host = host.replace("..", "_").strip(".-") or "unknown"
    port = f"-{parsed.port}" if parsed.port else ""
    digest = hashlib.sha256(url.encode()).hexdigest()[:8]
    return f"{host}{port}-{digest}.png"


def shot_dir(scan_id: int | None) -> Path:
    return Path(ARTIFACT_DIR) / "screenshots" / str(scan_id or "adhoc")


def _record(scan_id: int, url: str, path: str) -> bool:
    """Attach the screenshot path to the matching asset row.

    Stored inside the asset's existing `raw` JSON rather than as a new column,
    so this needs no migration and an older database keeps working.
    """
    try:
        from sqlalchemy import select

        from ..db import SessionLocal
        from ..models import Asset
    except Exception:  # noqa: BLE001
        return False

    try:
        with SessionLocal() as db:
            asset = db.scalar(
                select(Asset).where(Asset.scan_id == scan_id, Asset.url == url))
            if asset is None:
                return False
            raw = dict(asset.raw or {})
            raw["screenshot"] = path
            asset.raw = raw
            db.commit()
            return True
    except Exception:  # noqa: BLE001 — a screenshot must never break a scan
        return False


@register(EngineSpec(
    name="screenshots",
    label="Capturing screenshots",
    description="A screenshot of every live host for visual triage — the "
                "fastest way to spot a forgotten staging box or an exposed "
                "admin panel across a large surface. Produces no findings; the "
                "images are written to the artifact directory and recorded on "
                "the asset.",
    phase="post_http",
    takes="urls",
    produces="findings",
    weight=6,
    limit=MAX_SHOTS,
    default_in=("deep",),
))
async def _engine(targets: list[str], ctx: dict) -> list[dict]:
    log = ctx.get("log")
    scan_id = ctx.get("scan_id")

    if not browser.available():
        if log:
            await log("info", "[screenshots] no Chrome/Chromium available — "
                              "skipping visual triage", "screenshots")
        return []

    out_dir = shot_dir(scan_id)
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        if log:
            await log("warn", f"[screenshots] cannot write to {out_dir}: {exc}",
                      "screenshots")
        return []

    # One per host: the first URL seen for a host wins.
    chosen: dict[str, str] = {}
    for url in targets:
        host = (urlparse(url).hostname or "").lower()
        if host and host not in chosen:
            chosen[host] = url

    taken = 0
    for url in chosen.values():
        path = out_dir / safe_name(url)
        render = await browser.render(url, screenshot=str(path))
        if not render.ok:
            continue
        taken += 1
        if scan_id:
            _record(scan_id, url, str(path))

    if log:
        await log("info", f"[screenshots] captured {taken} of {len(chosen)} "
                          f"host(s) into {out_dir}", "screenshots")
    return []
