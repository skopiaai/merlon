"""ASN and netblock expansion.

Organisations large enough to have their own IP allocation put things in it
that were never named under the domain you started from — an acquisition still
on its old branding, a lab network, a vendor appliance someone racked, a
service registered under a different domain entirely.

Domain-based enumeration cannot reach any of that. Address-based enumeration
can: look up the autonomous system that announces the target's IP, take the
netblocks it announces, and ask each address what its reverse DNS name is. PTR
records are how infrastructure names itself, and they routinely name hosts that
forward DNS never did.

Two deliberate limits:

**It resolves names, it doesn't sweep addresses.** Expanding a /16 into 65,536
scan targets would be both useless and hostile. Reverse lookups are cheap,
bounded, and produce *names*, which is what the rest of the pipeline wants.

**It's bounded by the scope guard like everything else, and that matters more
here than anywhere.** A shared or cloud netblock contains other people's
machines. Every name this produces is checked against the engagement's allow
rules before anything touches it, and names outside them are dropped and
recorded. If your engagement is scoped to a domain rather than to a netblock,
that is the correct outcome — the finding you want from this engine is the
netblock inventory itself, which is reported either way.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import shutil

from ..models import Severity
from ..normalize import make_dedupe_key
from .registry import EngineSpec, register

# A /22 is 1024 addresses; anything larger is a cloud provider's range rather
# than an organisation's own, and reverse-resolving it tells you nothing.
MAX_PREFIX_HOSTS = 1024
MAX_LOOKUPS = 768


def parse_asnmap(output: str) -> list[dict]:
    """asnmap JSONL → netblock records."""
    out = []
    for line in (output or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(rec, dict):
            continue
        ranges = rec.get("as_range") or []
        if isinstance(ranges, str):
            ranges = [ranges]
        out.append({
            "asn": str(rec.get("as_number") or "").upper(),
            "org": rec.get("as_name") or "",
            "country": rec.get("as_country") or "",
            "ranges": [r for r in ranges if isinstance(r, str)],
        })
    return out


def usable_networks(records: list[dict], limit: int = MAX_LOOKUPS) -> list[str]:
    """Addresses worth reverse-resolving, from the netblocks announced.

    Oversized prefixes are skipped rather than truncated: the first 1024
    addresses of a /16 are not a meaningful sample of it, and pretending
    otherwise produces a confident-looking result built on nothing.
    """
    addresses: list[str] = []
    for rec in records:
        for cidr in rec["ranges"]:
            try:
                net = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue
            if net.version != 4 or net.num_addresses > MAX_PREFIX_HOSTS:
                continue
            for addr in net.hosts():
                addresses.append(str(addr))
                if len(addresses) >= limit:
                    return addresses
    return addresses


async def _asnmap(target: str, timeout: int = 90) -> str:
    if not shutil.which("asnmap"):
        return ""
    try:
        proc = await asyncio.create_subprocess_exec(
            "asnmap", "-d", target, "-json", "-silent",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except (asyncio.TimeoutError, OSError):
        return ""
    return out.decode("utf-8", "replace")


async def _ptr(ip: str, timeout: int = 5) -> str:
    try:
        proc = await asyncio.create_subprocess_exec(
            "dig", "+short", "+timeout=2", "+tries=1", "-x", ip,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except (asyncio.TimeoutError, OSError):
        return ""
    for line in out.decode().splitlines():
        name = line.strip().rstrip(".").lower()
        if name and not name.endswith(".arpa"):
            return name
    return ""


@register(EngineSpec(
    name="netblock",
    label="Expanding by ASN and netblock",
    description="Looks up the autonomous system announcing the target's addresses, "
                "then reverse-resolves its netblocks. Finds infrastructure the "
                "organisation owns under names that forward DNS never mentions.",
    phase="early",
    takes="seeds",
    produces="hosts",
    weight=8,
    limit=3,
    default_in=("deep",),
))
async def _engine(targets: list[str], ctx: dict) -> list[str]:
    log = ctx.get("log")

    if not shutil.which("asnmap"):
        if log:
            await log("warn", "[netblock] asnmap is not installed — skipping", "netblock")
        return []

    records: list[dict] = []
    for seed in targets[:3]:
        records += parse_asnmap(await _asnmap(seed))

    if not records:
        if log:
            await log("info", "[netblock] no ASN allocation found — the target's "
                              "addresses belong to a hosting provider, not to the "
                              "organisation", "netblock")
        return []

    if log:
        summary = ", ".join(
            f"{r['asn']} {r['org']} ({len(r['ranges'])} range(s))" for r in records[:4])
        await log("info", f"[netblock] {summary}", "netblock")

    addresses = usable_networks(records)
    if not addresses:
        if log:
            await log("info",
                      "[netblock] announced prefixes are too large to reverse-resolve "
                      "usefully — recorded as inventory only", "netblock")
        return []

    sem = asyncio.Semaphore(24)

    async def lookup(ip: str) -> str:
        async with sem:
            return await _ptr(ip)

    names = await asyncio.gather(*(lookup(a) for a in addresses),
                                 return_exceptions=True)
    found = sorted({n for n in names if isinstance(n, str) and n})

    if log:
        await log("info",
                  f"[netblock] {len(addresses)} reverse lookup(s) → {len(found)} "
                  f"name(s); scope filtering decides which are in play", "netblock")
    return found


@register(EngineSpec(
    name="asninfo",
    label="Recording netblock ownership",
    description="Reports which autonomous system and address ranges the target's "
                "infrastructure sits in — the inventory an audit needs, and the "
                "answer to whether an engagement should be scoped by netblock.",
    phase="early",
    takes="seeds",
    produces="findings",
    weight=2,
    limit=2,
    default_in=("standard", "deep"),
))
async def _asninfo(targets: list[str], ctx: dict) -> list[dict]:
    if not shutil.which("asnmap"):
        return []

    findings = []
    for seed in targets[:2]:
        records = parse_asnmap(await _asnmap(seed))
        if not records:
            continue
        rec = records[0]
        ranges = sorted({r for x in records for r in x["ranges"]})
        findings.append({
            "engine": "netblock", "rule_id": "asn-inventory",
            "name": f"Infrastructure sits in {rec['asn']} ({rec['org']})",
            "severity": Severity.info,
            "host": seed, "url": f"https://{seed}", "matched_at": seed,
            "description": (
                f"`{seed}` resolves into {rec['asn']}, announced by "
                f"{rec['org'] or 'an unnamed operator'}"
                f"{' in ' + rec['country'] if rec['country'] else ''}, covering "
                f"{len(ranges)} address range(s).\n\n"
                + ("Because the organisation holds its own allocation, address-based "
                   "enumeration is worth doing: hosts in these ranges belong to it "
                   "regardless of what domain they answer to, including acquisitions "
                   "and systems under other brands. If the engagement is scoped only "
                   "by domain, consider whether it should cover these ranges too — "
                   "and get that in writing before testing them.\n\n"
                   if len(ranges) <= 40 else
                   "The number of ranges suggests a hosting or cloud provider rather "
                   "than the organisation's own allocation, in which case other "
                   "customers share these addresses and they must not be treated as "
                   "in scope.\n\n")
                + "Recorded as inventory; nothing here was scanned."),
            "evidence": f"{rec['asn']} — {rec['org']}\n"
                        + "\n".join(f"  {r}" for r in ranges[:20])
                        + (f"\n  … {len(ranges) - 20} more" if len(ranges) > 20 else ""),
            "remediation": (
                "No defect. For the asset owner, this is the external inventory to "
                "reconcile against: every address announced under your ASN should "
                "map to a system someone owns and patches. The ones that don't are "
                "where incidents start."),
            "references": ["https://bgp.he.net/"],
            "tags": ["recon", "inventory"], "cve": [], "cwe": [],
            "cvss_score": None,
            "dedupe_key": make_dedupe_key("netblock", "asn-inventory", seed, seed),
            "raw": {"asn": rec["asn"], "org": rec["org"], "ranges": ranges[:200]},
        })
    return findings
