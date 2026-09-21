"""Scan pipeline.

    seeds -> subfinder -> scope filter -> naabu -> httpx -> scope filter
          -> nuclei -> normalize -> dedupe -> persist -> LLM triage

Scope is re-checked after every discovery stage, not just at the start.
That is the single most important property of this file.
"""

from __future__ import annotations

import asyncio
import traceback
from datetime import datetime, timezone

from sqlalchemy import select

from . import auth as authmod
from . import compliance, headers, intel, kev, normalize, updater, verify
from .config import MAX_CONCURRENCY, MAX_CONCURRENT_SCANS, MAX_RATE_LIMIT
from .db import SessionLocal
from .engines import extra, recon, registry
from .engines import nuclei as nuclei_engine
from .events import hub
from .models import Asset, Engagement, Finding, Scan, ScanLog, ScanState
from .scope import ScopeViolation, filter_hosts
from .triage import triage_findings

_semaphore = asyncio.Semaphore(MAX_CONCURRENT_SCANS)
_running: dict[int, asyncio.Task] = {}

# FastAPI runs `def` endpoints in an anyio worker thread, where there is no
# running event loop — so calling asyncio.create_task() from one raises
# "RuntimeError: no running event loop". We capture the main loop at startup
# and schedule onto it thread-safely instead.
_main_loop: asyncio.AbstractEventLoop | None = None


def bind_loop(loop: asyncio.AbstractEventLoop) -> None:
    """Called once from the app lifespan, on the event loop."""
    global _main_loop
    _main_loop = loop


def utcnow():
    return datetime.now(timezone.utc)


class ScanRunner:
    def __init__(self, scan_id: int, resume: bool = False):
        self.scan_id = scan_id
        # When resuming, stages already recorded as finished are skipped and the
        # hosts and URLs they produced are read back from the assets the scan
        # already saved, rather than rediscovered.
        self.resume = resume
        self._already_done: set[str] = set()
        self.rejected: list[dict] = []
        self._stage_plan: list[str] = []
        self._weights: list[int] = []
        self._total_weight = 1
        self._done_weight = 0
        self._active = ""
        self.auth_headers: dict = {}
        # Additional accounts. A second identity is what makes broken access
        # control testable: one account asking for another's data is the bug,
        # and you cannot see it with a single session.
        self.identities: list[dict] = []
        self.cdn_hosts: set[str] = set()

    # ---------- logging ----------

    async def log(self, level: str, message: str, stage: str = ""):
        with SessionLocal() as db:
            db.add(ScanLog(scan_id=self.scan_id, level=level, stage=stage, message=message[:4000]))
            db.commit()
        await hub.publish(self.scan_id, {
            "type": "log", "level": level, "stage": stage,
            "message": message, "ts": utcnow().isoformat(),
        })

    async def set_stage(self, stage: str, progress: float):
        with SessionLocal() as db:
            scan = db.get(Scan, self.scan_id)
            scan.stage_current = stage
            scan.progress = progress
            db.commit()
        await hub.publish(self.scan_id, {"type": "stage", "stage": stage, "progress": progress})

    # ---------- main ----------

    async def run(self):
        async with _semaphore:
            with SessionLocal() as db:
                scan = db.get(Scan, self.scan_id)
                engagement = db.get(Engagement, scan.engagement_id)
                seeds = list(scan.seeds)
                profile = scan.profile
                stages = list(scan.stages)
                if self.resume:
                    self._already_done = set(scan.completed_stages or [])
                else:
                    # A fresh run of an existing scan row starts clean, so a
                    # re-run is never mistaken for a resume.
                    scan.completed_stages = []
                allow = list(engagement.allow_rules)
                deny = list(engagement.deny_rules)
                self.auth_headers = dict(engagement.auth_headers or {})
                self.identities = list(engagement.auth_identities or [])
                auth_check_url = engagement.auth_check_url
                auth_check_string = engagement.auth_check_string
                expired = engagement.is_expired

                scan.state = ScanState.running
                scan.started_at = utcnow()
                db.commit()

            await hub.publish(self.scan_id, {"type": "state", "state": "running"})

            try:
                if expired:
                    raise ScopeViolation(
                        "Engagement authorization has expired. Renew it before scanning."
                    )
                if self.auth_headers:
                    ok, reason = await authmod.verify_session(
                        auth_check_url, auth_check_string, self.auth_headers, log=self.log)
                    await self.log('info' if ok else 'warn',
                                   f'{authmod.describe(self.auth_headers)} — {reason}', 'seed')
                    if not ok:
                        await self.log('warn', 'Continuing UNAUTHENTICATED — results will cover only the logged-out surface.', 'seed')
                        self.auth_headers = {}

                # Each additional account is verified independently. A second
                # identity that has silently expired doesn't produce a wrong
                # answer — it produces a *confident* wrong answer, because
                # "account B could not read account A's data" looks identical
                # whether B was blocked by authorization or by being logged out.
                if self.identities:
                    self.identities = await authmod.verify_identities(
                        self.identities, log=self.log)
                    live = [i["name"] for i in self.identities]
                    await self.log(
                        "info" if live else "warn",
                        f"{len(live)} additional identity(ies) verified"
                        + (f": {', '.join(live)}" if live else
                           " — access-control comparison is unavailable"),
                        "seed")
                await self._pipeline(seeds, profile, stages, allow, deny)
                await self._finish(ScanState.completed)
            except asyncio.CancelledError:
                await self._finish(ScanState.cancelled, "cancelled by operator")
                raise
            except Exception as exc:  # noqa: BLE001
                await self.log("error", f"{type(exc).__name__}: {exc}")
                await self.log("debug", traceback.format_exc())
                await self._finish(ScanState.failed, str(exc))
            finally:
                _running.pop(self.scan_id, None)

    async def _finish(self, state: ScanState, error: str = ""):
        with SessionLocal() as db:
            scan = db.get(Scan, self.scan_id)
            scan.state = state
            scan.error = error
            scan.finished_at = utcnow()
            scan.progress = 1.0
            scan.rejected_hosts = self.rejected
            counts = {}
            for f in db.scalars(select(Finding).where(Finding.scan_id == self.scan_id)):
                counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
            stats = dict(scan.stats or {})
            stats["findings_by_severity"] = counts
            scan.stats = stats
            db.commit()
        await hub.publish(self.scan_id, {"type": "state", "state": state.value, "error": error})

    # ---------- stages ----------

    @staticmethod
    def _host_of(item: str) -> str:
        """Hostname from either a bare host or a full URL."""
        if "://" in item:
            from urllib.parse import urlparse
            return (urlparse(item).hostname or item).lower()
        return item.split("/")[0].split(":")[0].lower()

    def _guard(self, hosts, allow, deny, stage):
        kept, rejected = filter_hosts(hosts, allow, deny)
        for d in rejected:
            self.rejected.append({"host": d.host, "reason": d.reason, "stage": stage})
        return kept

    # ---------- progress accounting ----------

    def _plan(self, stages: list[str]) -> None:
        """Weight each stage by roughly how long it takes, so the percentage
        moves at a believable rate instead of jumping 0 -> 90 -> 100."""
        # Core recon stages have data dependencies and stay hardcoded; every
        # registered engine contributes its own weight, so a new engine gets a
        # sensible progress share without touching this file.
        weights = {
            "seed": 1, "subfinder": 6, "dnsx": 3, "cdncheck": 2, "naabu": 10,
            "httpx": 6, "nmap": 18, "tlsx": 4, "ffuf": 15, "katana": 10,
            "nuclei": 45, "permute": 12, "correlate": 2, "verify": 10,
            "intel": 8, "triage": 12,
            **registry.weights(),
        }
        self._stage_plan = (["seed"] + [s for s in stages if s in weights]
                            + ["correlate", "verify"])
        if "triage" in stages:
            self._stage_plan.append("intel")
        self._weights = [weights.get(s, 5) for s in self._stage_plan]
        self._total_weight = sum(self._weights) or 1
        self._done_weight = 0

    async def _begin(self, stage: str):
        """Mark a stage active and publish the percentage it starts at."""
        self._active = stage
        pct = self._done_weight / self._total_weight
        await self.set_stage(stage, round(pct, 4))

    async def _end(self, stage: str):
        if stage in self._stage_plan:
            self._done_weight += self._weights[self._stage_plan.index(stage)]
        pct = min(self._done_weight / self._total_weight, 0.999)
        await hub.publish(self.scan_id, {"type": "progress", "progress": round(pct, 4)})
        with SessionLocal() as db:
            scan = db.get(Scan, self.scan_id)
            if scan:
                scan.progress = round(pct, 4)
                # Recorded here rather than at the end of the run because the
                # whole point is surviving a run that never reaches its end.
                done = list(scan.completed_stages or [])
                if stage not in done:
                    done.append(stage)
                    scan.completed_stages = done
                db.commit()

    async def _run_engine_phase(self, phase: str, stages: list[str],
                                targets: dict, allow, deny):
        """Run every registered engine for this phase, concurrently.

        Engines declare what they need (seeds/hosts/urls/assets) and what they
        cost; the orchestrator just supplies it. Adding a detection therefore
        costs one file and no edits here — the point of the registry.
        """
        specs = registry.for_phase(phase, stages)
        if not specs:
            return

        tasks = []
        for spec in specs:
            items = list(targets.get(spec.takes) or [])
            if spec.skip_cdn and self.cdn_hosts:
                items = [i for i in items if i not in self.cdn_hosts]
            if spec.limit:
                items = items[:spec.limit]
            if not items:
                await self.log("info", f"[{spec.name}] no targets — skipped", spec.name)
                continue
            # Engines get the session, plus the scope rules that decide which
            # hosts may receive it. Without this every engine silently tests
            # the logged-out view of an application the operator configured
            # credentials for — which is the failure mode that makes a scan
            # look thorough while covering a fraction of the surface.
            tasks.append((spec.name, spec.run(items, {
                "log": self.log,
                "scan_id": self.scan_id,
                "auth_headers": self.auth_headers,
                "identities": self.identities,
                "allow": allow,
                "deny": deny,
            })))

        produced: dict[str, list[str]] = {"hosts": [], "urls": []}

        async def handler(name, result):
            spec = registry.get(name)
            kind = spec.produces if spec else "findings"

            if kind in ("hosts", "urls"):
                # Discovery engines widen the attack surface — but every asset
                # they return is scope-checked before it can be touched, exactly
                # like subdomain enumeration.
                items = [str(i) for i in (result or []) if i]
                in_scope = self._guard(
                    [self._host_of(i) for i in items], allow, deny, name)
                allowed = {h for h in in_scope}
                kept = [i for i in items if self._host_of(i) in allowed]
                dropped = len(items) - len(kept)
                produced[kind] += kept
                await self.log("info",
                               f"[{name}] {len(kept)} new {kind}"
                               + (f", {dropped} out of scope" if dropped else ""),
                               name)
                return

            saved = 0
            for finding in result or []:
                if not self._guard([finding["host"]], allow, deny, name):
                    continue
                if await self._save_finding(finding):
                    saved += 1
            await self.log("info", f"[{name}] {saved} finding(s)", name)

        await self._run_group(tasks, handler)
        return produced

    async def _run_group(self, tasks: list[tuple[str, object]], handler):
        """Run independent stages concurrently, reporting each as it finishes.

        Previously this used asyncio.gather and only announced the first stage,
        so the UI sat on "Identifying services and versions" for the whole group
        and the percentage didn't move until every task was done. Now each
        completion updates the display immediately.
        """
        if not tasks:
            return
        pending = {asyncio.ensure_future(coro): name for name, coro in tasks}
        names = [n for n, _ in tasks]
        await self._begin(names[0])
        await self.log("info", f"running concurrently: {', '.join(names)}",
                       names[0])

        while pending:
            done, _ = await asyncio.wait(pending.keys(),
                                         return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                name = pending.pop(task)
                try:
                    result = task.result()
                except asyncio.CancelledError:
                    raise
                except Exception as exc:  # noqa: BLE001
                    await self.log("warn", f"[{name}] failed: {exc}", name)
                else:
                    await handler(name, result)
                await self._end(name)
                # Point the UI at whatever is still running.
                if pending:
                    await self.set_stage(next(iter(pending.values())),
                                         self._done_weight / self._total_weight)

    async def _sub_progress(self, stage: str, fraction: float):
        """Fine-grained movement inside a long stage (nuclei mostly)."""
        if stage not in self._stage_plan:
            return
        w = self._weights[self._stage_plan.index(stage)]
        pct = min((self._done_weight + w * max(0.0, min(1.0, fraction))) / self._total_weight, 0.999)
        await hub.publish(self.scan_id, {"type": "progress", "progress": round(pct, 4)})

    # ---------- the pipeline ----------

    async def _pipeline(self, seeds, profile, stages, allow, deny):
        cfg = recon.PROFILES.get(profile, recon.PROFILES["standard"])
        rate = min(cfg["rate"], MAX_RATE_LIMIT)
        conc = min(cfg["conc"], MAX_CONCURRENCY)

        # Plan against the *original* stage list so the percentage still means
        # the same thing on a resumed run, then credit the work already done.
        # Planning against only what is left would show a scan that died at 80%
        # restarting at 0% and racing to 100% having done less.
        self._plan(stages)
        if self._already_done:
            for finished in self._already_done:
                if finished in self._stage_plan:
                    self._done_weight += self._weights[self._stage_plan.index(finished)]
            stages = [st for st in stages if st not in self._already_done]
            await self.log(
                "info",
                f"resuming: {len(self._already_done)} stage(s) already done "
                f"({', '.join(sorted(self._already_done))}) — skipping them",
                "seed")

        # --- validate the seeds themselves ---
        await self._begin("seed")
        hosts = self._guard(seeds, allow, deny, "seed")
        if not hosts:
            raise ScopeViolation(
                "No seed target is in scope for this engagement. "
                "Check the allowlist rules before retrying."
            )
        await self.log("info", f"{len(hosts)} seed host(s) in scope", "seed")
        await self._end("seed")

        # --- passive subdomain enumeration ---
        if "subfinder" in stages:
            await self._begin("subfinder")
            apex = [h for h in hosts if not h.replace(".", "").isdigit()]
            discovered = await recon.subfinder(apex, log=self.log)
            await self.log("info", f"subfinder returned {len(discovered)} name(s)", "subfinder")
            # Enumeration routinely surfaces third-party hosts — re-check scope.
            in_scope = self._guard(discovered, allow, deny, "subfinder")
            dropped = len(discovered) - len(in_scope)
            if dropped:
                await self.log("warn", f"dropped {dropped} out-of-scope host(s)", "subfinder")
            hosts = sorted(set(hosts) | set(in_scope))
            await self._end("subfinder")

        # --- permutation: find hosts nobody published ---
        if "permute" in stages:
            await self._begin("permute")
            apex = [h for h in seeds if not h.replace(".", "").isdigit()]
            guessed = await recon.permute(hosts, apex, rate=rate, log=self.log)
            # Same scope discipline as enumeration: a guessed name that lands
            # outside the allowlist is dropped before anything touches it.
            in_scope = self._guard(guessed, allow, deny, "permute")
            dropped = len(guessed) - len(in_scope)
            if dropped:
                await self.log("warn", f"dropped {dropped} out-of-scope host(s)", "permute")
            hosts = sorted(set(hosts) | set(in_scope))
            await self._save_stat("permuted_hosts", len(in_scope))
            await self._end("permute")

        await self._save_stat("hosts_in_scope", len(hosts))

        # --- registered early-phase engines (operate on the seed domains) ---
        produced = await self._run_engine_phase(
            "early", stages, {"seeds": seeds, "hosts": hosts}, allow, deny)

        # URLs found before probing (archived endpoints, for instance) can't join
        # the URL list yet — nothing has been probed. Their *hosts* go into the
        # probe list now, and the URLs themselves are held until after httpx so
        # crawling and template scanning both see them.
        early_urls: list[str] = list(produced["urls"]) if produced else []
        if produced:
            new_hosts = set(produced["hosts"]) | {
                self._host_of(u) for u in early_urls}
            new_hosts -= set(hosts)
            if new_hosts:
                before = len(hosts)
                hosts = sorted(set(hosts) | new_hosts)
                await self.log("info",
                               f"attack surface widened: {len(hosts) - before} host(s) "
                               f"from passive discovery", "discovery")
                await self._save_stat("hosts_in_scope", len(hosts))

        # --- DNS + CDN identification run concurrently: both are network-bound
        #     lookups against different services, so serialising them wastes time.
        dns_tasks = []
        if "dnsx" in stages:
            dns_tasks.append(("dnsx", extra.dnsx(hosts, log=self.log)))
        if "cdncheck" in stages:
            dns_tasks.append(("cdncheck", extra.cdncheck(hosts, log=self.log)))

        if dns_tasks:
            await self._begin(dns_tasks[0][0])
            results = await asyncio.gather(*(t[1] for t in dns_tasks),
                                           return_exceptions=True)
            for (name, _), result in zip(dns_tasks, results, strict=True):
                if isinstance(result, Exception):
                    await self.log("warn", f"[{name}] failed: {result}", name)
                    await self._end(name)
                    continue
                if name == "dnsx":
                    takeovers = 0
                    for rec in result:
                        if not self._guard([rec["host"]], allow, deny, "dnsx"):
                            continue
                        finding = normalize.from_dnsx_takeover(rec)
                        if finding and await self._save_finding(finding):
                            takeovers += 1
                    await self.log("info", f"resolved {len(result)} name(s), "
                                           f"{takeovers} dangling", "dnsx")
                elif name == "cdncheck" and result:
                    self.cdn_hosts = set(result)
                    await self._save_stat("cdn_fronted", len(result))
                    await self.log("info", f"{len(result)} host(s) behind a CDN/WAF — "
                                           f"a quiet result there may mean blocked, "
                                           f"not secure", "cdncheck")
                await self._end(name)

        # --- port discovery ---
        probe_targets = list(hosts)
        if "naabu" in stages and cfg["ports"]:
            await self._begin("naabu")
            port_hosts = [h for h in hosts if h not in self.cdn_hosts] or hosts
            open_ports = await recon.naabu(port_hosts, ports=cfg["ports"],
                                           rate=rate, log=self.log)
            await self.log("info", f"{len(open_ports)} open port(s) found", "naabu")
            probe_targets = sorted({f"{p['host']}:{p['port']}" for p in open_ports
                                    if p["port"]}) or hosts
            await self._save_stat("open_ports", len(open_ports))
            await self._end("naabu")

        # --- live HTTP probing ---
        # Unlike the stages above, this one is not optional, so skipping it on a
        # resume is explicit. The assets it produced were already written to the
        # database, so a resumed scan reads them back instead of probing every
        # host again — which is the expensive half of getting back to where the
        # scan died.
        await self._begin("httpx")
        if "httpx" in self._already_done:
            assets = self._saved_assets()
            await self.log("info",
                           f"resuming: {len(assets)} live service(s) restored "
                           f"from the last run, not re-probed", "httpx")
        else:
            assets = await recon.httpx(probe_targets, concurrency=conc, rate=rate,
                                       auth_headers=self.auth_headers, log=self.log)
            assets = [a for a in assets if self._guard([a["host"]], allow, deny, "httpx")]
            await self.log("info", f"{len(assets)} live HTTP service(s)", "httpx")
            await self._save_assets(assets)
            await self._save_stat("live_services", len(assets))

        # heuristic findings + strict header audit
        for a in assets:
            f = normalize.from_httpx_exposure(a)
            if f:
                await self._save_finding(f)

        header_hits = 0
        for a in assets:
            for finding in headers.audit(a):
                if not self._guard([finding["host"]], allow, deny, "headers"):
                    continue
                if await self._save_finding(finding):
                    header_hits += 1
        if header_hits:
            await self.log("info", f"header audit: {header_hits} issue(s)", "httpx")
        await self._end("httpx")

        urls = [a["url"] for a in assets if a["url"]]
        if early_urls:
            live_hosts = {a["host"] for a in assets}
            # Only keep archived URLs whose host actually answered — a dead host
            # produces nothing but timeouts in every later stage.
            revived = [u for u in early_urls if self._host_of(u) in live_hosts]
            if revived:
                urls = sorted(set(urls) | set(revived))
                await self.log("info",
                               f"{len(revived)} archived URL(s) on live hosts folded "
                               f"into the scan", "discovery")
        if not urls:
            await self.log("warn", "no live HTTP services — nothing further to test", "httpx")
            return

        # Technology fingerprints drive nuclei template selection later.
        detected_tech = sorted({t for a in assets for t in (a.get("tech") or [])})
        if detected_tech:
            await self.log("info", f"stack: {', '.join(detected_tech[:12])}", "httpx")
            await self._save_stat("tech", detected_tech)

        # --- nmap, tlsx and ffuf are independent of each other: run together ---
        # Port scanning a CDN-fronted host scans the CDN's edge, not the target.
        # It is slow, noisy and tells you nothing about the origin.
        scan_hosts = [h for h in hosts if h not in self.cdn_hosts]
        if self.cdn_hosts:
            await self.log("warn",
                           f"skipping port/service scans on {len(self.cdn_hosts)} "
                           f"CDN-fronted host(s) — those scan the CDN edge, not the "
                           f"origin", "nmap")

        mid_tasks = []
        if "nmap" in stages and scan_hosts:
            mid_tasks.append(("nmap", extra.nmap(
                scan_hosts, top_ports=1000 if profile == "thorough" else 200,
                log=self.log)))
        if "tlsx" in stages:
            mid_tasks.append(("tlsx", extra.tlsx([a["host"] for a in assets], log=self.log)))
        if "ffuf" in stages:
            mid_tasks.append(("ffuf", self._run_ffuf(urls, rate)))

        async def _mid_handler(name, result):
            if name == "nmap":
                risky = 0
                for svc in result:
                    if not self._guard([svc["host"]], allow, deny, "nmap"):
                        continue
                    finding = normalize.from_nmap_service(svc)
                    if finding and await self._save_finding(finding):
                        risky += 1
                await self.log("info", f"{len(result)} service(s) identified, "
                                       f"{risky} risky", "nmap")
                await self._save_stat("services_identified", len(result))
            elif name == "tlsx":
                issues = 0
                for rec in result:
                    finding = normalize.from_tlsx(rec)
                    if not finding:
                        continue
                    if not self._guard([finding["host"]], allow, deny, "tlsx"):
                        continue
                    if await self._save_finding(finding):
                        issues += 1
                await self.log("info", f"TLS checked on {len(result)} endpoint(s), "
                                       f"{issues} issue(s)", "tlsx")
            elif name == "ffuf":
                found = [u for u in result if self._guard([u], allow, deny, "ffuf")]
                await self.log("info", f"content discovery found {len(found)} path(s)",
                               "ffuf")
                nonlocal_urls.extend(found)
                await self._save_stat("discovered_paths", len(found))

        nonlocal_urls: list[str] = []
        await self._run_group(mid_tasks, _mid_handler)
        if nonlocal_urls:
            urls = sorted(set(urls) | set(nonlocal_urls))

        # --- registered post-HTTP engines (operate on live URLs and hosts) ---
        produced = await self._run_engine_phase(
            "post_http", stages,
            {"urls": urls, "hosts": hosts, "assets": assets, "seeds": seeds},
            allow, deny)
        if produced and produced["urls"]:
            before = len(urls)
            urls = sorted(set(urls) | set(produced["urls"]))
            await self.log("info",
                           f"attack surface widened: {len(urls) - before} URL(s) "
                           f"from discovery engines", "discovery")
            await self._save_stat("discovered_urls", len(urls))

        # --- crawl ---
        nuclei_targets = list(urls)
        if "katana" in stages:
            await self._begin("katana")
            endpoints = await recon.katana(urls, concurrency=min(conc, 10),
                                           auth_headers=self.auth_headers, log=self.log)
            endpoints = [e for e in endpoints if self._guard([e], allow, deny, "katana")]
            await self.log("info", f"crawled {len(endpoints)} endpoint(s)", "katana")
            nuclei_targets = sorted(set(urls) | set(endpoints))[:5000]
            await self._end("katana")

        # --- nuclei ---
        if "nuclei" in stages:
            await self._begin("nuclei")
            await self.log("info", f"testing {len(nuclei_targets)} target(s) — "
                                   f"this is the long part", "nuclei")
            count = 0
            seen_progress = {"pct": 0.0}

            async def nuclei_log(level, message, stage=""):
                # Mirror nuclei's own progress into the scan percentage.
                if "% —" in message:
                    try:
                        pct = float(message.split("]")[1].split("%")[0].strip()) / 100
                        seen_progress["pct"] = pct
                        await self._sub_progress("nuclei", pct)
                    except (ValueError, IndexError):
                        pass
                await self.log(level, message, stage or "nuclei")

            async for rec in nuclei_engine.scan(
                nuclei_targets,
                severities=cfg["nuclei_sev"],
                rate=rate, concurrency=conc,
                tech=detected_tech,
                deep=(profile == "thorough"),
                # Community template repositories synced by the updater. Empty
                # until the first update run, so this changes nothing until
                # there is something to add.
                community=updater.extra_template_paths() if profile != "passive" else [],
                auth_headers=self.auth_headers,
                log=nuclei_log,
            ):
                finding = normalize.from_nuclei(rec)
                if not self._guard([finding["host"]], allow, deny, "nuclei"):
                    continue
                if await self._save_finding(finding):
                    count += 1
            await self.log("info", f"nuclei produced {count} unique finding(s)", "nuclei")
            await self._end("nuclei")

        # --- correlation: chain findings into attack paths ---
        await self._begin("correlate")
        chains = intel.correlate(self.scan_id)
        for chain in chains:
            await self._save_finding(chain)
        if chains:
            await self.log("info", f"correlated {len(chains)} attack path(s)", "correlate")
        await self._end("correlate")

        # --- independent re-verification ---
        # Runs before triage on purpose. Triage is the LLM reading findings;
        # verification is the machine re-testing them. If a finding doesn't
        # reproduce, no amount of LLM commentary makes it submittable, and
        # knowing that first stops the model from writing a confident narrative
        # around something that isn't there.
        await self._begin("verify")
        try:
            checked, ready = await verify.verify_scan(
                self.scan_id,
                ctx={"auth_headers": self.auth_headers, "allow": allow, "deny": deny},
                log=self.log)
            await self.log("info",
                           f"re-verified {checked} finding(s) — {ready} reproduce "
                           f"with evidence and are ready to submit", "verify")
            await self._save_stat("submittable", ready)
        except Exception as exc:  # noqa: BLE001
            # Verification is additive. A failure here must never lose findings.
            await self.log("warn", f"verification failed: {exc}", "verify")
        await self._end("verify")

        # --- LLM triage ---
        if "triage" in stages:
            await self._begin("triage")
            n = await triage_findings(self.scan_id, log=self.log)
            await self.log("info", f"triaged {n} finding(s)", "triage")
            await self._end("triage")

            # --- attack surface analysis: where a human should look next ---
            await self._begin("intel")
            analysis = await intel.analyze(self.scan_id, seeds[0], log=self.log)
            if analysis:
                added = intel.store_intel(self.scan_id, analysis)
                smap = analysis.get("surface", {})
                await self.log("info",
                               f"attack surface: {smap.get('total_urls', 0)} endpoint(s) "
                               f"across {len(smap.get('categories', []))} category(ies), "
                               f"{added} lead(s) to investigate", "intel")
            await self._end("intel")

        await self.set_stage("done", 1.0)

    async def _run_ffuf(self, urls: list[str], rate: int) -> list[str]:
        """Content discovery across the first few hosts, concurrently."""
        targets = urls[:5]
        results = await asyncio.gather(
            *(extra.ffuf(u, rate=min(rate, 40), log=self.log) for u in targets),
            return_exceptions=True,
        )
        found: list[str] = []
        for r in results:
            if isinstance(r, Exception):
                continue
            found += [h["url"] for h in r if h.get("url")]
        return found

    # ---------- persistence ----------

    async def _save_stat(self, key, value):
        with SessionLocal() as db:
            scan = db.get(Scan, self.scan_id)
            stats = dict(scan.stats or {})
            stats[key] = value
            scan.stats = stats
            db.commit()

    async def _save_assets(self, assets):
        with SessionLocal() as db:
            for a in assets:
                db.add(Asset(
                    scan_id=self.scan_id, host=a["host"], url=a["url"], ip=a.get("ip", ""),
                    port=a.get("port"), status_code=a.get("status_code"),
                    title=a.get("title", ""), tech=a.get("tech", []), raw=a.get("raw", {}),
                ))
            db.commit()
        await hub.publish(self.scan_id, {"type": "assets", "count": len(assets)})

    def _saved_assets(self) -> list[dict]:
        """The assets this scan already discovered, in the shape httpx returns.

        Resume leans on these rather than on a separate checkpoint blob: they
        are written as the scan runs and are the same data the later stages
        would have been handed anyway, so there is no second copy of the truth
        to drift.
        """
        with SessionLocal() as db:
            rows = db.scalars(
                select(Asset).where(Asset.scan_id == self.scan_id)).all()
            return [{
                "host": r.host, "url": r.url, "ip": r.ip, "port": r.port,
                "status_code": r.status_code, "title": r.title,
                "tech": list(r.tech or []), "raw": dict(r.raw or {}),
            } for r in rows]

    async def _save_finding(self, data: dict) -> bool:
        """Insert, or bump the occurrence counter if we've seen it. Returns
        True only for genuinely new findings.

        (This docstring used to sit *below* the first statement, which made it
        a discarded string expression rather than a docstring — the function
        had no help text at all.)
        """
        compliance.enrich(data)

        # A CVE that is being exploited in the wild outranks a higher-scoring
        # one that nobody has ever weaponised. CVSS can't express that, because
        # it scores the vulnerability rather than the threat.
        exploited = kev.apply(data)
        if exploited:
            await self.log(
                "warn",
                f"[kev] {data.get('rule_id')} on {data.get('host')} is on CISA's "
                f"actively-exploited list "
                f"({', '.join(e['cve'] for e in exploited[:3])})"
                + (" — used in ransomware campaigns"
                   if any(e["ransomware"] for e in exploited) else ""),
                "kev")

        with SessionLocal() as db:
            existing = db.scalar(
                select(Finding).where(
                    Finding.scan_id == self.scan_id,
                    Finding.dedupe_key == data["dedupe_key"],
                )
            )
            if existing:
                existing.occurrences += 1
                db.commit()
                return False

            finding = Finding(scan_id=self.scan_id, **data)
            db.add(finding)
            db.commit()
            payload = {
                "id": finding.id, "name": finding.name,
                "severity": finding.severity.value, "host": finding.host,
                "url": finding.url, "engine": finding.engine,
            }
        await hub.publish(self.scan_id, {"type": "finding", "finding": payload})
        return True


# ---------- public API ----------

def _spawn(scan_id: int, resume: bool = False) -> None:
    """Create the task. Must run ON the event loop."""
    if scan_id in _running:
        return
    runner = ScanRunner(scan_id, resume=resume)
    _running[scan_id] = asyncio.create_task(runner.run())


def start_scan(scan_id: int, resume: bool = False) -> None:
    """Safe to call from either an async endpoint or a threadpool one."""
    if scan_id in _running:
        return
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        # We're on a worker thread — hand it to the main loop.
        if _main_loop is None or _main_loop.is_closed():
            raise RuntimeError(
                "Scan scheduler is not ready — the event loop was never bound. "
                "This is a bug; restart the backend."
            ) from None
        _main_loop.call_soon_threadsafe(_spawn, scan_id, resume)
        return
    _spawn(scan_id, resume)


class NotResumable(Exception):
    """The scan is not in a state that can be resumed."""


def resume_scan(scan_id: int) -> int:
    """Continue a scan that stopped before it finished.

    Only a scan that actually stopped short can be resumed: a completed one has
    nothing left to do, and a running one would end up with two runners writing
    the same rows. Returns how many stages will be skipped.
    """
    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        if scan is None:
            raise NotResumable(f"scan {scan_id} not found")
        if scan_id in _running or scan.state == ScanState.running:
            raise NotResumable(f"scan {scan_id} is still running")
        if scan.state == ScanState.completed:
            raise NotResumable(f"scan {scan_id} already completed")
        already = len(scan.completed_stages or [])

    start_scan(scan_id, resume=True)
    return already


def _force_state(scan_id: int, state: ScanState, error: str) -> bool:
    """Write a terminal state directly. Used when no task is tracking the scan."""
    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        if not scan or scan.state not in (ScanState.queued, ScanState.running):
            return False
        scan.state = state
        scan.error = error
        scan.finished_at = utcnow()
        scan.progress = 1.0
        db.commit()
    return True


def cancel_scan(scan_id: int) -> str:
    """Cancel a scan. Always leaves it in a terminal state.

    The important case is the second one: if the backend restarted while a scan
    was running, the asyncio task is gone but the database row still says
    "running" forever. Previously this returned 409 and the scan stayed stuck
    with no way out of the UI.

    Returns "cancelled" (task was live) or "forced" (row reconciled).
    """
    task = _running.get(scan_id)
    if task:
        try:
            asyncio.get_running_loop()
            task.cancel()
        except RuntimeError:
            # Called from a threadpool endpoint — Task.cancel() isn't thread-safe.
            if _main_loop is not None and not _main_loop.is_closed():
                _main_loop.call_soon_threadsafe(task.cancel)
        return "cancelled"

    if _force_state(scan_id, ScanState.cancelled,
                    "Cancelled — no running task was found. The backend was most "
                    "likely restarted while this scan was in progress."):
        return "forced"
    return "already-finished"


def reconcile_orphans() -> int:
    """Mark scans that were interrupted by a restart.

    Called at startup. A process that dies mid-scan leaves its row saying
    "running", and nothing else will ever change that.
    """
    with SessionLocal() as db:
        stuck = list(db.scalars(
            select(Scan).where(Scan.state.in_([ScanState.queued, ScanState.running]))))
        for scan in stuck:
            scan.state = ScanState.failed
            scan.error = ("Interrupted — the backend restarted while this scan was "
                          "running. Start a new scan to retry.")
            scan.finished_at = utcnow()
            scan.progress = 1.0
        db.commit()
        return len(stuck)


# A scan with no log output for this long is not progressing. nuclei reports
# every 10 seconds, so 45 minutes of silence means something has genuinely hung.
STALL_SECONDS = 45 * 60


async def watchdog(interval: int = 300) -> None:
    """Fail scans that have stopped producing output.

    Without this a wedged subprocess leaves the scan "running" indefinitely,
    holding a concurrency slot and showing a progress bar that never moves.
    """
    while True:
        try:
            await asyncio.sleep(interval)
            now = utcnow()
            with SessionLocal() as db:
                running = list(db.scalars(
                    select(Scan).where(Scan.state == ScanState.running)))
                for scan in running:
                    last = db.scalar(
                        select(ScanLog.created_at)
                        .where(ScanLog.scan_id == scan.id)
                        .order_by(ScanLog.id.desc()).limit(1))
                    marker = last or scan.started_at
                    if not marker:
                        continue
                    if marker.tzinfo is None:
                        marker = marker.replace(tzinfo=timezone.utc)
                    if (now - marker).total_seconds() < STALL_SECONDS:
                        continue

                    task = _running.get(scan.id)
                    if task:
                        task.cancel()
                    scan.state = ScanState.failed
                    scan.error = (f"Stalled — no output for over "
                                  f"{STALL_SECONDS // 60} minutes. The scan was stopped "
                                  f"automatically.")
                    scan.finished_at = now
                    scan.progress = 1.0
                    db.commit()
                    await hub.publish(scan.id, {"type": "state", "state": "failed",
                                                "error": scan.error})
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001  — a watchdog must never die
            continue


def is_running(scan_id: int) -> bool:
    return scan_id in _running
