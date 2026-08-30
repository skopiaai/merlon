"""Nuclei wrapper — the detection workhorse.

Two things make this faster and more thorough than a single blind run:

1. **Tech-aware targeting.** httpx tells us what the target actually runs.
   A WordPress site gets the full WordPress template set at every severity;
   it doesn't get 400 Jenkins checks. That's both better coverage where it
   matters and far less wasted time.

2. **Two passes.** A broad severity-filtered sweep catches anything serious
   regardless of stack, then a narrow tech-specific sweep goes deep on what's
   actually there. Dedupe in the orchestrator makes the overlap free.
"""

from __future__ import annotations

import asyncio
from typing import AsyncIterator, Callable

from ..auth import header_args as _auth_args
from .base import LogFn, require_binary, stream_jsonl

# Excluded by default: intrusive, destructive, or slow enough that they should
# be an explicit opt-in rather than something you trip over.
DEFAULT_EXCLUDE_TAGS = ["dos", "fuzz", "intrusive", "brute-force"]

# httpx fingerprint substring -> nuclei tags worth running deeply.
TECH_TAGS: dict[str, list[str]] = {
    "wordpress": ["wordpress", "wp-plugin", "wp-theme"],
    "drupal": ["drupal"],
    "joomla": ["joomla"],
    "magento": ["magento"],
    "shopify": ["shopify"],
    "laravel": ["laravel"],
    "symfony": ["symfony"],
    "django": ["django"],
    "flask": ["flask"],
    "rails": ["rails", "ruby"],
    "express": ["nodejs", "express"],
    "next.js": ["nextjs"],
    "nuxt": ["nuxt"],
    "react": ["javascript"],
    "angular": ["angular"],
    "spring": ["springboot", "java"],
    "tomcat": ["tomcat", "java"],
    "jboss": ["jboss", "java"],
    "weblogic": ["weblogic"],
    "jenkins": ["jenkins"],
    "gitlab": ["gitlab"],
    "github": ["github"],
    "grafana": ["grafana"],
    "kibana": ["kibana", "elastic"],
    "elasticsearch": ["elastic"],
    "prometheus": ["prometheus"],
    "jira": ["jira", "atlassian"],
    "confluence": ["confluence", "atlassian"],
    "phpmyadmin": ["phpmyadmin"],
    "nginx": ["nginx"],
    "apache": ["apache"],
    "iis": ["iis", "microsoft"],
    "openresty": ["nginx"],
    "cloudflare": ["cloudflare"],
    "php": ["php"],
    "asp.net": ["aspx", "microsoft"],
    "graphql": ["graphql"],
    "swagger": ["swagger", "api"],
    "wso2": ["wso2"],
    "zimbra": ["zimbra"],
    "exchange": ["exchange", "microsoft"],
    "citrix": ["citrix"],
    "fortinet": ["fortinet"],
    "vmware": ["vmware"],
    "oracle": ["oracle"],
    "sap": ["sap"],
}

# Always worth running regardless of stack — these are the categories that
# produce real bounty findings rather than hardening noise.
ALWAYS_TAGS = [
    "exposure", "config", "backup", "takeover", "default-login",
    "auth-bypass", "rce", "lfi", "ssrf", "sqli", "xss", "redirect",
    "cve", "misconfig", "disclosure",
]


def tags_for(tech: list[str]) -> list[str]:
    """Map detected technologies onto nuclei tags."""
    found: set[str] = set()
    for item in tech or []:
        low = item.lower()
        for key, tags in TECH_TAGS.items():
            if key in low:
                found.update(tags)
    return sorted(found)


def _base_argv(severities: str, rate: int, concurrency: int,
               exclude_tags: list[str] | None) -> list[str]:
    return [
        "nuclei", "-jsonl", "-silent", "-no-color",
        "-severity", severities,
        "-rate-limit", str(rate),
        "-concurrency", str(concurrency),
        "-timeout", "8", "-retries", "1",
        "-max-host-error", "30",       # stop hammering a host that keeps failing
        "-disable-update-check",
        # Progress to stderr. This stage runs thousands of templates; without
        # it the UI looks frozen for twenty minutes.
        "-stats", "-stats-interval", "10",
        "-exclude-tags", ",".join(exclude_tags or DEFAULT_EXCLUDE_TAGS),
    ]


def split_severities(severities: str) -> tuple[str, str]:
    """(urgent, rest) — what to run first and what can wait.

    Time-to-first-critical is the number that matters in a bug bounty, not
    total runtime. A single sweep at `low,medium,high,critical` runs templates
    in whatever order they load, so a critical can surface forty minutes in,
    behind three thousand informational checks. Splitting the pass costs a few
    per cent in total time and moves criticals to the first few minutes.
    """
    wanted = [s.strip() for s in (severities or "").split(",") if s.strip()]
    urgent = [s for s in wanted if s in ("critical", "high")]
    rest = [s for s in wanted if s not in ("critical", "high")]
    return ",".join(urgent), ",".join(rest)


async def scan(
    targets: list[str],
    *,
    severities: str = "low,medium,high,critical",
    rate: int = 60,
    concurrency: int = 15,
    tech: list[str] | None = None,
    extra_tags: list[str] | None = None,
    exclude_tags: list[str] | None = None,
    templates: list[str] | None = None,
    community: list[str] | None = None,
    deep: bool = False,
    auth_headers: dict | None = None,
    log: LogFn | None = None,
    on_progress: Callable[[str, float], None] | None = None,
) -> AsyncIterator[dict]:
    """Yield raw nuclei records, most urgent first.

    Four passes, ordered so that anything worth reporting immediately arrives
    immediately:

      1. critical and high only — the pass that decides whether you have
         something to submit, finished in minutes rather than hours
      2. everything else at the requested severities
      3. technology-specific templates for the stack httpx actually detected
      4. community template repositories, if any have been synced

    Passes 2–4 are where the long tail lives; a scan cancelled after pass 1
    has still done the part that pays.
    """
    if not targets:
        return

    require_binary("nuclei")
    tech_tags = tags_for(tech or [])
    urgent, rest = split_severities(severities)

    async def run(argv: list[str], label: str, timeout: int):
        if log:
            await log("info", f"[nuclei] {label}", "nuclei")
        async for rec in stream_jsonl(argv, engine="nuclei", input_lines=targets,
                                      input_flag="-list", log=log, timeout=timeout):
            yield rec

    def build(sev: str) -> list[str]:
        argv = _base_argv(sev, rate, concurrency, exclude_tags)
        argv += _auth_args(auth_headers)
        if extra_tags:
            argv += ["-tags", ",".join(extra_tags)]
        elif not deep:
            # Constrain the broad passes to categories that matter. In deep
            # mode we skip this and genuinely run everything.
            argv += ["-tags", ",".join(ALWAYS_TAGS)]
        for t in templates or []:
            argv += ["-t", t]
        return argv

    # ---- pass 1: the urgent severities, on their own ----
    if urgent:
        async for rec in run(build(urgent),
                             f"pass 1/4 — {urgent} only, so anything serious "
                             f"surfaces now rather than at the end", 3600):
            yield rec

    # ---- pass 2: the rest ----
    if rest:
        async for rec in run(build(rest), f"pass 2/4 — remaining severities ({rest})",
                             7200):
            yield rec

    # ---- pass 3: technology-specific ----
    if tech_tags:
        argv = _base_argv("info,low,medium,high,critical", rate, concurrency,
                          exclude_tags)
        argv += _auth_args(auth_headers)
        argv += ["-tags", ",".join(tech_tags)]
        async for rec in run(argv, f"pass 3/4 — deep on detected stack: "
                                   f"{', '.join(tech_tags)}", 5400):
            yield rec

    # ---- pass 4: community templates ----
    # These have to be a separate pass: `-t` restricts nuclei to the given
    # paths, so adding community directories to an earlier pass would silently
    # disable the official set rather than supplement it.
    for path in community or []:
        argv = _base_argv("medium,high,critical", rate, concurrency, exclude_tags)
        argv += _auth_args(auth_headers)
        argv += ["-t", path]
        name = path.rstrip("/").rsplit("/", 1)[-1]
        async for rec in run(argv, f"pass 4/4 — community templates: {name}", 3600):
            yield rec


async def update_templates(log: LogFn | None = None) -> str:
    """Pull the latest community templates. Run this weekly (or nightly)."""
    require_binary("nuclei")
    proc = await asyncio.create_subprocess_exec(
        "nuclei", "-update-templates", "-silent",
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
    )
    out, _ = await proc.communicate()
    text = out.decode("utf-8", "replace").strip()
    if log:
        await log("info", f"[nuclei] template update: {text or 'up to date'}")
    return text
