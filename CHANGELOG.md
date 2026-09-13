# Changelog

All notable changes to Merlon are recorded here. Dates are ISO-8601.
Versions follow [Semantic Versioning](https://semver.org); while the project is
in beta the minor version moves on anything that changes an interface.

## [0.1.0] — 2026-09-13

The first tagged release. Merlon has been usable for a while; this is the point
at which the interfaces are worth pinning to.

### Detection

* **42 engines.** Reconnaissance, exposure and misconfiguration, broken access
  control across multiple sessions, and the AI/agent surface.
* **Injection coverage**, all of it reflection-gated and safe to run unattended:
  * `sqli` — error-signature and boolean-differential SQL injection. No stacked
    queries, no time delays, no UNION extraction.
  * `nosqli` — MongoDB-style operator injection on a strict true/false split.
  * `ssti` — server-side template injection proven by making the engine
    evaluate wrapped random arithmetic.
  * `xss` — reflected XSS, reported only when an inert injected tag survives
    unencoded.
  * `domxss` — DOM-based XSS **proven by executing** the payload in headless
    Chromium. The class that never appears in an HTTP response.
* `jwt` — `alg=none`, guessable HMAC secrets recovered by recomputing the
  signature, sensitive claims, non-expiring tokens.
* `cachepoison` — web cache poisoning and cache deception. Every probe is
  cache-busted so nothing real is ever poisoned.
* `screenshots` — a screenshot of every live host for visual triage.

### Verification

* **Findings are tiered: proven, reproduced, observed, unverified.** A rule is
  `proven` when detection itself was a demonstration — the target computed our
  arithmetic, returned its own database error, executed our payload, or matched
  a signature we recomputed. Which rules qualify is declared by each engine
  next to the code that detects them.
* Everything that cannot be proved is **kept and ranked below**, not discarded.
  A finding a scanner cannot auto-prove is not thereby false; it is unproven.

### Interfaces

* **MCP server** (`python -m app.mcp_server`) — drive scans and read findings
  from Claude Code, Cursor or any MCP client. `start_scan` keeps the same
  authorization gate as the web UI, and the gate is in the tool rather than a
  prompt.
* Runs on **macOS, Linux and Windows**; `start.ps1` is a native PowerShell
  launcher so Windows does not require WSL.
* Installs Docker for you if it is missing, after asking.

### Fixed

* `--globoff` on every fetch: curl read `[` and `]` in a URL as glob syntax, so
  an ordinary `?filter[]=x` never went out.
* Simultaneous identical requests are coalesced into one, without ever becoming
  a response cache — the verification gate depends on re-requesting for real.
* Line endings pinned via `.gitattributes`: a Windows checkout gave
  `entrypoint.sh` CRLF and the backend container would not start.

### Known limits

* Beta. Engine names, the finding schema and API routes are not stable yet.
* The GHCR images are published private by default, so `docker pull` needs the
  package visibility set to public first. Building from source with `./start.sh`
  is the supported path and needs nothing.
* No out-of-band collaborator, so blind SSRF and blind XXE are out of reach.
* Detection is uneven across classes — a clean scan is not proof a target is
  clean.

[0.1.0]: https://github.com/skopiaai/merlon/releases/tag/v0.1.0
