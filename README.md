# Sentinel

**A self-hosted attack surface scanner and Hack The Box companion that runs entirely on your machine.**

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-827%20passing-brightgreen.svg)](backend/tests)
[![Python](https://img.shields.io/badge/python-3.12-blue.svg)](backend/requirements.txt)

Sentinel runs 32 detection engines over a target, normalises everything they
emit into one finding schema, re-tests each result to see whether it actually
reproduces, and drafts the report. A **local** LLM does the triage — nothing
leaves your machine. No cloud service, no telemetry, no account.

It does three jobs: **bug bounty reconnaissance**, **auditing systems you own**,
and **working Hack The Box machines and CTFs** without leaving the app.

---

## Install and run

One command. It checks Docker, installs and starts Ollama if it is missing,
picks an AI model that fits your machine's RAM, builds the containers, and
opens the UI.

```bash
git clone https://github.com/<you>/sentinel.git
cd sentinel
./start.sh
```

That is the whole setup. It takes about ten minutes the first time (most of it
downloading detection templates and the model) and about twenty seconds after
that.

**What `./start.sh` actually does, in order:**

| Step | What happens | If it fails |
| --- | --- | --- |
| 1 | Checks Docker is running; starts Docker Desktop if it isn't | Tells you exactly which step wedged and how to reset it |
| 2 | Installs Ollama (Homebrew on macOS, official script on Linux) | Skips it — the app runs without AI triage |
| 3 | Reads your RAM and picks a model to match | Override with `OLLAMA_MODEL=...` |
| 4 | Pulls the model in the background | The app starts anyway; triage switches on when it lands |
| 5 | `docker compose up --build -d` | Prints the build error and what usually causes it |
| 6 | Waits for the backend, then opens http://127.0.0.1:5173 | Shows the last 40 log lines rather than hanging |

**Model sizing.** A 14b model on 8 GB of RAM does not fail cleanly — it swaps,
and triage takes minutes per finding, which reads as "the app is broken". So
the model is chosen from the machine:

| Detected RAM | Model |
| --- | --- |
| 32 GB or more | `qwen2.5:14b` |
| 16–31 GB | `qwen2.5:7b` |
| 8–15 GB | `qwen2.5:3b` |
| under 8 GB | `qwen2.5:1.5b` |

Set `OLLAMA_MODEL` to override. AI triage is optional throughout — every
finding is scored by deterministic re-verification, and the model only writes
commentary.

**Requirements:** Docker Desktop, and about 12 GB of free disk. Everything else
is installed for you.

**Stop it:** `docker compose down` · **Logs:** `docker compose logs -f backend`
· **Something wrong:** `./diagnose.sh`

> ### ⚠️ Read this before you scan anything
>
> **Scanning a system you don't own or have written permission to test is a
> criminal offence** — India's IT Act §43/§66, the US CFAA, the UK Computer
> Misuse Act, and equivalents nearly everywhere. Good intentions are not a
> defence. Neither is finding a real bug.
>
> Sentinel makes you record who authorized the work before it will scan. That
> friction is deliberate and it exists to protect you.
> See [SECURITY.md](SECURITY.md) and [docs/ethics.md](docs/ethics.md).

---

## The three tabs

### Scan — find bugs on a target

Type a domain you are allowed to test, choose a depth, press Execute. Findings
appear as they are found rather than at the end.

Everything is re-tested after the scan: fetched again, fetched a second time to
rule out a fluke, and compared against a control request. The submission queue
is then ordered by **whether a finding reproduces**, not by how severe it claims
to be — because a critical that does not reproduce costs you more to file than
it is worth.

→ [How scanning works, depth profiles, engine list](docs/scanning.md)
→ [Authenticated and multi-account scanning](docs/authenticated.md)
→ [Reports, the submission queue, monitoring](docs/reporting.md)

### HTB — work a box or a CTF

Add a machine by address and difficulty. Sentinel scans it, works out which
phase you are in, and gives you a short ranked list of what to do next — with
the target already substituted into every command.

**The hint ladder.** When you are stuck, ask for help one rung at a time:

| Rung | What you get |
| --- | --- |
| 1 · nudge | A question that points at what you have not looked at |
| 2 · direction | Why that thing matters on this kind of box |
| 3 · technique | The named attack to use |
| 4 · exact command | The literal command, ready to paste |

Every rung is worked out from **your own scan of your own instance**. There is
no answer key in this repository and there will not be one: a stored flag is
wrong the moment a box respawns, sharing solutions for active machines is
against HTB's rules and is what their anti-cheat looks for, and a rank earned
by copying is worth nothing in the interview where the rank actually gets spent.
Writeups for *retired* machines are fair game and the app will say so.

**Difficulty is not cosmetic.** It decides which techniques you are shown. An
easy box gets the everyday checks; a hard box additionally gets credential
spraying, BloodHound, ADCS template abuse (ESC1–ESC8), Kerberos delegation,
DCSync, pivoting to loopback-bound services, deserialization, SSTI, container
escape and source review. Showing forest-level AD advice on an easy box is how
the obvious path gets missed.

**Privilege escalation gives commands, not reading lists.** Paste `sudo -l`
output and each entry is joined against a local copy of GTFOBins:

```
(root) NOPASSWD: /usr/bin/find   →   sudo /usr/bin/find . -exec /bin/sh \; -quit
```

458 GTFOBins binaries and the LOLBAS set, refreshed with the **Update
knowledge** button — these projects gain entries constantly, and a two-year-old
privesc database will miss the binary the box was built around.

**Flags.** A machine flag is 32 hex characters, which is also the shape of every
MD5 digest ever printed. So tell it where the text came from: output of
`cat /root/root.txt` is a root flag at 97% confidence, output of `md5sum` is
suppressed, and anything without context is listed at low confidence rather
than hidden — a suppressed real flag costs more than a listed hash.

**XP and streaks.** Machine XP uses HTB's published tables (200/250 for an easy
box user/root, ×1.3 for active content). The weekly streak needs 200 XP between
Monday and Sunday UTC, and the app tells you how much you still need and the
cheapest way to get it. It does **not** guess your level — HTB says the XP curve
is exponential but does not publish the coefficients, and a wrong level number
that looks authoritative is worse than none.

### CTF — Jeopardy challenges

Per-category triage order, tools and recurring patterns for web, binary, crypto,
forensics, network/ICS and drone telemetry. Drop any challenge file and it runs
the whole triage chain for that file type and puts flag candidates first. RSA
parameter analysis, encoding-chain peeling, and a challenge tracker with
writeup drafting.

---

## What it finds

**Reconnaissance** — subdomains from ~30 passive sources, certificate
transparency logs, archived URLs, DNS resolution, CDN/WAF identification, port
and service discovery, TLS auditing, crawling, content discovery, ASN and
netblock expansion, virtual hosts that exist without DNS records.

**Vulnerabilities** — nuclei's full template library, plus purpose-built engines
for subdomain takeover, exposed `.git` and `.env` files, debug endpoints and
heap dumps, CORS misconfiguration, open redirects, dangerous HTTP methods, 403
bypasses, exposed cloud buckets, credentials in JavaScript bundles, GraphQL
introspection, hidden parameters, and email/DNS policy (SPF, DKIM, DMARC,
DNSSEC, CAA, zone transfer).

**Broken access control** — with two accounts configured, Sentinel compares what
each can reach and reports endpoints that need no session at all, and records
one user can read that belong to another. This is the bug class that pays most,
and it is absent from scanners that hold a single session.

**Modern surface** — AI and LLM application testing including prompt injection,
MCP and agent tool-poisoning exposure, client-side supply chain, post-quantum
TLS readiness, and SEO spam and cloaking across 14 languages.

**Prioritisation** — CISA KEV enrichment, so a CVE that is being exploited right
now sorts above one that merely exists.

→ [Full engine list and what each depth runs](docs/scanning.md)

---

## Configuration

Copy `.env.example` to `.env` to change anything. Common ones:

```bash
OLLAMA_MODEL=qwen2.5:14b        # override the RAM-based choice
SENTINEL_AUTO_UPDATE=0          # stop the daily content refresh
SENTINEL_AUTO_INSTALL=0         # never install Ollama for me
SENTINEL_MAX_RATE_LIMIT=150     # global requests/sec ceiling
```

→ [Keeping detection content current](docs/UPDATING.md)

---

## Development

```bash
cd backend && python -m pytest tests/ -q     # 827 unit tests, no network
./run-lab-tests.sh                           # integration, against local targets
```

→ [Architecture, adding an engine, test layout](docs/development.md)
→ [CONTRIBUTING.md](CONTRIBUTING.md) · [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)

---

## Credit

Sentinel is an orchestrator. The scanning is done by
[ProjectDiscovery](https://github.com/projectdiscovery)'s tools (nuclei,
subfinder, httpx, naabu, katana, dnsx, tlsx, cdncheck), plus nmap, ffuf,
gitleaks and testssl.sh. The HTB privilege-escalation lookups come from
[GTFOBins](https://gtfobins.github.io/) and
[LOLBAS](https://lolbas-project.github.io/). Takeover fingerprints come from
[can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz).
Exploited-vulnerability data is CISA's KEV catalogue.

See [NOTICE](NOTICE) for full attribution and licences.

## Licence

Apache 2.0 — see [LICENSE](LICENSE).
