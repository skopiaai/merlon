# Sentinel

**A self-hosted attack surface scanner that runs entirely on your machine.**

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-697%20passing-brightgreen.svg)](backend/tests)
[![Python](https://img.shields.io/badge/python-3.12-blue.svg)](backend/requirements.txt)

Sentinel orchestrates twenty-odd established open-source scanners, normalises
everything they emit into one finding schema, deduplicates across tools, and
uses a **local** LLM to triage results and draft remediation. Nothing leaves
your machine — no cloud service, no telemetry, no account.

It is built for three jobs: bug bounty reconnaissance, auditing systems you own,
and producing a report a non-security reader can act on.

```bash
git clone <this repo> && cd sentinel
./start.sh          # or: docker compose up -d --build
```

Open http://127.0.0.1:5173, type a domain you're allowed to test, press Execute.

> ### ⚠️ Read this before you scan anything
>
> **Scanning a system you don't own or have written permission to test is a
> criminal offence** — India's IT Act §43/§66, the US CFAA, the UK Computer
> Misuse Act, and equivalents nearly everywhere. Good intentions are not a
> defence. Neither is finding a real bug.
>
> Sentinel makes you record who authorized the work before it will scan. That
> friction is deliberate and it exists to protect you. See
> [SECURITY.md](SECURITY.md) for the full acceptable-use position.

---

## What it finds

**Reconnaissance** — subdomains from ~30 passive sources, certificate
transparency logs, archived URLs, DNS resolution, CDN/WAF identification, port
and service discovery, TLS auditing, crawling, content discovery, ASN and
netblock expansion, virtual hosts that exist without DNS records.

**Vulnerabilities** — nuclei's full template library, plus purpose-built
engines for subdomain takeover, exposed `.git` and `.env` files, debug
endpoints and heap dumps, CORS misconfiguration, open redirects, dangerous HTTP
methods, 403 bypasses, exposed cloud buckets, credentials in JavaScript bundles,
GraphQL introspection, hidden parameters, and email/DNS policy (SPF, DKIM,
DMARC, DNSSEC, CAA, zone transfer).

**Broken access control** — with two accounts configured, Sentinel compares
what each can reach and reports endpoints that need no session at all, and
records one user can read that belong to another. This is the bug class that
pays most, and it's absent from scanners that hold a single session.

**Site compromise** — SEO spam and cloaking across 14 languages, covering the
gambling, pharma and counterfeit-goods campaigns. The Japanese keyword hack
(fake luxury goods aimed at Japanese buyers) has been the single most
frequently detected website malware, on roughly one in ten infected sites.

The variant worth calling out is **hidden injection**: spam inside a
`display:none` block, invisible to the owner loading their own page and fully
visible to the crawler indexing it. That's why the honest answer from a site
owner is usually "I looked and there's nothing there" — they're right, and
they're still delisted. Hidden text alone is never reported (screen-reader
labels and tab panels are legitimate); hidden text *selling replica watches*
is not ambiguous.

**Origin servers behind a CDN** — hosts reachable directly despite sitting
behind Cloudflare or similar, found via DNS history, mail records, un-proxied
subdomains and certificate data. Confirmed by asking the candidate address for
the target's `Host` and checking it serves the target's site.

**AI assistants and agents** — LLM-backed endpoints tested for prompt
injection, system prompt leakage and unbounded consumption (OWASP LLM01/07/10).
Plus exposed **MCP servers** and **tool poisoning**: a Model Context Protocol
tool description is inserted straight into the context of every agent that
connects, which makes it an instruction channel into somebody else's model.
Prompt injection reports rose 540% year on year and almost nothing scans for
any of this.

**Data left behind** — twenty-five years of archived URLs read for emails,
tokens, pre-signed storage links and identity numbers carried in the URL
string itself. Entirely passive; the leak is already public and cannot be
patched away.

**Post-quantum readiness** — whether TLS negotiates hybrid ML-KEM key
agreement. Traffic recorded today under classical key exchange is decryptable
later, so the confidentiality deadline has already passed for anything that
must stay secret past 2030. Executive Order 14412 sets 31 December 2030 for
federal systems.

**Client-side supply chain** — scripts loaded from hosts that no longer
resolve (whoever registers the domain gets JavaScript execution on every
page), third-party code without Subresource Integrity, and known-vulnerable
library versions.

**Client-side logic** — the local model reads the site's own JavaScript for
authorization and logic code, and proposes what to test on the server. The one
job here a regex cannot do. Every claim is checked against the source before it
becomes a finding, and nothing from it can reach the submission queue — a
hypothesis about server behaviour inferred from client code is a lead, not a
result.

**Reporting** — findings cross-referenced against CISA's Known Exploited
Vulnerabilities catalogue, so a CVE that is being used in the wild outranks a
higher-scoring one nobody has weaponised; findings mapped to OWASP Top 10, ASVS 4.0, ISO 27001 Annex A,
CIS v8 and GIGW 3.0; SARIF export; and an audit-grade document with the
authorization record, methodology, tool versions and evidence hashes.

## What it will not do

Not missing features — deliberate limits, documented in [SECURITY.md](SECURITY.md):

- **No exploitation.** Takeovers are detected, never claimed. `PUT` is reported
  from the `Allow` header, never proved by writing a file. Redirects are read
  from `Location`, never followed.
- **No evasion.** No log avoidance, no concealment. If you have permission,
  being seen is fine; if you don't, hiding doesn't make it legal.
- **No reaching outside scope.** Every host is checked at every stage boundary,
  including ones discovered mid-scan. Cloud metadata ranges are hard-denied and
  cannot be allowlisted.

## What it can't do

Race conditions, business logic flaws, and anything requiring an understanding
of what the application is *for*. Those come from a human reading the thing.
Sentinel's job is to clear everything mechanical fast, so your attention goes
to the parts that actually pay.

---

## Authorization is not optional

Scans hang off *engagements*, and an engagement requires a recorded
authorization: who granted permission, and a reference to the proof. That's
deliberate friction.

- **Bug bounty:** the program's scope page is your authorization. Paste the URL,
  and paste the scope table itself into **Import scope** — it turns the table
  into allow and deny rules, applies exclusions over wildcards, and names the
  asset types this tool can't cover so you don't assume the program is fully
  scanned. It parses; you confirm it against the page and press Create. Testing
  an excluded host is the most common way researchers get removed from
  programs, and it's nearly always a transcription error.
- **Your college or employer:** get an email from whoever owns the system before
  you scan it. Students have been expelled and prosecuted over scans they
  believed were helpful. One paragraph and a reply is enough — get it first.
- **Anything else:** if you can't name who authorized it, don't scan it.

The scope guard (`backend/app/scope.py`) re-checks every host at every stage
boundary. Subdomain enumeration routinely returns third-party hosts — CDN
endpoints, SaaS CNAMEs, a shared hosting neighbour — and those get dropped
before a single packet is sent to them. Stored credentials go through the same
gate on every individual request.

---

## Setup

### Requirements

- **Docker** with Compose v2 (Docker Desktop on macOS/Windows, or Docker Engine
  on Linux). Everything runs in containers; nothing is installed on your host.
- **~8 GB free disk** for the image, scanner binaries, nuclei templates and
  SecLists.
- **[Ollama](https://ollama.com)** — optional. Runs on the host, not in a
  container. Without it everything still works; findings just stay untriaged
  and you lose the AI attack-surface leads. The header shows `AI on` / `AI off`
  either way.

Tested on macOS (Apple silicon and Intel) and Linux. Windows works via WSL2.

### Running it

```bash
./start.sh
```

That's the whole thing. It checks Docker (launching Docker Desktop if it isn't
running), starts Ollama in the background, pulls the model if you don't have it,
brings up both containers, waits for the backend to answer, refreshes the nuclei
templates, and opens the browser.

First run takes a few minutes — it downloads a dozen scanner binaries and the
template library. After that it's seconds.

If you'd rather drive it manually:

```bash
docker compose up -d --build     # then open http://127.0.0.1:5173
docker compose down              # stop
docker compose down -v           # stop and delete all scan data
```

Both containers bind to `127.0.0.1` only. See
[SECURITY.md](SECURITY.md#known-limitations) before changing that — the API has
no authentication, and a service that makes HTTP requests to arbitrary hosts on
request is an SSRF gateway if you expose it.

### Configuration

Copy `.env.example` to `.env` if you want to change anything. Every value has a
working default. With under 16 GB of RAM, use a smaller model:

```bash
OLLAMA_MODEL=llama3.1:8b ./start.sh
```

Dark mode is the default; the sun/moon button in the header toggles it and the
choice sticks.

---

## Two ways to use it

### Scan tab — the everyday way

Type a domain, tick the permission box, hit **Scan**. That's the whole flow.

Results come back as plain English: what the issue is, why it matters, and the
specific header or config line that fixes it. Pick **Sprint** (~2 min, critical
and high only — for when being first matters), **Quick** (~5 min, main site),
**Standard** (~10 min, includes subdomains), or **Deep** (30 min+, ports and
crawling).

When it finishes, **Submission queue** is the view worth opening — it splits
findings by whether they actually reproduce rather than by how severe they
claim to be.

Behind the scenes this still creates a proper engagement with scope rules and an
authorization record — it just derives them from the domain instead of making
you fill in a form.

### Console tab — the operator view

Everything the simple flow hides: hand-written scope rules with wildcards and
CIDR ranges, exclusions, per-stage pipeline control, the raw finding queue with
triage states, live tool output, and the scan history with out-of-scope rejects.

Use this when you're working a bounty program with a complicated scope, or when
a scan does something surprising and you need to see what the tools actually
said.

### First time

Run **Quick** against something you own. It's the fastest way to confirm the
whole pipeline works end to end.

---

## Attack surface discovery

More assets means more findings, so discovery is deliberately wide. Thirteen
independent sources feed the same scope-guarded pipeline:

| Source | Finds | Passive? |
|---|---|---|
| subfinder | Subdomains from ~30 passive data sources | ✓ |
| **ctlogs** | Every hostname in a public TLS certificate — staging, internal and forgotten hosts DNS never shows | ✓ |
| **archive** | Every URL the Wayback Machine ever recorded — dead-but-live endpoints and old parameter names | ✓ |
| **netblock / asninfo** | The ASN announcing the target's addresses, then its netblocks reverse-resolved to names | ✓ |
| permute | Names generated from the ones already found, then resolved | active |
| naabu / nmap | Open ports and the services behind them | active |
| katana | Crawled endpoints | active |
| ffuf | Directory brute force | active |
| **jsendpoints** | API routes read out of the site's own JavaScript — the ones the UI never links to | active |
| **apispec** | Routes declared in an exposed OpenAPI/Swagger document | active |
| **wellknown** | robots.txt, sitemaps, security.txt — paths the owner declares but doesn't link | active |
| **vhosts** | Applications served by Host header but absent from DNS — invisible to any DNS-based enumeration | active |
| **paramminer** | Query parameters the application accepts but never links | active |

Four of those find what nothing else does. **Certificate transparency** is a
permanent public log of every certificate ever issued, so it surfaces hosts that
were never in DNS. **JavaScript endpoint extraction** reads the API surface a
single-page app ships to every browser, including admin and feature-flagged
routes. **Virtual host probing** starts from the IP rather than from DNS, which
is the only way to reach an application whose name was removed from DNS but
left configured on the server. **Parameter mining** finds the `?debug=1` and
`?admin=true` switches, and — more importantly — the ID- and URL-carrying
parameters that IDOR and SSRF testing need before they can start.

Everything a discovery engine returns passes through the same scope guard as
every other stage, so a wider surface can never become a surface outside the
engagement. That's asserted in `tests/test_discovery.py`.

### Active vulnerability engines

Discovery widens the surface; these test it. Each is one file, and each stops
short of the step that would change something on the target.

| Engine | Looks for | Notable restraint |
|---|---|---|
| **takeover** | Dangling CNAMEs pointing at hosting services where the name can be re-registered | Verifies against the service's own unclaimed-name page; never claims the name |
| **cors** | Reflected origins, `null` origin, and prefix/suffix bypasses of origin validation | Probe origins use the reserved `.invalid` TLD |
| **redirect** | Unvalidated redirect parameters, incl. protocol-relative, backslash and userinfo forms | Redirects are read from `Location`, never followed |
| **methods** | PUT, DELETE, TRACE and WebDAV verbs left enabled | Read from OPTIONS/Allow — never proved by writing |
| **authbypass** | 403s defeated by path normalisation or `X-Original-URL`-style headers | Read-only rewrites only |
| **apidocs** | Swagger/OpenAPI, GraphQL introspection, Spring actuator, framework debuggers | — |
| **exposures** | `.git`, `.env`, backups, dumps, editor leftovers, private keys | Confirmed by content signature, not status code; credentials redacted from evidence |
| **favicon** | Software identified by default icon hash (Shodan-compatible) | — |
| **paramminer** | Undocumented parameters, bisected out of batched probes | Deep scans only; skipped entirely on pages that differ from themselves |

The recurring theme in that last column is the difference between a scanner and
an intrusion. Proving `PUT` works means writing a file to someone's server;
proving a takeover works means seizing their hostname. Both are the attack, not
the test — so the report says what to verify and how to fix it instead.

The other recurring theme is false-positive suppression, which is most of the
engineering. A single-page app answers 200 for `/.env`; a CNAME to CloudFront
is not takeoverable; a `Location` containing your canary as a *query parameter*
is not a redirect to it. Each of those has a test whose whole purpose is to keep
a plausible-looking non-finding out of the report.

---

## How this compares to the established tools

Benchmarked against [reNgine](https://github.com/yogeshojha/rengine),
[BBOT](https://github.com/blacklanternsecurity/bbot) and
[reconFTW](https://github.com/six2dez/reconftw) — the three most capable
open-source recon frameworks — and the gaps they exposed have been closed.

| | reNgine | BBOT | reconFTW | this |
|---|---|---|---|---|
| Passive subdomain enumeration | ✓ | ✓ | ✓ | ✓ |
| Permutation / active discovery | ✓ | ✓✓ | ✓ | ✓ |
| Cloud bucket exposure | ✓ | ✓ | ✓ | ✓ |
| Port, service and TLS auditing | ✓ | partial | ✓ | ✓ |
| Email / DNS policy (SPF, DMARC, DNSSEC) | partial | partial | partial | ✓ |
| Subdomain takeover with service fingerprints | ✓ | ✓ | ✓ | ✓ |
| Virtual host discovery | ✗ | ✓ | ✓ | ✓ |
| Hidden parameter mining | ✗ | ✗ | ✓ | ✓ |
| Authenticated scanning across all engines | partial | ✗ | ✗ | ✓ |
| **Access control testing (IDOR, missing auth)** | ✗ | ✗ | ✗ | ✓ |
| CORS / open redirect / 403 bypass | via nuclei | ✗ | via nuclei | ✓ dedicated |
| Favicon fingerprinting | ✗ | ✓ | ✓ | ✓ |
| ASN / netblock expansion | ✗ | ✓ | ✓ | ✓ |
| Origin IP discovery behind a CDN | ✗ | partial | ✓ | ✓ |
| **AI/LLM application testing** | ✗ | ✗ | ✗ | ✓ |
| **MCP server / tool poisoning detection** | ✗ | ✗ | ✗ | ✓ |
| **Independent re-verification + submission gate** | ✗ | ✗ | ✗ | ✓ |
| Continuous monitoring / asset diffing | ✓ | ✗ | ✗ | ✓ |
| Screenshot gallery | ✓ | – | ✓ | ✗ |
| **Compliance control mapping** | ✗ | ✗ | ✗ | ✓ |
| **Cloaking / SEO-spam detection** | ✗ | ✗ | ✗ | ✓ |
| **AI attack-surface leads** | ✗ | ✗ | ✗ | ✓ |
| **Log forensics** | ✗ | ✗ | ✗ | ✓ |
| **Audit report with evidence hashes** | partial | ✗ | ✗ | ✓ |
| SARIF export | ✗ | ✓ | ✗ | ✓ |
| Integration tests vs. a vulnerable target | ✗ | ✓ | ✗ | ✓ |

The remaining gap is a screenshot gallery, which needs headless Chrome in the
image — worth adding when visual triage of a hundred hosts becomes the
bottleneck.

Two honest caveats on that table. BBOT still has more passive data sources than
anything here, because several of them require paid API keys. And "dedicated"
in the CORS/redirect row means a purpose-built engine with its own
false-positive handling rather than a template match — better precision, but
nuclei's template library remains far broader than any hand-written set of
checks and is doing most of the CVE work.

---

## Authenticated scanning

The single biggest coverage multiplier. Logged out, a scanner sees the marketing
site; logged in, it sees the application — account pages, the API, admin
functions, the places data actually lives.

Set it up under **Console → Credentials**: paste the request headers from your
browser's dev tools (Network → any request → Request Headers → copy the Cookie
line), give it a URL only a logged-in user can see, and save.

Before every scan the session is **verified** against that URL. If it's expired
the scan says so plainly and continues unauthenticated, rather than silently
producing logged-out results that look complete — which is the failure mode that
makes authenticated scanning worse than useless when it goes wrong.

Every engine receives the session. That's enforced at one chokepoint in
`engines/fetch.py`, with a test asserting it still exists, because an engine
added later that forgets to pass the context doesn't error — it just quietly
tests the logged-out view.

### A second account: testing access control

Add another account and the scanner can do something no single-session tool can.
Access control is a question about intent — *should* this caller reach this? —
and the intent isn't in the response. But it becomes observable by comparison:

| Comparison | What a match means |
|---|---|
| With session vs. without | The endpoint never required authentication. It was unlinked, not protected. |
| Account A vs. account B | One user can read another user's record. That's an IDOR. |

The second row is the bug class that pays most on real programs, and it's absent
from every scanner that only holds one session.

Two properties keep it honest. **A response is only "access" if it's substantive
and isn't a login page** — a 200 carrying a sign-in form is a refusal, and
counting it as access invents an IDOR out of nothing. **Cross-account comparison
only runs on URLs that address a record** (`/orders/1042`, `?invoice_id=…`), not
on pages, because two users legitimately see the same dashboard.

Both accounts are verified independently before the scan. A silently expired
second session is worse than no second session: "account B could not read
account A's data" looks identical whether B was blocked by authorization or was
simply logged out, so a dead identity removes itself rather than producing a
confident wrong answer.

Use two genuinely unrelated accounts — not two members of the same organisation,
or every result is a false positive. And open the response before reporting:
this finding is worth a great deal when it's real and costs you a triage team's
trust when it isn't.

### Where credentials go

Scope-checked before **every single request** that would carry them, not once
per scan. Enumeration routinely turns up hosts that aren't yours, and a session
cookie sent to one of them is an incident you caused. The API describes what's
configured and never returns the stored values.

> Credentials are stored in plaintext in the local SQLite file. Acceptable for a
> single-user offline tool; **not** acceptable if this ever becomes multi-user.

---

## Audit-grade reporting

`Audit report` produces a formal document rather than a finding list:
authorization record, methodology with every phase described, **tool versions**
for reproducibility, an asset inventory, a control coverage matrix, per-finding
references, and SHA-256 evidence hashes so the report can be shown unmodified.

Findings are mapped to **OWASP Top 10 (2021), OWASP ASVS, ISO/IEC 27001:2022
Annex A, CIS Controls v8, and GIGW 3.0** security areas — the four standards
GIGW 3.0 builds its own baseline on, which makes the output usable for both
bounty submissions and institutional audit work.

The coverage matrix lists Top 10 categories with **zero** findings too, and
explicitly marks A04 (Insecure Design) and A09 (Logging and Monitoring) as *not
assessable by scanning*. Absence of evidence has to be distinguishable from
evidence of absence, or the report is misleading.

---

## How it goes beyond a plain nuclei run

**Tech-aware targeting.** httpx fingerprints the stack, and nuclei is driven
from that. A WordPress target gets the entire WordPress template set at every
severity; it doesn't waste ten minutes on Jenkins checks. Two passes: a broad
severity-filtered sweep, then a deep stack-specific one. Faster *and* better
coverage than one blind run.

**Parallel stages.** dnsx and cdncheck run together; nmap, tlsx and ffuf run
together after probing. Only genuinely dependent stages are serialised.

**Attack path correlation.** Individually-minor findings get chained into real
attack paths. A cookie without HttpOnly is "low". A cookie without HttpOnly
*plus* no CSP is "any XSS on this origin is full account takeover" — that
framing is often the difference between a rejected and an accepted report.

**The hunting workspace.** The most useful screen in the app, and the one that
addresses what scanners structurally can't do. Two halves:

*Surface map* — deterministic, no model involved. Every discovered endpoint is
classified into categories chosen for what they imply about manual testing
(auth, api, admin, upload, payment, user-object, export, webhook, debug,
search), with a parameter inventory that flags URL-taking parameters as
SSRF/redirect candidates and identifier parameters as IDOR candidates,
identifiers embedded in paths, and every endpoint returning 401/403 — the
application's own stated permission boundaries.

*Leads* — a tracked checklist. Each lead carries what to test, why it's
promising, and the likely vulnerability class. Mark them `testing` /
`found` / `clear` / `skipped` and add notes; progress is stored, so you can
close the tab and pick up where you left off. **Deep dive** generates a fuller
per-lead test plan on demand: what to observe, how to tell a real flaw from
expected behaviour, what evidence to capture, and the false positives common to
that class.

Leads come from two sources. The LLM proposes target-specific ones; the surface
map generates the rest deterministically — so the workspace stays useful with
Ollama switched off, and the highest-signal categories are never missed because
a small model overlooked them.

### An honest note on what this can't do

No scanner out-detects a good hunter, and it's worth being clear about why:
scanners answer *"does this match a known-bad pattern?"* Hunters ask *"given how
this application works, where is the logic wrong?"* Business logic flaws, broken
access control, IDORs and race conditions have no signature to match — that's
precisely why they pay.

So the goal here isn't to beat a human. It's to clear the known-pattern space in
minutes rather than hours, and hand you a ranked list of where to point your own
attention. The attack surface panel is the most valuable output on the page.

---

## What each depth runs

| Depth | Stages | Typical time |
|---|---|---|
| **Sprint** | httpx → cheap engines → nuclei (critical/high only) | ~2 min |
| **Quick** | httpx ‖ tlsx → engines → nuclei → correlate → triage → intel | ~5 min |
| **Standard** | subfinder → (dnsx ‖ cdncheck) → httpx → tlsx → engines → nuclei → correlate → triage → intel | ~10 min |
| **Deep** | subfinder → (dnsx ‖ cdncheck) → naabu → httpx → (nmap ‖ tlsx ‖ ffuf) → katana → engines → nuclei → correlate → triage → intel | 25 min+ |

`‖` means those stages run concurrently. Every scan except Sprint ends with
correlation, AI triage, and attack-surface analysis.

Pick individual stages in the Console tab if you want something in between.

| Profile | Ports | Nuclei severities | Use for |
|---|---|---|---|
| `sprint` | none | critical, high | a new program just dropped and first report wins |
| `passive` | none | medium+ | first look, or when rate limits are tight |
| `standard` | top 100 | low+ | normal work |
| `thorough` | top 1000 | info+ | you own the target and have time |

### Time to first finding

Total runtime is the wrong number to optimise. What matters is how long until
something reportable appears, because a bug found at minute three and a bug
found at minute thirty-eight are the same bug — but only one of them gets
filed first.

Three decisions follow from that:

**Nuclei runs urgent severities in their own pass.** A single sweep across
`info,low,medium,high,critical` loads templates in arbitrary order, so a
critical can surface behind three thousand informational checks. Splitting
`critical,high` into pass 1 costs a few per cent in total runtime and moves the
findings that matter into the first minutes. A scan you cancel after pass 1 has
still done the part that pays.

**Engines are ordered cheapest first.** They run concurrently and save results
as each finishes, so ordering decides what's on screen at minute one. A takeover
check shouldn't be queued behind a parameter miner. This is enforced by a test,
not by hand-maintaining the preset lists.

**Sprint exists for the actual bug bounty situation.** New scope drops, you have
minutes rather than hours, and you need to know whether a host is worth an hour
of attention. It runs httpx plus the engines that can produce something
immediately reportable on their own — takeover, exposed files, debug endpoints,
leaked secrets, CORS — with nuclei restricted to critical and high. No port
scan, no fuzzing, no crawl, no AI triage. It is not thorough and isn't trying
to be.

---

## The submission queue

The scarce thing in bug bounty is no longer finding issues — it's proving them.
Autonomous agents reached the top of HackerOne's leaderboard in 2026, and in the
same year Google stopped accepting AI-generated vulnerability reports and the
Internet Bug Bounty suspended payouts, because the volume of machine-generated
findings made triage impossible.

That changes the economics for whoever is submitting. A researcher with 200
reports and 50 accepted gets slower triage and smaller payouts than one with 50
reports and 40 accepted. **Acceptance rate is the currency, not volume.**

So every scan ends with a verification pass that asks one question about each
finding: *if a triager runs this right now, does it still happen?*

| | |
|---|---|
| **Reproduce** | Re-request it. Doesn't answer? It doesn't reach the queue. |
| **Reproduce again** | A second attempt, because transients are the most common false positive. |
| **Control** | A path that shouldn't exist. If the host answers that identically, the finding is an artefact of the host, not a bug. |
| **Evidence quality** | Does the finding show a request/response exchange, or just assert something? |

Findings land in one of three buckets — **ready to submit**, **needs your
eyes**, **did not reproduce** — and nothing is hidden; the failures are listed
with their reasons.

**Confidence comes from evidence, never from opinion.** The local LLM still
writes triage commentary and it's still useful, but its score is stored
separately (`triage_confidence`) and given zero weight in the gate. An LLM's
belief that a finding is real is precisely the signal that produced the
industry's flood of unreproducible reports.

Every verified finding carries a reproduction block: the exact request, the
exact response, a SHA-256 of the body, and a UTC timestamp — with credentials
redacted, so a report never becomes the second copy of a leak.

```
GET /api/scans/{id}/queue          the three buckets
POST /api/findings/{id}/verify     re-check one on demand
GET /api/findings/{id}/evidence    reproduction block, ready to paste
```

---

## Monitoring for new attack surface

The most reliable edge is arriving first, and the moment that's possible is the
moment an asset appears. A subdomain that went live this morning has not been
hunted by anyone — every other researcher's last scan predates it.

So `GET /api/engagements/{id}/diff` compares the two most recent completed scans
and reports the **difference**, not the state:

- **New hosts** — unhunted by definition, and the highest-value line in the output
- **Changed hosts** — a 404 that became a 200, a login form that appeared, a framework that changed version
- **Disappeared hosts** — worth knowing for the opposite reason: a name still pointing at a decommissioned service is exactly how subdomain takeovers happen

Signatures are status, title and technology rather than response bodies. Diffing
bodies would fire on every deploy and every rotating CSRF token, which trains
you to ignore the alert.

`POST /api/engagements/{id}/rescan` repeats the last scan's configuration so
there's something to diff against. Expired engagements are excluded — a
scheduler is exactly where a scan against lapsed authorization would happen
without anyone noticing.

---

## Keeping detection content current

The code here changes monthly. The content — templates, fingerprints,
wordlists — changes daily, and a template published this morning finds bugs
this afternoon that yesterday's copy walks straight past. For a bounty that gap
*is* the game: when a new CVE template lands, the first valid report is the one
that gets paid.

**Update now** sits above the Execute button on the scan page, with the age of
your content next to it. If it's more than a day old the bar turns amber and
says so, because "I updated it at some point" is not the same as knowing.

It also runs automatically every 24 hours. Set `SENTINEL_AUTO_UPDATE=0` to
disable that.

| Source | What it refreshes |
|---|---|
| nuclei-templates | The official set — several commits a day |
| Community repos | 5 repositories maintained by bounty hunters, where checks for very recent disclosures usually appear first |
| Takeover fingerprints | Service signatures from `can-i-take-over-xyz` |
| Wordlists | SecLists, if installed as a git checkout |
| Tool binaries | httpx, subfinder, dnsx, cdncheck, katana, naabu, tlsx, nuclei — their detection logic changes too |

Community repositories are cloned into `/data/templates/<name>` and run as a
**separate nuclei pass**. That's deliberate: `-t` restricts nuclei to the given
paths, so adding a community directory to the main pass would silently disable
the official set instead of supplementing it.

Each source updates independently. A repository that's been renamed or deleted
costs you that repository and nothing else — the UI names which sources failed
and carries on.

**A note on `ffuf`.** Content discovery is by far the noisiest thing here — it
sends thousands of requests for paths that mostly don't exist. It's capped to
five hosts and rate-limited, and it's only in Deep for that reason. On a bounty
program, check their rate-limit policy before using it.

Rate limits are capped globally in `backend/app/config.py`. A scan can request
less than the ceiling, never more — that's what stops a mistyped config from
hammering someone's production box.

---

## Architecture

```
React (Vite)  ──REST + WebSocket──>  FastAPI
                                       │
                                       ├── orchestrator.py   pipeline + scope re-checks
                                       ├── engines/          subfinder, naabu, httpx, katana, nuclei
                                       ├── normalize.py      → unified Finding
                                       ├── triage.py         → Ollama (advisory only)
                                       └── SQLite (WAL)
```

Scans run as asyncio tasks with streaming subprocess output — no Celery, no
Redis, no broker. For a single-user local tool that's the right amount of
machinery.

### Adding an engine

One file. Drop it in `backend/app/engines/` and declare what it is:

```python
from .registry import EngineSpec, register

@register(EngineSpec(
    name="myengine",
    label="Checking for X",          # shown in the progress view
    description="What it looks for and why it matters.",
    phase="post_http",               # "early" (seeds) or "post_http" (live URLs)
    takes="urls",                    # seeds | hosts | urls | assets
    weight=6,                        # relative duration, for the progress bar
    limit=25,                        # cap on targets (0 = no cap)
    skip_cdn=False,                  # skip hosts behind a CDN
    default_in=("standard", "deep"), # which depth presets include it
))
async def run(targets: list[str], ctx: dict) -> list[dict]:
    return [ ...finding dicts... ]
```

That's the whole integration. The stage becomes valid, joins the right depth
presets in the right order, gets a progress weight, names itself in the UI, and
its findings flow through scope filtering, dedupe, compliance enrichment,
correlation, triage and both reports — with no edits to the orchestrator,
schemas, or the frontend.

`engines/secrets.py` is the worked example: credential and source-map detection
in client-side JavaScript, written entirely as one file. `tests/test_registry.py`
asserts the architecture holds, including a guard that the orchestrator contains
no direct reference to any engine.

---

## Tests

Two layers, and the second one is the important one.

### Unit tests — components in isolation

```bash
cd backend && python -m pytest -q
```

Scope rules, parsers, compliance mapping, crypto solvers, log forensics. The
scope tests matter most: suffix-confusion (`example.com.evil.net`), CIDR
boundaries, deny-beats-allow, hard-denied cloud metadata.

### Integration tests — the real pipeline against a real vulnerable target

```bash
./run-lab-tests.sh            # ~1 min
./run-lab-tests.sh --slow     # includes the nuclei stage, ~15 min
```

This starts **OWASP Juice Shop** and **DVWA** on an internal Docker network,
runs the genuine orchestrator against them, and asserts what it should find:
the service is discovered, response headers are captured, the missing CSP is
reported, every finding carries a compliance mapping, nothing is duplicated,
and an out-of-scope host produces zero findings.

Why this layer exists: the unit tests passed happily while the scanner was
broken in five separate ways — `/dev/stdin` failing under asyncio, the 64 KiB
stream limit, `create_task` with no event loop, unmigrated schema columns,
missing arm64 packages. Every one of those is caught here in seconds.

> The lab containers are **deliberately insecure**. They sit on an `internal`
> Docker network with no host ports and no internet route, and never start
> during a normal `docker compose up`. Don't expose them.

---

## Layout

```
sentinel/
├── docker-compose.yml
├── docs/UPDATING.md          ← the weekly maintenance runbook
├── backend/
│   ├── Dockerfile            ← pins scanner versions
│   └── app/
│       ├── scope.py          ← read this first
│       ├── orchestrator.py   ← the pipeline
│       ├── normalize.py      ← unified finding schema
│       ├── compliance.py     ← OWASP / ASVS / ISO / CIS / GIGW mapping
│       ├── updater.py        ← keeps templates and tools current
│       ├── triage.py         ← LLM prompts
│       ├── reporting.py
│       └── engines/          ← one file per detection
└── frontend/src/
```

---

## Contributing

The architecture was built so that adding a detection costs **one file**.
Register an engine and it becomes a valid scan stage, joins the right depth
presets, gets a progress weight, shows a label in the UI, and flows through
dedupe, compliance mapping and reporting — with no edits to the orchestrator,
the schemas, or the frontend.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the template and the rules. The
short version: put the judgement in a pure function, pass `ctx` to
`fetch.request`, cap your requests, and **write a test for your detection's
most likely false positive** — a large fraction of the existing test suite
exists for exactly that, because precision is what a scanner's reputation is
made of.

- [CONTRIBUTING.md](CONTRIBUTING.md) — adding engines, tests, what won't be merged
- [SECURITY.md](SECURITY.md) — reporting vulnerabilities, known limitations, acceptable use
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)

---

## Credit

Sentinel is an orchestrator. The scanning is done by tools other people built
and maintain — [ProjectDiscovery's](https://github.com/projectdiscovery) suite
and the nuclei template library above all, plus ffuf, SecLists, nmap,
testssl.sh, gitleaks and semgrep. Most of what this finds, it finds because of
their work. See [NOTICE](NOTICE) for the full list and their licences.

## Licence

[Apache License 2.0](LICENSE).

Note that the Docker image redistributes Nmap, which carries the Nmap Public
Source License rather than an OSI-approved one and restricts commercial
redistribution. Apache 2.0 on this repository does not relicense it. If you
plan to ship this commercially, read [NOTICE](NOTICE) first.
