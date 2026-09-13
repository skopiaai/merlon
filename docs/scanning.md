# Scanning in depth

[← back to the README](../README.md)

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
| **domxss** | DOM-based XSS proven by executing a payload in headless Chromium; the class no body-reading check can see | The payload only sets document.title and runs solely in the scanner's own browser; a fragment never reaches the server |
| **xss** | Reflected XSS decided from the response: an inert nonsense tag is injected and reported only if it survives unencoded | Reflection-gated; existing GET params only; nothing scripts or changes state |
| **nosqli** | NoSQL (MongoDB-style) injection via operator injection (param[$ne]) on a strict true/false differential, plus driver errors | GET params only; no $where JavaScript, extraction or writes |
| **sqli** | SQL injection via database error signatures and a strict boolean true/false differential | GET params only; no stacked queries, time delays or data extraction are ever sent |
| **ssti** | Server-side template injection, proven by evaluating wrapped random arithmetic (Jinja2, Twig, ERB, Velocity, Razor and more) | Only multiplication is ever evaluated; reflection cannot cause a false positive; existing params only |
| **jwt** | alg=none, HMAC secrets recovered by recomputing the signature, sensitive claims, and tokens that never expire | Decided from the captured token offline; no forged token is sent |
| **cachepoison** | Unkeyed headers that change a cached response, and static-looking suffixes that make a cache store a logged-in user's page | Every probe carries a unique cache-buster, so a poisoned entry is only ever our own URL |
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
| **DOM XSS proven by execution** | ✗ | ✗ | ✗ | ✓ |
| Screenshots / visual triage | ✓ | – | ✓ | ✓ |
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

Headless Chromium now ships in the image, which closed the screenshot gap and
added something none of the three has: **DOM-based XSS proven by execution**.
That class never appears in an HTTP response — a fragment is not even sent to
the server — so a scanner that only reads response bodies is structurally blind
to it.

Two honest caveats on that table. BBOT still has more passive data sources than
anything here, because several of them require paid API keys. And "dedicated"
in the CORS/redirect row means a purpose-built engine with its own
false-positive handling rather than a template match — better precision, but
nuclei's template library remains far broader than any hand-written set of
checks and is doing most of the CVE work.

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

