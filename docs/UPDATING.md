# Keeping the app current

You said you want to improve this every week. Here's the split that makes that
sustainable: **detection coverage updates itself, the tooling updates monthly,
and your own judgment is the part that compounds.**

Don't rewrite the app every week. Add one capability, then leave it alone.

---

## Weekly — 10 minutes

**1. Refresh nuclei templates.** This is 90% of your detection freshness. New
CVE templates land within days of disclosure.

```bash
docker compose exec backend nuclei -update-templates
```

Or click it in the UI (`POST /api/system/update-templates`). Nothing else you
do gives this much coverage for this little effort.

**2. Skim what's new.** The nuclei changelog tells you what classes of issue
just became detectable — useful for knowing what to go looking for manually.

```bash
docker compose exec backend sh -c \
  'cd /root/nuclei-templates && git log --oneline --since="1 week ago" | head -40'
```

**3. Add one heuristic.** If you manually noticed something a scanner missed
this week, encode it. `normalize.from_httpx_exposure()` in `normalize.py` is
the cheap place for pattern-matching heuristics; a custom nuclei template is
the right place for anything request/response based.

Custom templates go in a directory you mount and pass with `-t`. Writing them
is YAML, not code — the nuclei docs are worth an hour of your time.

---

## Monthly — 30 minutes

**Rebuild to pick up new scanner releases.** The Dockerfile downloads the
latest official release binary for each tool at build time — no compilation, so
a rebuild is seconds rather than minutes.

If a new release ever breaks a parser, swap that one tool's lookup for a fixed
asset URL in `backend/Dockerfile`; the others keep tracking latest.

To see what versions you're actually running:

```bash
for t in subfinder httpx naabu nuclei katana; do
  echo -n "$t: "; docker compose exec -T backend "$t" -version 2>&1 | head -1
done
```

Rebuild without cache so the `@latest` layers actually re-resolve — a plain
rebuild will happily reuse the cached layer and change nothing:

```bash
docker compose build --no-cache backend
cd backend && python -m pytest tests -q
```

Then run a scan against a target you own and compare the finding count to last
month's. A sudden drop to zero means an output format changed and a parser in
`normalize.py` needs updating.

**Review your false positives.** Filter Findings by `false_positive` and look
for a pattern. Repeated FPs from the same nuclei template mean you should
exclude that template; repeated FPs from the LLM mean the triage prompt in
`triage.py` needs a specific instruction added.

---

## When you have a free weekend

Roughly in order of value-per-hour:

1. **Auth-aware scanning.** Feed session cookies or a bearer token through to
   httpx and nuclei. Most of a real application is behind login, so this
   roughly doubles what you can see. Store credentials per-engagement.
2. **Diffing between scans.** "What's new since last week" is the single most
   useful view for continuous monitoring, and you already store everything you
   need for it. Compare `dedupe_key` sets across two scans of the same
   engagement.
3. **Scheduled re-scans.** A cron-triggered scan plus the diff above turns this
   from a manual tool into monitoring.
4. **ZAP integration.** Active web scanning via the ZAP daemon's API. Much
   deeper than nuclei on web-specific issues, much noisier. Add it as a stage.
5. **Semgrep / trivy / gitleaks.** For when you have source access — your own
   projects, and college code you're allowed to review.
6. **Screenshot capture.** `gowitness` or similar. Wildly useful for triaging a
   hundred hosts quickly; your eye catches things a fingerprint doesn't.

---

## What not to build

- **Your own vulnerability detection logic.** You will spend months matching
  what nuclei does today, and it'll be stale next month.
- **Exploit automation.** Beyond the ethics, "proof of exploitation" on a
  target you don't own crosses a line that scanning doesn't.
- **A public version.** You already decided this. It's the right call — a
  polished scanner with a nice UI lowers the barrier for people with worse
  intentions than yours, and you gain nothing from publishing it.

---

## If you want to keep a portfolio

You can't publish the tool, but you can publish what it taught you. Write-ups
of disclosed findings (after the program permits disclosure), a blog post on
your dedupe or triage approach, the scope-guard design — all of that
demonstrates the same skill without handing anyone a weapon. For a cybersecurity
student that's a stronger portfolio than the code itself.

---

## Reference: what the updater actually refreshes

*(Moved here from the README when it was split into docs/.)*

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

