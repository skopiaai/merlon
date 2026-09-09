# Reporting and submission

[← back to the README](../README.md)

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
GET  /api/scans/{id}/queue                       the three buckets
POST /api/findings/{id}/verify                   re-check one on demand
GET  /api/findings/{id}/evidence                 reproduction block
GET  /api/findings/{id}/submission?platform=…    hackerone | bugcrowd | intigriti
GET  /api/findings/{id}/template                 a reusable nuclei template
```

### Submitting

Every platform reads reports in a different shape, and the difference isn't
cosmetic — HackerOne triagers work Summary → Steps to Reproduce → Impact and
bounce reports missing reproduction steps; Bugcrowd wants a VRT category up
front because that determines the payout band. A good finding in the wrong
shape gets sent back for "more information" and loses a week.

Reports are **assembled from the captured evidence**, not generated. There is
no model in that path, and a test asserts it: a report is a rendering problem,
and generated reports are what programs are currently drowning in.

**A finding that didn't reproduce won't render as a submission.** It returns a
refusal that names the three possibilities — the target changed, the result was
intermittent, or it was never real — and tells you to re-verify. Making it one
click to file an unreproducible finding would undo the entire verification
layer.

### Keeping the work

`GET /api/findings/{id}/template` turns a verified finding into a nuclei
template. A finding is worth one report; a template is worth every future scan
against every target, and it runs in anyone else's nuclei too.

Matchers come from the response that was actually recorded — never inferred —
and anything that describes *this* target rather than the vulnerability (a
hostname, a date, a session id) is kept out, because a matcher like that looks
like a working check and silently matches nothing everywhere else. The
generated YAML is parsed before it's handed over, so a malformed file is
raised as a generator bug rather than delivered.

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

