# Security Policy

## Reporting a vulnerability in Merlon itself

Please **do not** open a public issue for a security problem in this tool.

Email the maintainer, or use GitHub's private vulnerability reporting
(Security → Report a vulnerability). Include what you found, how to reproduce
it, and what you think the impact is. You'll get an acknowledgement within a
few days.

This is a personal project maintained by one person, so there's no bounty and
no guaranteed response time. What there is: credit in the release notes if you
want it, and a fix.

### What is in scope

Anything that lets Merlon harm its operator or a third party:

| Class | Why it matters |
|---|---|
| **Credential leakage** | Stored session headers reaching a host outside the engagement's scope, appearing in logs, reports, or the API |
| **Scope guard bypass** | Any path that causes a request to a host the engagement doesn't allow |
| **Command injection** | The tool builds subprocess arguments from scan targets and user input |
| **SSRF via target input** | A crafted target reaching cloud metadata or internal services |
| **Path traversal** | Artifact and report handling, uploaded evidence files |
| **XSS in the UI** | Finding content is attacker-controlled — a scanned site can put anything in a response body, and that body ends up rendered |

That last row deserves emphasis, because it's the non-obvious one. **Evidence
in a finding is data controlled by whoever runs the scanned site.** A malicious
target that gets script into a finding's evidence, and then into the operator's
browser, has attacked the person scanning them. Reports of that kind are very
welcome.

### What is not in scope

- The tool finding vulnerabilities in your site. That's what it's for.
- Missing authentication on the API. Known and documented below.
- Credentials stored unencrypted in the local database. Known and documented.
- Reports from automated scanners with no analysis.

---

## Known limitations

These are deliberate trade-offs for a single-user local tool, documented so
nobody discovers them the hard way. They would all be defects in a hosted or
multi-user deployment.

**The API has no authentication.** Anything that can reach
`127.0.0.1:8000` can start scans, read findings, and configure credentials.
Docker Compose binds to localhost only. If you expose this to a network, put
an authenticating proxy in front of it — and understand that you're then
running a service that will make requests to arbitrary hosts on request, which
is an SSRF gateway by design.

**Credentials are stored in plaintext** in the local SQLite database. Acceptable
for one person's laptop; not acceptable for anything shared. If you're storing
a production session cookie, that file is as sensitive as the cookie.

**Scan data is sensitive.** `data/` contains findings about real systems and
is gitignored for that reason. Don't commit it, don't put it in a bug report.

**No sandboxing between scans.** All scans run in the same container with the
same filesystem access.

---

## What this tool deliberately does not do

These are not missing features. They were considered and rejected, and pull
requests adding them will be declined.

### It does not exploit

Detection stops at the point where proving the issue would mean changing
something on a system you don't own.

- **Subdomain takeover** is confirmed by reading the hosting service's
  "unclaimed name" page. It never registers the name — registering it *is* the
  attack.
- **Dangerous HTTP methods** are reported from `OPTIONS` and the `Allow`
  header. It never sends `PUT` or `DELETE` to prove they work, because that
  writes to or removes files on someone else's server.
- **Open redirect** reads the `Location` header. It doesn't follow it.
- **Access control testing** issues `GET` requests as accounts you configured.
  It reads resources those accounts can already reach.

The reports say what to verify and how to fix it instead. A finding that
required an intrusion to confirm is a finding you can't ethically submit.

### It does not evade

There is no traffic obfuscation, no attempt to avoid logging, no WAF bypass
for the purpose of concealment. Scans are made to be visible in the target's
logs.

This was requested during development and declined. The reasoning: concealment
has no legitimate purpose in authorized testing — if you have permission, being
seen is fine, and if you don't have permission, no amount of hiding makes it
legal. Under India's IT Act §43 and §66, and equivalents elsewhere,
unauthorized access is a criminal offence, and evasion is evidence of intent.

### It does not reach outside its scope

Every host is checked against the engagement's allow and deny rules before it
is touched, at every stage boundary — including hosts discovered mid-scan by
certificate transparency, archived URLs, JavaScript parsing or reverse DNS.
Cloud metadata ranges (`169.254.0.0/16`) and loopback are hard-denied and
cannot be allowlisted.

Credentials go through the same gate on **every individual request**, not once
per scan.

There are tests whose entire purpose is to hold these properties. If you change
`scope.py` or `engines/fetch.py`, they should fail loudly before you get near a
merge.

---

## Acceptable use

**Scanning a system you do not own or have written permission to test is a
crime in most jurisdictions.** In India that's the Information Technology Act,
2000 — §43 (unauthorized access) and §66 (computer-related offences). In the
United States it's the Computer Fraud and Abuse Act. In the UK, the Computer
Misuse Act 1990. The details differ; the conclusion doesn't.

"I was only scanning" is not a defence. Neither is "I meant well," "I found a
real bug," or "the site was insecure anyway."

Before you scan anything, you should be able to point to one of these:

- You own the system.
- A bug bounty program lists it in scope, and you're inside that program's
  rules — including its rate limits and its exclusions.
- You have written permission from someone with authority to grant it. Verbal
  permission from a professor or a manager evaporates the moment something
  goes wrong.

The tool requires you to record who authorized the work and where the proof is
before it will scan. That record isn't bureaucracy — it's the thing that
protects you if anyone ever asks. Fill it in honestly; a self-attestation that
you own a domain you don't own is worse than no record at all.

**On testing your college or university:** get it in writing, from someone who
can actually authorize it, before you touch anything. Students have been
expelled and prosecuted for scans they believed were helpful. If the
institution has no disclosure process, the correct first step is asking for
one — not demonstrating the need for one.

---

## Responsible disclosure of what you find

If you find a vulnerability in someone else's system using this tool:

1. **Report it to them**, through their published process. The tool checks for
   a `security.txt` on every target partly to make that easy.
2. **Give them time.** 90 days is the usual norm; less if it's actively being
   exploited, more if they're engaging in good faith and the fix is genuinely
   hard.
3. **Don't access more than you need** to demonstrate the issue. One record
   proves an IDOR. Ten thousand records is a data breach that you caused.
4. **Don't publish** the details until it's fixed, or until you've given them
   reasonable time and warning.

The reports this tool generates are written to be sent to the affected
organisation, and are deliberately shaped around remediation rather than
proof-of-concept.
