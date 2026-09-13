# Scope, ethics and limits

[← back to the README](../README.md)

## What it will not do

Not missing features — deliberate limits, documented in [SECURITY.md](../SECURITY.md):

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
Merlon's job is to clear everything mechanical fast, so your attention goes
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

