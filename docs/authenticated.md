# Authenticated scanning

[← back to the README](../README.md)

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

