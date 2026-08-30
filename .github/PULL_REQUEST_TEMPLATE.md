## What this changes

<!-- One or two sentences. -->

## Why

<!-- What problem this solves. For a new detection: what an attacker does with
     the thing it finds. -->

## Checklist

- [ ] `cd backend && pytest` passes
- [ ] `cd frontend && npx tsc --noEmit` passes
- [ ] New detections include a test for their most likely **false positive**
- [ ] New `rule_id`s have a mapping in `compliance.py`
- [ ] Network calls go through `fetch.request(..., ctx=ctx)` — not a private client
- [ ] Nothing here modifies, writes to, or claims a resource on a target
- [ ] No credentials, scan data, or real hostnames in the diff

## Anything reviewers should look at closely

<!-- Optional. Assumptions you're unsure about are more useful here than
     reassurance. -->
