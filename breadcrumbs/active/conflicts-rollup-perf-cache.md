---
status: active
priority: medium
kind: enhancement
created: 2026-06-23
---

# Cache the resolved precedence-conflict rollup (~3s per load)

## Problem
The `/conflicts` "Resolved (who wins)" tab calls
`topology.precedence_conflict_rollup(estate)`, which calls
`precedence_conflicts(estate)` — that resolves the link chain and re-buckets
settings for **every** OU/domain SOM. On a real ~910-OU estate this takes
~3.0–3.3s per request. The route already avoids paying it on the "defined" tab
(it only computes the rollup when `view=resolved`), but the resolved tab itself
is slow on every visit and every pagination click.

## Risk
A 3s synchronous handler blocks a worker and feels broken to the user, and it
will scale with OU count. Not dangerous (read-only, opt-in page), but the one
rough edge in the otherwise-instant UI.

## Suggested fix
Options, cheapest first:
- **Dedup by resolved-chain signature.** Most leaf OUs share the same ordered
  enabled-GPO chain (the rollup shows single conflicts spanning 860+ scopes);
  compute `som_conflicts` once per *distinct* chain signature, then fan the
  result back out to the scopes that share it. Likely an order-of-magnitude win
  with no caching infrastructure.
- **Memoize the rollup** keyed by the estate's content hash / ingest id, so
  repeat visits and pagination are free until the next import.
- Longer term, precompute on ingest and store alongside the estate.

## Context
Filed during the 2026-06-23 Conflicts-view session. The rollup itself is correct
and validated (10,935 per-OU instances → 58 distinct conflicts on the test estate); this
is purely the cost of recomputing it live. See CHANGELOG "Conflicts view" perf
note.
