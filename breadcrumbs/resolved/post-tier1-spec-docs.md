---
status: resolved
priority: low
kind: design
created: 2026-06-20
resolved: 2026-06-22
wi: WI-035
---

# Post-Tier-1 modules lack formal spec documents (wi_*.md)

## Problem

The five original work-item specs (`wi_ingest.md`, `wi_queries.md`,
`wi_store.md`, `wi_cli.md`, `wi_narration.md`) cover the Tier-1 and Tier-2.5
surface. All modules added after that wave — `danger.py`, `merge.py`,
`topology.py`, `authz.py`, `events.py`, `sinks.py`, `registry_pol.py`,
`snapshot_diff.py`, `paths.py`, `query_dispatch.py` — have no formal spec
documents. Their de-facto specs are the plan files (007-021), which are less
precise (no numbered ACs, no function signatures).

This matters for `merge.py` especially: it's 982 lines with complex CSE merge
modes, token expansion, security-gate evaluation, and principal resultant
logic. The plan (021) describes the "what" but not the testable acceptance
criteria.

## Suggested fix

Add `wi_merge.md` as the highest-priority new spec — it documents the most
complex post-Tier-1 module and would serve as the contract for any future
refactoring. The others can remain plan-specified until a 1.0 spec pass.

## Resolution (2026-06-22)

`wi_merge.md` landed 2026-06-20. The remaining nine specs — `wi_danger.md`,
`wi_registry_pol.md`, `wi_topology.md`, `wi_authz.md`, `wi_snapshot_diff.md`,
`wi_events.md`, `wi_sinks.md`, `wi_paths.md`, `wi_query_dispatch.md` — written
in the `wi_merge.md` format (Dependencies, Notes with drift documentation,
Module map, numbered ACs). Each spec documents discovered plan-vs-code drift
in its Notes section rather than papering over it.
