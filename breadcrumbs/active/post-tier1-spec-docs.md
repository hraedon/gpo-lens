---
status: open
priority: low
kind: design
created: 2026-06-20
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
