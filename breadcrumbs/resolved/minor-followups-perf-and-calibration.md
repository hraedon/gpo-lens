---
status: resolved
resolved: 2026-06-17
priority: low
kind: defect
created: 2026-06-17
---

# Minor follow-ups: N+1 changelog query + loose calibration bounds

Two small, independent items bundled here as low priority.

## 1. snapshot_changelog is N+1

`src/gpo_lens/queries.py` `snapshot_changelog` (around line 499-506) issues one
`_version_query` per GPO id in the common set. For the documented 100+ GPO /
1000+ SOM work domain that is 100+ round-trips. Used by both web `/changelog`
(`web/app.py`) and CLI `changelog`. Mostly hidden by SQLite's page cache, but
it shows up as web page latency.

**Fix:** replace the per-GPO loop with one batched
`WHERE snapshot_id IN (?, ?) AND id IN (...)` query.

## 2. Calibration bounds are loose

`tests/test_calibration.py` uses soft lower bounds:
- `test_loopback_detected` asserts `>= 28` while the comment + `tier1`
  doc cite **31** actual loopback hits. A regression from 31 → 20 still passes.
- `test_work_no_precedence_conflicts_on_clean_soms` is conditional on finding
  a single-link SOM and only asserts "doesn't crash" — it cannot catch a bug
  in the conflict-folding logic.

**Fix:** tighten `>= 28` to the documented 31 (or `>= 30` with a noted delta);
either pin a specific conflict finding or drop the no-op precedence test.

## Context

Raised during the 2026-06-17 architecture review (L4 / L5). Low severity, no
correctness impact today — deferred to keep this session focused on the
charter-integrity and contract fixes.
