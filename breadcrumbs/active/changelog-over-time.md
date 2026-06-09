---
status: open
priority: medium
created: 2026-06-09
---

# Enhanced Change-Log-Over-Time

The `snapshot_diff` and `diff` commands exist but only report "which GPOs changed"
at the metadata/link/delegation level.  What's missing for AGPM replacement:

## Per-setting delta
Between snapshot A and B, show exactly which settings appeared, disappeared,
or changed value — not just "this GPO's settings changed."

The store already has per-setting rows keyed by `(snapshot_id, gpo_id, cse, identity)`.
A query that joins `setting` between two snapshot_ids and diffs `(display_value)`
would produce the structured delta.

## Version-aware diffing
Correlate GPO version number increments with the specific settings that changed.
If `user_ver_sysvol` went from 3→4, show which User-side settings differ.

## Who/when attribution (stretch)
Ingest Security event logs (Event ID 5136 — DS attribute change) and correlate
timestamps with snapshot diffs.  Requires audit logging enabled in advance;
cannot reconstruct unlogged past.

## Implementation sketch
- `queries.snapshot_diff` already queries `setting` between snapshots — extend
  it to return `(gpo_id, cse, identity, old_value, new_value)` tuples
- Add `SnapshotSettingChange` dataclass
- CLI: `gpo-lens diff-settings <snap_a> <snap_b> [--gpo NAME]`
- Wire into `cmd_diff` or a new `cmd_diff_settings`

## Depends on
Nothing — store schema already supports it.
