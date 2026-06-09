---
status: open
priority: medium
created: 2026-06-09
---

# settings-diff Pipeline

The `settings-dump` command exports all settings as a flat table.
The missing second half is a structured diff between two exports.

## Use case
```
gpo-lens settings-dump snapshot-1 > before.csv
gpo-lens settings-dump snapshot-2 > after.csv
gpo-lens settings-diff before.csv after.csv
```

Shows exactly which settings changed between two points in time,
at the (gpo_id, cse, identity) level — not just "this GPO changed."

## Implementation sketch
- `settings-diff` reads two JSON exports (from `settings-dump --json`)
- Joins on `(gpo_id, cse, identity)`
- Reports: added, removed, value-changed
- Supports `--side`, `--cse`, `--gpo` filters (same as settings-dump)
- CLI: `gpo-lens settings-diff <file_a> <file_b>`

## Alternative: direct snapshot diff
Could also work directly against the store:
```
gpo-lens settings-diff --db gpo-lens.sqlite3 1 2
```
This would be faster (no intermediate files) and reuses the existing
`snapshot_diff` infrastructure.

## Depends on
`settings-dump` (already implemented).
