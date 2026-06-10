---
status: closed
priority: medium
created: 2026-06-09
resolved: 2026-06-10
---

# settings-diff Pipeline

The `settings-dump` command exports all settings as a flat table.
The missing second half is a structured diff between two exports.

## Use case
```
gpo-lens settings-dump snapshot-1 --json > before.json
gpo-lens settings-dump snapshot-2 --json > after.json
gpo-lens settings-diff before.json after.json
```

Shows exactly which settings changed between two points in time,
at the (gpo_id, cse, identity) level — not just "this GPO changed."

## Implementation
- `settings_diff()` in `queries.py`: reads two JSON exports, joins on `(gpo_id, cse, identity)`, reports added/removed/modified settings
- Uses `normalize.canonical_guid` for GPO ID normalization and `normalize.load_json` for BOM-tolerant loading
- Supports `--side`, `--cse`, `--gpo` filters (same as settings-dump, but gpo filters by id not name)
- `SettingsDiffRow` dataclass for result rows
- CLI: `gpo-lens settings-diff <file_a> <file_b>` with `--side`, `--cse`, `--gpo` filters
- Display: `render_settings_diff()` in display.py for grouped text output; table rendering for default CLI output
- Tests: 9 unit tests in test_queries.py, 4 CLI integration tests in test_cli.py, 3 display tests in test_display.py
