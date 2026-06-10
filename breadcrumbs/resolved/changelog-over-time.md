---
status: resolved
priority: medium
created: 2026-06-09
resolved: 2026-06-10
---

# Enhanced Change-Log-Over-Time

**Partially resolved.** What landed:

- `snapshot_settings_diff` (per-setting delta, committed `61670c0`) — matches the "Per-setting delta" requirement.
- `snapshot_changelog` (version-aware, this session) — correlates version counters with setting changes, distinguishing "metadata says N edits" from full setting detail.

**Deferred:**
- Event-log attribution (Event ID 5136 correlation with snapshot diffs) — stretch goal, requires event log access beyond file-based input.

**Completed this session:**
- `gpo-lens settings-diff <file_a> <file_b>` — implemented in settings-diff-pipeline breadcrumb (now closed).
