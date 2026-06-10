---
status: open
priority: low
kind: todo
created: 2026-06-10
---

# Consistent --admx-dir error handling across all commands

## Problem

Three commands accept `--admx-dir`: `baseline-diff`, `admx-gaps`, and `report`.
The `report` command now warns on nonexistent paths and on `--admx-dir` without
`--baseline`. The other two commands silently degrade to an empty crosswalk on
bad paths with no warning.

## Fix direction

Extract the `--admx-dir` handling into a shared helper or apply the same warning
pattern from `_report.py` to `_diff.py` and `_settings.py`.

## Files

- `src/gpo_lens/cli/_report.py:45-53` — has warnings (reference implementation)
- `src/gpo_lens/cli/_diff.py:192-195` — silently degrades
- `src/gpo_lens/cli/_settings.py:312-315` — silently degrades
