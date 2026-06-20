---
status: resolved
priority: medium
kind: defect
created: 2026-06-20
resolved: 2026-06-20
---

# Malformed TOML danger rule entry crashes danger evaluation

## Problem

`danger._load_rules_file` (danger.py:406-407) accessed TOML entries via
`entry["id"]`, `entry["title"]`, etc. using `dict.__getitem__`. A malformed
TOML rule — missing required fields, non-table `rules` value, or non-dict
`[[rules]]` entry — would raise `KeyError`/`AttributeError`/`TypeError` and
crash the entire `danger_findings()` call.

## Resolution

The function now:

1. Validates `rules` is a list (warns + returns empty if not).
2. Validates each entry is a dict (warns + skips if not).
3. Validates required fields via `_REQUIRED_RULE_FIELDS` (warns + skips if
   missing).

5 new tests in `tests/test_danger.py::TestDangerRules` cover all three
categories. All 1352 tests pass; coverage 86.71%.

The first review surfaced one additional category (non-dict entries) that
the breadcrumb's suggested fix didn't cover — adversarial review caught
this before the fix was committed.
