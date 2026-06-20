---
status: open
priority: medium
kind: defect
created: 2026-06-20
---

# Malformed TOML danger rule entry crashes danger evaluation

## Problem

`danger._load_rules_file` (danger.py:406-407) accesses TOML entries via
`entry["id"]`, `entry["title"]`, `entry["severity"]`, `entry["applies"]`,
`entry["identity"]`, and `entry["reference"]` using `dict.__getitem__`. If a
TOML rule entry is missing any required field, an unhandled `KeyError`
propagates up and crashes the entire danger evaluation.

The function catches `OSError` and `TOMLDecodeError` (line 399) but not
`KeyError`. The shipped `danger_rules.toml` is valid, but a user-supplied TOML
via `GPO_LENS_DANGER_RULES_DIR` with a missing key will take down the whole
`danger_findings()` call.

## Suggested fix

Wrap the entry parsing in a try/except `KeyError` that logs a warning and skips
the malformed entry, or validate required keys before access. The existing
`TestDangerRulesToml.test_shipped_rules_parse` validates post-parse structure
but doesn't test the parser's resilience to malformed input.
