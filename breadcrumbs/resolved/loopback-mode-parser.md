---
status: resolved
priority: medium
kind: defect
created: 2026-06-17
resolved: 2026-06-18
wi: WI-028
---

# WI-028: Loopback mode parser classifies every real-world setting as 'unknown'

The `_extract_loopback_mode` function in `topology.py` only handled the
`Security` CSE shape (`SettingString`/`SettingBoolean` children with text
"Merge"/"Replace"/"1"/"2"). Real-world GPO exports configure loopback via
the `Registry` CSE, where the raw dict has a `Policy` tag with a different
child structure:

- `Policy > State` ("Enabled"/"Disabled") — whether loopback is active
- `Policy > DropDownList > Value > Name` — the mode ("Merge"/"Replace")

The parser never checked this path, so every real-world loopback setting
was classified as "unknown" (merge/replace never resolved).

## Fix

Extended `_extract_loopback_mode` to handle three raw-dict shapes:

1. **Security CSE** (test fixtures): `SettingString`/`SettingBoolean` children
2. **Registry CSE / Policy** (real-world): `DropDownList > Value > Name` path,
   with `State = "Disabled"` returning None (not actually configured)
3. **Fallback**: `display_value` substring matching for "replace"/"merge"

## Validation

- 4 new unit tests with realistic `Policy > DropDownList` raw dicts
- Calibration test `test_loopback_modes_resolved` against the real work
  estate: asserts zero "unknown" modes across all 28 loopback GPOs
- All existing loopback tests still pass (no regression on Security CSE path)
