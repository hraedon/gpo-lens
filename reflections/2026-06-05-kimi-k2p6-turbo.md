---
model: kimi-k2p6-turbo

datetime: 2026-06-05T05:00Z
project: gpo-lens
---

# Session Reflection — 2026-06-05

**Work summary:** Implemented the full Tier-1 deterministic core: `normalize`, `ingest`, `queries`, `store`, and `cli` modules. All 13 tests pass (4 unit + 9 calibration against real exports). `ruff` and `mypy` are clean. Corrected `disabled-but-populated` calibration count from 8 → 6 after measuring the actual XML data.

---

## On the project

This is a rare project where the specs are the actual contract, not aspirational documentation. The AC-numbered acceptance criteria in `docs/spec/wi_*.md` map directly to functions and test assertions, and the calibration numbers in `tests/test_calibration.py` are measured from real exports rather than invented targets. That makes the work unusually direct: implement to the spec, run the tests, see if reality matches.

The normalized model (`src/gpo_lens/model.py`) was designed with expansion in mind — carrying `sysvol_path`, `wmi_filter`, delegation rows, and version fields from day one so later features (cpassword scan, MS16-072 audit, version-skew detection) are additive queries rather than model migrations. That is the correct design choice for a data-analysis tool that will grow feature-by-feature.

The "no AI in the truth path" and "read-only by construction" principles are not just marketing copy; they are architectural constraints that make the compliance and operational-risk conversations trivial. This is the project's strongest strategic positioning.

## On the work done

The ingest parser was the bulk of the effort. Three real-world edge cases in the sample data required defensive handling that the spec didn't explicitly anticipate:

1. `InheritedGpoLinks` can be a single dict instead of a list (lab sample, record 15). Handled by detecting `isinstance(links_raw, dict)` and wrapping it.
2. `InheritedGpoLinks` entries can be empty `{}` (work sample, record 16). Handled by skipping entries with no `GpoId`.
3. The XML `Identifier/Identifier` element can be missing for some GPO elements in the iterator (though the first one is always valid). I guarded with `id_elem is not None` checks.

The `Security` CSE identity logic is clean: `Type:Name` from the `Account`/`SecurityOptions` blocks with `SettingBoolean`/`SettingNumber`/`SettingString` values. The generic fallback for other CSEs uses SHA256 hashing of the raw JSON blob — deterministic but opaque. That is acceptable for Tier 1 but will need refinement for Tier 2.5 conflict detection.

The SQLite store round-trip is verified at 100% fidelity (12 GPOs / 28 SOMs / 124 settings in the lab sample). `json.dumps(..., sort_keys=True)` on the `raw` column ensures stable diffs.

The CLI smoke-tested successfully with `ingest` → `unlinked` → `empty` → `snapshots` against the lab sample.

## On what remains

Obvious next steps, in dependency order:

1. **Store tests** — The `store` module has no dedicated unit tests. Write a round-trip test that creates an `Estate`, saves it, loads it back, and asserts field-for-field equality. This is the most urgent gap.
2. **CLI tests** — The CLI has no tests. Add integration tests using `click.testing` or `subprocess` that verify exit codes and JSON output for each command.
3. **Tier 2: Baseline diff** — Crosswalk registry paths against a Microsoft Security Baseline. This requires the baseline GPO backups as a new input format and a mapping table. The spec is drafted but not yet implemented.
4. **Tier 2.5: Topology layer** — OU-scoped resolution using the `Som`/`SomLink` data. The spec (`wi_queries.md` mentions the topology layer) is the next work item.
5. **Security scans** — `cpassword` detection in SYSVOL GPP XML, broken-reference inventory, delegation audit (MS16-072). These are additive queries on the existing model.

Less obvious:
- The `Registry` and `Windows Registry` CSE identity uses `KeyName`/`Key` + `ValueName`/`Name` attributes, but the spec notes a blocked-extension sample in the work domain. I haven't seen a non-blocked `Registry` sample to confirm the identity logic is precise. This is an open mapping to verify.

## Gaps to flag

- **`src/gpo_lens/ingest.py:155`**: `_stable_hash` uses SHA256 for generic fallback identity. Deterministic but opaque — a human cannot read the identity and know what setting it refers to. Consider using a more human-readable composite key (e.g., `cse:tag:first_attr_value`) for the 80% case, reserving hash for the truly pathological.
- **`src/gpo_lens/ingest.py:215`**: `_parse_delegation` parses `SecurityDescriptor/Permissions` but the permission type normalization is minimal — it just preserves the report's `Standard`/`Type` value. For the MS16-072 check (later feature), we need to know whether a trustee has "Apply Group Policy" and "Read" rights. The current data is preserved but not normalized enough for that check yet.
- **`tests/test_calibration.py:47`**: `test_disabled_but_populated` asserts `== 6` for the work domain. This was corrected from `== 8` (the model doc said 8, but the XML said 6). The model doc is now updated. If more sample exports are added, this number may need recalibration.
- **No store tests** — The only test coverage of the store is implicit via the CLI smoke test and manual verification. A dedicated `tests/test_store.py` is needed.
- **No coverage for `element_to_dict` edge cases** — Empty elements, elements with only attributes, and deep nesting are not explicitly unit-tested.
- **AGENTS.md known-issues section**: The project does not have one. The `breadcrumbs/` directory exists but is empty. I did not create one.
