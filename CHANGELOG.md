# Changelog

## Unreleased (toward v0.3.0)

### Scope honesty
- **`is_security_filtered` hardened (WI-009).** Now recognises `Everyone`
  (S-1-1-0) alongside Authenticated Users and Domain Computers, applies
  deny-ACE precedence (a deny Read/Apply on a broad trustee overrides its
  allow), and treats an *empty* delegation list as "not filtered" rather than
  a confident false positive — absence of delegation data is not evidence of
  filtering. Nested membership and inherited ACEs remain explicitly not
  modeled (charter: flag, don't simulate). Scope caveat reworded to "appears
  security-filtered (… nested membership and inherited ACEs not evaluated)".
- **All-disabled SOM is flagged, not silent.** `scope_caveats` now
  distinguishes "SOM not found" from "SOM exists but every GPO link is
  disabled," emitting a caveat for the latter instead of returning nothing
  (previously both cases were silent).

### Added
- **Four hygiene categories surfaced on the estate summary (WI-007).**
  `EstateSummary` now carries `broken_wmi_ref_count`,
  `orphaned_wmi_filter_count`, `ilt_gpo_count`, and `stale_gpo_count`,
  rendered in the Markdown/HTML report tables and the web dashboard.

### Bug fixes
- **`stale_gpos` leap-year drift.** Year math now divides elapsed days by
  365.25 so a GPO just under the threshold is not rounded up across a leap
  day. Added an injectable `now` parameter so staleness tests pin a reference
  clock and no longer rot as wall-clock time passes the fixed fixture
  timestamps (WI-010). `estate_doctor` accepts the same `now` so its
  stale-GPO finding is deterministic under test too.
- **Item-level-targeting findings name the file.** `IltHit` now reports the
  specific GPP XML file(s) (e.g. `Registry.xml`) that carry `<Filters>`
  instead of a hard-coded `SYSVOL`.
- **`settings-at` dead loopback branch removed.** The text view's estate-wide
  loopback block could surface GPOs not in scope at the queried SOM; loopback
  is already covered, correctly scoped, by `scope_caveats`.

### Tests
- New `tests/test_scope_honesty.py` and `tests/test_scope_cli.py` covering
  scope-caveat / effective-scope / ILT edge cases and the `scope` CLI command
  (WI-008). Suite: 665 passed, 25 skipped; ruff and mypy --strict clean.

## v0.2.2 — 2026-06-10

- **Note:** v0.2.1 was folded into this release.

### Bug fixes
- **`report --db` no longer shadows top-level `--db`**: Removed duplicate `--db` argument from the report subparser that silently overrode the parent parser's value (report-db-shadow).
- **`ask` validates required params before dispatch**: `settings_at_som` now errors clearly if `ou_path` is missing instead of silently returning empty results. Unexpected params from LLM routing produce a warning (dispatch-param-validation).
- **Consistent `--admx-dir` warnings**: `baseline-diff` and `admx-gaps` now warn on nonexistent/invalid `--admx-dir` paths, matching the existing `report` behavior (admx-dir-consistent-errors).

### Added
- `--version` flag to CLI (prints version and exits).
- Version-sync test asserting `pyproject.toml` version matches `__init__.__version__`.

## v0.2.0 — 2026-06-10

### Workstream D — Distribution & Polish
- **CLI decomposition**: Monolithic `cli.py` (1,749 lines) refactored into a 13-module `cli/` package. Entry points preserved; all 389 tests pass.
- **Collector hardening** (`Export-GpoEstate.ps1`): `-DryRun` flag, per-section `Write-Progress`, module validation, writability check, export summary, `-LiteralPath` for wildcard safety, least-privilege documentation.
- **Design debt fixes**: `_get_estate` raises `FileNotFoundError` instead of `sys.exit()`, DB connections wrapped in `try/finally`, architecture guard test scans all `cli/*.py` files, `settings-diff` reports `skipped_count`, dead `_PD()` import removed.
- **GitHub Actions CI**: ruff + mypy --strict + pytest, pinned action SHAs, uv caching, `permissions: contents: read`.
- **Public repo**: [github.com/hraedon/gpo-lens](https://github.com/hraedon/gpo-lens).

### Test coverage
- 389 tests. `ruff` and `mypy --strict` clean. CI green in 21s.

## v0.1.0 — 2026-06-10

### Infrastructure (Phase 0)
- **CI-ready fixture estate** (`tests/fixtures/`): 8 synthetic GPOs covering cpassword, MS16-072, version-skew, broken UNC, loopback, block-inheritance, enforced links, precedence conflicts, and blocked extensions. 25 fixture tests run without real `samples/`.

### Workstream A — AGPM-replacement story
- **`snapshot_changelog()` + `changelog` CLI**: Version-aware change log that pairs GPC/GPT version counter deltas with per-setting diffs. Distinguishes "metadata says N edits" from full setting detail.
- **`gpo-lens report` CLI**: Self-contained Markdown/HTML estate documentation export. Synthesizes estate summary, doctor findings by severity, topology overview, baseline compliance %, and change history. Print-to-PDF friendly.
- **`gpo-lens ingest --diff-latest`**: Auto-diff against the previous snapshot on ingest, appending to the changelog workflow.

### Workstream B — Security-analysis depth
- **`delegation` CLI + `delegation_deep_dive()`**: Privilege rollup (which trustees edit which GPOs), orphaned SID detection, and non-default-editor flagging.
- **`admx-gaps --admx-dir`**: Optional ADMX crosswalk integration — resolved registry paths are excluded from gap reports.
- **`loopback_awareness()` + `settings-at` banner**: Detects loopback mode (merge/replace) and prints a caveat banner when any GPO in scope configures loopback.

### Test coverage
- 280 tests (was 233), 237 non-samples tests (91.9% of total). `ruff` and `mypy --strict` clean.
