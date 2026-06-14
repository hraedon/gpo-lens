# Changelog

## v0.4.0 — 2026-06-14

Headline: **sees site scope, and honest about collection coverage.** AD
site-linked GPOs are captured and flagged; GPOs the collector can't read are
named (reconciliation) instead of silently dropped.

### Honest about collection coverage (Plan 015)
- **Coverage reconciliation.** A GPO with Authenticated Users Read fully
  stripped is invisible to a least-privilege collector account (verified on a
  real domain). Rather than chase full read by granting per-GPO permissions, the
  collector emits `gpo-inventory.json` (every GPC GUID it could enumerate — run
  it once as a privileged account for an authoritative baseline), and gpo-lens
  reconciles inventory + `collection-errors.json` against the export: any GPO
  that exists but was not collected is surfaced as a **coverage gap** (new
  `doctor` `coverage_gap` finding + `summary.coverage_gap_count`) — named, never
  silently dropped. Backward compatible (absent manifests → no gaps).
- **Collector hardening.** Per-GPO report collection is resilient (one
  unreadable GPO no longer aborts the rest); inaccessible GPOs are detected via
  an AD enumeration cross-check and recorded in `collection-errors.json`.
- **Collector fix:** `Get-GPOReport` uses `-Path` (was the nonexistent
  `-LiteralPath`, which silently failed every report — surfaced by live testing).

### Sees site scope (Plan 014)
- **AD site-linked GPOs are now captured and surfaced.** The collector exports
  `sites.json` (Configuration-partition site `gPLink`/`gPOptions`); ingest models
  each site as a `container_type="site"` SOM with its direct links. New
  `gpo-lens sites` command (text + `--json`, contract `kind: "sites"`) lists
  sites and their GPO links.
- **OU views now flag site scope.** `settings-at` / `scope` caveats note that
  site-linked GPOs apply before the domain/OU chain based on the client's AD
  site, which is **not** resolved per-machine (flag, don't simulate).
- **Summary gains `linked_site_count`**; `som_count` now counts OU/domain SOMs
  only (sites counted separately). `enforced_links` / `dangling_links` correctly
  include enforced/broken site links.
- **Backward compatible:** an export without `sites.json` ingests unchanged.

## v0.3.0 — 2026-06-14

Headline: **honest about scope, and a frozen machine-readable contract.**
Scope-honesty across loopback/security-filtering/WMI/ILT, plus a versioned
JSON output contract that downstream tools can build against.

### JSON output contract (frozen, `schema_version: 1`)
- **Versioned envelope on every `--json` payload.** All machine-readable output
  is now wrapped as `{schema_version, kind, tool_version, generated_at, data}`,
  so downstream consumers can depend on a stable shape and detect contract
  evolution. Documented in `docs/spec/json-contract.md` and pinned by
  `tests/test_json_contract.py` (the freeze guard). Consumers read `data`.
- **`report --json` no longer silently emits Markdown.** It now refuses `--json`
  (exit 2, stderr) and points at the real machine-readable commands. `report`
  is a human document (`--format md|html`); the snapshot is `summary --json`,
  the per-setting body is `settings-dump --json`.
- **`settings-dump --json` now carries `source_state`** (`"normal"`/`"blocked"`)
  per row, exposing `<Blocked/>`-extension settings to consumers.
- **Errors under `--json` no longer leak to stdout.** `scope <gpo>` for a
  missing GPO now exits nonzero with the message on stderr (was exit 0 with a
  plain-text line on stdout), so "exit 0 ⟹ stdout is the envelope" holds.
- **Documented precondition:** the `events` stream is populated only by
  `ingest --diff-latest`.

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
