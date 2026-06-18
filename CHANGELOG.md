# Changelog

## v0.6.0 — 2026-06-18

### Production-readiness: IIS deployment, observability, access control

First **Windows smoke test** of `install-windows.ps1` on a real IIS host
(`LAB-HOST-1`), closing the "untested on Windows" gap flagged in prior
reflections. The installer ran end-to-end: Python 3.14.6 resolution, venv
creation, idempotent upgrade, IIS site/pool management, TLS binding, and
firewall — all clean. cert-watch (sharing the host on port 443) was not
disrupted.

- **`-Sni` switch (install-windows.ps1).** gpo-lens can now share port 443
  with cert-watch (or any HTTPS site) via SNI, instead of requiring its own
  port. Sets `sslFlags=1` on the IIS binding before the netsh
  `hostnameport` sslcert add — the ordering that the prior error-87 failure
  (cert-watch WI-047) got wrong. Non-SNI remains the default (dedicated port,
  catch-all cert). The catch-all `ipport` binding is never touched in SNI
  mode.
- **`-WindowsAuth` switch (install-windows.ps1).** Installs the
  `Web-Windows-Auth` role service if missing, enables Windows Authentication,
  and disables anonymous access — so only authenticated domain users reach
  the app. The smoke test found the role service was not installed by
  default, leaving the site open; this switch makes the fix a one-liner.
  Windows Auth is sticky: re-running without the flag does not re-enable
  anonymous access (security-positive default).
- **`GET /healthz`** (unauthenticated) — liveness probe for IIS/app-pool
  supervisors. Returns `{"status":"ok"}`.
- **`GET /api/version`** (unauthenticated) — version surface for ops.
  Returns `{"version":"…","name":"gpo-lens"}`.
- **Audit log (JSON-lines, best-effort).** Every ingest path (success,
  malformed zip, invalid estate, size limit, concurrent 409) is appended to
  `<db_dir>/audit.log` (or `GPO_LENS_AUDIT_LOG` override) with timestamp,
  principal, outcome, detail, and request-id. Thread-safe via
  double-checked locking. Never raises into the request path.
- **Backup/restore runbook** added to `deploy/iis/README.md`: online SQLite
  `.backup` (no downtime), offline copy, restore procedure, migration note.

### CI gate: no work-domain identifiers in committed files (WI-022)

Mechanically enforces the AGENTS.md hard rule. The checker reads forbidden
identifiers from `GPO_LENS_FORBIDDEN_IDENTIFIERS` (CI secret) so the real
identifiers never touch the repo. No-op locally when the env var is unset
(warns on stderr, exits 0). UTF-16 aware (BOM detection), streaming binary
sniff (no OOM), skips `samples/` and `.venv/`. 13 tests.

### Web UI: dashboard filtering, pagination, export (WI-025/026/027)

- **Dashboard findings table**: filter by severity, search by text, sort by
  severity/GPO/finding, paginated (default 50, max 200, "all" supported).
- **In-app CSV/JSON export** of findings and settings dump.
- **OU list and GPO detail paginated** for large estates.
- Shared `_pagination.html` partial with page/per_page controls.

### Test quality (WI-024)

OU-detail loopback caveat test tightened: was vacuously matching the word
"loopback" in fallback text; now asserts `"loopback="` which only appears in
rendered caveats.

### Plan 016 — Splunk change attribution (proposed, shelved)

Tracked but not started. Has a hard discovery dependency (confirm what
Splunk holds re: AD event 5136 / SYSVOL 4663) before any code. Ingest model
(not live query) keeps the deterministic core offline.

## v0.5.0 — 2026-06-15

### Windows deployment run-through fixes (first end-to-end run on real AD)
First full collector→ingest→doctor run against a live domain (read-only, via a
least-privilege service account) surfaced several defects that the flat,
hand-built test fixtures had hidden:
- **GPP scanners now work against a real SYSVOL.** `gpp-tasks`, `gpp-groups`,
  and cpassword detection silently returned nothing on real exports: a real
  SYSVOL nests each CSE in its own subfolder (`Preferences/Groups/Groups.xml`),
  but the walker only looked one level too shallow (`Preferences/Groups.xml`).
  It now handles both the nested and flat shapes.
- **Case-insensitive SYSVOL path resolution.** Default GPOs ship as
  `MACHINE`/`USER` (upper-case); on a case-sensitive (Linux) analysis host the
  literal `Machine`/`User` lookups missed them entirely — affecting GPP scans,
  `Registry.pol` resolution, and script-reference checks. New `paths.py`
  (`ci_child`/`ci_path`) resolves SYSVOL children case-insensitively.
- **`doctor` no longer crashes on an unreadable SYSVOL subtree.** A
  security-filtered GPO copied with its ACLs intact (or an extraction that
  dropped a directory's traversal bit) raised `PermissionError` and aborted the
  whole run; such subtrees are now skipped (coverage gaps are still surfaced via
  `collection-errors.json`).
- **Collector: resilient SYSVOL copy.** One inaccessible policy folder
  (Authenticated Users Read stripped) aborted the entire SYSVOL copy; it now
  skips and records each denied folder in `collection-errors.json`, mirroring
  the per-GPO `Get-GPOReport` resilience.
- **Collector: portable archive.** Replaced `Compress-Archive` (Windows
  PowerShell 5.1 writes backslash separators and directory entries that extract
  on Linux without the traversal bit) with a forward-slash, file-only zip — so
  the export ingests cleanly on a non-Windows analysis box.
- **Collector: create `OutputRoot` if missing** (the write-test failed when the
  output directory did not yet exist).
- **`gpp-tasks`: no spurious empty row** for the nested `<Task>` wrapper inside
  an `ImmediateTaskV2`'s `<Properties>` (iterate direct children, not all
  descendants).
- **README: `-OutputDir` → `-OutputRoot`** (the documented flag did not exist).

### Added — deeper coverage (GPP structured audits, Registry.pol, GPO descriptions)
- **GPP scheduled-task audit (`gpp-tasks`).** Structured inventory of every
  scheduled task / immediate task deployed by GPO (`ScheduledTasks.xml`),
  with name, action, command, arguments, and run-as account. Deterministic,
  read-only; surfaces what is configured without evaluating reachability.
  Text + `--json` (envelope `kind: "gpp-tasks"`).
- **GPP local-group audit (`gpp-groups`).** Structured inventory of local-group
  membership changes (`Groups.xml` / `LocalUsersAndGroups.xml`): target group
  + SID, members added, members removed. The single most common "who is a
  local admin where" audit question, now answerable from the estate.
- **`Registry.pol` binary parser — resolves `<Blocked/>` Registry settings.**
  When the GPO report renders the Registry CSE as `<Blocked/>`, the
  authoritative values live in `Machine`/`User` `Registry.pol` (PReg format).
  gpo-lens now parses it and replaces the opaque blocked placeholder with the
  real key/value/type triples (`source_state="registry_pol"`). New
  `registry_pol.py` module (pure stdlib). Where `Registry.pol` is absent the
  blocked placeholder is kept (we do not fabricate values).
- **`Gpo.description`.** The GPO `<Description>` field (the admin's note) is
  now captured, persisted, and surfaced in `show`, the web detail view, and
  the report — letting `stale_gpo` findings distinguish "forgotten" from
  "intentionally frozen."
- **SQLite additive migrations.** `init_db` now runs `_migrate_schema` so an
  existing DB from an older gpo-lens gains new columns (additive only) on
  open, rather than silently producing wrong results.

### Charter & correctness fixes (deep review)
- **`settings_at_som` / `som_conflicts` no longer present disabled-side
  settings as effective.** A setting on a side whose `Enabled=false` does not
  apply regardless of link enforcement — surfacing it as "effective" violated
  the "flag, don't simulate" charter. These settings are still reported by
  `disabled_but_populated` (the correct channel).
- **Tightened Domain Computers SID matching.** Both `is_security_filtered`
  (topology) and the MS16-072 check (detection) now require the `S-1-5-21-*`
  domain-SID prefix before matching the `-515` RID. Previously any SID ending
  in `-515` (e.g. a builtin-domain group) could false-match Domain Computers,
  masking real security-filtering / MS16-072 findings.
- **Determinism hardening.** `settings_dump`, `conflicts`, `som_conflicts`,
  and `precedence_conflicts` now sort their output; `load_estate` adds
  `ORDER BY` to every table read. Estate reconstruction from a DB snapshot is
  now order-independent of insertion order, which snapshot diffs and the
  `--json` contract depend on.

### Hardening
- **CSRF: `0.0.0.0` removed from the localhost Origin allow-list.** It is the
  bind-any wildcard, not a legitimate client Origin, and a cross-origin POST
  can spoof it. `localhost`/`127.0.0.1`/`::1`/`localhost.localdomain` remain.
- **SQLite DB files are created `0600`.** `init_db` now tightens the snapshot
  DB to owner-only regardless of the process umask — the DB holds the full
  estate (GPO names, delegation, settings) and must not be world/group
  readable on a shared host.

### Docs
- **README: "zero runtime dependencies" corrected** to "minimal runtime
  dependencies (defusedxml)" — the prior claim was inaccurate. Added a
  Requirements section (Python 3.12+, RSAT modules) and documented the
  `<Blocked/>` limit.

### Cleanup
- Removed dead `_QUERY_PARAMS` alias from `query_dispatch.py`.

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
