# AGENTS.md

Conventions and quick reference for agents (and humans) working on gpo-lens.

## What this is

Local-first, **read-only** Group Policy analysis. The tool ingests *copies* of a
GPO estate (it never touches live AD) and answers questions about it. The
deterministic core has **no AI in the truth path** — the LLM layer only
narrates facts the core computed. See `README.md` for the full charter.

## Orient

1. **Read the model.** `docs/tier1-normalized-model.md` — the normalized data
   model, mapped against two real exports, with the join-key and parser gotchas.
   The dataclasses in `src/gpo_lens/model.py` are the concrete contract.
2. **Read the spec.** `docs/spec/wi_*.md` — one file per work item, with explicit
   acceptance criteria (`AC-NN`) and exact function signatures. **The spec is the
   contract.** Implement to the ACs.
3. **Validate against reality.** `tests/` encodes the *measured* numbers from the
    real exports (e.g. work domain = 100+ GPOs, several disabled-but-populated sides,
    1,000+ SOMs). Your implementation is correct when those pass. The sample exports
   live in `samples/` (gitignored — never commit them; WORK-DOMAIN.local is a real work
   domain's SYSVOL). Sample-dependent tests skip if `samples/` is absent.

## Hard rules

- **No work-domain identifiers in committed files.** Reflections and docs use
  placeholders (`WORK-DOMAIN.local`, `LABDOMAIN`). Exact counts are allowed
  only in test assertions against `samples/`; docs use ranges.
- **Fixture data is synthetic.** No real GPO names, OU paths, or domain names
  in committed test files.
- **`samples/` is gitignored and must never be committed.**
- **Read-only.** No code writes to or connects to Active Directory. Input is
  files only.
- **No AI in the deterministic core.** Tiers 1–2.5 must run with zero model calls.
- **Flag, don't simulate.** Topology resolution is OU-level; never claim
  object-level RSoP (no per-user security/WMI/loopback evaluation). Scoping
  mechanisms (loopback, security filtering, WMI filters, item-level targeting,
  AD-site links) are flagged with caveats in topology views, never simulated.
  Sites are modeled as `container_type="site"` SOMs (a parallel axis, excluded
  from OU-precedence views); per-machine site membership is not resolved.
- **Coverage honesty.** Collection is bounded by the collector account's AD
  access (a stripped-AU GPO is invisible to a least-privilege account). Don't
  paper over it — reconcile `gpo-inventory.json` (authoritative, privileged run)
  + `collection-errors.json` against the export and surface missing GPOs as
  `coverage_gap` findings. Never present a partial estate as complete.
- **Canonical GPO id everywhere:** lowercase, braces stripped. All cross-input
  joins use it (see `normalize.canonical_guid`).
- **BOM-tolerant JSON:** collector JSON may carry a UTF-8 BOM (PowerShell 5.1).
  Always load with `utf-8-sig`.
- **Import boundary:** Core modules (`model`, `normalize`, `ingest`, `store`, `queries`, `snapshot_diff`, `detection`, `admx_parser`, `display`, `report`, `events`, `sinks`, `query_dispatch`, `authz`, `topology`, `registry_pol`, `paths`, `danger`, `merge`) must never import `narration` or `web`. An architecture test enforces this.

## Build / test / lint

```bash
uv venv && uv pip install -e ".[dev]"
.venv/bin/pytest -q            # unit + calibration tests (sample tests skip if samples/ absent)
.venv/bin/pytest -q -m samples # calibration tests against the real exports (needs samples/)
.venv/bin/ruff check .
.venv/bin/mypy src
```

Slice 1 is **stdlib-only** (`xml.etree.ElementTree`, `json`, `sqlite3`,
`argparse`) — keep it dependency-free so the core stays portable/air-gappable.

## Collectors

`scripts/Export-GpoEstate.ps1` produces the inputs (read-only PowerShell, run on
a DC/RSAT box). The tool consumes its output dir.

## Module map

| Module | Purpose |
|--------|---------|
| `model.py` | Dataclasses — the normalized contract |
| `normalize.py` | Pure helpers: `canonical_guid`, `load_json`, `parse_bool/int/dt` |
| `ingest.py` | Parse collector outputs → `Estate`. Also `parse_report_xml` for raw bytes (UTF-8/16), `load_baseline_from_zip` for Microsoft baseline zips, `augment_blocked_registry_from_pol` to resolve `<Blocked/>` Registry extensions from `Registry.pol` |
| `store.py` | SQLite persistence for snapshot history (additive schema migrations in `_migrate_schema`) |
| `queries.py` | Query composition, Tier 2/2.5 queries, estate_doctor, baseline diff, topology, conflicts |
| `snapshot_diff.py` | SQLite-bound snapshot diffing — `snapshot_changelog`, `snapshot_settings_diff`, `snapshot_diff` |
| `detection.py` | Pure scanner functions — cpassword, MS16-072, version skew, broken refs, scheduled tasks, local-group mods, etc. Result types: `CpasswordHit`, `BrokenRef`, `AdmxGap`, `ScheduledTaskInfo`, `LocalGroupMod` |
| `registry_pol.py` | PReg binary parser — decodes `Registry.pol` files into `PregRecord`s (resolves `<Blocked/>` settings) |
| `danger.py` | Dangerous-configuration detectors — curated, cited Bucket 1 (setting-value rules) + Bucket 2 (structural attack-path) checks |
| `admx_parser.py` | ADMX/ADML template parser — builds registry-path → policy-name crosswalk for baseline diff |
| `display.py` | Table renderer |
| `report.py` | Markdown/HTML estate report generation |
| `events.py` | Append-only event store for tracking GPO estate changes |
| `sinks.py` | Event sinks for NDJSON file export and Splunk HEC |
| `query_dispatch.py` | Centralized query dispatch table (single source of truth for CLI and web) |
| `merge.py` | Per-CSE merge-resolution model + principal resultant (Plan 021). Token, security-gate eval, CSE merge modes |
| `narration.py` | Tier 3 — LLM narration (`call_llm`, `explain_findings`, `route_question`). Optional; core never imports this |
| `web/` | FastAPI web UI — dashboard, GPO detail, ingest, ask, changelog, baseline diff |
| `cli/` | CLI package — argparse subcommands. Entry point: `cli._core:main` |

## Baseline diff

Microsoft ships Security Baselines as nested zips containing GPO backups.
`load_baseline_from_zip` handles the nesting.  Each GPO's `gpreport.xml`
is UTF-16 encoded — `parse_report_xml` detects the encoding.

Baseline settings are compared by `(cse, identity)` — the ADMX crosswalk
in `admx_parser.py` resolves registry paths back to policy names for display.

## Active breadcrumbs

Check `breadcrumbs/active/` for active work items. Resolved items move to `breadcrumbs/resolved/`.
