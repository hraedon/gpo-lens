# Work Item: CLI

## Dependencies

- `interface_ref`: `ingest`, `store`, `queries`

## Notes

Stdlib `argparse`. Entry point `gpo_lens.cli:main` (wired in `pyproject.toml`
`[project.scripts]` as `gpo-lens`). Read-only over inputs; the only thing it
writes is the SQLite snapshot DB (path via `--db`, default
`./gpo-lens.sqlite3`). All commands accept `--json` to emit machine-readable
output instead of a text table.

Module: `src/gpo_lens/cli/` (package — `__init__.py` re-exports `main`,
`_core.py` builds the argparse tree and dispatches, subcommand handlers live
in sibling `_*.py` modules).

---

## AC-01: `ingest`
`gpo-lens ingest <sample_dir> [--db PATH]` calls `ingest.load_estate`, then
`store.init_db` + `store.save_estate`, and prints a one-line summary
(`domain, N GPOs, M SOMs, snapshot=<id>`). Exit 0 on success.

## AC-02: Analysis subcommands
Each maps to a `queries` function and renders a table (or `--json`). It operates
on the latest snapshot in `--db`, or — for convenience — accepts a `<sample_dir>`
and ingests in-memory without persisting:
- `gpo-lens unlinked [src]`
- `gpo-lens empty [src]`
- `gpo-lens disabled-populated [src]`
- `gpo-lens who-sets <term> [src]`
- `gpo-lens conflicts [src]`
- `gpo-lens blocked [src]`
- `gpo-lens version-skew [src]` — GPOs with GPC/GPT version mismatch
- `gpo-lens ms16-072 [src]` — GPOs missing AU/DC Read
- `gpo-lens perms [src]` — delegation audit (MS16-072, write count, orphans)

Where `src` is a sample dir → ingest fresh; if omitted → read `--db` latest
snapshot.

## AC-03: `snapshots`
`gpo-lens snapshots [--db PATH]` lists stored snapshots (id, domain, taken_at),
newest first.

## AC-04: Exit codes & errors
Missing `AllGPOs.xml` in `src` → exit 2 with a clear stderr message. No matches
for a query is exit 0 with an empty table (not an error). `--json` always emits
valid JSON, including the empty case (`[]`).

## AC-05: `diff`
`gpo-lens diff <snapshot_a> <snapshot_b> [--db PATH] [--json]` — compute the
structured diff between two stored snapshots via `queries.snapshot_diff`. Reports
GPOs added/removed, settings/links/delegation changes, metadata/WMI/enabled flips.

## AC-06: cpassword
`gpo-lens cpassword [src] [--show-secrets] [--json]` — scan for GPP cpassword
attributes. By default masks values; `--show-secrets` reveals them.

## AC-07: Search
`gpo-lens search <term> [--scope all|settings|names|delegation] [src] [--json]` —
full-text search across GPO names, settings, and delegations.

## AC-08: Show GPO
`gpo-lens show <gpo_id> [--format text|json] [src]` — display details for one
GPO, matched by id or name.

## AC-09: Summary
`gpo-lens summary [src] [--json]` — one-command estate health overview combining
all query counts.

## AC-10: REPL
`gpo-lens repl [src]` — drop into an interactive Python REPL with `estate` and
`queries` available.

---

## Tier 2.5 — Topology commands

### AC-20: `som`
`gpo-lens som <som_path> [src] [--json]` — show the resolved, ordered GPO chain
at a SOM path.

### AC-21: `dangling`
`gpo-lens dangling [src] [--json]` — SOM links pointing to non-existent GPO ids.

### AC-22: `enforced`
`gpo-lens enforced [src] [--json]` — all enforced (NoOverride) links.

### AC-23: `som-conflicts`
`gpo-lens som-conflicts <som_path> [src] [--json]` — settings that fight in the
SOM chain, with winner/overridden annotation.

### AC-24: `precedence-conflicts`
`gpo-lens precedence-conflicts [src] [--json]` — estate-wide precedence conflict
summary across all SOMs.

### AC-25: `settings-at`
`gpo-lens settings-at <som_path> [src] [--json]` — folded effective settings at
a SOM, grouped by winner GPO.

---

## Feature-flag commands

### AC-30: `loopback`
`gpo-lens loopback [src] [--json]` — GPOs that configure loopback processing.

### AC-31: `wmi`
`gpo-lens wmi [src] [--json]` — GPOs with WMI filters attached.

### AC-32: `wmi-filters`
`gpo-lens wmi-filters [src] [--json]` — list all WMI filters with query text.

---

## Security / hygiene commands

### AC-40: `broken-refs`
`gpo-lens broken-refs [src] [--json]` — detect broken references (UNC paths,
missing scripts, drive mappings, scheduled task paths, GPP XML references).

### AC-41: `admx-gaps`
`gpo-lens admx-gaps [src] [--json]` — Registry CSE settings with raw key paths
(no ADMX policy name resolved).

### AC-42: `topology-check`
`gpo-lens topology-check [src] [--json]` — cross-check ou-tree.json against
gp-inheritance.json for block mismatches and missing OUs.
