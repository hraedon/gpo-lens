# Work Item: CLI

## Dependencies

- `interface_ref`: `ingest`, `store`, `queries`

## Notes

Stdlib `argparse`. Entry point `gpo_lens.cli:main` (wired in `pyproject.toml`
`[project.scripts]` as `gpo-lens`). Read-only over inputs; the only thing it
writes is the SQLite snapshot DB (path via `--db`, default
`./gpo-lens.sqlite3`). All commands accept `--json` to emit machine-readable
output instead of a text table.

Module: `src/gpo_lens/cli.py`.

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

Where `src` is a sample dir → ingest fresh; if omitted → read `--db` latest
snapshot.

## AC-03: `snapshots`
`gpo-lens snapshots [--db PATH]` lists stored snapshots (id, domain, taken_at),
newest first.

## AC-04: Exit codes & errors
Missing `AllGPOs.xml` in `src` → exit 2 with a clear stderr message. No matches
for a query is exit 0 with an empty table (not an error). `--json` always emits
valid JSON, including the empty case (`[]`).
