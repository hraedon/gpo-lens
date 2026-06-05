# Work Item: Store (SQLite persistence)

## Dependencies

- `interface_ref`: `model`, `ingest`

## Notes

The store persists an `Estate` to a local SQLite DB (`sqlite3`, stdlib). Its
first job is just round-tripping the model; the snapshot-history / change-log
feature (later) builds on it by stamping each ingest as a dated snapshot, so the
schema reserves a `snapshot` table from the start even though slice 1 writes a
single snapshot.

Module: `src/gpo_lens/store.py`. Read-only-by-nature app, but this is the one
component that writes — only ever to its own SQLite file, never anything else.

---

## AC-01: Initialize schema
`store.init_db(conn: sqlite3.Connection) -> None` creates tables (idempotent,
`IF NOT EXISTS`): `snapshot(id, domain, taken_at)`, `gpo(...)`, `gpo_link(...)`,
`setting(...)`, `delegation(...)`, `som(...)`, `som_link(...)`. Every non-snapshot
row carries a `snapshot_id` FK. Settings store `raw` as a JSON `TEXT` column.
Enable `PRAGMA foreign_keys=ON`.

## AC-02: Save an estate as a snapshot
`store.save_estate(conn, estate: Estate, taken_at: datetime | None = None) -> int`
inserts one `snapshot` row (taken_at defaults to now, UTC) and all child rows,
returning the new `snapshot_id`. Re-running creates a *new* snapshot (history is
append-only); it never mutates prior snapshots. `raw` is serialized with
`json.dumps(..., sort_keys=True)` for stable diffs later.

## AC-03: Load an estate from a snapshot
`store.load_estate(conn, snapshot_id: int | None = None) -> Estate` reconstructs
the `Estate` (default: the most recent snapshot). Round-trip fidelity:
`load_estate(conn, save_estate(conn, e))` equals `e` field-for-field (settings’
`raw` survives the JSON round-trip).

## AC-04: List snapshots
`store.list_snapshots(conn) -> list[tuple[int, str, datetime]]` returns
`(id, domain, taken_at)` newest first. (Foundation for the change-log diff.)
