# Work Item: Append-only event store (estate change tracking)

## Dependencies

- `interface_ref`: `store` (the events table lives in the same SQLite DB
  as snapshots; `store.init_db` does **not** create the events table —
  `init_events_table` is a separate call).
- Consumer: `cli/_estate.py::_emit_ingest_events` (emits `gpo.created`/
  `gpo.modified`/`gpo.deleted`/`ingest.summary` events during ingest),
  `cli/_events.py` (read/query CLI), `sinks.emit_events` (replay path).
- Reference: `plans/016-splunk-change-attribution.md` (the "why" — the
  event store is the local source of truth that the Splunk/NDJSON sinks
  drain). There is **no dedicated plan file** for `events.py` itself;
  this spec is the first formal contract.

## Notes

This module is the **append-only event store** for estate changes. It
is a **core module** (`tests/_arch.py::CORE_MODULES`); no
`narration`/`web` imports. The store is SQLite-backed — the same DB
file as `store.py`'s snapshot tables — and is written only through
`INSERT`. The append-only contract is enforced by an AST-walk test
(`tests/test_events.py::TestAppendOnly`) that fails if any source file
contains `UPDATE events…` or `DELETE FROM events…`.

The event store is **orthogonal to the snapshot history**. Snapshots
capture point-in-time estate state; events capture *transitions*
between states. Both can be replayed independently — the snapshot diff
(`wi_snapshot_diff`) recomputes transitions from snapshots, while the
event store records them as they were observed. The two should agree
post-ingest (the CLI's `_emit_ingest_events` derives events from a
snapshot diff), but they are not coupled at the schema level.

### Drift / known simplifications

- **`append_events` hardcodes `schema_version=1`** and does not accept
  a per-event override. `append_event` (singular) does accept
  `schema_version`. This asymmetry is the current contract — if a
  future schema bump needs per-event versions in a batch, extend
  `append_events` to take `(event_type, payload, schema_version)`
  tuples.
- **All events in a batch share one timestamp.** `append_events`
  computes `datetime.now(timezone.utc).isoformat()` once before the
  loop. Sub-millisecond intra-batch ordering is preserved only by the
  `AUTOINCREMENT` `id` column (monotonic). Callers that need per-event
  timestamps must call `append_event` in a loop.
- **`query_events` default ordering is `id ASC`, not `timestamp ASC`.**
  This matters when an event row was inserted with a back-dated
  timestamp (e.g. the test's `2020-01-01T00:00:00+00:00` row). It stays
  in insertion order regardless of its timestamp value. A future caller
  that wants timestamp-strict order must sort at the call site.
- **`event_type` filter is a substring `LIKE`.** `query_events(event_type=
  "gpo")` matches `"gpo.created"`, `"gpo.modified"`, `"gpo.deleted"`, but
  also a hypothetical `"agpo.foo"`. The match is case-insensitive
  (SQLite `LIKE` default). The `_escape_like` helper escapes `\\`, `%`,
  `_` so a user-supplied `"100%"` doesn't act as a wildcard.
- **`init_events_table` is a separate call from `store.init_db`.** A
  caller that only runs `store.init_db` will have snapshot tables but
  no `events` table — `append_event` will then fail at SQL prepare
  time. The CLI ingest path calls both. This separation is deliberate
  (events are optional for read-only historical analysis) but is a
  gotcha for new callers.
- **`commit=True` is the default.** Each `append_event` /
  `append_events` call auto-commits. Callers doing batched ingest
  inside a larger transaction pass `commit=False` and commit themselves.
- **`payload` is serialized with `json.dumps(payload, sort_keys=True)`.**
  Key order is canonical; the same payload dict always produces the
  same `TEXT` blob. This is a deterministic-storage invariant — never
  change it without a schema migration.
- **No `__all__`.** Public exports are implicit: `init_events_table`,
  `append_event`, `append_events`, `query_events`. `_escape_like` is
  private but tested indirectly.

## Module map

`src/gpo_lens/events.py` — stdlib-only (`json`, `sqlite3`, `datetime`,
`typing`). Core module (`tests/_arch.py`).

| Public surface | Role |
|----------------|------|
| `init_events_table(conn) -> None` | Create the `events` table + 2 indexes (idempotent). |
| `append_event(conn, event_type, payload, schema_version=1, *, commit=True) -> int` | Insert one event, return its row id. |
| `append_events(conn, events, *, commit=True) -> list[int]` | Batch insert, return row ids. |
| `query_events(conn, *, since=None, event_type=None, limit=1000) -> list[dict]` | Filtered read with LIKE substring + ASC-by-id ordering. |

Private: `_escape_like(value) -> str` (LIKE metacharacter escaper for
safe substring filtering).

---

## AC-01: Module purity and connection boundary

`events.py` is a core module. Imports: `json`, `sqlite3`, `datetime`,
`typing` — stdlib only, no `gpo_lens` imports at all. Must never import
`gpo_lens.narration` or `gpo_lens.web`
(`tests/_arch.py::forbidden_imports_in("events")`). Every function takes
a `sqlite3.Connection` explicitly. No globals, no environment reads.

The module writes only via `INSERT INTO events …`
(`tests/test_events.py::TestAppendOnly`). No `UPDATE events`, no
`DELETE FROM events`, no `DROP TABLE events` may appear anywhere in
`src/gpo_lens/`.

## AC-02: `init_events_table` — schema and idempotency

```python
def init_events_table(conn: sqlite3.Connection) -> None: ...
```

Creates (idempotently, `IF NOT EXISTS`):

- Table `events`:
  - `id INTEGER PRIMARY KEY AUTOINCREMENT`
  - `timestamp TEXT NOT NULL`
  - `event_type TEXT NOT NULL`
  - `schema_version INTEGER NOT NULL DEFAULT 1`
  - `payload TEXT NOT NULL`
- Index `idx_events_timestamp ON events(timestamp)`.
- Index `idx_events_event_type ON events(event_type)`.

Calls `conn.commit()` at the end. Calling twice is a no-op
(`test_init_events_table_idempotent`). The table is separate from
`store.init_db`'s schema — see Notes.

## AC-03: `append_event` — single-event insert

```python
def append_event(
    conn: sqlite3.Connection,
    event_type: str,
    payload: dict[str, Any],
    schema_version: int = 1,
    *,
    commit: bool = True,
) -> int: ...
```

- `ts = datetime.now(timezone.utc).isoformat()` (full ISO 8601 with
  `+00:00` offset — **not** `Z` suffix).
- `INSERT INTO events (timestamp, event_type, schema_version, payload)
  VALUES (?, ?, ?, ?)` with `(ts, event_type, schema_version,
  json.dumps(payload, sort_keys=True))`.
- If `commit=True` (default): `conn.commit()`.
- Return `cursor.lastrowid` (the new row's `id`).

`schema_version` defaults to `1`. The payload is JSON-encoded with
`sort_keys=True` (deterministic storage, see Notes).

## AC-04: `append_events` — batch insert

```python
def append_events(
    conn: sqlite3.Connection,
    events: list[tuple[str, dict[str, Any]]],
    *,
    commit: bool = True,
) -> list[int]: ...
```

- `ts = datetime.now(timezone.utc).isoformat()` — computed **once**
  before the loop (see Notes — all events in the batch share one
  timestamp).
- For each `(event_type, payload)` in `events` (input order):
  - `INSERT INTO events (timestamp, event_type, schema_version, payload)
    VALUES (?, ?, 1, ?)` — **`schema_version` is hardcoded to `1`**
    (see Notes). Per-event schema_version is not supported by the batch
    API.
  - Append `cursor.lastrowid` to the result list.
- If `commit=True`: `conn.commit()` once at the end.
- Return the list of new row ids, in input order.

Empty `events` list returns `[]` and writes nothing (but still computes
the timestamp and may commit — the no-op commit is harmless).

## AC-05: `query_events` — filtered read

```python
def query_events(
    conn: sqlite3.Connection,
    *,
    since: str | None = None,
    event_type: str | None = None,
    limit: int = 1000,
) -> list[dict[str, Any]]: ...
```

- Build WHERE clause from optional filters:
  - `since` (non-None): `timestamp >= ?` with the literal string
    compared lexically against the ISO-8601 timestamp column. Both
    sides must be in the same format for this to work — pass
    `"2025-01-01"` or a full ISO timestamp; mixed formats compare
    lexically.
  - `event_type` (non-None): `event_type LIKE ? ESCAPE '\\'` with
    `f"%{_escape_like(event_type)}%"` — substring match,
    case-insensitive (SQLite `LIKE` default). Wildcards in the user
    input are escaped so `"100%"` is a literal match, not a wildcard.
- If both filters absent: `WHERE 1=1`.
- `ORDER BY id ASC LIMIT ?` — insertion order, not timestamp order
  (see Notes).
- For each row, build `{"id": row[0], "timestamp": row[1],
  "event_type": row[2], "schema_version": row[3], "payload":
  json.loads(row[4])}`. The payload is parsed back to a dict.

`limit` defaults to `1000`. There is no pagination offset — callers
needing more must re-query with a tighter filter or a higher limit.

## AC-06: `_escape_like` — LIKE metacharacter escaper

```python
def _escape_like(value: str) -> str: ...
```

Returns `value.replace("\\", "\\\\").replace("%", "\\%").replace("_",
"\\_")`. The corresponding WHERE clause must use `ESCAPE '\\'` (which
`query_events` does). Without the ESCAPE declaration, the backslashes
would themselves be treated as literal characters.

## AC-07: Determinism and append-only invariant

- All timestamp generation uses `datetime.now(timezone.utc)` — UTC,
  ISO-8601 with offset. No local time, no `Z` suffix.
- All payload serialization uses `json.dumps(payload, sort_keys=True)`
  — canonical key order. The same dict always produces the same TEXT.
- `cursor.lastrowid` is the row's integer id, monotonically increasing
  per-DB (SQLite `AUTOINCREMENT`).
- The append-only AST test (`TestAppendOnly`) walks every `*.py` under
  `src/gpo_lens/` and fails on any `UPDATE`/`DELETE` against the
  events table (with explicit allow-list carve-outs for `IF NOT
  EXISTS`, `ON DELETE` cascade declarations, `INSERT`, and `SELECT`).
  Adding a new mutation path requires extending the carve-out or
  reframing the change as additive inserts.
