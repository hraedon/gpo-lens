---
status: resolved
priority: medium
kind: design
created: 2026-06-19
resolved: 2026-06-20
---

# Inconsistent DB connection lifecycle in the web app

## Problem

The web app uses three different patterns for SQLite connections:

1. **`_get_ro_conn(db_path)`** — most routes use this (`?mode=ro` URI, in a
   `try/finally`). Properly read-only.
2. **`sqlite3.connect(app.state.db_path)`** — the audit logging path and the
   ingest path create raw RW connections. The audit path opens a *second*
   connection per request just to append one event.
3. **`sqlite3.connect(str(db_file))`** — `create_app()` uses this for the
   initial `init_db` call.

The raw `sqlite3.connect()` calls bypass `_restrict_db_permissions` (only called
via `_store.init_db`), so the DB file may have relaxed permissions if the
initial `init_db` call didn't run (e.g. opening an existing DB). The audit
connection also doesn't benefit from the `_restrict_db_permissions` hardening.

## Risk

Low. The audit write failure path is safe (swallowed and logged), and the DB
permissions are tightened on every `init_db` call. But the inconsistency means
a new route author has to choose between three patterns, and the wrong choice
bypasses hardening.

## Suggested fix

Centralize connection creation:

- Add `_get_rw_conn(db_path)` that applies `_restrict_db_permissions` and
  returns a connection with `PRAGMA foreign_keys = ON`.
- Route all audit/event writes through a single `app.state.audit_conn` (opened
  once at startup, thread-safe via SQLite's serialized mode or a lock).
- Or: accept the per-request audit connection but use `_get_rw_conn` so
  permissions are always tightened.
