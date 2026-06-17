---
status: resolved
resolved: 2026-06-17
priority: medium
kind: design
created: 2026-06-17
---

# store._migrate_schema has no version stamp, rollback, or future-DB detection

## Problem

`src/gpo_lens/store.py` `_migrate_schema` relies entirely on
`CREATE TABLE IF NOT EXISTS` + `_column_exists` guards for additive columns.
There is:

- No `PRAGMA user_version` stamp — so the DB carries no record of which schema
  version created it.
- No detection of a DB written by a **future** gpo-lens version (a column the
  current code doesn't know about is silently ignored, no warning).
- No rollback / no test for a partial `ALTER TABLE` failure (corrupt DB, disk
  full, lock) — `load_estate` would then crash on a missing column.

This is currently safe: there is exactly one additive migration (the
`description` column on `gpo`), and it runs after table creation, idempotently.

## Risk

Low today. Becomes real the moment a **second** migration lands: ordering and
idempotency across multiple `ALTER`s are not enforced by anything in the
function, and a half-applied migration has no recovery path.

## Suggested fix

- Stamp `PRAGMA user_version` (e.g. `2` = current) and have `_migrate_schema`
  check the current version, run the delta, then set the new version.
- Add a test that constructs a DB at a *future* version (set a fake column +
  `user_version=99`) and asserts a clear error rather than silent truncation.
- Add ordering discipline (ordered migration list) before adding migration #2.

## Context

Raised during the 2026-06-17 adversarial architecture review (M6 /
H5-equivalent). The PRAGMA-table-info f-string footgun in the same file was
fixed inline (now `isidentifier()` + quoted); this version-stamp gap is the
larger forward-looking piece.
