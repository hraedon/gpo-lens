# Work Item: Snapshot diff (SQLite-bound change computation)

## Dependencies

- `interface_ref`: `store` (`init_db`, `save_estate`, `load_estate` — the
  schema these queries run against). The diff reads the `gpo`,
  `setting`, `gpo_link`, `delegation` tables directly.
- `interface_ref`: `model` (none at runtime — the diff returns its own
  dataclasses; it does not reconstruct an `Estate`).
- Consumer: `queries.py` re-exports `snapshot_diff`, `snapshot_changelog`,
  `snapshot_settings_diff` (the CLI/web/JSON contract goes through
  `queries.*`). `cli/_diff.py`, `web/app.py` `/changelog`, `report.py`
  are the render consumers.
- Reference: `plans/016-splunk-change-attribution.md` (the "why" —
  Splunk HEC event sourcing needs a version-aware, structured change
  log). The original AC lives in `wi_store.md` AC-13 ("Snapshot diff")
  and `wi_queries.md` AC-13 — both pre-date this module's split from
  `queries.py`. There is **no dedicated plan file** for the
  `snapshot_diff.py` module split itself; this spec is the first formal
  contract.

## Notes

This module hosts every SQLite-bound snapshot-diff query. It is a
**core module** (`tests/_arch.py::CORE_MODULES`); no `narration`/`web`
imports. Every function takes a raw `sqlite3.Connection` plus two
snapshot ids — the connection boundary is visible at the call site, not
hidden behind an `Estate` wrapper. This is deliberate: diff queries
operate on raw rows for performance and never need the fully-resolved
model.

The split from `queries.py` is structural, not semantic — `queries.py`
re-exports every public name here, so callers continue to write
`queries.snapshot_diff(...)`. The module exists so that the SQL-bound
surface is greppable and so that a future swap (e.g. a different
storage backend) has a clear blast radius.

### Three diffs, three shapes

| Function | Granularity | Use case |
|----------|-------------|----------|
| `snapshot_diff` | Estate-wide rollup, GPO-keyed lists + metadata changes | "What changed between these two snapshots?" (high-level) |
| `snapshot_settings_diff` | Per-setting, with `gpo_id`/`side`/`cse` filters | "Show me every setting that was added/removed/modified" (deep) |
| `snapshot_changelog` | Per-(GPO, side), version-aware | "Tell me a human-readable story of edits per side" (narrative) |

`snapshot_diff` is the broad stroke; `snapshot_settings_diff` is the
machine-readable drill-down; `snapshot_changelog` is the human-readable
drill-down keyed on Windows version counters.

### Drift / known simplifications vs Plan 016

- **`snapshot_diff.settings_changed` compares `display_value` only,
  not the `raw` JSON column.** Two settings whose `display_value` is
  unchanged but whose `raw` dict differs (e.g. an ADMX `State` flip
  inside an unchanged value string) are NOT flagged. The contract is
  "the rendered value differs"; raw-JSON drift is invisible. This is
  the load-bearing simplification — Surface it if a caller asks why a
  known ADMX state change doesn't appear.
- **`snapshot_diff` `metadata_changes` uses `str(value or "")`.** A SQL
  `NULL` and an empty string `""` both normalize to `""`, so a flip
  between them is NOT detected. `sddl`, `owner`, `name`, `domain` are
  the four metadata fields compared this way.
- **`enabled_flips` renders booleans as `"True"`/`"False"` strings.**
  `str(bool(value))` — SQLite stores 0/1, the diff renders Python's
  `bool.__str__`. Callers comparing on `field.old_value` must use these
  exact strings.
- **`snapshot_changelog` can emit **two** entries for one GPO** (one
  per side). It is per-(GPO, side), not per-GPO. A GPO whose Computer
  and User versions both bumped yields two `ChangelogEntry` rows. This
  matches Windows' two-version-counter model (one per CSE side).
- **`snapshot_changelog.edit_count = new_sysvol - old_sysvol`.** Can be
  negative (version counter went backwards, e.g. on a GPO restore).
  When either counter is `None`, `edit_count` is `None` and the summary
  renders `'?'` instead. Note: a true zero-delta (`new == old`) also
  renders as `'?'` because the summary uses `edit_count or '?'` —
  falsy 0 collapses into the unknown marker. This is a presentation
  quirk; the underlying `edit_count` field is correct.
- **`snapshot_changelog` excludes added/removed GPOs.** Only common
  GPOs (in both `snap_a` and `snap_b`) appear. A GPO new in `snap_b`
  is not in the changelog — use `snapshot_diff.gpos_added` for that.
- **GPO-name resolution prefers `snap_b`'s name.** Both
  `snapshot_changelog` and `snapshot_settings_diff` build the name map
  by querying `snap_b` first, then `setdefault` from `snap_a`. A GPO
  that was renamed AND modified shows the **new** name on its diff
  rows. (`snap_a`'s name is used only when the GPO was removed by
  `snap_b`, which by definition excludes it from common-GPO diff
  anyway.)
- **`snapshot_diff.links_changed` compares `(som_path, link_enabled,
  enforced)` triples.** A link whose `order` changed (precedence
  shuffle) but whose enabled/enforced state is unchanged is NOT
  flagged. Order reshuffles show up only in
  `queries.som_effective_gpos` re-runs, not in the diff.
- **`snapshot_diff.delegation_changed` compares `(trustee, permission,
  allowed)` triples.** Trustee **SID** changes (the `DelegationEntry`
  also carries `trustee_sid`) are not compared — a flip in the SID
  column alone is invisible. Real delegation changes usually flip the
  name too, so this is rarely observable.

## Module map

`src/gpo_lens/snapshot_diff.py` — stdlib-only (`sqlite3`, `collections`,
`dataclasses`). Core module (`tests/_arch.py`); no I/O outside the
passed-in `Connection`, no model calls.

| Public surface | Role |
|----------------|------|
| `GpoMetadataChange` (frozen dataclass) | One metadata field that changed. |
| `SnapshotDiff` (frozen dataclass) | Estate-wide rollup diff (9 lists). |
| `SnapshotSettingChange` (frozen dataclass) | One added/removed/modified setting. |
| `VersionChangeLog` (frozen dataclass) | One GPO-side whose DS/SYSVOL versions changed. |
| `ChangelogEntry` (frozen dataclass) | One (GPO, side) human-readable changelog row. |
| `snapshot_diff(conn, snap_a, snap_b) -> SnapshotDiff` | Estate-wide rollup. |
| `snapshot_settings_diff(conn, snap_a, snap_b, *, gpo_id=None, side=None, cse=None) -> list[SnapshotSettingChange]` | Per-setting delta with optional filters. |
| `snapshot_changelog(conn, snap_a, snap_b) -> list[ChangelogEntry]` | Per-(GPO, side) version-aware log. |

There is no `__all__` — the public surface is implicit (the 5
dataclasses + 3 functions). `queries.py` re-exports all of them.

---

## AC-01: Module purity and connection boundary

`snapshot_diff.py` is a core module. Imports: `sqlite3`, `collections`,
`dataclasses`, stdlib only — no `gpo_lens` imports at all. Must never
import `gpo_lens.narration` or `gpo_lens.web`
(`tests/_arch.py::forbidden_imports_in("snapshot_diff")`). Every function
takes a `sqlite3.Connection` explicitly — no global state, no file paths,
no environment reads. The connection is assumed to come from
`store.init_db` (schema must match).

## AC-02: `snapshot_diff` — GPO add/remove

```python
def snapshot_diff(conn, snap_a, snap_b) -> SnapshotDiff: ...
```

- `a_ids = SELECT id FROM gpo WHERE snapshot_id = snap_a` (a set).
- `b_ids = SELECT id FROM gpo WHERE snapshot_id = snap_b` (a set).
- `gpos_added = sorted(b_ids - a_ids)`.
- `gpos_removed = sorted(a_ids - b_ids)`.
- `common = a_ids & b_ids` (set — iteration uses `sorted(common)`).

## AC-03: `snapshot_diff` — per-common-GPO field comparison

For each `gpo_id in sorted(common)`, fetch the metadata row from both
snapshots:

```
SELECT name, domain, sddl, owner, computer_enabled, user_enabled,
       wmi_filter, computer_ver_ds, computer_ver_sysvol,
       user_ver_ds, user_ver_sysvol
FROM gpo WHERE snapshot_id = ? AND id = ?
```

If either row is missing, skip the GPO. Otherwise:

1. **metadata_changes** — for `(name, domain, sddl, owner)` (column
   indices 0..3), compute `old_v = str(old_row[i] or "")` and
   `new_v = str(new_row[i] or "")`. If they differ, append
   `GpoMetadataChange(gpo_id, field_name, old_v, new_v)`. The `str(… or
   "")` normalization means `NULL` and `""` are indistinguishable (see
   Notes).
2. **enabled_flips** — for `(computer_enabled, user_enabled)` (column
   indices 4..5), compute `old_v = str(bool(old_row[i]))` and
   `new_v = str(bool(new_row[i]))`. Strings are `"True"` or `"False"`
   (Python `bool.__str__`). Append `GpoMetadataChange` on diff.
3. **wmi_filter_changes** — `old_wmi = str(old_row[6] or "")`, `new_wmi
   = str(new_row[6] or "")`. On diff, append
   `GpoMetadataChange(gpo_id, field="wmi_filter", old_value=old_wmi,
   new_value=new_wmi)`.
4. **version_skew_changed** — `old_skew = (old_ds_c != old_sv_c) or
   (old_ds_u != old_sv_u)`. Same for `new_skew`. If `old_skew !=
   new_skew`, append `gpo_id` to `version_skew_changed` (a list of ids,
   no field detail).
5. **settings_changed** — compare the **sets** of
   `(side, cse, identity, display_value)` rows from the `setting` table
   for this GPO in each snapshot. If the sets differ, append `gpo_id`.
   `display_value`-only — `raw` column drift is invisible (see Notes).
6. **links_changed** — compare sets of `(som_path, link_enabled,
   enforced)` from `gpo_link`. Order/precedence changes invisible (see
   Notes).
7. **delegation_changed** — compare sets of `(trustee, permission,
   allowed)` from `delegation`. Trustee-SID changes invisible.

Return `SnapshotDiff(gpos_added, gpos_removed, settings_changed,
links_changed, delegation_changed, version_skew_changed,
metadata_changes, wmi_filter_changes, enabled_flips)`.

## AC-04: `SnapshotDiff` dataclass shape

`@dataclass(frozen=True)`. All lists are `list[str]` for the simple
fields and `list[GpoMetadataChange]` for the structured fields.

| Field | Type |
|-------|------|
| `gpos_added` | `list[str]` (GPO ids) |
| `gpos_removed` | `list[str]` |
| `settings_changed` | `list[str]` |
| `links_changed` | `list[str]` |
| `delegation_changed` | `list[str]` |
| `version_skew_changed` | `list[str]` |
| `metadata_changes` | `list[GpoMetadataChange]` |
| `wmi_filter_changes` | `list[GpoMetadataChange]` |
| `enabled_flips` | `list[GpoMetadataChange]` |

Note: `SnapshotDiff` is frozen but its list fields are mutable. Treat
them as read-only — callers that mutate break determinism.

## AC-05: `GpoMetadataChange` dataclass shape

`@dataclass(frozen=True)`:

| Field | Type |
|-------|------|
| `gpo_id` | `str` |
| `field` | `str` — `"name"`, `"domain"`, `"sddl"`, `"owner"`, `"computer_enabled"`, `"user_enabled"`, or `"wmi_filter"`. |
| `old_value` | `str` — always stringified (`str(value or "")` or `str(bool(value))`). |
| `new_value` | `str` |

## AC-06: `snapshot_settings_diff` — per-setting delta

```python
def snapshot_settings_diff(
    conn, snap_a, snap_b, *,
    gpo_id: str | None = None,
    side: str | None = None,
    cse: str | None = None,
) -> list[SnapshotSettingChange]: ...
```

- Build the name map: query `SELECT id, name FROM gpo WHERE snapshot_id
  = snap_b`, then `setdefault` from `snap_a` (see Notes — `snap_b`
  names win).
- Apply the same optional filters to both snapshot queries:
  `gpo_id`, `side`, `cse` (all `None` by default → no filter). Each
  non-None filter adds `AND <col> = ?` to both WHERE clauses.
- Build `old_rows: dict[(gpo_id, side, cse, identity), display_value]`
  and `new_rows` likewise.
- For each key in `sorted(set(old_rows) | set(new_rows))`:
  - `old_v = old_rows.get(key)`, `new_v = new_rows.get(key)`.
  - If `old_v is None and new_v is not None`: change_type=`"added"`,
    `old_value=None`, `new_value=new_v`.
  - If `old_v is not None and new_v is None`: change_type=`"removed"`,
    `old_value=old_v`, `new_value=None`.
  - If `old_v != new_v` (both non-None, different): change_type=
    `"modified"`, `old_value=old_v`, `new_value=new_v`.
  - If `old_v == new_v`: no entry.
- Build `SnapshotSettingChange(gpo_id, gpo_name=name_map.get(gpo_id,
  gpo_id), side, cse, identity, change_type, old_value, new_value)`.

Result list is sorted by the key tuple — i.e. by
`(gpo_id, side, cse, identity)` ascending.

## AC-07: `SnapshotSettingChange` dataclass shape

`@dataclass(frozen=True)`:

| Field | Type |
|-------|------|
| `gpo_id` | `str` |
| `gpo_name` | `str` (resolved from snap_b first, then snap_a) |
| `side` | `str` (`"Computer"` or `"User"`) |
| `cse` | `str` |
| `identity` | `str` |
| `change_type` | `str` — `"added"`, `"removed"`, or `"modified"`. |
| `old_value` | `str \| None` (None for `"added"`) |
| `new_value` | `str \| None` (None for `"removed"`) |

## AC-08: `snapshot_changelog` — version-aware per-(GPO, side) log

```python
def snapshot_changelog(conn, snap_a, snap_b) -> list[ChangelogEntry]: ...
```

1. Build `name_map` (snap_b names first, snap_a `setdefault`).
2. Compute `common = sorted(a_ids & b_ids)`.
3. Call `snapshot_settings_diff(conn, snap_a, snap_b)` once and bucket
   the changes by `gpo_id` into `settings_by_gpo`.
4. Load version rows for all common GPOs in **one query per snapshot**
   (batched — not N+1). The query is
   `SELECT id, computer_ver_ds, computer_ver_sysvol, user_ver_ds,
   user_ver_sysvol FROM gpo WHERE snapshot_id = ? AND id IN (?, ?, ...)`.
5. For each `gpo_id in common`, for each `(side, ds_idx, sv_idx)` in
   `(("Computer", 0, 1), ("User", 2, 3))`:
   - If `old_ds != new_ds or old_sv != new_sv`:
     - `edit_count = new_sv - old_sv` if both are `int`, else `None`.
     - Build `VersionChangeLog(gpo_id, gpo_name, side, old_ds, old_sv,
       new_ds, new_sv, edit_count)`.
     - If the GPO has setting changes on this side (`any(c.side ==
       side for c in settings_by_gpo.get(gpo_id, []))`): kind=
       `"settings_detail"`, `setting_changes` filtered to this side,
       summary `f"{side} side edited ({edit_count or '?'} edits);
       {len(side_changes)} setting(s) changed"`.
     - Else: kind=`"metadata_only"`, `setting_changes=[]`, summary
       `f"{side} side metadata changed ({edit_count or '?'} edits);
       settings unchanged"`.
     - Append `ChangelogEntry(gpo_id, gpo_name, kind, side,
       version_change=vcl, setting_changes, summary)`.

**Two entries per GPO are possible** when both sides' versions changed
(see Notes). Added/removed GPOs (not in `common`) do not appear.

The `edit_count or '?'` rendering means a true `0` displays as `'?'`
(see Notes). The underlying `VersionChangeLog.edit_count` field is
correct (`0`, not `None`).

## AC-09: `VersionChangeLog` and `ChangelogEntry` shapes

`VersionChangeLog` (`@dataclass(frozen=True)`):

| Field | Type |
|-------|------|
| `gpo_id` | `str` |
| `gpo_name` | `str` |
| `side` | `str` (`"Computer"` or `"User"`) |
| `old_ds` | `int \| None` (Computer/User DS version in snap_a) |
| `old_sysvol` | `int \| None` |
| `new_ds` | `int \| None` |
| `new_sysvol` | `int \| None` |
| `edit_count` | `int \| None` (`new_sysvol - old_sysvol` when both int) |

`ChangelogEntry` (`@dataclass(frozen=True)`):

| Field | Type |
|-------|------|
| `gpo_id` | `str` |
| `gpo_name` | `str` |
| `kind` | `str` — `"metadata_only"` or `"settings_detail"`. |
| `side` | `str \| None` (always set today; `None` reserved) |
| `version_change` | `VersionChangeLog \| None` (always set today) |
| `setting_changes` | `list[SnapshotSettingChange]` (empty for `metadata_only`) |
| `summary` | `str` — human-readable one-liner |

## AC-10: Determinism

- All set operations (`a_ids & b_ids`, `b_ids - a_ids`) and list
  constructions are deterministic given the same DB contents.
- Every output list is sorted: `gpos_added`/`gpos_removed` and all
  `*_changed` lists by `gpo_id` ascending; `metadata_changes` and
  `wmi_filter_changes`/`enabled_flips` in field-iteration order
  (per-GPO, in `sorted(common)` GPO order, fields in the fixed order
  `name, domain, sddl, owner, computer_enabled, user_enabled,
  wmi_filter`); `snapshot_settings_diff` by `(gpo_id, side, cse,
  identity)`; `snapshot_changelog` in `sorted(common)` GPO order, with
  Computer side emitted before User side within a GPO.
- No randomness, no time, no environment reads, no model calls
  (`tests/_arch.py`).
- The DB-row-set comparisons in `snapshot_diff` (`old_s != new_s`)
  compare tuples; row order within a `SELECT` does not affect the set
  equality. Two runs over the same DB produce identical results.
