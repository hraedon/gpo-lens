# JSON output contract (machine-readable seam)

**Status:** frozen, `schema_version: 1` (since v0.3.0).
**Enforced by:** `tests/test_json_contract.py` (golden shapes) + `src/gpo_lens/cli/_helpers.py` (envelope).

This is the stable interface downstream consumers build against. gpo-lens's
analysis pipeline is read-only and air-gapped; its *outputs* are the only
coupling point for sibling tools (see `/projects/maybe-projects/`). Those tools
trust the JSON shapes documented here as their input contract — no shared code,
no DB import, no parsing duplication. Freezing this contract is what lets a
complement be built without tracking gpo-lens's internals.

## The envelope

Every `--json` invocation prints exactly one JSON document to **stdout** on
success: a self-describing envelope with the command payload under `data`.

```json
{
  "schema_version": 1,
  "kind": "settings-dump",
  "tool_version": "0.3.0",
  "generated_at": "2026-06-14T15:58:05.032933+00:00",
  "data": [ ... ]
}
```

| Field | Meaning | Stability |
|-------|---------|-----------|
| `schema_version` | Contract version (integer). | Pinned; bumped only on a breaking change. |
| `kind` | The subcommand that produced the payload (`summary`, `doctor`, …). | Stable; equals the CLI subcommand name. |
| `tool_version` | gpo-lens version that emitted it. | Informational — **do not** branch on it. |
| `generated_at` | UTC ISO-8601 emit time. | Informational — volatile, not part of the comparable shape. |
| `data` | The command-specific payload (object or array). | Per-command shapes below. |

### Versioning policy

- **Additive change** (a new field on an object, a new optional key): the shape
  stays at the same `schema_version`. Consumers must ignore unknown fields.
- **Breaking change** (removing/renaming a field, retyping, reshaping the
  envelope): bump `schema_version`, and update both this document and
  `tests/test_json_contract.py` in the same change.
- A consumer should read `data`, tolerate unknown fields, and may assert
  `schema_version == 1` if it wants to fail loudly on a future break.

## Stream and exit-code semantics

- **Success:** the envelope is the *only* thing on stdout; exit `0`.
- **Warnings** (e.g. a missing `--admx-dir`): go to **stderr**; stdout stays
  clean JSON. A warning is not a failure.
- **Errors** (not-found, bad input, missing DB): a message on **stderr** and a
  **nonzero** exit. Errors are never printed as plain text on stdout, so a
  consumer can trust "exit 0 ⟹ stdout parses as the envelope."
- **`report --json` is refused** (exit 2, stderr): `report` produces a
  human-readable document (`--format md|html`), not part of this contract. For
  a machine-readable estate snapshot use `summary --json`; for the per-setting
  body use `settings-dump --json`; for findings use `doctor --json`.

## Preconditions

- **`events` requires `ingest --diff-latest`.** The append-only event log is
  populated only when an ingest is run with `--diff-latest` (which diffs the new
  snapshot against the prior one). Without it the table exists but stays empty,
  and `events --json` returns `{"data": []}`.

## Per-command `data` shapes (the consumed surface)

Required fields are listed; commands may add fields additively. These are the
shapes complements consume — the golden test pins exactly this set.

### `summary --json` → object (estate snapshot)
`domain`, `gpo_count`, `som_count` (OU/domain SOMs only),
`linked_site_count` (AD sites carrying ≥1 enabled GPO link),
`coverage_gap_count` (GPOs that exist but could not be collected),
`wmi_filter_count`, `broken_ref_count` (plus the full set of hygiene counts:
`unlinked_count`, `empty_count`,
`disabled_but_populated_count`, `conflict_count`, `version_skew_count`,
`ms16_072_vulnerable_count`, `cpassword_hit_count`, `loopback_gpo_count`,
`wmi_filtered_gpo_count`, `enforced_link_count`, `dangling_link_count`,
`admx_gap_count`, `broken_wmi_ref_count`, `orphaned_wmi_filter_count`,
`ilt_gpo_count`, `stale_gpo_count`).

### `doctor --json` → object
`findings`: array of `{severity, category, gpo_id, gpo_name, summary, detail}`.
`category` includes `coverage_gap` for GPOs that exist but could not be
collected (reconciled from `gpo-inventory.json` / `collection-errors.json`) —
the analysis is explicit that it is incomplete rather than silently partial.

### `settings-dump --json` → array of rows
`{gpo_id, gpo_name, side, cse, identity, display_name, display_value,
from_disabled_side, source_state}`.
`source_state` is `"normal"` or `"blocked"` (the `<Blocked/>` extension).

### `broken-refs --json` → array
`{gpo_id, gpo_name, ref_type, ref_value, detail}`.

### `baseline-diff <baseline> --json` → array
`{status, side, cse, identity, display_name, expected_value, actual_value,
gpo_id, admx_name}`. `status` ∈ `{compliant, drift, missing, extra}`.
Accepts a baseline GPO-backup directory or a `.zip` (incl. Microsoft's nested
Security Baseline packaging).

### `events --json` → array of records
`{id, timestamp, event_type, schema_version, payload}`. `payload` is an object
whose shape depends on `event_type`:
- `ingest.summary` → `{old_snapshot_id, new_snapshot_id, gpos_added,
  gpos_removed, gpos_modified, gpo_count}`
- `gpo.created` / `gpo.deleted` → `{gpo_id, gpo_name}`
- `gpo.modified` → `{gpo_id, gpo_name, deltas: [{cse, identity, gpo_name, old,
  new}]}` (+ `truncated`, `total_count` when >100 deltas)
- `audit.ingest` / `audit.narrate` → web-UI access-audit records
  (`{principal, …}`)

Note: the per-record `schema_version` here is the *event* schema version, which
is independent of the top-level contract `schema_version`.

### `sites --json` → array
AD sites and their direct GPO links. `[{name, dn, links: [{gpo_id, gpo_name,
enabled, enforced, order}]}]`. Site-linked GPOs are applied before domain/OU
(lowest precedence); per-machine site membership is not resolved (flag, don't
simulate). Empty when the export carried no `sites.json`.

### `scope <gpo> --json` → object
`{gpo_id, gpo_name, domain, computer_enabled, user_enabled, links,
security_filtering, wmi_filter, loopback_mode, caveats}`, where
`security_filtering` = `{is_filtered, apply_trustees, has_au_read, has_dc_read}`
and `wmi_filter` is `{name, query, is_broken}` or `null`.

## Who consumes what (current complements)

| Complement (parked) | Consumes |
|---------------------|----------|
| audit-evidence-packager | `summary`, `doctor`, `baseline-diff`, `events` |
| gpo-remediation-player | `doctor`, `baseline-diff`, `broken-refs` |
| cross-estate-diff | `settings-dump`, `baseline-diff` |
| rsop-simulator | `scope`, `settings-dump` (incl. `source_state`) |
