# Work Item: Trend Analysis (WI-056)

## Dependencies

- `interface_ref`: `store`, `queries` (`estate_summary`)

## Notes

Computes posture-over-time metrics by running `estate_summary` on each stored
snapshot and presenting the result as a time-ordered series.  This lets an
admin see whether the estate is improving or degrading over time.

Module: `src/gpo_lens/trend.py`.  Core module — stdlib-only, no AI in the
truth path, must not import `narration` or `web`.

---

## AC-01: TrendPoint dataclass

`trend.TrendPoint` is a frozen dataclass with:

| Field                        | Type | Source (EstateSummary)         |
|------------------------------|------|---------------------------------|
| `snapshot_id`                | int  | snapshot row id                 |
| `taken_at`                   | str  | ISO format from snapshot row    |
| `gpo_count`                  | int  | `gpo_count`                     |
| `danger_finding_count`       | int  | `danger_finding_count`          |
| `cpassword_hit_count`        | int  | `cpassword_hit_count`           |
| `ms16_072_vulnerable_count`  | int  | `ms16_072_vulnerable_count`     |
| `version_skew_count`         | int  | `version_skew_count`            |
| `broken_ref_count`           | int  | `broken_ref_count`              |
| `unlinked_count`             | int  | `unlinked_count`                |
| `empty_count`                | int  | `empty_count`                   |
| `total_settings`             | int  | `total_settings`                |
| `coverage_gap_count`         | int  | `coverage_gap_count`            |

## AC-02: compute_trend

`trend.compute_trend(conn: sqlite3.Connection) -> list[TrendPoint]`

- Iterates all snapshots **oldest first** (reverses `store.list_snapshots`).
- For each, calls `store.load_estate(conn, snapshot_id)` then
  `queries.estate_summary(estate)`.
- Maps summary fields to `TrendPoint`.
- Snapshots that fail to load are **skipped** with a `warnings.warn` (does
  not raise).
- Returns an empty list when there are no snapshots.

## AC-03: changes_only

`trend.changes_only(points: list[TrendPoint]) -> list[TrendPoint]`

- Always includes the first point (baseline).
- Includes a subsequent point only if at least one of the tracked metrics
  differs from the immediately preceding point.
- Tracked metrics: `gpo_count`, `danger_finding_count`,
  `cpassword_hit_count`, `ms16_072_vulnerable_count`,
  `version_skew_count`, `broken_ref_count`, `unlinked_count`,
  `empty_count`, `total_settings`, `coverage_gap_count`.

## AC-04: sparkline

`trend.sparkline(values: list[int]) -> str`

- Maps non-negative ints to Unicode block characters (`▁▂▃▄▅▆▇█`).
- Zero -> lowest block; max value -> highest block.
- Empty list -> empty string.
- All-zero list -> row of lowest blocks.

## AC-05: CLI `trends` subcommand

- Registered as `gpo-lens trends` in `cli/_core.py`.
- Uses `--db` (top-level flag).
- `--json`: full TrendPoint list in the versioned JSON envelope.
- `--changes-only`: filter to changed points before output.
- Default: table with columns Snapshot ID, Date, GPOs, Dangers, Cpassword,
  MS16-072, Skew, Broken Refs, Coverage Gaps.

## AC-06: Web route `/trends`

- `GET /trends` — HTML page with trend table + sparklines.
- Row highlighting: red when danger count increased, green when decreased.
- Requires `Permission.VIEW`.
- Registered in `app.py` via `trends.register(app, templates)`.

## AC-07: API endpoint `GET /api/v1/trends`

- Returns `{"status": "ok", "data": [TrendPoint, ...]}`.
- Requires `Permission.VIEW`.
- Uses `serialize_result` for dataclass-to-dict conversion.
