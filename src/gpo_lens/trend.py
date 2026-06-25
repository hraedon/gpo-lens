"""Posture-over-time trend analysis from snapshot history.

Computes ``estate_summary`` on each stored snapshot and presents the
resulting metrics as a time-ordered series, so an admin can see whether
the estate is improving or degrading over time.

This is a **core module** — it must not import ``narration`` or ``web``
(the import-boundary architecture test enforces this).  It is
third-party-dependency-free.
"""

from __future__ import annotations

import dataclasses
import sqlite3
import warnings
from dataclasses import dataclass

from gpo_lens.queries import estate_summary
from gpo_lens.store import list_snapshots, load_estate


@dataclass(frozen=True)
class TrendPoint:
    """Posture metrics for a single snapshot, for time-series display."""

    snapshot_id: int
    taken_at: str  # ISO format
    gpo_count: int
    danger_finding_count: int
    cpassword_hit_count: int
    ms16_072_vulnerable_count: int
    version_skew_count: int
    broken_ref_count: int
    unlinked_count: int
    empty_count: int
    total_settings: int
    coverage_gap_count: int


# Metrics compared by ``changes_only``: if any of these differ from the
# previous TrendPoint, the current point is included in the changes-only view.
# Derived automatically from TrendPoint fields so it stays in sync if new
# metrics are added.
_CHANGE_METRICS: tuple[str, ...] = tuple(
    f.name for f in dataclasses.fields(TrendPoint)
    if f.name not in ("snapshot_id", "taken_at")
)

# Unicode block elements for sparklines (low -> high).
_BLOCKS = "\u2581\u2582\u2583\u2584\u2585\u2586\u2587\u2588"


def compute_trend(conn: sqlite3.Connection) -> list[TrendPoint]:
    """Compute posture-over-time metrics for all snapshots.

    Iterates all snapshots (oldest first), loads each estate, computes
    ``estate_summary``, and returns the time-ordered list.  Snapshots that
    fail to load are skipped (with a warning).
    """
    snapshots = list_snapshots(conn)  # newest first
    points: list[TrendPoint] = []
    for snapshot_id, _domain, taken_at in reversed(snapshots):
        try:
            estate = load_estate(conn, snapshot_id)
        except Exception as exc:  # noqa: BLE001 -- skip corrupt snapshots
            warnings.warn(
                f"Skipping snapshot {snapshot_id}: failed to load ({exc})",
                stacklevel=2,
            )
            continue
        summary = estate_summary(estate)
        points.append(
            TrendPoint(
                snapshot_id=snapshot_id,
                taken_at=taken_at.isoformat() if taken_at else "",
                gpo_count=summary.gpo_count,
                danger_finding_count=summary.danger_finding_count,
                cpassword_hit_count=summary.cpassword_hit_count,
                ms16_072_vulnerable_count=summary.ms16_072_vulnerable_count,
                version_skew_count=summary.version_skew_count,
                broken_ref_count=summary.broken_ref_count,
                unlinked_count=summary.unlinked_count,
                empty_count=summary.empty_count,
                total_settings=summary.total_settings,
                coverage_gap_count=summary.coverage_gap_count,
            )
        )
    return points


def changes_only(points: list[TrendPoint]) -> list[TrendPoint]:
    """Filter to points where a key metric changed from the previous point.

    The first point is always included (baseline).  Subsequent points are
    included only if at least one metric in ``_CHANGE_METRICS`` differs
    from the immediately preceding point.
    """
    if not points:
        return []
    result: list[TrendPoint] = [points[0]]
    for prev, curr in zip(points, points[1:], strict=False):
        if any(getattr(prev, m) != getattr(curr, m) for m in _CHANGE_METRICS):
            result.append(curr)
    return result


def sparkline(values: list[int]) -> str:
    """Render a list of non-negative ints as a Unicode block sparkline.

    Zero maps to the lowest block; the maximum value maps to the highest.
    An empty list returns an empty string.  All-zero lists return a row of
    lowest blocks (flat baseline).

    Raises ``ValueError`` if any value is negative — sparklines are only
    meaningful for non-negative data.
    """
    if any(v < 0 for v in values):
        raise ValueError("sparkline values must be non-negative")
    if not values:
        return ""
    hi = max(values)
    if hi == 0:
        return _BLOCKS[0] * len(values)
    n = len(_BLOCKS) - 1
    return "".join(
        _BLOCKS[min(n, int(v / hi * n))]
        for v in values
    )
