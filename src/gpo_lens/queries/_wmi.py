"""WMI-filter and freshness helpers over an Estate."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from gpo_lens.model import Estate, Gpo, WmiFilter


@dataclass(frozen=True)
class BrokenWmiRef:
    """A GPO referencing a WMI filter absent from wmi-filters.json."""

    gpo_id: str
    gpo_name: str
    filter_name: str


def orphaned_wmi_filters(estate: Estate) -> list[WmiFilter]:
    """WMI filters defined but referenced by zero GPOs."""
    referenced = {
        g.wmi_filter for g in estate.gpos if g.wmi_filter
    }
    return [f for f in estate.wmi_filters if f.name not in referenced]


def broken_wmi_refs(estate: Estate) -> list[BrokenWmiRef]:
    """GPOs referencing a WMI filter absent from wmi-filters.json."""
    known = {f.name for f in estate.wmi_filters}
    results: list[BrokenWmiRef] = []
    for g in estate.gpos:
        if g.wmi_filter and g.wmi_filter not in known:
            results.append(BrokenWmiRef(
                gpo_id=g.id,
                gpo_name=g.name,
                filter_name=g.wmi_filter,
            ))
    return results


def stale_gpos(
    estate: Estate,
    threshold_years: int = 2,
    *,
    now: datetime | None = None,
) -> list[tuple[Gpo, int]]:
    """Linked GPOs modified more than *threshold_years* ago.

    Returns ``(Gpo, years_since_modification)`` sorted oldest first. *now*
    defaults to the current UTC time; tests pin it so staleness assertions
    do not rot as wall-clock time advances past fixed fixture timestamps.
    """
    results: list[tuple[Gpo, int]] = []
    if now is None:
        now = datetime.now(timezone.utc)
    elif now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    for g in estate.gpos:
        if not g.links:
            continue
        if g.modified is None:
            continue
        mod = g.modified
        if mod.tzinfo is None:
            mod = mod.replace(tzinfo=timezone.utc)
        # 365.25 accounts for leap years so a GPO just under the threshold is
        # not rounded up across a leap day (e.g. 730 days != a full 2 years).
        delta_years = int((now - mod).days / 365.25)
        if delta_years >= threshold_years:
            results.append((g, delta_years))
    results.sort(key=lambda t: t[1], reverse=True)
    return results
