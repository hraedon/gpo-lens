"""Tier-1 deterministic queries over an ``Estate``."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from gpo_lens.model import Estate, Gpo, Setting

Side = str


@dataclass(frozen=True)
class Conflict:
    """Settings sharing ``(cse, side, identity)`` across GPOs with differing values."""

    cse: str
    side: Side
    identity: str
    display_name: str
    entries: list[tuple[str, str]]  # (gpo_id, display_value)


def unlinked_gpos(estate: Estate) -> list[Gpo]:
    """GPOs with no ``links``. These apply nowhere."""
    return [g for g in estate.gpos if not g.links]


def empty_gpos(estate: Estate) -> list[Gpo]:
    """GPOs with no ``settings`` on either side."""
    return [g for g in estate.gpos if not g.settings]


def disabled_but_populated(estate: Estate) -> list[tuple[Gpo, Side]]:
    """Each (GPO, side) where that side's ``*_enabled`` is False but it has ≥1 setting with ``from_disabled_side=True``."""
    results: list[tuple[Gpo, Side]] = []
    for g in estate.gpos:
        if not g.computer_enabled and any(s.side == "Computer" and s.from_disabled_side for s in g.settings):
            results.append((g, "Computer"))
        if not g.user_enabled and any(s.side == "User" and s.from_disabled_side for s in g.settings):
            results.append((g, "User"))
    return results


def who_sets(estate: Estate, term: str) -> list[Setting]:
    """Settings whose ``display_name``, ``identity``, or ``display_value`` contains ``term`` (case-insensitive)."""
    term_lower = term.lower()
    return [
        s
        for g in estate.gpos
        for s in g.settings
        if term_lower in s.display_name.lower()
        or term_lower in s.identity.lower()
        or term_lower in s.display_value.lower()
    ]


def conflicts(estate: Estate) -> list[Conflict]:
    """Cross-estate conflict surface: same setting identity, different values, across GPOs."""
    # Group by (cse, side, identity)
    buckets: dict[tuple[str, str, str], list[Setting]] = defaultdict(list)
    for g in estate.gpos:
        for s in g.settings:
            buckets[(s.cse, s.side, s.identity)].append(s)

    results: list[Conflict] = []
    for (cse, side, identity), settings in buckets.items():
        # Need two or more distinct GPOs
        gpo_ids = {s.gpo_id for s in settings}
        if len(gpo_ids) < 2:
            continue
        # Need two or more distinct display_values
        values = {s.display_value for s in settings}
        if len(values) < 2:
            continue
        entries = [(s.gpo_id, s.display_value) for s in settings]
        # Use the most common display_name, or first
        display_name = settings[0].display_name
        results.append(Conflict(cse=cse, side=side, identity=identity, display_name=display_name, entries=entries))
    return results


def blocked_extensions(estate: Estate) -> list[tuple[Gpo, Side, str]]:
    """(GPO, side, cse) where an extension was ``<Blocked/>`` / unreadable."""
    results: list[tuple[Gpo, Side, str]] = []
    for g in estate.gpos:
        for s in g.settings:
            if s.source_state == "blocked":
                results.append((g, s.side, s.cse))
    return results
