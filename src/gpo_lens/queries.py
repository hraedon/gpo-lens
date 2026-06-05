"""Tier-1 deterministic queries over an ``Estate``."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
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


@dataclass(frozen=True)
class CpasswordHit:
    """One detected ``cpassword`` attribute in a SYSVOL GPP XML file."""

    gpo_id: str
    gpo_name: str
    file: str
    tag: str
    cpassword: str


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


# ---------------------------------------------------------------------------
# Security / hygiene scans
# ---------------------------------------------------------------------------


def version_skew(estate: Estate) -> list[tuple[Gpo, Side]]:
    """GPOs where GPC and GPT versions differ for a side (replication skew)."""
    results: list[tuple[Gpo, Side]] = []
    for g in estate.gpos:
        if g.computer_version_skew:
            results.append((g, "Computer"))
        if g.user_version_skew:
            results.append((g, "User"))
    return results


# Well-known trustee names / SIDs we care about for MS16-072
_MS16_072_TRUSTEES = {"authenticated users", "domain computers"}


def _trustee_matches_ms16_072(trustee: str, sid: str | None) -> bool:
    t = trustee.strip().lower()
    if t in _MS16_072_TRUSTEES:
        return True
    if sid:
        s = sid.strip().lower()
        if s == "s-1-5-11":
            return True
        if s.endswith("-515"):
            return True
    return False


def ms16_072_vulnerable(estate: Estate) -> list[Gpo]:
    """GPOs missing ``Read`` for AU or DC (MS16-072 SYSVOL access trap).

    Microsoft guidance: after MS16-072 the client runs as the computer
    account, so the computer must be able to read the SYSVOL GPT folder.
    The preferred fix is ``Read`` for ``Authenticated Users``; an
    alternative is ``Read`` for ``Domain Computers``.  We flag a GPO
    when *neither* trustee has ``Read``.
    """
    results: list[Gpo] = []
    for g in estate.gpos:
        has_read = any(
            e.allowed
            and _trustee_matches_ms16_072(e.trustee, e.trustee_sid)
            and e.permission.lower() == "read"
            for e in g.delegation
        )
        if not has_read:
            results.append(g)
    return results


_GPP_XML_FILES = (
    "Groups.xml",
    "Services.xml",
    "Drives.xml",
    "ScheduledTasks.xml",
    "DataSources.xml",
    "Printers.xml",
    "Folders.xml",
    "Files.xml",
    "Registry.xml",
    "Environment.xml",
    "Shortcuts.xml",
    "InternetSettings.xml",
    "Regional.xml",
    "PowerOptions.xml",
    "NetworkShares.xml",
    "LocalUsersAndGroups.xml",
    "EventLogs.xml",
)


def _scan_gpo_for_cpassword(gpo: Gpo) -> list[CpasswordHit]:
    """Walk one GPO's SYSVOL Preferences XML for ``cpassword`` attributes."""
    results: list[CpasswordHit] = []
    if not gpo.sysvol_path:
        return results
    base = Path(gpo.sysvol_path)
    for side_dir in ("Machine", "User"):
        prefs_dir = base / side_dir / "Preferences"
        if not prefs_dir.exists():
            continue
        for filename in _GPP_XML_FILES:
            file_path = prefs_dir / filename
            if not file_path.exists():
                continue
            try:
                tree = ET.parse(file_path)
            except ET.ParseError:
                continue
            for elem in tree.iter():
                cpw = elem.get("cpassword")
                if cpw is not None:
                    tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
                    results.append(
                        CpasswordHit(
                            gpo_id=gpo.id,
                            gpo_name=gpo.name,
                            file=str(file_path.relative_to(base)),
                            tag=tag,
                            cpassword=cpw,
                        )
                    )
    return results


def cpassword_scan(estate: Estate) -> list[CpasswordHit]:
    """Scan SYSVOL GPP XML for lingering ``cpassword`` attributes (MS14-025)."""
    results: list[CpasswordHit] = []
    for g in estate.gpos:
        results.extend(_scan_gpo_for_cpassword(g))
    return results
