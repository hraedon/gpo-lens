"""Tier-1 deterministic queries over an Estate."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from collections import defaultdict
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from gpo_lens.model import Estate, Gpo, Setting, Side

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
    """One ``cpassword`` attribute found in a GPP XML file."""

    gpo_id: str
    gpo_name: str
    file: str
    tag: str
    cpassword: str


@dataclass(frozen=True)
class SearchResult:
    """One search hit."""

    gpo_id: str
    gpo_name: str
    match_field: str  # "gpo_name", "setting", "delegation"
    detail: str
    side: str | None = None
    cse: str | None = None


# ---------------------------------------------------------------------------
# Tier-1 queries
# ---------------------------------------------------------------------------

def unlinked_gpos(estate: Estate) -> list[Gpo]:
    """GPOs with no links.  These apply nowhere."""
    return [g for g in estate.gpos if not g.links]


def empty_gpos(estate: Estate) -> list[Gpo]:
    """GPOs with no settings on either side."""
    return [g for g in estate.gpos if not g.settings]


def disabled_but_populated(estate: Estate) -> list[tuple[Gpo, Side]]:
    """(Gpo, Side) pairs where the side is disabled but has settings."""
    results: list[tuple[Gpo, Side]] = []
    for g in estate.gpos:
        if not g.computer_enabled and any(s.side == "Computer" and s.from_disabled_side for s in g.settings):
            results.append((g, "Computer"))
        if not g.user_enabled and any(s.side == "User" and s.from_disabled_side for s in g.settings):
            results.append((g, "User"))
    return results


def who_sets(estate: Estate, term: str) -> list[Setting]:
    """Settings whose display_name, identity, or display_value contains *term* (case-insensitive)."""
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
    """Cross-estate conflict surface: same setting identity across GPOs with differing values."""
    buckets: dict[tuple, list[Setting]] = defaultdict(list)
    for g in estate.gpos:
        for s in g.settings:
            key = (s.cse, s.side, s.identity)
            buckets[key].append(s)

    results: list[Conflict] = []
    for (cse, side, identity), settings in buckets.items():
        gpo_ids = {s.gpo_id for s in settings}
        if len(gpo_ids) < 2:
            continue
        values = {s.display_value for s in settings}
        if len(values) < 2:
            continue
        entries = [(s.gpo_id, s.display_value) for s in settings]
        results.append(Conflict(
            cse=cse, side=side, identity=identity,
            display_name=settings[0].display_name, entries=entries,
        ))
    return results


def blocked_extensions(estate: Estate) -> list[tuple[Gpo, Side, str]]:
    """(Gpo, side, cse) where an extension was Blocked/Unreadable."""
    results: list[tuple[Gpo, Side, str]] = []
    for g in estate.gpos:
        for s in g.settings:
            if s.source_state == "blocked":
                results.append((g, s.side, s.cse))
    return results


def version_skew(estate: Estate) -> list[tuple[Gpo, Side]]:
    """GPOs where GPC (AD) and GPT (SYSVOL) version numbers differ."""
    results: list[tuple[Gpo, Side]] = []
    for g in estate.gpos:
        if g.computer_version_skew:
            results.append((g, "Computer"))
        if g.user_version_skew:
            results.append((g, "User"))
    return results


# ---------------------------------------------------------------------------
# Security / hygiene
# ---------------------------------------------------------------------------

_MS16_072_TRUSTEES = {"authenticated users", "domain computers", "domain computers"}

def _trustee_matches_ms16_072(trustee: str, sid: str | None) -> bool:
    t = trustee.strip().lower()
    if t in _MS16_072_TRUSTEES:
        return True
    if sid:
        s = sid.strip().lower()
        if s == "s-1-5-11":  # Authenticated Users SID
            return True
        if s.endswith("-515"):  # Domain Computers SID suffix
            return True
    return False


def ms16_072_vulnerable(estate: Estate) -> list[Gpo]:
    """GPOs missing Read for Authenticated Users or Domain Computers (MS16-072)."""
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


def permissions_audit(estate: Estate) -> list[tuple[Gpo, str]]:
    """Audit delegation for common security issues.

    Returns a list of (Gpo, description) tuples.
    """
    issues: list[tuple[Gpo, str]] = []
    for g in estate.gpos:
        # 1. MS16-072: no Authenticated Users / Domain Computers read
        has_read = any(
            e.allowed
            and e.permission.lower() in ("read", "read, apply")
            and _trustee_matches_ms16_072(e.trustee, e.trustee_sid)
            for e in g.delegation
        )
        if not has_read:
            issues.append((g, "No Authenticated Users / Domain Computers Read (MS16-072)"))

        # 2. Too many principals with Edit rights
        writers = [d for d in g.delegation if d.allowed and "write" in d.permission.lower()]
        if len(writers) > 3:
            issues.append((g, f"{len(writers)} principals have write/modify permissions"))

        # 3. Orphan: no delegation at all
        if not g.delegation:
            issues.append((g, "No delegation entries"))

    return issues


# ---------------------------------------------------------------------------
# Search
# ---------------------------------------------------------------------------

def search(
    estate: Estate, term: str, scope: str = "all"
) -> list[SearchResult]:
    """Full-text search across GPOs, settings, and delegations."""
    term_lower = term.lower()
    results: list[SearchResult] = []

    for g in estate.gpos:
        # GPO name
        if scope in ("all", "names") and term_lower in g.name.lower():
            results.append(SearchResult(
                gpo_id=g.id, gpo_name=g.name,
                match_field="gpo_name", detail=g.name,
            ))

        # Settings
        if scope in ("all", "settings"):
            for s in g.settings:
                if (term_lower in s.display_name.lower()
                        or term_lower in s.identity.lower()
                        or term_lower in s.display_value.lower()):
                    results.append(SearchResult(
                        gpo_id=g.id, gpo_name=g.name,
                        match_field="setting",
                        detail=f"[{s.cse}] {s.side}/{s.identity}: {s.display_value}",
                        side=s.side, cse=s.cse,
                    ))

        # Delegation
        if scope in ("all", "delegation"):
            for d in g.delegation:
                if term_lower in d.trustee.lower() or term_lower in d.permission.lower():
                    results.append(SearchResult(
                        gpo_id=g.id, gpo_name=g.name,
                        match_field="delegation",
                        detail=f"{d.trustee}: {d.permission} (allowed={d.allowed})",
                    ))
    return results


# ---------------------------------------------------------------------------
# GPP cpassword scan
# ---------------------------------------------------------------------------

_GPP_XML_FILES = (
    "Groups.xml", "Services.xml", "Drives.xml", "ScheduledTasks.xml",
    "DataSources.xml", "Printers.xml", "Folders.xml", "Files.xml",
    "Registry.xml", "Environment.xml", "Shortcuts.xml", "InternetSettings.xml",
    "Regional.xml", "PowerOptions.xml", "NetworkShares.xml",
    "LocalUsersAndGroups.xml", "EventLogs.xml",
)


def _scan_gpo_for_cpassword(gpo: Gpo) -> list[CpasswordHit]:
    """Walk one GPO's SYSVOL Preference XML for lingering cpassword attributes."""
    results: list[CpasswordHit] = []
    if not gpo.sysvol_path:
        return results
    from pathlib import Path
    base = Path(gpo.sysvol_path)
    for side_dir in ("Machine", "User"):
        prefs = base / side_dir / "Preferences"
        if not prefs.exists():
            continue
        for filename in _GPP_XML_FILES:
            file_path = prefs / filename
            if not file_path.exists():
                continue
            try:
                tree = ET.parse(file_path)
            except ET.ParseError:
                continue
            for elem in tree.getroot().iter():
                cpw = elem.get("cpassword")
                if cpw is not None:
                    tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
                    rel = file_path.relative_to(base)
                    results.append(CpasswordHit(
                        gpo_id=gpo.id, gpo_name=gpo.name,
                        file=str(rel), tag=tag, cpassword=cpw,
                    ))
    return results


def cpassword_scan(estate: Estate) -> list[CpasswordHit]:
    """Scan SYSVOL GPP XML for lingering ``cpassword`` attributes (MS14-025)."""
    results: list[CpasswordHit] = []
    for g in estate.gpos:
        results.extend(_scan_gpo_for_cpassword(g))
    return results


# ---------------------------------------------------------------------------
# Snapshot diff
# ---------------------------------------------------------------------------

def snapshot_diff(conn, snap_a: int, snap_b: int) -> dict:
    """Compute the diff between two snapshots.

    Returns a dict with keys: gpos_added, gpos_removed, gpos_modified,
    delegation_changed.
    """
    def _load_snapshot_gpos(snap_id):
        return set(
            row[0] for row in
            conn.execute(
                "SELECT id FROM gpo WHERE snapshot_id = ?", (snap_id,)
            ).fetchall()
        )

    a_ids = _load_snapshot_gpos(snap_a)
    b_ids = _load_snapshot_gpos(snap_b)

    added = b_ids - a_ids
    removed = a_ids - b_ids

    # Settings changes
    changed = []
    for gpo_id in a_ids & b_ids:
        old_settings = set(
            conn.execute(
                "SELECT cse, identity, display_value FROM setting "
                "WHERE snapshot_id = ? AND gpo_id = ?",
                (snap_a, gpo_id),
            ).fetchall()
        )
        # Reload for snap_b
        new_settings = set(
            conn.execute(
                "SELECT cse, identity, display_value FROM setting "
                "WHERE snapshot_id = ? AND gpo_id = ?",
                (snap_b, gpo_id),
            ).fetchall()
        )
        if old_settings != new_settings:
            changed.append(gpo_id)

    return {"added": list(added), "removed": list(removed), "changed": changed}
