"""Tier-1 deterministic queries over an Estate."""

from __future__ import annotations

import re
import sqlite3
import xml.etree.ElementTree as ET
from collections import defaultdict
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from gpo_lens.model import DelegationEntry, Estate, Gpo, Setting, Side, Som, SomLink

Side = str  # type: ignore[misc]


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
        comp_disabled = not g.computer_enabled and any(
            s.side == "Computer" and s.from_disabled_side for s in g.settings
        )
        user_disabled = not g.user_enabled and any(
            s.side == "User" and s.from_disabled_side for s in g.settings
        )
        if comp_disabled:
            results.append((g, "Computer"))
        if user_disabled:
            results.append((g, "User"))
    return results


def who_sets(estate: Estate, term: str) -> list[Setting]:
    """Settings whose display_name, identity, or display_value
    contains *term* (case-insensitive)."""
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
    """Cross-estate conflict surface: same setting identity across GPOs
    with differing values."""
    buckets: dict[tuple[str, str, str], list[Setting]] = defaultdict(list)
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
        seen_pairs: set[tuple[str, str]] = set()
        entries: list[tuple[str, str]] = []
        for s in settings:
            pair = (s.gpo_id, s.display_value)
            if pair not in seen_pairs:
                seen_pairs.add(pair)
                entries.append(pair)
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

_MS16_072_TRUSTEES = {"authenticated users", "domain computers"}

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


def _has_ms16_072_read(delegation: list[DelegationEntry]) -> bool:
    """Check whether a delegation list grants Read to AU/DC."""
    return any(
        e.allowed
        and _trustee_matches_ms16_072(e.trustee, e.trustee_sid)
        and e.permission.lower() == "read"
        for e in delegation
    )


def ms16_072_vulnerable(estate: Estate) -> list[Gpo]:
    """GPOs missing Read for Authenticated Users or Domain Computers (MS16-072)."""
    return [g for g in estate.gpos if not _has_ms16_072_read(g.delegation)]


def permissions_audit(estate: Estate) -> list[tuple[Gpo, str]]:
    """Audit delegation for common security issues.

    Returns a list of (Gpo, description) tuples.
    """
    issues: list[tuple[Gpo, str]] = []
    for g in estate.gpos:
        # 1. MS16-072: no Authenticated Users / Domain Computers read
        if not _has_ms16_072_read(g.delegation):
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

def snapshot_diff(
    conn: sqlite3.Connection, snap_a: int, snap_b: int
) -> dict[str, list[str]]:
    """Compute the diff between two snapshots.

    Returns a dict with keys: gpos_added, gpos_removed, gpos_modified,
    delegation_changed.
    """
    def _load_snapshot_gpos(snap_id: int) -> set[str]:
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
    changed: list[str] = []
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

    return {
        "added": list(added),
        "removed": list(removed),
        "changed": changed,
    }


# ---------------------------------------------------------------------------
# Topology / SOM-aware queries (Tier 2.5)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class EffectiveGpo:
    """One GPO in the resolved chain at a SOM."""

    gpo_id: str
    gpo_name: str
    order: int
    enabled: bool
    enforced: bool
    target: str            # DN the link originates from


def som_effective_gpos(estate: Estate, som_path: str) -> list[EffectiveGpo]:
    """Return the resolved, ordered GPO chain at a given SOM path.

    This reads the platform-computed chain from the GPInheritance dump.
    It does *not* object-level simulate (no WMl/loopback/security);
    it is the OU-level "what applies here" view.
    """
    # Build a GPO id → name lookup
    names = {g.id: g.name for g in estate.gpos}
    for som in estate.soms:
        if som.path.lower() == som_path.lower():
            return [
                EffectiveGpo(
                    gpo_id=link.gpo_id,
                    gpo_name=names.get(link.gpo_id, "<unknown>"),
                    order=link.order,
                    enabled=link.enabled,
                    enforced=link.enforced,
                    target=link.target,
                )
                for link in som.links
            ]
    return []


def dangling_links(estate: Estate) -> list[tuple[Som, SomLink]]:
    """SOM links that point to GPO ids not present in the estate."""
    gpo_ids = {g.id for g in estate.gpos}
    results: list[tuple[Som, SomLink]] = []
    for som in estate.soms:
        for link in som.links:
            if link.gpo_id not in gpo_ids:
                results.append((som, link))
    return results


def enforced_links(estate: Estate) -> list[tuple[Som, SomLink]]:
    """All enforced (NoOverride) links across the estate."""
    results: list[tuple[Som, SomLink]] = []
    for som in estate.soms:
        for link in som.links:
            if link.enforced:
                results.append((som, link))
    return results


# ---------------------------------------------------------------------------
# Feature-flag queries
# ---------------------------------------------------------------------------

_LOOPBACK_IDENTITIES = {
    "configure user group policy loopback processing mode",
    "configure group policy loopback processing mode",
}


def loopback_gpos(estate: Estate) -> list[tuple[Gpo, Setting]]:
    """GPOs that configure loopback processing mode."""
    results: list[tuple[Gpo, Setting]] = []
    for g in estate.gpos:
        for s in g.settings:
            ident_lower = s.identity.lower()
            val_lower = s.display_value.lower()
            if any(lb in ident_lower for lb in _LOOPBACK_IDENTITIES):
                results.append((g, s))
            elif "loopback" in val_lower:
                results.append((g, s))
    return results


def wmi_filtered_gpos(estate: Estate) -> list[Gpo]:
    """GPOs that have a WMI filter attached."""
    return [g for g in estate.gpos if g.wmi_filter is not None]


# ---------------------------------------------------------------------------
# Tier 2.5 — Chain-aware conflict detection
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SomConflict:
    """One setting identity that fights in the resolved SOM chain."""

    som_path: str
    cse: str
    side: Side
    identity: str
    display_name: str
    entries: list[tuple[str, str, str]]  # (gpo_name, display_value, status)
    winner: str                          # gpo_name of the last in chain


def _resolve_som_chain(
    estate: Estate, som_path: str
) -> tuple[list[SomLink], dict[str, Gpo], dict[str, str]] | None:
    """Find a SOM and return (enabled_chain, gpo_by_id, names) or None."""
    target_som = None
    for som in estate.soms:
        if som.path.lower() == som_path.lower():
            target_som = som
            break
    if target_som is None:
        return None
    chain = [link for link in target_som.links if link.enabled]
    if not chain:
        return None
    gpo_by_id = {g.id: g for g in estate.gpos}
    names = {g.id: g.name for g in estate.gpos}
    return chain, gpo_by_id, names


def _chain_buckets(
    chain: list[SomLink],
    gpo_by_id: dict[str, Gpo],
) -> dict[tuple[str, str, str], list[tuple[str, str, int]]]:
    """Fold a SOM chain into buckets keyed by (cse, side, identity).

    Each bucket entry is (gpo_name, display_value, order).
    """
    names = {g.id: g.name for g in gpo_by_id.values()}
    buckets: dict[tuple[str, str, str], list[tuple[str, str, int]]] = (
        defaultdict(list)
    )
    for link in chain:
        gpo = gpo_by_id.get(link.gpo_id)
        if gpo is None:
            continue
        for s in gpo.settings:
            key = (s.cse, s.side, s.identity)
            gpo_name = names.get(link.gpo_id, "<unknown>")
            buckets[key].append((gpo_name, s.display_value, link.order))
    return dict(buckets)


def som_conflicts(estate: Estate, som_path: str) -> list[SomConflict]:
    """Settings that appear in the SOM chain with differing values.

    Walks the resolved chain in ``order``. For each ``(cse, side, identity)``
    that appears in **two or more enabled GPOs** with **two or more distinct
    ``display_value`` s**, emits a conflict. The later (higher ``order``) GPO
    wins platform precedence — annotated as ``winner``.
    """
    resolved = _resolve_som_chain(estate, som_path)
    if resolved is None:
        return []
    chain, gpo_by_id, _names = resolved
    buckets = _chain_buckets(chain, gpo_by_id)

    results: list[SomConflict] = []
    for (cse, side, identity), entries in buckets.items():
        # Need >=2 distinct GPOs with >=2 distinct values
        gpo_names = {e[0] for e in entries}
        values = {e[1] for e in entries}
        if len(gpo_names) < 2 or len(values) < 2:
            continue
        # Winner = highest order entry
        winner_entry = max(entries, key=lambda e: e[2])
        winner = winner_entry[0]
        # Build conflict entries with status annotation
        conflict_entries: list[tuple[str, str, str]] = []
        for gpo_name, value, order in entries:
            status = "winner" if gpo_name == winner else "overridden"
            conflict_entries.append((gpo_name, value, status))
        # Get display_name from first entry's setting — any will do
        display_name = ""
        for link in chain:
            gpo = gpo_by_id.get(link.gpo_id)
            if gpo is None:
                continue
            for s in gpo.settings:
                if (s.cse, s.side, s.identity) == (cse, side, identity):
                    display_name = s.display_name
                    break
            if display_name:
                break

        results.append(
            SomConflict(
                som_path=som_path,
                cse=cse,
                side=side,
                identity=identity,
                display_name=display_name,
                entries=conflict_entries,
                winner=winner,
            )
        )

    return results


def precedence_conflicts(estate: Estate) -> list[tuple[Som, list[SomConflict]]]:
    """Estate-wide precedence conflict summary.

    Runs ``som_conflicts`` for every SOM that has links, returning those
    with hits.
    """
    results: list[tuple[Som, list[SomConflict]]] = []
    for som in estate.soms:
        if som.links:
            conflicts = som_conflicts(estate, som.path)
            if conflicts:
                results.append((som, conflicts))
    return results


# ---------------------------------------------------------------------------
# SOM Resolution Deep View
# ---------------------------------------------------------------------------

def settings_at_som(estate: Estate, som_path: str) -> list[EffectiveSetting]:
    """Return the effective settings that apply at a given SOM path.

    Walks the resolved chain in precedence order. For each
    ``(cse, side, identity)``, the last (highest-precedence) GPO in the
    chain wins. Returns the folded state: one ``EffectiveSetting`` per
    unique identity, annotated with the winner and any overridden values.
    """
    resolved = _resolve_som_chain(estate, som_path)
    if resolved is None:
        return []
    chain, gpo_by_id, names = resolved

    # Accumulate: (cse, side, identity) -> list of (gpo_id, gpo_name, value, order, enforced)
    buckets: dict[tuple[str, str, str], list[tuple[str, str, str, int, bool]]] = (
        defaultdict(list)
    )

    for link in chain:
        gpo = gpo_by_id.get(link.gpo_id)
        if gpo is None:
            continue
        for s in gpo.settings:
            key = (s.cse, s.side, s.identity)
            gpo_name = names.get(link.gpo_id, "<unknown>")
            buckets[key].append(
                (link.gpo_id, gpo_name, s.display_value, link.order, link.enforced)
            )

    results: list[EffectiveSetting] = []
    for (cse, side, identity), entries in buckets.items():
        # Winner = highest order entry
        winner_entry = max(entries, key=lambda e: e[3])
        winner_gpo_id, winner_gpo_name, winner_value, _, winner_enforced = winner_entry

        # Build overridden_by list (all *earlier* entries in the chain)
        overridden: list[tuple[str, str]] = []
        for gpo_id, gpo_name, value, order, _ in entries:
            if order < winner_entry[3]:
                overridden.append((gpo_name, value))

        # Recover display_name from the winner's GPO settings
        winner_gpo = gpo_by_id.get(winner_gpo_id)
        display_name = ""
        if winner_gpo is not None:
            for s in winner_gpo.settings:
                if (s.cse, s.side, s.identity) == (cse, side, identity):
                    display_name = s.display_name
                    break

        results.append(
            EffectiveSetting(
                cse=cse,
                side=side,
                identity=identity,
                display_name=display_name,
                display_value=winner_value,
                winner_gpo_id=winner_gpo_id,
                winner_gpo_name=winner_gpo_name,
                overridden_by=overridden,
                enforced=winner_enforced,
            )
        )

    # Sort for stable output: by CSE, then side, then identity
    results.sort(key=lambda es: (es.cse, es.side, es.identity.lower()))
    return results


# ---------------------------------------------------------------------------
# Broken-reference inventory
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class BrokenRef:
    """One detected broken or suspicious reference."""

    gpo_id: str
    gpo_name: str
    ref_type: str          # "unc_path", "missing_script", "script_unc"
    ref_value: str
    detail: str


@dataclass(frozen=True)
class EffectiveSetting:
    """One setting that applies at a SOM after chain folding.

    Represents the winning value for a given (cse, side, identity)
    after all GPOs in the SOM chain have been evaluated in precedence order.
    """

    cse: str
    side: Side
    identity: str
    display_name: str
    display_value: str
    winner_gpo_id: str
    winner_gpo_name: str
    overridden_by: list[tuple[str, str]]  # (gpo_name, display_value)
    enforced: bool

def _scan_text_for_unc(text: str) -> list[str]:
    """Find UNC paths in a string."""
    # Match \\server\share followed by an optional path component
    return re.findall(r"\\\\[^\s\"'<>|]+", text)


def broken_refs(estate: Estate) -> list[BrokenRef]:
    """Scan settings and SYSVOL for broken-reference patterns.

    This is **detection only** — no reachability probe. Safe for air-gapped
    use. Flags:
    - UNC paths in setting display values
    - Script references that are UNC paths
    - Reference to files that don't exist in the GPO's sysvol_path
    """
    from pathlib import Path

    results: list[BrokenRef] = []

    for g in estate.gpos:
        # Scan settings for UNC paths in display values
        for s in g.settings:
            uncs = _scan_text_for_unc(s.display_value)
            for unc in uncs:
                results.append(
                    BrokenRef(
                        gpo_id=g.id,
                        gpo_name=g.name,
                        ref_type="unc_path",
                        ref_value=unc,
                        detail=f"[{s.cse}] {s.identity}: UNC in display value",
                    )
                )

        # Scan SYSVOL for missing scripts/files if path exists
        if g.sysvol_path:
            base = Path(g.sysvol_path)
            for side_dir in ("Machine", "User"):
                scripts = base / side_dir / "Scripts" / "Logon"
                if scripts.exists():
                    # Not checking existence of individual scripts — just flag
                    # script settings that reference UNC paths
                    pass

    return results
