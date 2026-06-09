"""Tier-1 deterministic queries over an Estate."""

from __future__ import annotations

import re
import sqlite3
import xml.etree.ElementTree as ET
from collections import defaultdict
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from gpo_lens.model import (
        DelegationEntry,
        Estate,
        Gpo,
        Setting,
        Side,
        Som,
        SomLink,
    )

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
# OU-tree / inheritance cross-check
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TopologyDiscrepancy:
    """One inconsistency between ``ou-tree.json`` and ``gp-inheritance.json``."""

    kind: str       # "block_mismatch", "ou_missing_from_soms", "gp_link_parse_failure"
    ou_dn: str
    detail: str


def _extract_gp_link_guids(gp_link: str | None) -> list[str]:
    """Extract canonical GPO GUIDs from a raw gPLink attribute value.

    Format: ``[DN1;flags][DN2;flags]...`` where DN contains ``CN={GUID,...}``.
    """
    if not gp_link:
        return []
    guids: list[str] = []
    import re as _re
    for m in _re.finditer(r"\{([0-9a-fA-F-]{36})\}", gp_link):
        from gpo_lens.normalize import canonical_guid
        try:
            guids.append(canonical_guid(m.group(0)))
        except ValueError:
            pass
    return guids


def topology_crosscheck(estate: Estate) -> list[TopologyDiscrepancy]:
    """Cross-check ``ou_tree`` against the platform-resolved ``soms``.

    Detects:
    - ``block_mismatch`` — OU has ``gPOptions=1`` (block inheritance) but the
      matching SOM doesn't show ``GpoInheritanceBlocked``, or vice versa.
    - ``ou_missing_from_soms`` — OU in ``ou_tree`` not found in ``soms``
      (collector gap).
    """
    results: list[TopologyDiscrepancy] = []
    som_by_dn: dict[str, Som] = {s.path.lower(): s for s in estate.soms}

    for ou in estate.ou_tree:
        dn_lower = ou.dn.lower()
        som = som_by_dn.get(dn_lower)
        if som is None:
            if ou.gp_link:
                results.append(TopologyDiscrepancy(
                    kind="ou_missing_from_soms",
                    ou_dn=ou.dn,
                    detail="OU has gPLink but no matching SOM in gp-inheritance.json",
                ))
            continue

        raw_blocked = ou.gp_options == 1
        resolved_blocked = som.inheritance_blocked
        if raw_blocked != resolved_blocked:
            results.append(TopologyDiscrepancy(
                kind="block_mismatch",
                ou_dn=ou.dn,
                detail=(
                    f"ou-tree gPOptions={ou.gp_options} (blocked={raw_blocked}) "
                    f"vs gp-inheritance blocked={resolved_blocked}"
                ),
            ))

    return results


# ---------------------------------------------------------------------------
# Snapshot diff
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SnapshotDiff:
    """Structured diff between two estate snapshots."""

    gpos_added: list[str]
    gpos_removed: list[str]
    settings_changed: list[str]          # gpo_ids with setting diffs
    links_changed: list[str]             # gpo_ids with link diffs
    delegation_changed: list[str]        # gpo_ids with delegation diffs
    version_skew_changed: list[str]      # gpo_ids where version skew appeared/disappeared


@dataclass(frozen=True)
class EstateSummary:
    """One-command estate health overview."""

    domain: str
    gpo_count: int
    som_count: int
    wmi_filter_count: int
    unlinked_count: int
    empty_count: int
    disabled_but_populated_count: int
    conflict_count: int
    blocked_extension_count: int
    version_skew_count: int
    ms16_072_vulnerable_count: int
    cpassword_hit_count: int
    loopback_gpo_count: int
    wmi_filtered_gpo_count: int
    enforced_link_count: int
    dangling_link_count: int
    broken_ref_count: int
    total_settings: int
    total_delegation_entries: int


def snapshot_diff(
    conn: sqlite3.Connection, snap_a: int, snap_b: int
) -> SnapshotDiff:
    """Compute the diff between two snapshots."""

    def _load_gpo_ids(snap_id: int) -> set[str]:
        return set(
            row[0] for row in
            conn.execute(
                "SELECT id FROM gpo WHERE snapshot_id = ?", (snap_id,)
            ).fetchall()
        )

    a_ids = _load_gpo_ids(snap_a)
    b_ids = _load_gpo_ids(snap_b)

    added = sorted(b_ids - a_ids)
    removed = sorted(a_ids - b_ids)
    common = a_ids & b_ids

    settings_changed: list[str] = []
    links_changed: list[str] = []
    delegation_changed: list[str] = []
    version_skew_changed: list[str] = []

    for gpo_id in sorted(common):
        # Settings diff
        old_s = set(
            conn.execute(
                "SELECT cse, identity, display_value FROM setting "
                "WHERE snapshot_id = ? AND gpo_id = ?",
                (snap_a, gpo_id),
            ).fetchall()
        )
        new_s = set(
            conn.execute(
                "SELECT cse, identity, display_value FROM setting "
                "WHERE snapshot_id = ? AND gpo_id = ?",
                (snap_b, gpo_id),
            ).fetchall()
        )
        if old_s != new_s:
            settings_changed.append(gpo_id)

        # Links diff
        old_l = set(
            conn.execute(
                "SELECT som_path, link_enabled, enforced FROM gpo_link "
                "WHERE snapshot_id = ? AND gpo_id = ?",
                (snap_a, gpo_id),
            ).fetchall()
        )
        new_l = set(
            conn.execute(
                "SELECT som_path, link_enabled, enforced FROM gpo_link "
                "WHERE snapshot_id = ? AND gpo_id = ?",
                (snap_b, gpo_id),
            ).fetchall()
        )
        if old_l != new_l:
            links_changed.append(gpo_id)

        # Delegation diff
        old_d = set(
            conn.execute(
                "SELECT trustee, permission, allowed FROM delegation "
                "WHERE snapshot_id = ? AND gpo_id = ?",
                (snap_a, gpo_id),
            ).fetchall()
        )
        new_d = set(
            conn.execute(
                "SELECT trustee, permission, allowed FROM delegation "
                "WHERE snapshot_id = ? AND gpo_id = ?",
                (snap_b, gpo_id),
            ).fetchall()
        )
        if old_d != new_d:
            delegation_changed.append(gpo_id)

        # Version skew diff (appeared or disappeared)
        old_v = conn.execute(
            "SELECT computer_ver_ds, computer_ver_sysvol, user_ver_ds, user_ver_sysvol "
            "FROM gpo WHERE snapshot_id = ? AND id = ?",
            (snap_a, gpo_id),
        ).fetchone()
        new_v = conn.execute(
            "SELECT computer_ver_ds, computer_ver_sysvol, user_ver_ds, user_ver_sysvol "
            "FROM gpo WHERE snapshot_id = ? AND id = ?",
            (snap_b, gpo_id),
        ).fetchone()
        if old_v and new_v:
            old_skew = (old_v[0] != old_v[1]) or (old_v[2] != old_v[3])
            new_skew = (new_v[0] != new_v[1]) or (new_v[2] != new_v[3])
            if old_skew != new_skew:
                version_skew_changed.append(gpo_id)

    return SnapshotDiff(
        gpos_added=added,
        gpos_removed=removed,
        settings_changed=settings_changed,
        links_changed=links_changed,
        delegation_changed=delegation_changed,
        version_skew_changed=version_skew_changed,
    )


def estate_summary(estate: Estate) -> EstateSummary:
    """One-command estate health overview."""
    return EstateSummary(
        domain=estate.domain,
        gpo_count=len(estate.gpos),
        som_count=len(estate.soms),
        wmi_filter_count=len(estate.wmi_filters),
        unlinked_count=len(unlinked_gpos(estate)),
        empty_count=len(empty_gpos(estate)),
        disabled_but_populated_count=len(disabled_but_populated(estate)),
        conflict_count=len(conflicts(estate)),
        blocked_extension_count=len(blocked_extensions(estate)),
        version_skew_count=len(version_skew(estate)),
        ms16_072_vulnerable_count=len(ms16_072_vulnerable(estate)),
        cpassword_hit_count=len(cpassword_scan(estate)),
        loopback_gpo_count=len(loopback_gpos(estate)),
        wmi_filtered_gpo_count=len(wmi_filtered_gpos(estate)),
        enforced_link_count=len(enforced_links(estate)),
        dangling_link_count=len(dangling_links(estate)),
        broken_ref_count=len(broken_refs(estate)),
        total_settings=sum(len(g.settings) for g in estate.gpos),
        total_delegation_entries=sum(len(g.delegation) for g in estate.gpos),
    )


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


@dataclass(frozen=True)
class BrokenRef:
    """One detected broken or suspicious reference."""

    gpo_id: str
    gpo_name: str
    ref_type: str          # "unc_path", "missing_script", "script_unc"
    ref_value: str
    detail: str


def _scan_text_for_unc(text: str) -> list[str]:
    """Find UNC paths in a string."""
    return re.findall(r"\\\\[^\s\"'<>|]+", text)


def _raw_strings(raw: dict[str, object]) -> list[str]:
    """Recursively extract all string values from a raw dict."""
    out: list[str] = []
    for v in raw.values():
        if isinstance(v, str):
            out.append(v)
        elif isinstance(v, list):
            for item in v:
                if isinstance(item, str):
                    out.append(item)
                elif isinstance(item, dict):
                    out.extend(_raw_strings(item))
        elif isinstance(v, dict):
            out.extend(_raw_strings(v))
    return out


def broken_refs(estate: Estate) -> list[BrokenRef]:
    """Scan settings and SYSVOL for broken-reference patterns.

    This is **detection only** — no reachability probe. Safe for air-gapped
    use. Flags:
    - UNC paths in setting display values and raw dicts
    - Script files referenced in settings that don't exist in the GPO's SYSVOL
    """
    from pathlib import Path

    results: list[BrokenRef] = []
    seen: set[tuple[str, str, str]] = set()

    def _add(ref: BrokenRef) -> None:
        key = (ref.gpo_id, ref.ref_type, ref.ref_value)
        if key not in seen:
            seen.add(key)
            results.append(ref)

    for g in estate.gpos:
        for s in g.settings:
            # 1. UNC paths in display_value
            for unc in _scan_text_for_unc(s.display_value):
                _add(BrokenRef(
                    gpo_id=g.id, gpo_name=g.name,
                    ref_type="unc_path", ref_value=unc,
                    detail=f"[{s.cse}] {s.identity}: UNC in display value",
                ))

            # 2. UNC paths in raw dict values
            for text in _raw_strings(s.raw):
                for unc in _scan_text_for_unc(text):
                    _add(BrokenRef(
                        gpo_id=g.id, gpo_name=g.name,
                        ref_type="unc_path", ref_value=unc,
                        detail=f"[{s.cse}] {s.identity}: UNC in raw data",
                    ))

            # 3. Script references — check if a .bat/.cmd/.ps1/.vbs is mentioned
            #    and verify the file exists in the GPO's SYSVOL Scripts tree
            if g.sysvol_path and s.cse in ("Scripts", "Group Policy Scripts"):
                script_name = s.display_value.strip()
                if script_name and not script_name.startswith("\\\\"):
                    base = Path(g.sysvol_path)
                    candidates = []
                    for side_dir in ("Machine", "User"):
                        candidates.extend([
                            base / side_dir / "Scripts" / script_name,
                            base / side_dir / "Scripts" / "Logon" / script_name,
                            base / side_dir / "Scripts" / "Shutdown" / script_name,
                            base / side_dir / "Scripts" / "Startup" / script_name,
                        ])
                    if not any(c.exists() for c in candidates):
                        _add(BrokenRef(
                            gpo_id=g.id, gpo_name=g.name,
                            ref_type="missing_script", ref_value=script_name,
                            detail=(
                                f"[{s.cse}] {s.side}: "
                                f"script '{script_name}' not found in SYSVOL"
                            ),
                        ))

    return results
