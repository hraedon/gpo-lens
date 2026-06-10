"""Deterministic queries over an Estate — composition, Tier 2, and Tier 2.5.

Pure detection/scanner functions live in detection.py; this module
composes them (estate_doctor), adds baseline comparison, snapshot
diffing, topology queries, and conflict detection.
"""

from __future__ import annotations

import sqlite3
from collections import defaultdict
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from gpo_lens.admx_parser import PolicyDefinitions
    from gpo_lens.model import (
        DelegationEntry,
        Estate,
        Gpo,
        Setting,
        Side,
        Som,
        SomLink,
    )

from gpo_lens.detection import (  # noqa: F401, I001
    AdmxGap,
    BrokenRef,
    CpasswordHit,
    admx_gaps,
    broken_refs,
    cpassword_scan,
    dangling_links,
    disabled_but_populated,
    empty_gpos,
    enforced_links,
    ms16_072_vulnerable,
    unlinked_gpos,
    version_skew,
)

from gpo_lens.detection import _has_ms16_072_read, _mask_cpassword

__all__ = [
    "AdmxGap",
    "BaselineDiffEntry",
    "BaselineSetting",
    "BrokenRef",
    "CpasswordHit",
    "ChangelogEntry",
    "Conflict",
    "DelegationAudit",
    "DoctorFinding",
    "EffectiveGpo",
    "EffectiveSetting",
    "EstateSummary",
    "GpoMetadataChange",
    "SearchResult",
    "SettingsDumpRow",
    "SnapshotDiff",
    "SnapshotSettingChange",
    "SomConflict",
    "TopologyDiscrepancy",
    "VersionChangeLog",
    "admx_gaps",
    "baseline_diff",
    "blocked_extensions",
    "broken_refs",
    "conflicts",
    "cpassword_scan",
    "dangling_links",
    "delegation_deep_dive",
    "disabled_but_populated",
    "empty_gpos",
    "enforced_links",
    "estate_doctor",
    "estate_summary",
    "load_baseline_from_estate",
    "loopback_awareness",
    "loopback_gpos",
    "ms16_072_vulnerable",
    "permissions_audit",
    "precedence_conflicts",
    "search",
    "settings_at_som",
    "settings_dump",
    "snapshot_changelog",
    "snapshot_diff",
    "snapshot_settings_diff",
    "som_conflicts",
    "som_effective_gpos",
    "topology_crosscheck",
    "unlinked_gpos",
    "version_skew",
    "who_sets",
    "wmi_filtered_gpos",
]


@dataclass(frozen=True)
class Conflict:
    """Settings sharing ``(cse, side, identity)`` across GPOs with differing values."""

    cse: str
    side: Side
    identity: str
    display_name: str
    entries: list[tuple[str, str]]  # (gpo_id, display_value)


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
# Security / hygiene helpers (used by permissions_audit, delegation_deep_dive)
# ---------------------------------------------------------------------------

_DEFAULT_WRITERS = {"domain admins", "enterprise admins", "system"}


def _is_default_writer(trustee: str) -> bool:
    return trustee.strip().lower() in _DEFAULT_WRITERS


@dataclass(frozen=True)
class DelegationAudit:
    """Deep-dive delegation analysis."""

    privilege_rollup: dict[str, list[str]]  # trustee -> GPO names with edit rights
    orphaned_sids: list[tuple[Gpo, str]]    # (Gpo, orphaned_sid)
    broad_writers: list[tuple[Gpo, DelegationEntry]]  # non-default editor with write


def delegation_deep_dive(estate: Estate) -> DelegationAudit:
    """Estate-wide delegation audit."""
    rollup: dict[str, list[str]] = {}
    orphaned: list[tuple[Gpo, str]] = []
    broad: list[tuple[Gpo, DelegationEntry]] = []

    for g in estate.gpos:
        for d in g.delegation:
            if not d.allowed:
                continue
            if (not d.trustee or d.trustee.strip() == "") and d.trustee_sid:
                orphaned.append((g, d.trustee_sid))

            if "write" in d.permission.lower() or "edit" in d.permission.lower():
                trustee_name = d.trustee.strip()
                rollup.setdefault(trustee_name, []).append(g.name)
                if not _is_default_writer(trustee_name):
                    broad.append((g, d))

    return DelegationAudit(
        privilege_rollup=rollup,
        orphaned_sids=orphaned,
        broad_writers=broad,
    )


def permissions_audit(estate: Estate) -> list[tuple[Gpo, str]]:
    """Audit delegation for common security issues."""
    issues: list[tuple[Gpo, str]] = []
    for g in estate.gpos:
        if not _has_ms16_072_read(g.delegation):
            issues.append((g, "No Authenticated Users / Domain Computers Read (MS16-072)"))

        writers = [d for d in g.delegation if d.allowed and "write" in d.permission.lower()]
        if len(writers) > 3:
            issues.append((g, f"{len(writers)} principals have write/modify permissions"))

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
        if scope in ("all", "names") and term_lower in g.name.lower():
            results.append(SearchResult(
                gpo_id=g.id, gpo_name=g.name,
                match_field="gpo_name", detail=g.name,
            ))

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

        if scope in ("all", "delegation"):
            for d in g.delegation:
                if term_lower in d.trustee.lower() or term_lower in d.permission.lower():
                    results.append(SearchResult(
                        gpo_id=g.id, gpo_name=g.name,
                        match_field="delegation",
                        detail=f"{d.trustee}: {d.permission} (allowed={d.allowed})",
                    ))
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


# ---------------------------------------------------------------------------
# OU-tree / inheritance cross-check
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TopologyDiscrepancy:
    """One inconsistency between ``ou-tree.json`` and ``gp-inheritance.json``."""

    kind: str       # "block_mismatch", "ou_missing_from_soms", "gp_link_parse_failure"
    ou_dn: str
    detail: str


def topology_crosscheck(estate: Estate) -> list[TopologyDiscrepancy]:
    """Cross-check ``ou_tree`` against the platform-resolved ``soms``."""
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
class GpoMetadataChange:
    """One metadata field that changed for a GPO between snapshots."""

    gpo_id: str
    field: str       # "name", "computer_enabled", "user_enabled", "wmi_filter",
                      # "owner", "sddl", "domain"
    old_value: str
    new_value: str


@dataclass(frozen=True)
class SnapshotDiff:
    """Structured diff between two estate snapshots."""

    gpos_added: list[str]
    gpos_removed: list[str]
    settings_changed: list[str]
    links_changed: list[str]
    delegation_changed: list[str]
    version_skew_changed: list[str]
    metadata_changes: list[GpoMetadataChange]
    wmi_filter_changes: list[GpoMetadataChange]
    enabled_flips: list[GpoMetadataChange]


@dataclass(frozen=True)
class SnapshotSettingChange:
    """One setting that changed between two snapshots."""

    gpo_id: str
    gpo_name: str
    side: str
    cse: str
    identity: str
    change_type: str  # "added", "removed", "modified"
    old_value: str | None
    new_value: str | None


@dataclass(frozen=True)
class VersionChangeLog:
    """One GPO whose version counters changed between snapshots."""

    gpo_id: str
    gpo_name: str
    side: str       # "Computer" | "User"
    old_ds: int | None
    old_sysvol: int | None
    new_ds: int | None
    new_sysvol: int | None
    edit_count: int | None  # positive delta means edits occurred


@dataclass(frozen=True)
class ChangelogEntry:
    """One line in the version-aware change log."""

    gpo_id: str
    gpo_name: str
    kind: str       # "metadata_only" | "settings_detail"
    side: str | None
    version_change: VersionChangeLog | None
    setting_changes: list[SnapshotSettingChange]
    summary: str


def snapshot_changelog(
    conn: sqlite3.Connection,
    snap_a: int,
    snap_b: int,
) -> list[ChangelogEntry]:
    """Version-aware change log between two snapshots."""
    name_map: dict[str, str] = {}
    for row in conn.execute(
        "SELECT id, name FROM gpo WHERE snapshot_id = ?", (snap_b,)
    ):
        name_map[row[0]] = row[1]
    for row in conn.execute(
        "SELECT id, name FROM gpo WHERE snapshot_id = ?", (snap_a,)
    ):
        name_map.setdefault(row[0], row[1])

    a_ids = {
        row[0] for row in conn.execute(
            "SELECT id FROM gpo WHERE snapshot_id = ?", (snap_a,)
        )
    }
    b_ids = {
        row[0] for row in conn.execute(
            "SELECT id FROM gpo WHERE snapshot_id = ?", (snap_b,)
        )
    }
    common = sorted(a_ids & b_ids)

    all_setting_changes = snapshot_settings_diff(conn, snap_a, snap_b)
    settings_by_gpo: dict[str, list[SnapshotSettingChange]] = defaultdict(list)
    for sc in all_setting_changes:
        settings_by_gpo[sc.gpo_id].append(sc)

    results: list[ChangelogEntry] = []

    _version_query = (
        "SELECT computer_ver_ds, computer_ver_sysvol, user_ver_ds, user_ver_sysvol "
        "FROM gpo WHERE snapshot_id = ? AND id = ?"
    )

    for gpo_id in common:
        old_v = conn.execute(_version_query, (snap_a, gpo_id)).fetchone()
        new_v = conn.execute(_version_query, (snap_b, gpo_id)).fetchone()
        if not old_v or not new_v:
            continue

        gpo_changes = settings_by_gpo.get(gpo_id, [])
        has_setting_changes = bool(gpo_changes)

        sides: list[tuple[str, int, int, int, int]] = []
        for side, ds_idx, sv_idx in (
            ("Computer", 0, 1),
            ("User", 2, 3),
        ):
            old_ds, old_sv = old_v[ds_idx], old_v[sv_idx]
            new_ds, new_sv = new_v[ds_idx], new_v[sv_idx]
            if old_ds != new_ds or old_sv != new_sv:
                edit_count = None
                if isinstance(old_sv, int) and isinstance(new_sv, int):
                    edit_count = new_sv - old_sv
                sides.append((side, old_ds, old_sv, new_ds, new_sv))
                vcl = VersionChangeLog(
                    gpo_id=gpo_id,
                    gpo_name=name_map.get(gpo_id, gpo_id),
                    side=side,
                    old_ds=old_ds,
                    old_sysvol=old_sv,
                    new_ds=new_ds,
                    new_sysvol=new_sv,
                    edit_count=edit_count,
                )
                if has_setting_changes:
                    side_changes = [c for c in gpo_changes if c.side == side]
                    summary = (
                        f"{side} side edited ({edit_count or '?'} edits); "
                        f"{len(side_changes)} setting(s) changed"
                    )
                    results.append(
                        ChangelogEntry(
                            gpo_id=gpo_id,
                            gpo_name=name_map.get(gpo_id, gpo_id),
                            kind="settings_detail",
                            side=side,
                            version_change=vcl,
                            setting_changes=side_changes,
                            summary=summary,
                        )
                    )
                else:
                    summary = (
                        f"{side} side metadata changed ({edit_count or '?'} edits); "
                        f"settings unchanged"
                    )
                    results.append(
                        ChangelogEntry(
                            gpo_id=gpo_id,
                            gpo_name=name_map.get(gpo_id, gpo_id),
                            kind="metadata_only",
                            side=side,
                            version_change=vcl,
                            setting_changes=[],
                            summary=summary,
                        )
                    )

    return results


def snapshot_settings_diff(
    conn: sqlite3.Connection,
    snap_a: int,
    snap_b: int,
    *,
    gpo_id: str | None = None,
    side: str | None = None,
    cse: str | None = None,
) -> list[SnapshotSettingChange]:
    """Per-setting delta between two snapshots."""
    gpo_name_map: dict[str, str] = {}
    for row in conn.execute(
        "SELECT id, name FROM gpo WHERE snapshot_id = ?", (snap_b,)
    ):
        gpo_name_map[row[0]] = row[1]
    for row in conn.execute(
        "SELECT id, name FROM gpo WHERE snapshot_id = ?", (snap_a,)
    ):
        gpo_name_map.setdefault(row[0], row[1])

    constraints_a: list[str] = ["snapshot_id = ?"]
    params_a: list[object] = [snap_a]
    constraints_b: list[str] = ["snapshot_id = ?"]
    params_b: list[object] = [snap_b]
    if gpo_id:
        constraints_a.append("gpo_id = ?")
        params_a.append(gpo_id)
        constraints_b.append("gpo_id = ?")
        params_b.append(gpo_id)
    if side:
        constraints_a.append("side = ?")
        params_a.append(side)
        constraints_b.append("side = ?")
        params_b.append(side)
    if cse:
        constraints_a.append("cse = ?")
        params_a.append(cse)
        constraints_b.append("cse = ?")
        params_b.append(cse)

    where_a = " AND ".join(constraints_a)
    where_b = " AND ".join(constraints_b)

    key_cols = "gpo_id, side, cse, identity"

    old_rows: dict[tuple[str, str, str, str], str] = {}
    for row in conn.execute(
        f"SELECT {key_cols}, display_value FROM setting WHERE {where_a}",
        params_a,
    ):
        old_rows[(row[0], row[1], row[2], row[3])] = row[4]

    new_rows: dict[tuple[str, str, str, str], str] = {}
    for row in conn.execute(
        f"SELECT {key_cols}, display_value FROM setting WHERE {where_b}",
        params_b,
    ):
        new_rows[(row[0], row[1], row[2], row[3])] = row[4]

    results: list[SnapshotSettingChange] = []
    all_keys = set(old_rows) | set(new_rows)

    for key in sorted(all_keys):
        gid, s, c, ident = key
        old_v = old_rows.get(key)
        new_v = new_rows.get(key)
        if old_v is None and new_v is not None:
            results.append(SnapshotSettingChange(
                gpo_id=gid, gpo_name=gpo_name_map.get(gid, gid),
                side=s, cse=c, identity=ident,
                change_type="added", old_value=None, new_value=new_v,
            ))
        elif old_v is not None and new_v is None:
            results.append(SnapshotSettingChange(
                gpo_id=gid, gpo_name=gpo_name_map.get(gid, gid),
                side=s, cse=c, identity=ident,
                change_type="removed", old_value=old_v, new_value=None,
            ))
        elif old_v != new_v:
            results.append(SnapshotSettingChange(
                gpo_id=gid, gpo_name=gpo_name_map.get(gid, gid),
                side=s, cse=c, identity=ident,
                change_type="modified", old_value=old_v, new_value=new_v,
            ))

    return results


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
    admx_gap_count: int
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
    metadata_changes: list[GpoMetadataChange] = []
    wmi_filter_changes: list[GpoMetadataChange] = []
    enabled_flips: list[GpoMetadataChange] = []

    _meta_query = (
        "SELECT name, domain, sddl, owner, computer_enabled, user_enabled, "
        "wmi_filter FROM gpo WHERE snapshot_id = ? AND id = ?"
    )

    for gpo_id in sorted(common):
        old_row = conn.execute(_meta_query, (snap_a, gpo_id)).fetchone()
        new_row = conn.execute(_meta_query, (snap_b, gpo_id)).fetchone()
        if not old_row or not new_row:
            continue

        for col_idx, field_name in enumerate(
            ("name", "domain", "sddl", "owner")
        ):
            old_v = str(old_row[col_idx] or "")
            new_v = str(new_row[col_idx] or "")
            if old_v != new_v:
                metadata_changes.append(GpoMetadataChange(
                    gpo_id=gpo_id, field=field_name,
                    old_value=old_v, new_value=new_v,
                ))

        for col_idx, field_name in enumerate(
            ("computer_enabled", "user_enabled"), start=4
        ):
            old_v = str(bool(old_row[col_idx]))
            new_v = str(bool(new_row[col_idx]))
            if old_v != new_v:
                enabled_flips.append(GpoMetadataChange(
                    gpo_id=gpo_id, field=field_name,
                    old_value=old_v, new_value=new_v,
                ))

        old_wmi = str(old_row[6] or "")
        new_wmi = str(new_row[6] or "")
        if old_wmi != new_wmi:
            wmi_filter_changes.append(GpoMetadataChange(
                gpo_id=gpo_id, field="wmi_filter",
                old_value=old_wmi, new_value=new_wmi,
            ))

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
        metadata_changes=metadata_changes,
        wmi_filter_changes=wmi_filter_changes,
        enabled_flips=enabled_flips,
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
        admx_gap_count=len(admx_gaps(estate)),
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
    """Return the resolved, ordered GPO chain at a given SOM path."""
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


def _extract_loopback_mode(setting: Setting) -> str | None:
    """Return 'merge' or 'replace' from a loopback setting's display_value."""
    val = setting.display_value.strip().lower()
    if "replace" in val:
        return "replace"
    if "merge" in val:
        return "merge"
    return None


def loopback_awareness(estate: Estate) -> dict[str, str]:
    """Map GPO id -> loopback mode for GPOs that configure loopback."""
    results: dict[str, str] = {}
    for g, s in loopback_gpos(estate):
        mode = _extract_loopback_mode(s)
        if mode:
            results[g.id] = mode
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
    """Fold a SOM chain into buckets keyed by (cse, side, identity)."""
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
    """Settings that appear in the SOM chain with differing values."""
    resolved = _resolve_som_chain(estate, som_path)
    if resolved is None:
        return []
    chain, gpo_by_id, _names = resolved
    buckets = _chain_buckets(chain, gpo_by_id)

    results: list[SomConflict] = []
    for (cse, side, identity), entries in buckets.items():
        gpo_names = {e[0] for e in entries}
        values = {e[1] for e in entries}
        if len(gpo_names) < 2 or len(values) < 2:
            continue
        winner_entry = max(entries, key=lambda e: e[2])
        winner = winner_entry[0]
        conflict_entries: list[tuple[str, str, str]] = []
        for gpo_name, value, order in entries:
            status = "winner" if gpo_name == winner else "overridden"
            conflict_entries.append((gpo_name, value, status))
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
    """Estate-wide precedence conflict summary."""
    results: list[tuple[Som, list[SomConflict]]] = []
    for som in estate.soms:
        if som.links:
            conflicts_ = som_conflicts(estate, som.path)
            if conflicts_:
                results.append((som, conflicts_))
    return results


# ---------------------------------------------------------------------------
# SOM Resolution Deep View
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class EffectiveSetting:
    """One setting that applies at a SOM after chain folding."""

    cse: str
    side: Side
    identity: str
    display_name: str
    display_value: str
    winner_gpo_id: str
    winner_gpo_name: str
    overridden_by: list[tuple[str, str]]  # (gpo_name, display_value)
    enforced: bool


def settings_at_som(estate: Estate, som_path: str) -> list[EffectiveSetting]:
    """Return the effective settings that apply at a given SOM path."""
    resolved = _resolve_som_chain(estate, som_path)
    if resolved is None:
        return []
    chain, gpo_by_id, names = resolved

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
        winner_entry = max(entries, key=lambda e: e[3])
        winner_gpo_id, winner_gpo_name, winner_value, _, winner_enforced = winner_entry

        overridden: list[tuple[str, str]] = []
        for gpo_id, gpo_name, value, order, _ in entries:
            if order < winner_entry[3]:
                overridden.append((gpo_name, value))

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

    results.sort(key=lambda es: (es.cse, es.side, es.identity.lower()))
    return results


# ---------------------------------------------------------------------------
# Estate doctor
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DoctorFinding:
    """One prioritized finding from the estate doctor."""

    severity: str       # "critical", "high", "medium", "low", "info"
    category: str       # "cpassword", "ms16_072", "version_skew", etc.
    gpo_id: str
    gpo_name: str
    summary: str
    detail: str


_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass(frozen=True)
class SettingsDumpRow:
    """One row in the flat settings export."""

    gpo_id: str
    gpo_name: str
    side: Side
    cse: str
    identity: str
    display_name: str
    display_value: str
    from_disabled_side: bool


def settings_dump(
    estate: Estate,
    *,
    side: str | None = None,
    cse: str | None = None,
    gpo_name: str | None = None,
) -> list[SettingsDumpRow]:
    """Flat export of all settings, optionally filtered."""
    side_lower = side.lower() if side else None
    cse_lower = cse.lower() if cse else None
    gpo_lower = gpo_name.lower() if gpo_name else None

    results: list[SettingsDumpRow] = []
    for g in estate.gpos:
        if gpo_lower and gpo_lower not in g.name.lower():
            continue
        for s in g.settings:
            if side_lower and side_lower not in s.side.lower():
                continue
            if cse_lower and cse_lower not in s.cse.lower():
                continue
            results.append(SettingsDumpRow(
                gpo_id=g.id, gpo_name=g.name,
                side=s.side, cse=s.cse, identity=s.identity,
                display_name=s.display_name, display_value=s.display_value,
                from_disabled_side=s.from_disabled_side,
            ))
    return results


# ---------------------------------------------------------------------------
# Baseline diff (Tier 2)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class BaselineSetting:
    """One expected setting from a baseline."""

    side: Side
    cse: str
    identity: str
    display_name: str
    expected_value: str


@dataclass(frozen=True)
class BaselineDiffEntry:
    """One finding from a baseline comparison."""

    status: str         # "compliant", "drift", "missing", "extra"
    side: Side
    cse: str
    identity: str
    display_name: str
    expected_value: str
    actual_value: str
    gpo_id: str         # GPO(s) that set this value (comma-separated if multiple)
    admx_name: str      # resolved ADMX policy name (empty if no crosswalk)


def load_baseline_from_estate(estate: Estate) -> list[BaselineSetting]:
    """Extract baseline settings from an estate (typically a single baseline GPO)."""
    results: list[BaselineSetting] = []
    for g in estate.gpos:
        for s in g.settings:
            if s.source_state == "blocked":
                continue
            results.append(BaselineSetting(
                side=s.side, cse=s.cse, identity=s.identity,
                display_name=s.display_name, expected_value=s.display_value,
            ))
    return results


def baseline_diff(
    estate: Estate,
    baseline: list[BaselineSetting],
    admx: PolicyDefinitions | None = None,
) -> list[BaselineDiffEntry]:
    """Compare estate settings against a baseline."""
    from gpo_lens.admx_parser import PolicyDefinitions as _PD

    if admx is None:
        admx = _PD()

    baseline_keys: dict[tuple[str, str], BaselineSetting] = {}
    for bs in baseline:
        key = (bs.cse.lower(), bs.identity.lower())
        if key not in baseline_keys:
            baseline_keys[key] = bs

    estate_settings: dict[tuple[str, str], list[tuple[str, str]]] = {}
    for g in estate.gpos:
        for s in g.settings:
            if s.source_state == "blocked":
                continue
            key = (s.cse.lower(), s.identity.lower())
            estate_settings.setdefault(key, []).append((g.id, s.display_value))

    results: list[BaselineDiffEntry] = []

    for bs in baseline:
        bkey = (bs.cse.lower(), bs.identity.lower())
        actuals = estate_settings.get(bkey, [])
        admx_name = admx.resolve_display_name(bs.identity) or ""

        if not actuals:
            results.append(BaselineDiffEntry(
                status="missing", side=bs.side, cse=bs.cse,
                identity=bs.identity, display_name=bs.display_name,
                expected_value=bs.expected_value, actual_value="",
                gpo_id="", admx_name=admx_name,
            ))
        else:
            values = {v for _, v in actuals}
            gpo_ids = ",".join(sorted(set(gid for gid, _ in actuals)))
            if bs.expected_value in values:
                results.append(BaselineDiffEntry(
                    status="compliant", side=bs.side, cse=bs.cse,
                    identity=bs.identity, display_name=bs.display_name,
                    expected_value=bs.expected_value,
                    actual_value=bs.expected_value,
                    gpo_id=gpo_ids, admx_name=admx_name,
                ))
            else:
                results.append(BaselineDiffEntry(
                    status="drift", side=bs.side, cse=bs.cse,
                    identity=bs.identity, display_name=bs.display_name,
                    expected_value=bs.expected_value,
                    actual_value=actuals[0][1],
                    gpo_id=gpo_ids, admx_name=admx_name,
                ))

    baseline_identity_set = {(bs.cse.lower(), bs.identity.lower()) for bs in baseline}
    for (cse, ident), entries in estate_settings.items():
        if (cse, ident) not in baseline_identity_set:
            display_name = ""
            side = ""
            for g in estate.gpos:
                for s in g.settings:
                    if s.cse.lower() == cse and s.identity.lower() == ident:
                        display_name = s.display_name
                        side = s.side
                        break
                if display_name:
                    break
            gpo_ids = ",".join(sorted(set(gid for gid, _ in entries)))
            admx_name = admx.resolve_display_name(ident) or ""
            results.append(BaselineDiffEntry(
                status="extra", side=side, cse=cse,
                identity=ident, display_name=display_name,
                expected_value="", actual_value=entries[0][1],
                gpo_id=gpo_ids, admx_name=admx_name,
            ))

    results.sort(key=lambda e: (
        {"drift": 0, "missing": 1, "extra": 2, "compliant": 3}[e.status],
        e.cse, e.side, e.identity,
    ))
    return results


def estate_doctor(estate: Estate) -> list[DoctorFinding]:
    """Run all hygiene checks and return prioritized findings."""
    findings: list[DoctorFinding] = []

    for hit in cpassword_scan(estate):
        findings.append(DoctorFinding(
            severity="critical",
            category="cpassword",
            gpo_id=hit.gpo_id,
            gpo_name=hit.gpo_name,
            summary=f"cpassword in {hit.file} <{hit.tag}> (MS14-025)",
            detail=f"Encrypted password found: {_mask_cpassword(hit.cpassword)}",
        ))

    for g in ms16_072_vulnerable(estate):
        findings.append(DoctorFinding(
            severity="high",
            category="ms16_072",
            gpo_id=g.id,
            gpo_name=g.name,
            summary="Missing Authenticated Users / Domain Computers Read (MS16-072)",
            detail="GPO may silently stop applying after MS16-072 patch",
        ))

    for g, side in version_skew(estate):
        findings.append(DoctorFinding(
            severity="medium",
            category="version_skew",
            gpo_id=g.id,
            gpo_name=g.name,
            summary=f"{side} version skew (GPC != GPT)",
            detail=(
                f"DS={getattr(g, f'{side.lower()}_ver_ds', '?')}, "
                f"SYSVOL={getattr(g, f'{side.lower()}_ver_sysvol', '?')}"
            ),
        ))

    for som, link in dangling_links(estate):
        findings.append(DoctorFinding(
            severity="medium",
            category="dangling_link",
            gpo_id=link.gpo_id,
            gpo_name="<missing>",
            summary=f"Dangling link at {som.name}",
            detail=f"SOM {som.path} links to missing GPO {link.gpo_id}",
        ))

    for d in topology_crosscheck(estate):
        findings.append(DoctorFinding(
            severity="medium",
            category="topology_discrepancy",
            gpo_id="",
            gpo_name="",
            summary=f"{d.kind}: {d.ou_dn}",
            detail=d.detail,
        ))

    for g, side in disabled_but_populated(estate):
        findings.append(DoctorFinding(
            severity="low",
            category="disabled_but_populated",
            gpo_id=g.id,
            gpo_name=g.name,
            summary=f"{side} side disabled but has settings",
            detail=(
                f"{sum(1 for s in g.settings if s.side == side)}"
                f" settings on disabled {side} side"
            ),
        ))

    for ref in broken_refs(estate):
        findings.append(DoctorFinding(
            severity="low",
            category=f"broken_ref:{ref.ref_type}",
            gpo_id=ref.gpo_id,
            gpo_name=ref.gpo_name,
            summary=ref.detail,
            detail=ref.ref_value,
        ))

    for gap in admx_gaps(estate):
        findings.append(DoctorFinding(
            severity="low",
            category="admx_gap",
            gpo_id=gap.gpo_id,
            gpo_name=gap.gpo_name,
            summary=f"Raw registry key (no ADMX): {gap.key_path}",
            detail=f"{gap.side}/{gap.identity}",
        ))

    for g in unlinked_gpos(estate):
        findings.append(DoctorFinding(
            severity="info",
            category="unlinked",
            gpo_id=g.id,
            gpo_name=g.name,
            summary="GPO has no links (applies nowhere)",
            detail="",
        ))

    for g in empty_gpos(estate):
        findings.append(DoctorFinding(
            severity="info",
            category="empty",
            gpo_id=g.id,
            gpo_name=g.name,
            summary="GPO has no settings on either side",
            detail="",
        ))

    for som, link in enforced_links(estate):
        findings.append(DoctorFinding(
            severity="info",
            category="enforced_link",
            gpo_id=link.gpo_id,
            gpo_name="",
            summary=f"Enforced link at {som.name} (order {link.order})",
            detail=f"Target: {link.target}",
        ))

    findings.sort(key=lambda f: (_SEVERITY_ORDER.get(f.severity, 99), f.category, f.gpo_id))
    return findings
