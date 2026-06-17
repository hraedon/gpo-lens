"""SQLite-bound snapshot diffing.

These functions operate directly on a raw ``sqlite3.Connection`` produced by
``store.py``; they are separate from the pure-over-``Estate`` queries in
``queries.py`` so the connection boundary is visible at import time.
"""

from __future__ import annotations

import sqlite3
from collections import defaultdict
from dataclasses import dataclass

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

    # Fetch version rows for all common GPOs in one query per snapshot instead
    # of the previous per-GPO N+1 loop.
    def _load_versions(
        snapshot_id: int, gpo_ids: list[str]
    ) -> dict[str, tuple[int | None, int | None, int | None, int | None]]:
        if not gpo_ids:
            return {}
        placeholders = ",".join("?" * len(gpo_ids))
        query = (
            "SELECT id, computer_ver_ds, computer_ver_sysvol, user_ver_ds, user_ver_sysvol "
            f"FROM gpo WHERE snapshot_id = ? AND id IN ({placeholders})"
        )
        return {
            row[0]: row[1:]
            for row in conn.execute(query, (snapshot_id, *gpo_ids))
        }

    versions_a = _load_versions(snap_a, common)
    versions_b = _load_versions(snap_b, common)

    for gpo_id in common:
        old_v = versions_a.get(gpo_id)
        new_v = versions_b.get(gpo_id)
        if not old_v or not new_v:
            continue

        gpo_changes = settings_by_gpo.get(gpo_id, [])
        has_setting_changes = bool(gpo_changes)

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
        "wmi_filter, computer_ver_ds, computer_ver_sysvol, "
        "user_ver_ds, user_ver_sysvol "
        "FROM gpo WHERE snapshot_id = ? AND id = ?"
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

        # Version skew — columns 7..10 (already in the meta row)
        old_ds_c, old_sv_c, old_ds_u, old_sv_u = old_row[7], old_row[8], old_row[9], old_row[10]
        new_ds_c, new_sv_c, new_ds_u, new_sv_u = new_row[7], new_row[8], new_row[9], new_row[10]
        old_skew = (old_ds_c != old_sv_c) or (old_ds_u != old_sv_u)
        new_skew = (new_ds_c != new_sv_c) or (new_ds_u != new_sv_u)
        if old_skew != new_skew:
            version_skew_changed.append(gpo_id)

        old_s = set(
            conn.execute(
                "SELECT side, cse, identity, display_value FROM setting "
                "WHERE snapshot_id = ? AND gpo_id = ?",
                (snap_a, gpo_id),
            ).fetchall()
        )
        new_s = set(
            conn.execute(
                "SELECT side, cse, identity, display_value FROM setting "
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
