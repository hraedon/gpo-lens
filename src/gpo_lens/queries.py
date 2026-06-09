"""Tier-1 deterministic queries over an Estate."""

from __future__ import annotations

import re
import sqlite3
import xml.etree.ElementTree as ET
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Iterable

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


def _walk_gpp_xml(
    gpo: Gpo, *, only_known: bool = False,
) -> Iterable[tuple[ET.ElementTree, Path, Path]]:
    """Yield ``(tree, abs_file, rel_file)`` for each parseable GPP XML file.

    Walks ``Machine/Preferences/`` and ``User/Preferences/`` under the GPO's
    ``sysvol_path``.  When *only_known* is True only files named in
    ``_GPP_XML_FILES`` are visited (used by cpassword scan); otherwise every
    ``*.xml`` file is visited (used by broken-ref scan).
    """
    if not gpo.sysvol_path:
        return
    base = Path(gpo.sysvol_path)
    for side_dir in ("Machine", "User"):
        prefs = base / side_dir / "Preferences"
        if not prefs.exists():
            continue
        if only_known:
            candidates = [prefs / f for f in _GPP_XML_FILES]
        else:
            candidates = sorted(prefs.iterdir())
        for file_path in candidates:
            if not file_path.is_file() or file_path.suffix.lower() != ".xml":
                continue
            try:
                tree = ET.parse(file_path)
            except ET.ParseError:
                continue
            if tree.getroot() is None:
                continue
            yield tree, file_path, file_path.relative_to(base)  # type: ignore[misc]


def _scan_gpo_for_cpassword(gpo: Gpo) -> list[CpasswordHit]:
    """Walk one GPO's SYSVOL Preference XML for lingering cpassword attributes."""
    results: list[CpasswordHit] = []
    for tree, _abs, rel in _walk_gpp_xml(gpo, only_known=True):
        root = tree.getroot()
        if root is None:
            continue
        for elem in root.iter():
            cpw = elem.get("cpassword")
            if cpw is not None:
                tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
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
# ADMX gap detection
# ---------------------------------------------------------------------------

_ADMX_REGISTRY_PREFIXES = (
    "software\\",
    "hklm\\",
    "hkcu\\",
    "hkcr\\",
    "hku\\",
    "hkcc\\",
    "hkey_",
    "system\\",
    "policies\\",
    "microsoft\\",
    "windows\\",
    "control set",
    "currentversion",
)


@dataclass(frozen=True)
class AdmxGap:
    """A Registry CSE setting where no ADMX policy name was resolved.

    The identity is a raw registry key path instead of a policy name,
    meaning the GPO is applying a preference-style registry setting
    without a corresponding ADMX template.
    """

    gpo_id: str
    gpo_name: str
    side: Side
    identity: str
    display_name: str
    key_path: str
    value_name: str


def _is_raw_registry_path(identity: str, display_name: str) -> bool:
    """Heuristic: identity/display_name looks like a raw registry path.

    Matches common hive abbreviations (HKLM, HKCU, HKCR, HKU, HKCC),
    full hive names (HKEY_*), and well-known subkey stems when the
    identity uses backslash-separated path segments (not colon-separated
    ADMX-style identifiers).
    """
    id_lower = identity.lower()
    if any(id_lower.startswith(p) for p in _ADMX_REGISTRY_PREFIXES):
        return True
    dn_lower = display_name.lower()
    if any(dn_lower.startswith(p) for p in _ADMX_REGISTRY_PREFIXES):
        return True
    if "\\" in identity and any(p in id_lower for p in _ADMX_REGISTRY_PREFIXES):
        return True
    return False


def admx_gaps(estate: Estate) -> list[AdmxGap]:
    """Flag Registry CSE settings where no ADMX policy name was resolved.

    These are settings applied via GPP Registry or raw registry preferences
    rather than through an ADMX policy definition. The identity will be a
    raw key path (e.g. ``HKLM\\Software\\...``) instead of a policy GUID/name.
    """
    results: list[AdmxGap] = []
    for g in estate.gpos:
        for s in g.settings:
            if s.cse not in ("Registry", "Windows Registry"):
                continue
            if s.source_state == "blocked":
                continue
            if not _is_raw_registry_path(s.identity, s.display_name):
                continue
            parts = s.identity.split(":", 1)
            key_path = parts[0] if parts else s.identity
            value_name = parts[1] if len(parts) > 1 else s.display_name
            results.append(AdmxGap(
                gpo_id=g.id, gpo_name=g.name,
                side=s.side, identity=s.identity,
                display_name=s.display_name,
                key_path=key_path, value_name=value_name,
            ))
    return results


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
    ref_type: str          # "unc_path", "missing_script", "script_unc",
                           # "scheduled_task_path", "drive_mapping_unc",
                           # "gpp_file_ref", "service_path"
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


def _extract_xml_attr(elem: ET.Element, *attrs: str) -> str | None:
    for a in attrs:
        v = elem.get(a)
        if v and v.strip():
            return v.strip()
    return None


_GPP_PATH_ATTRS: dict[str, tuple[str, ...]] = {
    "ScheduledTask": ("appPath", "exePath", "Path", "Arguments"),
    "Task": ("appPath", "exePath", "Path", "Arguments"),
    "ImmediateTask": ("appPath", "exePath", "Path", "Arguments"),
    "Drive": ("Path",),
    "File": ("fromPath", "toPath", "targetPath", "SourcePath", "DestinationPath"),
    "Service": ("serviceName",),
    "DataSource": ("dsn", "dsnTarget"),
}


def _scan_gpp_xml_for_refs(gpo: Gpo) -> list[BrokenRef]:
    """Walk GPP Preference XML for file/path/service references."""
    results: list[BrokenRef] = []
    for tree, _abs, rel_file in _walk_gpp_xml(gpo, only_known=False):
        root = tree.getroot()
        if root is None:
            continue
        for elem in root.iter():
            tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
            path_attrs = _GPP_PATH_ATTRS.get(tag)
            if path_attrs is None:
                continue
            for attr in path_attrs:
                val = elem.get(attr)
                if not val or not val.strip():
                    continue
                val = val.strip()
                for unc in _scan_text_for_unc(val):
                    results.append(BrokenRef(
                        gpo_id=gpo.id, gpo_name=gpo.name,
                        ref_type="gpp_file_ref", ref_value=unc,
                        detail=f"GPP {rel_file} <{tag} @{attr}>: UNC path",
                    ))
            exe_val = _extract_xml_attr(elem, "appPath", "exePath", "Path")
            if exe_val and tag in ("ScheduledTask", "Task", "ImmediateTask"):
                if exe_val and not exe_val.startswith("\\\\") and not exe_val.startswith("%"):
                    results.append(BrokenRef(
                        gpo_id=gpo.id, gpo_name=gpo.name,
                        ref_type="scheduled_task_path", ref_value=exe_val,
                        detail=f"GPP {rel_file} <{tag}>: executable path '{exe_val}'",
                    ))
    return results


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
    """Flat export of all settings, optionally filtered.

    Filters are case-insensitive substring matches on the respective field.
    """
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
    """Compare estate settings against a baseline.

    For each baseline setting, finds matching estate settings by
    ``(cse, identity)`` (case-insensitive).  Reports:
    - ``compliant`` — estate has the expected value
    - ``drift`` — estate has a different value
    - ``missing`` — estate does not apply this setting at all

    Also reports ``extra`` for estate settings not in the baseline
    (informational — not necessarily wrong).

    Uses the ADMX crosswalk to annotate Registry CSE settings with
    their policy names when available.
    """
    from gpo_lens.admx_parser import PolicyDefinitions as _PD

    if admx is None:
        admx = _PD()

    # Build baseline lookup: (cse_lower, identity_lower) -> BaselineSetting
    baseline_keys: dict[tuple[str, str], BaselineSetting] = {}
    for bs in baseline:
        key = (bs.cse.lower(), bs.identity.lower())
        if key not in baseline_keys:
            baseline_keys[key] = bs

    # Build estate lookup: (cse_lower, identity_lower) -> list of (gpo_id, value)
    estate_settings: dict[tuple[str, str], list[tuple[str, str]]] = {}
    for g in estate.gpos:
        for s in g.settings:
            if s.source_state == "blocked":
                continue
            key = (s.cse.lower(), s.identity.lower())
            estate_settings.setdefault(key, []).append((g.id, s.display_value))

    results: list[BaselineDiffEntry] = []

    # Check each baseline setting
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
            # Check if any actual matches the expected value
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
                # Use the first actual value for the report
                results.append(BaselineDiffEntry(
                    status="drift", side=bs.side, cse=bs.cse,
                    identity=bs.identity, display_name=bs.display_name,
                    expected_value=bs.expected_value,
                    actual_value=actuals[0][1],
                    gpo_id=gpo_ids, admx_name=admx_name,
                ))

    # Check for extra settings not in baseline
    baseline_identity_set = {(bs.cse.lower(), bs.identity.lower()) for bs in baseline}
    for (cse, ident), entries in estate_settings.items():
        if (cse, ident) not in baseline_identity_set:
            # Find display_name from the first estate setting
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
    """Run all hygiene checks and return prioritized findings.

    Categories and severities:
    - critical: cpassword hits (MS14-025 — lingering GPP secrets)
    - high:     MS16-072 vulnerable (missing AU/DC read — silent non-apply)
    - medium:   version_skew, dangling_links, topology discrepancies
    - low:      disabled_but_populated, broken_refs, admx_gaps
    - info:     unlinked, empty, enforced_links
    """
    findings: list[DoctorFinding] = []

    # Critical — cpassword
    for hit in cpassword_scan(estate):
        findings.append(DoctorFinding(
            severity="critical",
            category="cpassword",
            gpo_id=hit.gpo_id,
            gpo_name=hit.gpo_name,
            summary=f"cpassword in {hit.file} <{hit.tag}> (MS14-025)",
            detail=f"Encrypted password found: {_mask_cpassword(hit.cpassword)}",
        ))

    # High — MS16-072
    for g in ms16_072_vulnerable(estate):
        findings.append(DoctorFinding(
            severity="high",
            category="ms16_072",
            gpo_id=g.id,
            gpo_name=g.name,
            summary="Missing Authenticated Users / Domain Computers Read (MS16-072)",
            detail="GPO may silently stop applying after MS16-072 patch",
        ))

    # Medium — version skew
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

    # Medium — dangling links
    for som, link in dangling_links(estate):
        findings.append(DoctorFinding(
            severity="medium",
            category="dangling_link",
            gpo_id=link.gpo_id,
            gpo_name="<missing>",
            summary=f"Dangling link at {som.name}",
            detail=f"SOM {som.path} links to missing GPO {link.gpo_id}",
        ))

    # Medium — topology discrepancies
    for d in topology_crosscheck(estate):
        findings.append(DoctorFinding(
            severity="medium",
            category="topology_discrepancy",
            gpo_id="",
            gpo_name="",
            summary=f"{d.kind}: {d.ou_dn}",
            detail=d.detail,
        ))

    # Low — disabled but populated
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

    # Low — broken refs
    for ref in broken_refs(estate):
        findings.append(DoctorFinding(
            severity="low",
            category=f"broken_ref:{ref.ref_type}",
            gpo_id=ref.gpo_id,
            gpo_name=ref.gpo_name,
            summary=ref.detail,
            detail=ref.ref_value,
        ))

    # Low — ADMX gaps
    for gap in admx_gaps(estate):
        findings.append(DoctorFinding(
            severity="low",
            category="admx_gap",
            gpo_id=gap.gpo_id,
            gpo_name=gap.gpo_name,
            summary=f"Raw registry key (no ADMX): {gap.key_path}",
            detail=f"{gap.side}/{gap.identity}",
        ))

    # Info — unlinked
    for g in unlinked_gpos(estate):
        findings.append(DoctorFinding(
            severity="info",
            category="unlinked",
            gpo_id=g.id,
            gpo_name=g.name,
            summary="GPO has no links (applies nowhere)",
            detail="",
        ))

    # Info — empty
    for g in empty_gpos(estate):
        findings.append(DoctorFinding(
            severity="info",
            category="empty",
            gpo_id=g.id,
            gpo_name=g.name,
            summary="GPO has no settings on either side",
            detail="",
        ))

    # Info — enforced links
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


def _mask_cpassword(cpw: str) -> str:
    if len(cpw) <= 4:
        return "****"
    return cpw[:4] + "****"


def broken_refs(estate: Estate) -> list[BrokenRef]:
    """Scan settings and SYSVOL for broken-reference patterns.

    This is **detection only** — no reachability probe. Safe for air-gapped
    use. Flags:
    - UNC paths in setting display values and raw dicts
    - Script files referenced in settings that don't exist in the GPO's SYSVOL
    - Drive mapping UNC patterns
    - Scheduled task executable paths
    - GPP XML file/path/service references
    """
    from pathlib import Path

    results: list[BrokenRef] = []
    seen: dict[tuple[str, str], int] = {}  # key -> index in results

    # Detail richness: higher = more specific source info.
    _REF_TYPE_RANK: dict[str, int] = {
        "gpp_file_ref": 3,
        "missing_script": 3,
        "scheduled_task_path": 2,
        "drive_mapping_unc": 1,
        "unc_path": 0,
    }

    def _add(ref: BrokenRef) -> None:
        key = (ref.gpo_id, ref.ref_value)
        idx = seen.get(key)
        if idx is None:
            seen[key] = len(results)
            results.append(ref)
        else:
            existing = results[idx]
            if _REF_TYPE_RANK.get(ref.ref_type, -1) > _REF_TYPE_RANK.get(existing.ref_type, -1):
                results[idx] = ref

    for g in estate.gpos:
        # 0. GPP XML-level scanning
        for ref in _scan_gpp_xml_for_refs(g):
            _add(ref)

        for s in g.settings:
            # 1. UNC paths in display_value
            for unc in _scan_text_for_unc(s.display_value):
                ref_type = "unc_path"
                if s.cse in ("Printers", "Drives", "Drive Maps"):
                    ref_type = "drive_mapping_unc"
                _add(BrokenRef(
                    gpo_id=g.id, gpo_name=g.name,
                    ref_type=ref_type, ref_value=unc,
                    detail=f"[{s.cse}] {s.identity}: UNC in display value",
                ))

            # 2. UNC paths in raw dict values
            for text in _raw_strings(s.raw):
                for unc in _scan_text_for_unc(text):
                    ref_type = "unc_path"
                    if s.cse in ("Printers", "Drives", "Drive Maps"):
                        ref_type = "drive_mapping_unc"
                    _add(BrokenRef(
                        gpo_id=g.id, gpo_name=g.name,
                        ref_type=ref_type, ref_value=unc,
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

            # 4. Scheduled task executable paths from settings
            if s.cse in ("Scheduled Tasks",):
                exe = s.display_value.strip()
                if exe and not exe.startswith("\\\\") and not exe.startswith("%"):
                    _add(BrokenRef(
                        gpo_id=g.id, gpo_name=g.name,
                        ref_type="scheduled_task_path", ref_value=exe,
                        detail=f"[{s.cse}] {s.identity}: task path '{exe}'",
                    ))

    return results
