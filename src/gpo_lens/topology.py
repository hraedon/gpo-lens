"""Topology and scope-aware queries over an Estate.

These functions resolve SOM chains, security filtering, WMI loops, and loopback
state.  They live in a separate module so queries.py can stay focused on
composition, diffing, and estate-wide scans.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import TYPE_CHECKING

from gpo_lens.detection import scan_ilt
from gpo_lens.model import Side

if TYPE_CHECKING:
    from gpo_lens.model import Estate, Gpo, GpoLink, Setting, Som, SomLink

__all__ = [
    "EffectiveGpo",
    "EffectiveScope",
    "EffectiveSetting",
    "SecurityFiltering",
    "SomConflict",
    "WmiFilterScope",
    "effective_scope",
    "is_security_filtered",
    "loopback_awareness",
    "loopback_gpos",
    "precedence_conflicts",
    "scope_caveats",
    "security_filtering_detail",
    "settings_at_som",
    "som_conflicts",
    "som_effective_gpos",
    "wmi_filtered_gpos",
]


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


def som_effective_gpos(
    estate: Estate, som_path: str, *, _som: Som | None = None,
) -> list[EffectiveGpo]:
    """Return the resolved, ordered GPO chain at a given SOM path."""
    names = {g.id: g.name for g in estate.gpos}
    target_som = _som
    if target_som is None:
        for som in estate.soms:
            if som.path.lower() == som_path.lower():
                target_som = som
                break
    if target_som is None:
        return []
    return [
        EffectiveGpo(
            gpo_id=link.gpo_id,
            gpo_name=names.get(link.gpo_id, "<unknown>"),
            order=link.order,
            enabled=link.enabled,
            enforced=link.enforced,
            target=link.target,
        )
        for link in target_som.links
    ]


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
            elif any(lb in val_lower for lb in _LOOPBACK_IDENTITIES):
                results.append((g, s))
    return results


def _extract_loopback_mode(setting: Setting) -> str | None:
    """Return 'merge', 'replace', 'unknown', or None from a loopback setting.

    Returns None when the setting does not actually configure loopback
    (Disabled/Not Configured/empty).  Returns 'unknown' when loopback IS
    configured but the specific mode cannot be determined.
    """
    raw = setting.raw
    if isinstance(raw, dict):
        children_raw = raw.get("children", [])
        if isinstance(children_raw, list):
            for child in children_raw:
                if not isinstance(child, dict):
                    continue
                tag = str(child.get("tag", "")).lower()
                if tag in ("settingboolean", "settingstring", "settingnumber"):
                    text = str(child.get("text") or "").strip().lower()
                    if text in ("replace", "1"):
                        return "replace"
                    if text in ("merge", "2"):
                        return "merge"
                    # Numeric 0 = Not Configured
                    if text == "0":
                        return None
    val = setting.display_value.strip().lower()
    if "replace" in val:
        return "replace"
    if "merge" in val:
        return "merge"
    if not val or val in ("not configured", "disabled"):
        return None
    return "unknown"


def loopback_awareness(estate: Estate) -> dict[str, str]:
    """Map GPO id -> loopback mode for GPOs that configure loopback.

    Every GPO that sets loopback will appear in the result.  Mode will be
    'merge', 'replace', 'mixed', or 'unknown' (never None / never absent).
    GPOs where loopback is not actually configured (Disabled/Not Configured)
    are excluded.
    """
    results: dict[str, str] = {}
    for g, s in loopback_gpos(estate):
        mode = _extract_loopback_mode(s)
        if mode is None:
            continue
        existing = results.get(g.id)
        if existing is None:
            results[g.id] = mode
        elif existing != mode:
            results[g.id] = "mixed"
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


def _find_som(estate: Estate, som_path: str) -> Som | None:
    """Case-insensitive SOM lookup by path, or None if absent."""
    for som in estate.soms:
        if som.path.lower() == som_path.lower():
            return som
    return None


def _resolve_som_chain(
    estate: Estate, som_path: str
) -> tuple[list[SomLink], dict[str, Gpo], dict[str, str]] | None:
    """Find a SOM and return (enabled_chain, gpo_by_id, names) or None.

    Returns None both when the SOM does not exist and when it exists but has
    no enabled links. Callers that need to tell those apart should use
    ``_find_som`` directly (see ``scope_caveats``).
    """
    target_som = _find_som(estate, som_path)
    if target_som is None:
        return None
    chain = [link for link in target_som.links if link.enabled]
    if not chain:
        return None
    gpo_by_id = {g.id: g for g in estate.gpos}
    names = {g.id: g.name for g in estate.gpos}
    return chain, gpo_by_id, names


@dataclass(frozen=True)
class _BucketEntry:
    """One setting occurrence folded into a SOM-chain bucket."""

    gpo_id: str
    gpo_name: str
    value: str
    display_name: str
    link_order: int
    enforced: bool


def _fold_chain_to_buckets(
    estate: Estate, som_path: str,
) -> dict[tuple[str, Side, str], list[_BucketEntry]] | None:
    """Resolve the SOM chain and build per-setting-identity buckets.

    Returns ``None`` when the SOM does not exist or has no enabled links.
    """
    resolved = _resolve_som_chain(estate, som_path)
    if resolved is None:
        return None
    chain, gpo_by_id, names = resolved

    buckets: dict[tuple[str, Side, str], list[_BucketEntry]] = defaultdict(list)
    for link in chain:
        gpo = gpo_by_id.get(link.gpo_id)
        if gpo is None:
            continue
        gpo_name = names.get(link.gpo_id, "<unknown>")
        for s in gpo.settings:
            key = (s.cse, s.side, s.identity)
            buckets[key].append(_BucketEntry(
                gpo_id=link.gpo_id,
                gpo_name=gpo_name,
                value=s.display_value,
                display_name=s.display_name,
                link_order=link.order,
                enforced=link.enforced,
            ))
    return dict(buckets)


def som_conflicts(estate: Estate, som_path: str) -> list[SomConflict]:
    """Settings that appear in the SOM chain with differing values."""
    buckets = _fold_chain_to_buckets(estate, som_path)
    if buckets is None:
        return []

    results: list[SomConflict] = []
    for (cse, side, identity), entries in buckets.items():
        gpo_names = {e.gpo_name for e in entries}
        values = {e.value for e in entries}
        if len(gpo_names) < 2 or len(values) < 2:
            continue
        winner_entry = max(entries, key=lambda e: e.link_order)
        winner = winner_entry.gpo_name
        conflict_entries: list[tuple[str, str, str]] = []
        for e in entries:
            status = "winner" if e.gpo_name == winner else "overridden"
            conflict_entries.append((e.gpo_name, e.value, status))
        display_name = next(
            (e.display_name for e in entries if e.display_name), ""
        )

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
    """Estate-wide precedence conflict summary (OU/domain SOMs only).

    Site SOMs are a parallel scoping axis whose per-machine application is not
    resolved here, so they are excluded from the OU-precedence view.
    """
    results: list[tuple[Som, list[SomConflict]]] = []
    for som in estate.soms:
        if som.links and som.container_type != "site":
            conflicts_ = som_conflicts(estate, som.path)
            if conflicts_:
                results.append((som, conflicts_))
    return results


# ---------------------------------------------------------------------------
# AD site links (parallel scoping axis — flagged, not resolved per-machine)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SiteGpoLink:
    """One GPO linked at an AD site."""

    gpo_id: str
    gpo_name: str
    enabled: bool
    enforced: bool
    order: int


@dataclass(frozen=True)
class SiteScope:
    """An AD site and its direct GPO links."""

    name: str
    dn: str
    links: list[SiteGpoLink]


def site_scopes(estate: Estate) -> list[SiteScope]:
    """All AD sites with their direct GPO links, resolved to GPO names."""
    names = {g.id: g.name for g in estate.gpos}
    out: list[SiteScope] = []
    for som in estate.soms:
        if som.container_type != "site":
            continue
        links = [
            SiteGpoLink(
                gpo_id=link.gpo_id,
                gpo_name=names.get(link.gpo_id, link.gpo_id),
                enabled=link.enabled,
                enforced=link.enforced,
                order=link.order,
            )
            for link in sorted(som.links, key=lambda link: link.order)
        ]
        out.append(SiteScope(name=som.name, dn=som.path, links=links))
    return out


def has_site_links(estate: Estate) -> bool:
    """True if any AD site carries at least one *enabled* GPO link."""
    return any(
        link.enabled
        for som in estate.soms
        if som.container_type == "site"
        for link in som.links
    )


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
    buckets = _fold_chain_to_buckets(estate, som_path)
    if buckets is None:
        return []

    results: list[EffectiveSetting] = []
    for (cse, side, identity), entries in buckets.items():
        winner_entry = max(entries, key=lambda e: e.link_order)

        overridden: list[tuple[str, str]] = []
        for e in entries:
            if e.link_order < winner_entry.link_order:
                overridden.append((e.gpo_name, e.value))

        results.append(
            EffectiveSetting(
                cse=cse,
                side=side,
                identity=identity,
                display_name=winner_entry.display_name,
                display_value=winner_entry.value,
                winner_gpo_id=winner_entry.gpo_id,
                winner_gpo_name=winner_entry.gpo_name,
                overridden_by=overridden,
                enforced=winner_entry.enforced,
            )
        )

    results.sort(key=lambda es: (es.cse, es.side, es.identity.lower()))
    return results


# ---------------------------------------------------------------------------
# Scope honesty — effective scope, security filtering, WMI analysis, ILT
# ---------------------------------------------------------------------------

_BROAD_TRUSTEES = {"authenticated users", "domain computers", "everyone"}
_AU_SID = "s-1-5-11"
_EVERYONE_SID = "s-1-1-0"
_DC_SID_SUFFIX = "-515"


def _broad_key(trustee: str, sid: str | None) -> str | None:
    """Canonical key for a broad-application trustee, or None.

    Collapses name and SID forms of Authenticated Users, Domain Computers,
    and Everyone to a single key so allow/deny ACEs on the same trustee can
    be paired for deny-precedence evaluation.
    """
    t = trustee.lower().strip()
    s = (sid or "").lower().strip()
    if t == "authenticated users" or s == _AU_SID:
        return "authenticated_users"
    if t == "domain computers" or s.endswith(_DC_SID_SUFFIX):
        return "domain_computers"
    if t == "everyone" or s == _EVERYONE_SID:
        return "everyone"
    return None


def _grants_read_or_apply(permission: str) -> bool:
    """True if the permission label conveys Read or Apply Group Policy."""
    p = permission.lower().strip()
    return "read" in p or "apply" in p


@dataclass(frozen=True)
class SecurityFiltering:
    """Security-filtering state for a GPO."""

    is_filtered: bool
    apply_trustees: list[str]
    has_au_read: bool
    has_dc_read: bool


@dataclass(frozen=True)
class WmiFilterScope:
    """WMI filter attached to a GPO (or broken reference)."""

    name: str
    query: str
    is_broken: bool


@dataclass(frozen=True)
class EffectiveScope:
    """The composed scoping view for a single GPO."""

    gpo_id: str
    gpo_name: str
    domain: str
    computer_enabled: bool
    user_enabled: bool
    links: list[GpoLink]
    security_filtering: SecurityFiltering
    wmi_filter: WmiFilterScope | None
    loopback_mode: str | None
    caveats: list[str]


def is_security_filtered(gpo: Gpo) -> bool:
    """True if the GPO's audience appears narrowed away from broad application.

    A broad trustee is Authenticated Users, Domain Computers, or Everyone
    (matched by name or SID). The GPO is considered *not* filtered when at
    least one broad trustee holds an *allow* Read / Apply Group Policy ACE
    that is not overridden by a *deny* on that same trustee.

    Honest-by-charter semantics (this flags; it does not simulate AD ACL
    evaluation):

    - **Deny precedence.** Windows evaluates deny ACEs before allow. A broad
      trustee whose allow is countered by a deny Read/Apply on the same
      trustee does not count as broad application.
    - **No delegation data → not filtered.** With an empty delegation list we
      return ``False``: absence of data is not evidence of filtering, and
      real AD inherits a default DACL granting Authenticated Users Read+Apply.
      Returning ``True`` here would be a confident false positive.

    Not modeled (deliberately): nested group membership, default/inherited
    ACEs not present on the GPO, and cross-trustee set relationships (e.g.
    that a deny on Everyone also blocks Authenticated Users).
    """
    if not gpo.delegation:
        return False
    allowed: set[str] = set()
    denied: set[str] = set()
    for entry in gpo.delegation:
        key = _broad_key(entry.trustee, entry.trustee_sid)
        if key is None or not _grants_read_or_apply(entry.permission):
            continue
        (allowed if entry.allowed else denied).add(key)
    applies_broadly = any(key not in denied for key in allowed)
    return not applies_broadly


def security_filtering_detail(gpo: Gpo) -> SecurityFiltering:
    """Detailed security-filtering breakdown for a GPO."""
    apply_trustees: list[str] = []
    has_au_read = False
    has_dc_read = False
    for entry in gpo.delegation:
        if not entry.allowed:
            continue
        trustee_lower = entry.trustee.lower().strip()
        sid_lower = (entry.trustee_sid or "").lower().strip()
        perm_lower = entry.permission.lower().strip()
        if (
            "read" in perm_lower
            or "apply" in perm_lower
            or "grouppolicy" in perm_lower.replace(" ", "")
        ):
            if trustee_lower == "authenticated users" or sid_lower == _AU_SID:
                has_au_read = True
            if trustee_lower == "domain computers" or sid_lower.endswith(_DC_SID_SUFFIX):
                has_dc_read = True
        if "apply" in perm_lower or "grouppolicy" in perm_lower.replace(" ", ""):
            if entry.trustee not in apply_trustees:
                apply_trustees.append(entry.trustee)
    return SecurityFiltering(
        is_filtered=is_security_filtered(gpo),
        apply_trustees=apply_trustees,
        has_au_read=has_au_read,
        has_dc_read=has_dc_read,
    )


def _wmi_filter_scope(gpo: Gpo, estate: Estate) -> WmiFilterScope | None:
    if not gpo.wmi_filter:
        return None
    known = {f.name: f for f in estate.wmi_filters}
    wf = known.get(gpo.wmi_filter)
    if wf:
        return WmiFilterScope(name=wf.name, query=wf.query, is_broken=False)
    return WmiFilterScope(name=gpo.wmi_filter, query="", is_broken=True)


def scope_caveats(estate: Estate, som_path: str) -> list[str]:
    """Scoping caveats for all GPOs in scope at a SOM path.

    Composes security-filtering, WMI, ILT, and loopback caveats.
    """
    resolved = _resolve_som_chain(estate, som_path)
    if resolved is None:
        # A missing SOM yields no caveats, but a SOM that exists with every
        # link disabled is a real (and easily-missed) state worth flagging —
        # not silence.
        som = _find_som(estate, som_path)
        if som is not None and som.links and not any(
            link.enabled for link in som.links
        ):
            return [
                f"  {som_path}: all {len(som.links)} GPO link(s) at this SOM are "
                f"disabled — no GPO settings apply here"
            ]
        return []
    chain, gpo_by_id, _names = resolved
    gpo_ids = {link.gpo_id for link in chain if link.enabled}

    caveats: list[str] = []
    loopback_map = loopback_awareness(estate)
    ilt_gpos = {hit.gpo_id for hit in scan_ilt(estate)}

    for gid in sorted(gpo_ids):
        gpo = gpo_by_id.get(gid)
        if gpo is None:
            continue
        if is_security_filtered(gpo):
            caveats.append(
                f"  {gpo.name}: appears security-filtered (no broad allow for "
                f"Authenticated Users / Domain Computers / Everyone; "
                f"nested membership and inherited ACEs not evaluated)"
            )
        if gpo.wmi_filter:
            caveats.append(f"  {gpo.name}: WMI filter attached ({gpo.wmi_filter})")
        if gid in ilt_gpos:
            caveats.append(
                f"  {gpo.name}: item-level targeting (per-object delivery not evaluated)"
            )
        mode = loopback_map.get(gid)
        if mode:
            caveats.append(
                f"  {gpo.name}: loopback={mode} (user settings may be replaced/merged)"
            )

    if has_site_links(estate):
        n_links = sum(
            1
            for som in estate.soms
            if som.container_type == "site"
            for link in som.links
            if link.enabled
        )
        caveats.append(
            f"  AD site links: {n_links} site-linked GPO link(s) apply before this "
            f"domain/OU chain based on the client's AD site (not resolved here; "
            f"see `gpo-lens sites`)"
        )

    return caveats


def effective_scope(estate: Estate, gpo_id_or_name: str) -> EffectiveScope | None:
    """Compose the full scoping view for a single GPO.

    Accepts a canonical GPO id (lowercase, braces stripped) or a GPO name
    (case-insensitive).  Returns ``None`` when not found.
    """
    target: Gpo | None = estate.gpo_by_id(gpo_id_or_name.lower().strip("{}"))
    if target is None:
        needle = gpo_id_or_name.lower().strip()
        for g in estate.gpos:
            if g.name.lower() == needle:
                target = g
                break
    if target is None:
        return None

    caveats: list[str] = []
    sec = security_filtering_detail(target)
    if not target.delegation:
        caveats.append("No delegation entries — security filtering state unknown")
    elif sec.is_filtered:
        trustees = ", ".join(sec.apply_trustees) if sec.apply_trustees else "(none found)"
        caveats.append(
            f"Security-filtered — explicit Apply Group Policy trustees: {trustees}"
            f" (exclusivity not evaluated; default ACEs and group membership not modeled)"
        )
    elif not sec.has_au_read and not sec.has_dc_read:
        caveats.append("MS16-072: missing Authenticated Users / Domain Computers Read")

    wmi = _wmi_filter_scope(target, estate)
    if wmi:
        if wmi.is_broken:
            caveats.append(f"WMI filter '{wmi.name}' is broken (not found in estate)")
        else:
            caveats.append(f"WMI filter attached: {wmi.name}")

    loopback_map = loopback_awareness(estate)
    mode = loopback_map.get(target.id)
    if mode:
        caveats.append(f"Loopback mode: {mode}")

    ilt_gpos = {hit.gpo_id for hit in scan_ilt(estate)}
    if target.id in ilt_gpos:
        caveats.append("Item-level targeting present (per-object delivery not evaluated)")

    if not target.links:
        caveats.append("GPO has no links (applies nowhere)")

    return EffectiveScope(
        gpo_id=target.id,
        gpo_name=target.name,
        domain=target.domain,
        computer_enabled=target.computer_enabled,
        user_enabled=target.user_enabled,
        links=target.links,
        security_filtering=sec,
        wmi_filter=wmi,
        loopback_mode=mode,
        caveats=caveats,
    )
