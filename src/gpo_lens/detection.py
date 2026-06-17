"""Scanner functions — pure detection logic that scans an Estate for issues."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Iterable
from xml.etree.ElementTree import Element, ElementTree

import defusedxml.ElementTree as ET

from gpo_lens.authz import (
    MS16_072_TRUSTEES,
    broad_trustee_key,
    is_deny_ace_type,
    parse_sddl,
    parse_sddl_rights,
)
from gpo_lens.model import (
    DenyAce,
    ExcessiveWriter,
    SddlAce,
    SddlAcl,
    Side,
)
from gpo_lens.paths import ci_child, ci_path

if TYPE_CHECKING:
    from gpo_lens.admx_parser import PolicyDefinitions
    from gpo_lens.model import (
        DelegationEntry,
        Estate,
        Gpo,
        Som,
        SomLink,
    )

__all__ = [
    "AdmxGap",
    "BrokenRef",
    "CpasswordHit",
    "DenyAce",
    "ExcessiveWriter",
    "LocalGroupMod",
    "ScheduledTaskInfo",
    "SddlAce",
    "SddlAcl",
    "admx_gaps",
    "broken_refs",
    "cpassword_scan",
    "dangling_links",
    "deny_aces",
    "excessive_writers",
    "has_ms16_072_read",
    "local_group_mods",
    "mask_cpassword",
    "parse_sddl",
    "scan_ilt",
    "scan_local_groups",
    "scan_scheduled_tasks",
    "scheduled_tasks",
    "disabled_but_populated",
    "empty_gpos",
    "enforced_links",
    "ms16_072_vulnerable",
    "unlinked_gpos",
    "version_skew",
]


@dataclass(frozen=True)
class CpasswordHit:
    """One ``cpassword`` attribute found in a GPP XML file."""

    gpo_id: str
    gpo_name: str
    file: str
    tag: str
    cpassword: str


@dataclass(frozen=True)
class BrokenRef:
    """One detected broken or suspicious reference."""

    gpo_id: str
    gpo_name: str
    ref_type: str
    ref_value: str
    detail: str


@dataclass(frozen=True)
class AdmxGap:
    """A Registry CSE setting where no ADMX policy name was resolved."""

    gpo_id: str
    gpo_name: str
    side: Side
    identity: str
    display_name: str
    key_path: str
    value_name: str


@dataclass(frozen=True)
class ScheduledTaskInfo:
    """One scheduled task / immediate task deployed by a GPP ScheduledTasks.xml."""

    gpo_id: str
    gpo_name: str
    side: Side              # "Computer" (Machine) or "User"
    file: str               # rel file path within SYSVOL
    kind: str               # element local name: "Task", "ImmediateTaskV2", ...
    name: str               # task name attribute
    action: str             # CREATE / REPLACE / UPDATE / DELETE
    command: str            # executable path (appName / Path)
    arguments: str
    run_as: str             # run-as account, if specified


@dataclass(frozen=True)
class LocalGroupMod:
    """One local-group membership modification from LocalUsersAndGroups.xml."""

    gpo_id: str
    gpo_name: str
    side: Side
    file: str
    group_name: str                 # target local group, e.g. "Administrators"
    group_sid: str                  # e.g. S-1-5-32-544
    members_added: tuple[str, ...]
    members_removed: tuple[str, ...]


@dataclass(frozen=True)
class _GppXmlFile:
    side: Side
    cse: str
    tree: ElementTree
    rel_file: Path


_GPP_XML_FILES = (
    "Groups.xml", "Services.xml", "Drives.xml", "ScheduledTasks.xml",
    "DataSources.xml", "Printers.xml", "Folders.xml", "Files.xml",
    "Registry.xml", "Environment.xml", "Shortcuts.xml", "InternetSettings.xml",
    "Regional.xml", "PowerOptions.xml", "NetworkShares.xml",
    "LocalUsersAndGroups.xml", "EventLogs.xml",
)

_SIDE_MAP: dict[str, Side] = {"Machine": "Computer", "User": "User"}

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

_GPP_PATH_ATTRS: dict[str, tuple[str, ...]] = {
    "ScheduledTask": ("appPath", "exePath", "Path", "Arguments"),
    "Task": ("appPath", "exePath", "Path", "Arguments"),
    "ImmediateTask": ("appPath", "exePath", "Path", "Arguments"),
    "Drive": ("Path", "path"),
    "File": ("fromPath", "toPath", "targetPath", "SourcePath", "DestinationPath"),
    "Service": ("serviceName",),
    "DataSource": ("dsn", "dsnTarget"),
    "SharedPrinter": ("path", "port"),
    "Printer": ("path", "port"),
    "LocalPrinter": ("path", "port"),
}


def _walk_gpp_xml(
    gpo: Gpo, *, only_known: bool = False,
) -> Iterable[_GppXmlFile]:
    """Yield normalized ``(side, cse, tree, rel_file)`` for parseable GPP XML."""
    if not gpo.sysvol_path:
        return
    base = Path(gpo.sysvol_path)
    known_lower = {f.lower() for f in _GPP_XML_FILES}
    for side_dir in ("Machine", "User"):
        # Side/Preferences casing varies on a real SYSVOL (e.g. the default GPOs
        # use MACHINE/USER); resolve case-insensitively for a Linux analysis host.
        side = ci_child(base, side_dir)
        side_out = _SIDE_MAP[side_dir]
        if side is None:
            continue
        prefs = ci_child(side, "Preferences")
        if prefs is None:
            continue
        # On a real SYSVOL each GPP CSE lives in its own subfolder
        # (Preferences/Groups/Groups.xml); some hand-built exports flatten them
        # (Preferences/Groups.xml). Collect XML from both shapes, one level deep.
        # Per-entry try/except keeps one unreadable subtree (a security-filtered
        # GPO copied with ACLs intact, or an extraction that dropped a dir's
        # traversal bit) from aborting the scan. Unreadable dirs are surfaced
        # as coverage_gaps by _scan_sysvol_coverage in ingest.load_estate.
        try:
            entries = sorted(prefs.iterdir())
        except OSError:
            continue
        candidates: list[Path] = []
        for entry in entries:
            try:
                if entry.is_dir():
                    candidates.extend(
                        sorted(c for c in entry.iterdir() if c.is_file())
                    )
                elif entry.is_file():
                    candidates.append(entry)
            except OSError:
                continue
        # Deduplicate by filename (case-insensitive). A mixed-layout export may
        # carry BOTH Preferences/Groups.xml (flat) AND Preferences/Groups/
        # Groups.xml (nested) — yielding both would double-count findings.
        # Prefer the nested path (more components = canonical SYSVOL shape).
        by_name: dict[str, Path] = {}
        for fp in candidates:
            key = fp.name.lower()
            prev = by_name.get(key)
            if prev is None or len(fp.parts) > len(prev.parts):
                by_name[key] = fp
        for file_path in by_name.values():
            if file_path.suffix.lower() != ".xml":
                continue
            if only_known and file_path.name.lower() not in known_lower:
                continue
            try:
                tree = ET.parse(file_path)
            except (ET.ParseError, OSError):
                continue
            if tree.getroot() is None:
                continue
            yield _GppXmlFile(
                side=side_out,
                cse=file_path.stem,
                tree=tree,
                rel_file=file_path.relative_to(base),
            )


def _scan_gpo_for_cpassword(gpo: Gpo) -> list[CpasswordHit]:
    results: list[CpasswordHit] = []
    for walk in _walk_gpp_xml(gpo, only_known=True):
        root = walk.tree.getroot()
        if root is None:
            continue
        for elem in root.iter():
            cpw = elem.get("cpassword")
            if cpw is not None:
                tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
                results.append(CpasswordHit(
                    gpo_id=gpo.id, gpo_name=gpo.name,
                    file=str(walk.rel_file), tag=tag, cpassword=cpw,
                ))
    return results


_READ_IMPLYING_PERMISSIONS = frozenset({
    "read",
    "edit settings",
    "edit settings, delete, modify security",
    "full control",
})


def _has_ms16_072_read(delegation: list[DelegationEntry]) -> bool:
    return any(
        e.allowed
        and broad_trustee_key(e.trustee, e.trustee_sid, MS16_072_TRUSTEES) is not None
        and e.permission.strip().lower() in _READ_IMPLYING_PERMISSIONS
        for e in delegation
    )


# Public API aliases
has_ms16_072_read = _has_ms16_072_read


def _is_raw_registry_path(identity: str, display_name: str) -> bool:
    id_lower = identity.lower()
    if any(id_lower.startswith(p) for p in _ADMX_REGISTRY_PREFIXES):
        return True
    dn_lower = display_name.lower()
    if any(dn_lower.startswith(p) for p in _ADMX_REGISTRY_PREFIXES):
        return True
    if "\\" in identity and any(p in id_lower for p in _ADMX_REGISTRY_PREFIXES):
        return True
    return False


def _scan_text_for_unc(text: str) -> list[str]:
    return re.findall(r"\\\\[^\s\"'<>|]+", text)


def _raw_strings(raw: dict[str, object]) -> list[str]:
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


def _extract_xml_attr(elem: Element, *attrs: str) -> str | None:
    for a in attrs:
        v = elem.get(a)
        if v and v.strip():
            return v.strip()
    return None


def _scan_gpp_xml_for_refs(gpo: Gpo) -> list[BrokenRef]:
    results: list[BrokenRef] = []
    for walk in _walk_gpp_xml(gpo, only_known=False):
        root = walk.tree.getroot()
        if root is None:
            continue
        rel_file = walk.rel_file
        for elem in root.iter():
            tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
            path_attrs = _GPP_PATH_ATTRS.get(tag)
            if path_attrs is None:
                continue
            # Check the element's own attributes AND its <Properties> child.
            # Real GPP XML puts path-like attributes on <Properties>, not on
            # the parent element (e.g. <Drive><Properties path="\\srv\share"/>
            # </Drive>), so scanning only the outer element misses them.
            check_elems: list[tuple[Element, str]] = [(elem, tag)]
            props = _props(elem)
            if props is not None:
                check_elems.append((props, f"{tag}/Properties"))
            for src_elem, src_tag in check_elems:
                for attr in path_attrs:
                    val = src_elem.get(attr)
                    if not val or not val.strip():
                        continue
                    val = val.strip()
                    for unc in _scan_text_for_unc(val):
                        cse_lower = walk.cse.lower()
                        ref_type = (
                            "drive_mapping_unc"
                            if cse_lower in ("drives", "printers")
                            else "gpp_file_ref"
                        )
                        results.append(BrokenRef(
                            gpo_id=gpo.id, gpo_name=gpo.name,
                            ref_type=ref_type, ref_value=unc,
                            detail=f"GPP {rel_file} <{src_tag} @{attr}>: UNC path",
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


# ---------------------------------------------------------------------------
# Structured GPP audits — ScheduledTasks and LocalUsersAndGroups
# ---------------------------------------------------------------------------

_TASK_ELEMENT_NAMES = frozenset({
    "Task", "TaskV2", "ScheduledTask", "ImmediateTask", "ImmediateTaskV2",
})


def _localname(tag: str) -> str:
    return tag.split("}", 1)[-1] if "}" in tag else tag


def _props(elem: Element) -> Element | None:
    """Find the first <Properties> child by local name (namespace-tolerant)."""
    for child in elem:
        if _localname(child.tag) == "Properties":
            return child
    return None


def _child_by_localname(parent: Element, name: str) -> Element | None:
    for child in parent:
        if _localname(child.tag) == name:
            return child
    return None


def scan_scheduled_tasks(gpo: Gpo) -> list[ScheduledTaskInfo]:
    """Structured inventory of every scheduled task deployed by this GPO.

    Walks ``Machine``/``User`` ``Preferences/ScheduledTasks.xml``. One
    :class:`ScheduledTaskInfo` per ``<Task>``/``<ImmediateTaskV2>`` element.
    Read-only; surfaces what is configured, does not evaluate reachability.
    """
    results: list[ScheduledTaskInfo] = []
    for walk in _walk_gpp_xml(gpo, only_known=True):
        if walk.cse.lower() != "scheduledtasks":
            continue
        root = walk.tree.getroot()
        if root is None:
            continue
        # GPP task elements are direct children of <ScheduledTasks>. Iterating all
        # descendants would also match the nested <Task> wrapper inside an
        # ImmediateTaskV2's <Properties>, emitting a spurious empty row.
        for elem in root:
            ln = _localname(elem.tag)
            if ln not in _TASK_ELEMENT_NAMES:
                continue
            props = _props(elem)
            command = ""
            arguments = ""
            action = ""
            run_as = ""
            if props is not None:
                command = _extract_xml_attr(props, "appName", "Path", "exePath") or ""
                arguments = props.get("arguments", "") or ""
                action = props.get("action", "") or ""
                run_as = (
                    _extract_xml_attr(props, "runAs")
                    or elem.get("runAs", "")
                    or ""
                )
                # V2 tasks store command/arguments/runAs in nested Task XML.
                is_v2 = ln.endswith("V2")
                if (not command or not arguments) and is_v2:
                    task = _child_by_localname(props, "Task")
                    if task is not None:
                        actions = _child_by_localname(task, "Actions")
                        if actions is not None:
                            # A task may define multiple <Exec> actions; we
                            # report the first with a non-empty Command.
                            exec_elem = _child_by_localname(actions, "Exec")
                            if exec_elem is not None:
                                if not command:
                                    cmd_elem = _child_by_localname(exec_elem, "Command")
                                    if cmd_elem is not None and cmd_elem.text:
                                        command = cmd_elem.text.strip()
                                if not arguments:
                                    arg_elem = _child_by_localname(exec_elem, "Arguments")
                                    if arg_elem is not None and arg_elem.text:
                                        arguments = arg_elem.text.strip()
                        if not run_as:
                            principals = _child_by_localname(task, "Principals")
                            if principals is not None:
                                principal = _child_by_localname(principals, "Principal")
                                if principal is not None:
                                    user_id = _child_by_localname(principal, "UserId")
                                    if user_id is not None and user_id.text:
                                        run_as = user_id.text.strip()
            else:
                run_as = elem.get("runAs", "") or ""
            results.append(ScheduledTaskInfo(
                gpo_id=gpo.id,
                gpo_name=gpo.name,
                side=walk.side,
                file=str(walk.rel_file),
                kind=ln,
                name=elem.get("name", "") or "",
                action=action,
                command=command,
                arguments=arguments,
                run_as=run_as,
            ))
    return results


def scan_local_groups(gpo: Gpo) -> list[LocalGroupMod]:
    """Structured inventory of local-group membership changes by this GPO.

    Walks ``Machine``/``User`` ``Preferences/LocalUsersAndGroups.xml``.
    One :class:`LocalGroupMod` per ``<Group>`` element. ``<User>`` account
    definitions are not reported here (they have no membership delta).
    Read-only.
    """
    results: list[LocalGroupMod] = []
    for walk in _walk_gpp_xml(gpo, only_known=True):
        # GPP stores group membership in Groups.xml; some tooling emits a
        # separate LocalUsersAndGroups.xml. Scan both.
        if walk.cse.lower() not in ("groups", "localusersandgroups"):
            continue
        root = walk.tree.getroot()
        if root is None:
            continue
        for elem in root.iter():
            if _localname(elem.tag) != "Group":
                continue
            props = _props(elem)
            group_name = ""
            group_sid = ""
            if props is not None:
                group_name = props.get("groupName", "") or props.get("name", "") or ""
                group_sid = props.get("groupSid", "") or ""
            added: list[str] = []
            removed: list[str] = []
            for member in elem.iter():
                if _localname(member.tag) != "Member":
                    continue
                m_name = member.get("name", "") or ""
                m_action = (member.get("action", "") or "").upper()
                if not m_name:
                    continue
                if m_action == "REMOVE":
                    if m_name not in removed:
                        removed.append(m_name)
                else:
                    if m_name not in added:
                        added.append(m_name)
            results.append(LocalGroupMod(
                gpo_id=gpo.id,
                gpo_name=gpo.name,
                side=walk.side,
                file=str(walk.rel_file),
                group_name=group_name,
                group_sid=group_sid,
                members_added=tuple(added),
                members_removed=tuple(removed),
            ))
    return results


def scheduled_tasks(estate: Estate) -> list[ScheduledTaskInfo]:
    """Estate-wide roll-up of :func:`scan_scheduled_tasks`, sorted for determinism."""
    out: list[ScheduledTaskInfo] = []
    for g in estate.gpos:
        out.extend(scan_scheduled_tasks(g))
    out.sort(key=lambda t: (t.gpo_id, t.side, t.name.lower(), t.kind))
    return out


def local_group_mods(estate: Estate) -> list[LocalGroupMod]:
    """Estate-wide roll-up of :func:`scan_local_groups`, sorted for determinism."""
    out: list[LocalGroupMod] = []
    for g in estate.gpos:
        out.extend(scan_local_groups(g))
    out.sort(key=lambda m: (m.gpo_id, m.side, m.group_name.lower()))
    return out


def unlinked_gpos(estate: Estate) -> list[Gpo]:
    """GPOs with no links.  These apply nowhere."""
    return [g for g in estate.gpos if not g.links]


def empty_gpos(estate: Estate) -> list[Gpo]:
    """GPOs with no readable settings on either side.

    Per ``docs/spec/wi_queries.md`` AC-02, a GPO with only ``<Blocked/>``
    extensions (and therefore source_state="blocked" settings) counts as
    empty.  Blocked extensions are still surfaced separately by
    ``blocked_extensions``.
    """
    return [g for g in estate.gpos if not any(s.source_state != "blocked" for s in g.settings)]


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


def version_skew(estate: Estate) -> list[tuple[Gpo, Side]]:
    """GPOs where GPC (AD) and GPT (SYSVOL) version numbers differ."""
    results: list[tuple[Gpo, Side]] = []
    for g in estate.gpos:
        if g.computer_version_skew:
            results.append((g, "Computer"))
        if g.user_version_skew:
            results.append((g, "User"))
    return results


def ms16_072_vulnerable(estate: Estate) -> list[Gpo]:
    """GPOs missing Read for Authenticated Users or Domain Computers (MS16-072)."""
    return [g for g in estate.gpos if not _has_ms16_072_read(g.delegation)]


def cpassword_scan(estate: Estate) -> list[CpasswordHit]:
    """Scan SYSVOL GPP XML for lingering ``cpassword`` attributes (MS14-025)."""
    results: list[CpasswordHit] = []
    for g in estate.gpos:
        results.extend(_scan_gpo_for_cpassword(g))
    return results


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


def admx_gaps(
    estate: Estate,
    admx: PolicyDefinitions | None = None,
) -> list[AdmxGap]:
    """Flag Registry CSE settings where no ADMX policy name was resolved."""
    results: list[AdmxGap] = []
    for g in estate.gpos:
        for s in g.settings:
            if s.cse not in ("Registry", "Windows Registry"):
                continue
            if s.source_state == "blocked":
                continue
            if not _is_raw_registry_path(s.identity, s.display_name):
                continue
            if admx is not None and admx.resolve_display_name(s.identity):
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


def _mask_cpassword(cpw: str) -> str:
    if len(cpw) <= 4:
        return "****"
    return cpw[:4] + "****"


# Public API alias
mask_cpassword = _mask_cpassword


def broken_refs(estate: Estate) -> list[BrokenRef]:
    """Scan settings and SYSVOL for broken-reference patterns."""
    results: list[BrokenRef] = []
    seen: dict[tuple[str, str], int] = {}

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
        for ref in _scan_gpp_xml_for_refs(g):
            _add(ref)

        for s in g.settings:
            for unc in _scan_text_for_unc(s.display_value):
                ref_type = "unc_path"
                if s.cse in ("Printers", "Drives", "Drive Maps"):
                    ref_type = "drive_mapping_unc"
                _add(BrokenRef(
                    gpo_id=g.id, gpo_name=g.name,
                    ref_type=ref_type, ref_value=unc,
                    detail=f"[{s.cse}] {s.identity}: UNC in display value",
                ))

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

            if g.sysvol_path and s.cse in ("Scripts", "Group Policy Scripts"):
                script_name = s.display_value.strip()
                if script_name and not script_name.startswith("\\\\"):
                    base = Path(g.sysvol_path)
                    # Resolve case-insensitively (real SYSVOL casing varies) and
                    # tolerate unreadable subtrees — a false "missing" here would
                    # be a spurious finding.
                    found_script = any(
                        ci_path(base, side_dir, "Scripts", *sub, script_name) is not None
                        for side_dir in ("Machine", "User")
                        for sub in ((), ("Logon",), ("Shutdown",), ("Startup",))
                    )
                    if not found_script:
                        _add(BrokenRef(
                            gpo_id=g.id, gpo_name=g.name,
                            ref_type="missing_script", ref_value=script_name,
                            detail=(
                                f"[{s.cse}] {s.side}: "
                                f"script '{script_name}' not found in SYSVOL"
                            ),
                        ))

            if s.cse in ("Scheduled Tasks",):
                exe = s.display_value.strip()
                if exe and not exe.startswith("\\\\") and not exe.startswith("%"):
                    _add(BrokenRef(
                        gpo_id=g.id, gpo_name=g.name,
                        ref_type="scheduled_task_path", ref_value=exe,
                        detail=f"[{s.cse}] {s.identity}: task path '{exe}'",
                    ))

    return results


_WRITE_RIGHTS = {"GA", "GW", "WD", "WO", "SD", "DT", "WP", "DC", "CC"}


def _is_domain_admins_sid(sid: str) -> bool:
    sid_lower = sid.lower()
    if sid_lower == "s-1-5-32-544":
        return True
    if not sid_lower.startswith("s-1-5-21-"):
        return False
    parts = sid_lower.split("-")
    if len(parts) >= 5 and parts[-1] == "512":
        return True
    if len(parts) >= 5 and parts[-1] == "519":
        return True
    return False


def _is_default_writer_sid(sid: str) -> bool:
    sid_lower = sid.lower()
    if sid_lower == "s-1-5-18":
        return True
    return _is_domain_admins_sid(sid_lower)


def _has_write_right(rights: str) -> bool:
    return any(r in _WRITE_RIGHTS for r in parse_sddl_rights(rights))


def deny_aces(estate: Estate) -> list[DenyAce]:
    """Scan GPO SDDL strings for deny ACEs."""
    results: list[DenyAce] = []
    for g in estate.gpos:
        if not g.sddl:
            continue
        acl = parse_sddl(g.sddl)
        for ace in acl.dacl:
            if is_deny_ace_type(ace.ace_type):
                results.append(DenyAce(
                    gpo_id=g.id,
                    gpo_name=g.name,
                    trustee_sid=ace.trustee_sid,
                    rights=ace.rights,
                    flags=ace.flags,
                    acl_section="dacl",
                ))
        for ace in acl.sacl:
            if is_deny_ace_type(ace.ace_type):
                results.append(DenyAce(
                    gpo_id=g.id,
                    gpo_name=g.name,
                    trustee_sid=ace.trustee_sid,
                    rights=ace.rights,
                    flags=ace.flags,
                    acl_section="sacl",
                ))
    return results


def excessive_writers(
    estate: Estate,
    threshold: int = 5,
) -> list[ExcessiveWriter]:
    """Find trustees with write access to >= *threshold* GPOs.

    Default writers (Domain Admins S-1-5-21-*-512, Enterprise Admins
    S-1-5-21-*-519, LocalSystem S-1-5-18, BUILTIN\\Administrators
    S-1-5-32-544) are excluded from the report.
    """
    writer_map: dict[str, dict[str, set[str]]] = {}
    for g in estate.gpos:
        if not g.sddl:
            continue
        acl = parse_sddl(g.sddl)
        for ace in acl.dacl:
            if ace.ace_type != "allow":
                continue
            if not _has_write_right(ace.rights):
                continue
            sid = ace.trustee_sid
            if not sid:
                continue
            entry = writer_map.setdefault(sid, {})
            gpo_entry = entry.setdefault(g.id, set())
            for r in parse_sddl_rights(ace.rights):
                if r in _WRITE_RIGHTS:
                    gpo_entry.add(r)

    results: list[ExcessiveWriter] = []
    for sid, gpo_rights in sorted(writer_map.items()):
        if _is_default_writer_sid(sid):
            continue
        if len(gpo_rights) < threshold:
            continue
        all_rights: set[str] = set()
        for rights_set in gpo_rights.values():
            all_rights |= rights_set
        results.append(ExcessiveWriter(
            trustee_sid=sid,
            gpo_count=len(gpo_rights),
            gpo_names=tuple(
                sorted(
                    g.name
                    for gid_ in gpo_rights
                    for g in estate.gpos
                    if g.id == gid_
                )
            ),
            rights=tuple(sorted(all_rights)),
        ))

    results.sort(key=lambda w: w.gpo_count, reverse=True)
    return results


# ---------------------------------------------------------------------------
# GPP item-level targeting (ILT) detection
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class IltHit:
    """One GPO carrying item-level targeting (``<Filters>``) in its GPP XML.

    Deduplicated to one hit per GPO; ``files`` lists every GPP XML (by
    SYSVOL-relative path, e.g. ``Registry.xml``) that carried a ``<Filters>``
    element, so the finding points at the specific preference file rather than
    the whole SYSVOL tree.
    """

    gpo_id: str
    gpo_name: str
    files: tuple[str, ...]
    filter_types: tuple[str, ...]


def _local_tag(elem: Element) -> str:
    """Strip XML namespace prefix from an element tag."""
    return elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag


def scan_ilt(estate: Estate) -> list[IltHit]:
    """Scan SYSVOL GPP XML for ``<Filters>`` elements (item-level targeting).

    Returns one ``IltHit`` per GPO (deduplicated across files/sides).
    """
    results: list[IltHit] = []
    for gpo in estate.gpos:
        gpo_filter_types: set[str] = set()
        gpo_files: set[str] = set()
        for walk in _walk_gpp_xml(gpo, only_known=False):
            root = walk.tree.getroot()
            if root is None:
                continue
            file_has_filters = False
            for elem in root.iter():
                if _local_tag(elem) == "Filters":
                    file_has_filters = True
                    for child in elem:
                        gpo_filter_types.add(_local_tag(child))
            if file_has_filters:
                gpo_files.add(walk.rel_file.as_posix())
        if gpo_filter_types:
            results.append(IltHit(
                gpo_id=gpo.id,
                gpo_name=gpo.name,
                files=tuple(sorted(gpo_files)),
                filter_types=tuple(sorted(gpo_filter_types)),
            ))
    return results
