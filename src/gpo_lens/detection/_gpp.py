"""GPP XML walking, structured audits, broken-ref and ILT detection."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING
from xml.etree.ElementTree import Element, ElementTree

import defusedxml.ElementTree as ET

from gpo_lens.model import SettingRaw, Side
from gpo_lens.normalize import child_by_localname as _child_by_localname
from gpo_lens.normalize import localname
from gpo_lens.paths import ci_child, ci_path

if TYPE_CHECKING:
    from gpo_lens.model import Estate, Gpo


@dataclass(frozen=True)
class BrokenRef:
    """One detected broken or suspicious reference."""

    gpo_id: str
    gpo_name: str
    ref_type: str
    ref_value: str
    detail: str


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

_TASK_ELEMENT_NAMES = frozenset({
    "Task", "TaskV2", "ScheduledTask", "ImmediateTask", "ImmediateTaskV2",
})

_localname = localname


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
        # as coverage_gaps by _scan_sysvol_gaps in ingest.load_estate.
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


def _scan_text_for_unc(text: str) -> list[str]:
    return re.findall(r"\\\\[^\s\"'<>|]+", text)


def _raw_strings(raw: dict[str, object] | SettingRaw) -> list[str]:
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


def _props(elem: Element) -> Element | None:
    """Find the first <Properties> child by local name (namespace-tolerant)."""
    for child in elem:
        if _localname(child.tag) == "Properties":
            return child
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
                if _localname(elem.tag) == "Filters":
                    file_has_filters = True
                    for child in elem:
                        gpo_filter_types.add(_localname(child.tag))
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
