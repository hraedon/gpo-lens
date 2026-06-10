"""Scanner functions — pure detection logic that scans an Estate for issues."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Iterable

if TYPE_CHECKING:
    from gpo_lens.admx_parser import PolicyDefinitions
    from gpo_lens.model import (
        DelegationEntry,
        Estate,
        Gpo,
        Side,
        Som,
        SomLink,
    )

__all__ = [
    "AdmxGap",
    "BrokenRef",
    "CpasswordHit",
    "admx_gaps",
    "broken_refs",
    "cpassword_scan",
    "dangling_links",
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


_GPP_XML_FILES = (
    "Groups.xml", "Services.xml", "Drives.xml", "ScheduledTasks.xml",
    "DataSources.xml", "Printers.xml", "Folders.xml", "Files.xml",
    "Registry.xml", "Environment.xml", "Shortcuts.xml", "InternetSettings.xml",
    "Regional.xml", "PowerOptions.xml", "NetworkShares.xml",
    "LocalUsersAndGroups.xml", "EventLogs.xml",
)

_MS16_072_TRUSTEES = {"authenticated users", "domain computers"}

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
    "Drive": ("Path",),
    "File": ("fromPath", "toPath", "targetPath", "SourcePath", "DestinationPath"),
    "Service": ("serviceName",),
    "DataSource": ("dsn", "dsnTarget"),
}


def _walk_gpp_xml(
    gpo: Gpo, *, only_known: bool = False,
) -> Iterable[tuple[ET.ElementTree, Path, Path]]:
    """Yield ``(tree, abs_file, rel_file)`` for each parseable GPP XML file."""
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


def _has_ms16_072_read(delegation: list[DelegationEntry]) -> bool:
    return any(
        e.allowed
        and _trustee_matches_ms16_072(e.trustee, e.trustee_sid)
        and e.permission.lower() == "read"
        for e in delegation
    )


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


def _extract_xml_attr(elem: ET.Element, *attrs: str) -> str | None:
    for a in attrs:
        v = elem.get(a)
        if v and v.strip():
            return v.strip()
    return None


def _scan_gpp_xml_for_refs(gpo: Gpo) -> list[BrokenRef]:
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

            if s.cse in ("Scheduled Tasks",):
                exe = s.display_value.strip()
                if exe and not exe.startswith("\\\\") and not exe.startswith("%"):
                    _add(BrokenRef(
                        gpo_id=g.id, gpo_name=g.name,
                        ref_type="scheduled_task_path", ref_value=exe,
                        detail=f"[{s.cse}] {s.identity}: task path '{exe}'",
                    ))

    return results
