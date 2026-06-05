"""Parse collector outputs into the normalized model."""

from __future__ import annotations

import hashlib
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from gpo_lens.model import (
    DelegationEntry,
    Estate,
    Gpo,
    GpoLink,
    Setting,
    Som,
    SomLink,
)
from gpo_lens.normalize import canonical_guid, load_json, parse_bool, parse_dt, parse_int


def _localname(tag: str) -> str:
    """Strip namespace prefix from an XML tag."""
    return tag.split("}")[-1] if "}" in tag else tag


def _child_by_localname(parent: ET.Element, name: str) -> ET.Element | None:
    """First child whose localname matches ``name``."""
    for child in parent:
        if _localname(child.tag) == name:
            return child
    return None


def _children_by_localname(parent: ET.Element, name: str) -> list[ET.Element]:
    """All children whose localname matches ``name``."""
    return [child for child in parent if _localname(child.tag) == name]


def _text(elem: ET.Element | None) -> str | None:
    """Text content of an element, or None."""
    if elem is None:
        return None
    return elem.text


def element_to_dict(elem: ET.Element) -> dict[str, Any]:
    """Recursively render an element as a lossless dict."""
    result: dict[str, Any] = {"tag": _localname(elem.tag)}
    if elem.text and elem.text.strip():
        result["text"] = elem.text.strip()
    if elem.attrib:
        result["@attr"] = {k: v for k, v in elem.attrib.items()}
    children = [element_to_dict(child) for child in elem]
    if children:
        result["children"] = children
    return result


def _stable_hash(raw: dict[str, Any]) -> str:
    """Deterministic hash of a raw dict for generic fallback identity."""
    payload = json.dumps(raw, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def _first_non_empty_text_or_attr(elem: ET.Element) -> str:
    """First non-empty text content or attribute value."""
    if elem.text and elem.text.strip():
        return elem.text.strip()
    for k, v in elem.attrib.items():
        if v and v.strip():
            return v.strip()
    for child in elem:
        result = _first_non_empty_text_or_attr(child)
        if result:
            return result
    return ""


def _parse_security_setting(block: ET.Element) -> tuple[str, str, str] | None:
    """Return (identity, display_name, display_value) for a Security CSE block."""
    name = block.get("Name")
    type_ = block.get("Type")
    if name and type_:
        # Look for SettingBoolean, SettingNumber, SettingString children
        value = ""
        for child in block:
            ln = _localname(child.tag)
            if ln in ("SettingBoolean", "SettingNumber", "SettingString"):
                if child.text and child.text.strip():
                    value = child.text.strip()
                    break
        identity = f"{type_}:{name}"
        return identity, name, value
    return None


def _parse_registry_setting(block: ET.Element) -> tuple[str, str, str] | None:
    """Return (identity, display_name, display_value) for Registry / Windows Registry."""
    key = block.get("KeyName") or block.get("Key") or ""
    value_name = block.get("ValueName") or block.get("Name") or ""
    if key or value_name:
        identity = f"{key}:{value_name}" if (key and value_name) else (key or value_name)
        display_name = value_name or key or _localname(block.tag)
        display_value = _first_non_empty_text_or_attr(block)
        return identity, display_name, display_value
    return None


def _parse_generic_setting(cse: str, block: ET.Element) -> tuple[str, str, str]:
    """Generic fallback identity/display for any CSE block."""
    raw = element_to_dict(block)
    identity = f"{cse}:{_localname(block.tag)}:{_stable_hash(raw)}"
    display_name = _localname(block.tag)
    display_value = _first_non_empty_text_or_attr(block)
    return identity, display_name, display_value


def _parse_settings(gpo_elem: ET.Element, gpo_id: str) -> list[Setting]:
    """Parse all settings from a GPO element."""
    settings: list[Setting] = []
    for side_name in ("Computer", "User"):
        side_elem = _child_by_localname(gpo_elem, side_name)
        if side_elem is None:
            continue
        enabled = parse_bool(_text(_child_by_localname(side_elem, "Enabled")))
        for ext_data in _children_by_localname(side_elem, "ExtensionData"):
            cse_elem = _child_by_localname(ext_data, "Name")
            cse = cse_elem.text if cse_elem is not None and cse_elem.text else "Unknown"
            for ext in _children_by_localname(ext_data, "Extension"):
                # Check for blocked extension
                children = list(ext)
                if len(children) == 1 and _localname(children[0].tag) == "Blocked":
                    settings.append(
                        Setting(
                            gpo_id=gpo_id,
                            side=side_name,
                            cse=cse,
                            identity=f"{cse}:blocked",
                            display_name="(blocked extension)",
                            display_value="",
                            raw={"blocked": True},
                            from_disabled_side=not enabled,
                            source_state="blocked",
                        )
                    )
                    continue
                # Walk direct child elements as setting blocks
                for block in children:
                    raw = element_to_dict(block)
                    # Try CSE-specific identity
                    parsed: tuple[str, str, str] | None = None
                    if cse == "Security":
                        parsed = _parse_security_setting(block)
                    if cse in ("Registry", "Windows Registry"):
                        parsed = _parse_registry_setting(block)
                    if parsed is None:
                        parsed = _parse_generic_setting(cse, block)
                    identity, display_name, display_value = parsed
                    settings.append(
                        Setting(
                            gpo_id=gpo_id,
                            side=side_name,
                            cse=cse,
                            identity=identity,
                            display_name=display_name,
                            display_value=display_value,
                            raw=raw,
                            from_disabled_side=not enabled,
                            source_state="normal",
                        )
                    )
    return settings


def _parse_links(gpo_elem: ET.Element, gpo_id: str) -> list[GpoLink]:
    """Parse all LinksTo elements."""
    links: list[GpoLink] = []
    for link_elem in _children_by_localname(gpo_elem, "LinksTo"):
        som_name = _text(_child_by_localname(link_elem, "SOMName")) or ""
        som_path = _text(_child_by_localname(link_elem, "SOMPath")) or ""
        enabled = parse_bool(_text(_child_by_localname(link_elem, "Enabled")))
        enforced = parse_bool(_text(_child_by_localname(link_elem, "NoOverride")))
        links.append(
            GpoLink(
                gpo_id=gpo_id,
                som_name=som_name,
                som_path=som_path,
                link_enabled=enabled,
                enforced=enforced,
            )
        )
    return links


def _parse_delegation(gpo_elem: ET.Element, gpo_id: str) -> list[DelegationEntry]:
    """Parse delegation entries from SecurityDescriptor/Permissions."""
    entries: list[DelegationEntry] = []
    sd = _child_by_localname(gpo_elem, "SecurityDescriptor")
    if sd is None:
        return entries
    perms = _child_by_localname(sd, "Permissions")
    if perms is None:
        return entries
    present = _child_by_localname(perms, "PermissionsPresent")
    if present is not None and present.text and present.text.strip().lower() == "false":
        return entries
    for perm in _children_by_localname(perms, "Permission"):
        trustee = _text(_child_by_localname(perm, "Trustee")) or ""
        trustee_sid = _text(_child_by_localname(perm, "TrusteeSID"))
        if trustee_sid is None:
            trustee_sid = _text(_child_by_localname(perm, "SID"))
        # The permission type could be in Standard or different child
        perm_type = _text(_child_by_localname(perm, "Standard"))
        if perm_type is None:
            perm_type = _text(_child_by_localname(perm, "Type"))
        if perm_type is None:
            perm_type = ""
        allowed = True
        deny = _child_by_localname(perm, "AccessDenied")
        if deny is not None and deny.text and deny.text.strip().lower() == "true":
            allowed = False
        entries.append(
            DelegationEntry(
                gpo_id=gpo_id,
                trustee=trustee,
                trustee_sid=trustee_sid,
                permission=perm_type,
                allowed=allowed,
            )
        )
    return entries


def parse_report(xml_path: str | Path) -> list[Gpo]:
    """Parse one or more GPOs from a report XML file."""
    tree = ET.parse(xml_path)
    root = tree.getroot()
    gpos: list[Gpo] = []
    # The report may contain many GPO elements (AllGPOs.xml) or one
    for gpo_elem in root.iter():
        if _localname(gpo_elem.tag) == "GPO":
            gpo = _parse_single_gpo(gpo_elem)
            gpos.append(gpo)
    return gpos


def _parse_single_gpo(gpo_elem: ET.Element) -> Gpo:
    """Parse a single GPO element."""
    id_elem = _child_by_localname(gpo_elem, "Identifier")
    raw_id = _text(_child_by_localname(id_elem, "Identifier")) if id_elem is not None else ""
    gpo_id = canonical_guid(raw_id) if raw_id else ""
    domain = (_text(_child_by_localname(id_elem, "Domain")) or "") if id_elem is not None else ""
    name = _text(_child_by_localname(gpo_elem, "Name")) or ""
    created = parse_dt(_text(_child_by_localname(gpo_elem, "CreatedTime")))
    modified = parse_dt(_text(_child_by_localname(gpo_elem, "ModifiedTime")))
    read = parse_dt(_text(_child_by_localname(gpo_elem, "ReadTime")))

    computer = _child_by_localname(gpo_elem, "Computer")
    user = _child_by_localname(gpo_elem, "User")

    computer_enabled = parse_bool(_text(_child_by_localname(computer, "Enabled")) if computer is not None else None)
    user_enabled = parse_bool(_text(_child_by_localname(user, "Enabled")) if user is not None else None)
    computer_ver_ds = parse_int(_text(_child_by_localname(computer, "VersionDirectory")) if computer is not None else None)
    computer_ver_sysvol = parse_int(_text(_child_by_localname(computer, "VersionSysvol")) if computer is not None else None)
    user_ver_ds = parse_int(_text(_child_by_localname(user, "VersionDirectory")) if user is not None else None)
    user_ver_sysvol = parse_int(_text(_child_by_localname(user, "VersionSysvol")) if user is not None else None)

    sd = _child_by_localname(gpo_elem, "SecurityDescriptor")
    sddl = _text(_child_by_localname(sd, "SDDL")) if sd is not None else None
    owner = _text(_child_by_localname(sd, "Owner")) if sd is not None else None
    filter_data = parse_bool(_text(_child_by_localname(gpo_elem, "FilterDataAvailable")))

    gpo = Gpo(
        id=gpo_id,
        name=name,
        domain=domain,
        created=created,
        modified=modified,
        read=read,
        computer_enabled=computer_enabled,
        user_enabled=user_enabled,
        computer_ver_ds=computer_ver_ds,
        computer_ver_sysvol=computer_ver_sysvol,
        user_ver_ds=user_ver_ds,
        user_ver_sysvol=user_ver_sysvol,
        sddl=sddl,
        owner=owner,
        filter_data_available=filter_data,
        wmi_filter=None,
        sysvol_path=None,
    )
    gpo.links = _parse_links(gpo_elem, gpo_id)
    gpo.settings = _parse_settings(gpo_elem, gpo_id)
    gpo.delegation = _parse_delegation(gpo_elem, gpo_id)
    return gpo


def parse_inheritance(json_path: str | Path) -> list[Som]:
    """Parse GPInheritance dump into a list of ``Som``."""
    data = load_json(json_path)
    if not isinstance(data, list):
        data = [data]
    soms: list[Som] = []
    for record in data:
        path = record.get("Path", "")
        name = record.get("Name", "")
        container_type = record.get("ContainerType", "")
        inheritance_blocked = record.get("GpoInheritanceBlocked", False)
        if isinstance(inheritance_blocked, str):
            inheritance_blocked = inheritance_blocked.strip().lower() == "true"
        som = Som(
            path=path,
            name=name,
            container_type=container_type,
            inheritance_blocked=bool(inheritance_blocked),
        )
        links_raw = record.get("InheritedGpoLinks", [])
        if isinstance(links_raw, dict):
            links_raw = [links_raw]
        for link in links_raw:
            gpo_id_raw = link.get("GpoId")
            if not gpo_id_raw:
                continue
            som.links.append(
                SomLink(
                    gpo_id=canonical_guid(gpo_id_raw),
                    order=int(link.get("Order", 0)),
                    enabled=bool(link.get("Enabled", True)),
                    enforced=bool(link.get("Enforced", False)),
                    target=link.get("Target", ""),
                )
            )
        soms.append(som)
    return soms


def merge_metadata(json_path: str | Path, gpos: list[Gpo]) -> None:
    """Read metadata JSON and back-fill WMI filter + version fields."""
    data = load_json(json_path)
    by_id = {g.id: g for g in gpos}
    if not isinstance(data, list):
        data = [data]
    for record in data:
        raw_id = record.get("Id", "")
        if not raw_id:
            continue
        gpo_id = canonical_guid(raw_id)
        gpo = by_id.get(gpo_id)
        if gpo is None:
            continue
        wmi = record.get("WmiFilter")
        if wmi is not None:
            gpo.wmi_filter = wmi if isinstance(wmi, str) else None
        # Back-fill versions if report value was missing
        if gpo.computer_ver_ds is None:
            gpo.computer_ver_ds = parse_int(str(record.get("ComputerVersionDirectory", "")))
        if gpo.computer_ver_sysvol is None:
            gpo.computer_ver_sysvol = parse_int(str(record.get("ComputerVersionSysvol", "")))
        if gpo.user_ver_ds is None:
            gpo.user_ver_ds = parse_int(str(record.get("UserVersionDirectory", "")))
        if gpo.user_ver_sysvol is None:
            gpo.user_ver_sysvol = parse_int(str(record.get("UserVersionSysvol", "")))


def attach_sysvol_paths(sysvol_dir: str | Path, gpos: list[Gpo]) -> None:
    """Match each GPO to its SYSVOL folder by canonical id."""
    base = Path(sysvol_dir)
    if not base.exists():
        return
    for gpo in gpos:
        # Try both braced and bare forms
        candidates = [
            base / f"{{{gpo.id.upper()}}}",
            base / gpo.id,
            base / gpo.id.upper(),
        ]
        for cand in candidates:
            if cand.exists():
                gpo.sysvol_path = str(cand.resolve())
                break


def load_estate(sample_dir: str | Path) -> Estate:
    """Orchestrate loading a full estate from a sample directory."""
    src = Path(sample_dir)
    report_path = src / "AllGPOs.xml"
    if not report_path.exists():
        raise FileNotFoundError(f"AllGPOs.xml not found in {src}")
    gpos = parse_report(report_path)
    domain = gpos[0].domain if gpos else ""

    inheritance_path = src / "gp-inheritance.json"
    soms: list[Som] = []
    if inheritance_path.exists():
        soms = parse_inheritance(inheritance_path)

    metadata_path = src / "gpo-metadata.json"
    if metadata_path.exists():
        merge_metadata(metadata_path, gpos)

    sysvol_dir = src / "SYSVOL-Policies"
    if sysvol_dir.exists():
        attach_sysvol_paths(sysvol_dir, gpos)
    else:
        # Also try the parent / SYSVOL-Policies pattern
        alt = src / "SYSVOL" / "Policies"
        if alt.exists():
            attach_sysvol_paths(alt, gpos)

    return Estate(domain=domain, gpos=gpos, soms=soms)
