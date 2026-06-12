"""Parse collector outputs into the normalized model."""

from __future__ import annotations

import hashlib
import json
import warnings
import zipfile
from pathlib import Path
from typing import Any
from xml.etree.ElementTree import Element

import defusedxml.ElementTree as ET

from gpo_lens.model import (
    DelegationEntry,
    Estate,
    Gpo,
    GpoLink,
    OuRecord,
    Setting,
    Som,
    SomLink,
    WmiFilter,
)
from gpo_lens.normalize import canonical_guid, load_json, parse_bool, parse_dt, parse_int


def _localname(tag: str) -> str:
    """Strip namespace prefix from an XML tag."""
    return tag.split("}")[-1] if "}" in tag else tag


def _child_by_localname(parent: Element, name: str) -> Element | None:
    """First child whose localname matches ``name``."""
    for child in parent:
        if _localname(child.tag) == name:
            return child
    return None


def _children_by_localname(parent: Element, name: str) -> list[Element]:
    """All children whose localname matches ``name``."""
    return [child for child in parent if _localname(child.tag) == name]


def _text(elem: Element | None) -> str | None:
    """Text content of an element, or None."""
    if elem is None:
        return None
    return elem.text


def element_to_dict(elem: Element) -> dict[str, Any]:
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


def _first_non_empty_text_or_attr(elem: Element) -> str:
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


def _parse_security_setting(block: Element) -> tuple[str, str, str] | None:
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


def _parse_registry_setting(block: Element) -> tuple[str, str, str] | None:
    """Return (identity, display_name, display_value) for Registry / Windows Registry."""
    key = block.get("KeyName") or block.get("Key") or ""
    value_name = block.get("ValueName") or block.get("Name") or ""
    if key or value_name:
        identity = f"{key}:{value_name}" if (key and value_name) else (key or value_name)
        display_name = value_name or key or _localname(block.tag)
        display_value = _first_non_empty_text_or_attr(block)
        return identity, display_name, display_value
    return None


def _parse_generic_setting(cse: str, block: Element) -> tuple[str, str, str]:
    """Generic fallback identity/display for any CSE block."""
    raw = element_to_dict(block)
    identity = f"{cse}:{_localname(block.tag)}:{_stable_hash(raw)}"
    display_name = _localname(block.tag)
    display_value = _first_non_empty_text_or_attr(block)
    return identity, display_name, display_value


def _parse_settings(gpo_elem: Element, gpo_id: str) -> list[Setting]:
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


def _parse_links(gpo_elem: Element, gpo_id: str) -> list[GpoLink]:
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


def _parse_delegation(gpo_elem: Element, gpo_id: str) -> list[DelegationEntry]:
    """Parse delegation entries from SecurityDescriptor/Permissions.

    Handles both the older flat ``Permission`` element (where Trustee/Standard
    are text) and the newer ``TrusteePermissions`` nested structure observed
    in real exports (Trustee/Name, Trustee/SID, Standard/GPOGroupedAccessEnum,
    Type/PermissionType).
    """
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

    # First try the newer nested TrusteePermissions structure
    for perm in _children_by_localname(perms, "TrusteePermissions"):
        trustee_elem = _child_by_localname(perm, "Trustee")
        trustee = ""
        trustee_sid = None
        if trustee_elem is not None:
            trustee = _text(_child_by_localname(trustee_elem, "Name")) or _text(trustee_elem) or ""
            trustee_sid = _text(_child_by_localname(trustee_elem, "SID"))
            if trustee_sid is None:
                trustee_sid = _text(_child_by_localname(trustee_elem, "TrusteeSID"))

        perm_type = ""
        standard_elem = _child_by_localname(perm, "Standard")
        if standard_elem is not None:
            perm_type = _text(_child_by_localname(standard_elem, "GPOGroupedAccessEnum")) or ""

        allowed = True
        type_elem = _child_by_localname(perm, "Type")
        if type_elem is not None:
            type_text = _text(_child_by_localname(type_elem, "PermissionType")) or ""
            if type_text.strip().lower() == "deny":
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

    # Only fall back to flat Permission if no TrusteePermissions were found
    if not entries:
        for perm in _children_by_localname(perms, "Permission"):
            trustee = _text(_child_by_localname(perm, "Trustee")) or ""
            trustee_sid = _text(_child_by_localname(perm, "TrusteeSID"))
            if trustee_sid is None:
                trustee_sid = _text(_child_by_localname(perm, "SID"))
            perm_type = (
                _text(_child_by_localname(perm, "Standard"))
                or _text(_child_by_localname(perm, "Type"))
                or ""
            )
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
    if root is None:
        return []
    gpos: list[Gpo] = []
    # The report may contain many <GPO> elements as children of the root
    # wrapper (AllGPOs.xml) or one <GPO> as the root itself.  We only look
    # at descendants that are actual GPO blocks, never the root wrapper.
    for gpo_elem in root.iter():
        if gpo_elem is root:
            continue
        if _localname(gpo_elem.tag) == "GPO":
            gpo = _parse_single_gpo(gpo_elem)
            gpos.append(gpo)
    return gpos


def parse_report_xml(xml_bytes: bytes) -> list[Gpo]:
    """Parse one or more GPOs from raw XML bytes (handles UTF-8 and UTF-16)."""
    if xml_bytes[:2] in (b"\xff\xfe", b"\xfe\xff"):
        text = xml_bytes.decode("utf-16")
    elif xml_bytes[:3] == b"\xef\xbb\xbf":
        text = xml_bytes.decode("utf-8-sig")
    else:
        text = xml_bytes.decode("utf-8")
    root = ET.fromstring(text)
    gpos: list[Gpo] = []
    if _localname(root.tag) == "GPO":
        gpos.append(_parse_single_gpo(root))
    else:
        for gpo_elem in root.iter():
            if gpo_elem is root:
                continue
            if _localname(gpo_elem.tag) == "GPO":
                gpos.append(_parse_single_gpo(gpo_elem))
    return gpos


def load_baseline_from_zip(zip_path: str | Path) -> list[Gpo]:
    """Load baseline GPOs from a Microsoft Security Baseline zip.

    Microsoft ships baselines as nested zips.  This function handles both:
    - Direct zip with ``GPOs/{GUID}/gpreport.xml`` structure
    - Outer zip containing inner baseline zips

    Returns all GPOs found across all baseline GPOs in the archive.
    """
    import io
    import zipfile

    gpos: list[Gpo] = []
    with zipfile.ZipFile(str(zip_path)) as outer:
        for name in outer.namelist():
            if name.endswith(".zip"):
                inner_data = outer.read(name)
                with zipfile.ZipFile(io.BytesIO(inner_data)) as inner:
                    gpos.extend(_extract_gpos_from_zip(inner))
            elif name.endswith("gpreport.xml"):
                raw = outer.read(name)
                gpos.extend(parse_report_xml(raw))

        if not gpos:
            # Try the outer zip itself as a GPO backup zip
            gpos.extend(_extract_gpos_from_zip(outer))

    return gpos


def _extract_gpos_from_zip(zf: zipfile.ZipFile) -> list[Gpo]:
    """Extract GPOs from gpreport.xml files in a zip."""
    gpos: list[Gpo] = []
    for name in zf.namelist():
        if name.endswith("gpreport.xml"):
            try:
                raw = zf.read(name)
                gpos.extend(parse_report_xml(raw))
            except (ET.ParseError, KeyError, ValueError) as exc:
                warnings.warn(f"Skipping entry in zip: {exc}", stacklevel=1)
                continue
    return gpos


def _side_bool(side_elem: Element | None, child_name: str) -> bool:
    """Parse a boolean child under a side element."""
    text = _text(_child_by_localname(side_elem, child_name)) if side_elem is not None else None
    return parse_bool(text)


def _side_int(side_elem: Element | None, child_name: str) -> int | None:
    """Parse an int child under a side element."""
    text = _text(_child_by_localname(side_elem, child_name)) if side_elem is not None else None
    return parse_int(text)


def _parse_single_gpo(gpo_elem: Element) -> Gpo:
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

    computer_enabled = _side_bool(computer, "Enabled")
    user_enabled = _side_bool(user, "Enabled")
    computer_ver_ds = _side_int(computer, "VersionDirectory")
    computer_ver_sysvol = _side_int(computer, "VersionSysvol")
    user_ver_ds = _side_int(user, "VersionDirectory")
    user_ver_sysvol = _side_int(user, "VersionSysvol")

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
            raw_order = link.get("Order", 0)
            order_val = parse_int(str(raw_order)) if raw_order is not None else 0
            raw_enabled = link.get("Enabled", True)
            raw_enforced = link.get("Enforced", False)
            enabled_val = (
                parse_bool(str(raw_enabled))
                if isinstance(raw_enabled, str)
                else bool(raw_enabled)
            )
            enforced_val = (
                parse_bool(str(raw_enforced))
                if isinstance(raw_enforced, str)
                else bool(raw_enforced)
            )
            som.links.append(
                SomLink(
                    gpo_id=canonical_guid(gpo_id_raw),
                    order=order_val or 0,
                    enabled=enabled_val,
                    enforced=enforced_val,
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
        try:
            gpo_id = canonical_guid(raw_id)
        except ValueError:
            continue
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
    base_resolved = base.resolve()
    unmatched = 0
    for gpo in gpos:
        candidates = [
            base / f"{{{gpo.id.upper()}}}",
            base / gpo.id,
            base / gpo.id.upper(),
        ]
        matched = False
        for cand in candidates:
            if cand.exists():
                resolved = cand.resolve()
                if resolved.is_relative_to(base_resolved):
                    gpo.sysvol_path = str(resolved)
                    matched = True
                    break
        if not matched and any(cand.exists() for cand in candidates):
            unmatched += 1
    if unmatched > 0:
        warnings.warn(
            f"{unmatched} GPO(s) had SYSVOL paths outside the base directory; skipped",
            stacklevel=1,
        )


def parse_wmi_filters(json_path: str | Path) -> list[WmiFilter]:
    """Parse ``wmi-filters.json`` into a list of :class:`WmiFilter`."""
    data = load_json(json_path)
    if not isinstance(data, list):
        data = [data]
    filters: list[WmiFilter] = []
    for record in data:
        name = record.get("Name", "")
        query = record.get("Query", "")
        if name:
            filters.append(WmiFilter(name=name, query=query))
    return filters


def parse_ou_tree(json_path: str | Path) -> list[OuRecord]:
    """Parse ``ou-tree.json`` (raw gPLink / gPOptions) into :class:`OuRecord` list."""
    data = load_json(json_path)
    if not isinstance(data, list):
        data = [data]
    records: list[OuRecord] = []
    for record in data:
        dn = record.get("DistinguishedName", "")
        name = record.get("Name", "")
        gp_link = record.get("gPLink")
        gp_options = record.get("gPOptions")
        opt_val: int | None = None
        if gp_options is not None:
            try:
                opt_val = int(gp_options)
            except (ValueError, TypeError):
                opt_val = None
        records.append(OuRecord(dn=dn, name=name, gp_link=gp_link, gp_options=opt_val))
    return records


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
        alt = src / "SYSVOL" / "Policies"
        if alt.exists():
            attach_sysvol_paths(alt, gpos)

    wmi_filters: list[WmiFilter] = []
    wmi_path = src / "wmi-filters.json"
    if wmi_path.exists():
        wmi_filters = parse_wmi_filters(wmi_path)

    ou_tree: list[OuRecord] = []
    ou_tree_path = src / "ou-tree.json"
    if ou_tree_path.exists():
        ou_tree = parse_ou_tree(ou_tree_path)

    return Estate(
        domain=domain, gpos=gpos, soms=soms,
        wmi_filters=wmi_filters, ou_tree=ou_tree,
    )
