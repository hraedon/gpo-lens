"""Parse collector outputs into the normalized model."""

from __future__ import annotations

import hashlib
import io
import json
import re
import warnings
import zipfile
from pathlib import Path
from typing import Any, Protocol, runtime_checkable
from xml.etree.ElementTree import Element

import defusedxml.ElementTree as ET

from gpo_lens.model import (
    CoverageGap,
    DelegationEntry,
    Estate,
    Gpo,
    GpoLink,
    GroupMembership,
    OuRecord,
    ResolvedPrincipal,
    Setting,
    Som,
    SomLink,
    WmiFilter,
)
from gpo_lens.normalize import canonical_guid, load_json, parse_bool, parse_dt, parse_int
from gpo_lens.paths import ci_child, ci_path
from gpo_lens.registry_pol import parse_registry_pol

# Decompression bomb guard: refuse to expand zip contents beyond this total.
_MAX_DECOMPRESSED_BYTES = 2 * 1024 * 1024 * 1024


@runtime_checkable
class _Readable(Protocol):
    def read(self, size: int = -1) -> bytes: ...


class SizeLimitedReader:
    """Wraps a readable stream and raises ValueError if bytes exceed a limit.

    Counts *actual* decompressed bytes during streaming reads, making it
    immune to zip-bomb attacks that spoof ``info.file_size`` headers.

    The ``read`` method caps the effective read size to 65536 bytes so that
    a caller passing a huge ``size`` (e.g. 1 GB) cannot cause an excessive
    single allocation before the limit check fires.
    """

    def __init__(self, source: _Readable, limit: int) -> None:
        self._source = source
        self._limit = limit
        self._total = 0

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            size = 65536
        elif size > 0:
            size = min(size, 65536)
        # size == 0: pass through as-is
        chunk = self._source.read(size)
        if chunk:
            self._total += len(chunk)
            if self._total > self._limit:
                raise ValueError("zip decompressed size exceeds limit")
        return chunk


def _streaming_zip_read(
    zf: zipfile.ZipFile,
    name: str,
    total_counter: list[int],
    max_bytes: int | None = None,
) -> bytes:
    """Read a zip entry with streaming decompression size enforcement.

    Unlike ``zf.read(name)`` which decompresses the entire entry into
    memory before any size check, this reads in fixed-size chunks through
    :class:`SizeLimitedReader`, enforcing the cap *during* decompression.
    This prevents zip-bomb attacks where ``info.file_size`` headers are
    spoofed to a small value while the actual content is much larger.

    **Memory tradeoff:** The size limit is enforced *during* streaming
    decompression, but the full (capped) content is buffered into a
    ``BytesIO`` object in memory.  This is necessary because the caller
    (e.g. ``load_baseline_from_zip``) needs the complete bytes to open a
    nested ``ZipFile``.  Baseline zips are typically under 100 MB, well
    within the 2 GB cap.  For the ``_safe_extract`` path (disk extraction),
    bytes are written directly to disk, not buffered.
    """
    if max_bytes is None:
        max_bytes = _MAX_DECOMPRESSED_BYTES
    remaining = max_bytes - total_counter[0]
    if remaining <= 0:
        raise ValueError("zip decompressed size exceeds limit")

    buf = io.BytesIO()
    with zf.open(name) as src:
        wrapped = SizeLimitedReader(src, remaining)
        while True:
            chunk = wrapped.read(65536)
            if not chunk:
                break
            buf.write(chunk)
        bytes_read = wrapped._total

    total_counter[0] += bytes_read
    if total_counter[0] > max_bytes:
        raise ValueError("zip decompressed size exceeds limit")

    return buf.getvalue()


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

    Uses streaming decompression with :func:`_streaming_zip_read` to enforce
    the uncompressed-size cap *during* extraction, preventing zip-bomb
    attacks that spoof ``info.file_size`` headers.

    **Memory tradeoff:** The size limit is enforced during streaming
    decompression via :class:`SizeLimitedReader`, but the full (capped)
    decompressed content of each entry is buffered in memory (as a
    ``BytesIO``) before parsing.  This is necessary because inner zips
    require the complete byte stream to open.  Baseline zips are
    typically under 100 MB, well within the 2 GB cap.
    """
    gpos: list[Gpo] = []
    total_bytes = [0]
    with zipfile.ZipFile(str(zip_path)) as outer:
        for name in outer.namelist():
            if name.endswith(".zip"):
                inner_data = _streaming_zip_read(outer, name, total_bytes)
                with zipfile.ZipFile(io.BytesIO(inner_data)) as inner:
                    gpos.extend(_extract_gpos_from_zip(inner, total_bytes))
            elif name.endswith("gpreport.xml"):
                try:
                    raw = _streaming_zip_read(outer, name, total_bytes)
                    gpos.extend(parse_report_xml(raw))
                except (ET.ParseError, KeyError, UnicodeDecodeError) as exc:
                    warnings.warn(f"Skipping entry in zip: {exc}", stacklevel=1)

        if not gpos:
            gpos.extend(_extract_gpos_from_zip(outer, total_bytes))

    return gpos


def _extract_gpos_from_zip(
    zf: zipfile.ZipFile, total_counter: list[int] | None = None
) -> list[Gpo]:
    """Extract GPOs from gpreport.xml files in a zip.

    Uses streaming decompression via :func:`_streaming_zip_read` to enforce
    the uncompressed-size cap during extraction.
    """
    _total = total_counter if total_counter is not None else [0]
    gpos: list[Gpo] = []
    for name in zf.namelist():
        if name.endswith("gpreport.xml"):
            try:
                raw = _streaming_zip_read(zf, name, _total)
                gpos.extend(parse_report_xml(raw))
            except (ET.ParseError, KeyError, ValueError, UnicodeDecodeError) as exc:
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
    description = _text(_child_by_localname(gpo_elem, "Description"))

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
        description=description,
    )
    gpo.links = _parse_links(gpo_elem, gpo_id)
    gpo.settings = _parse_settings(gpo_elem, gpo_id)
    gpo.delegation = _parse_delegation(gpo_elem, gpo_id)
    return gpo


# ``Get-GPInheritance`` returns a ``Microsoft.GroupPolicy.SomType`` enum for
# ``ContainerType``. The console *displays* it as "Domain"/"OU", but
# ``ConvertTo-Json`` (PowerShell 5.1) serializes the underlying integer
# (observed: Domain=1, OU=2). The rest of gpo-lens treats ``container_type`` as
# the canonical lowercase string ("domain"/"ou"/"site") — sites are appended
# separately with that contract — so normalize here, tolerating both the int
# and string forms (a future ``-EnumsAsStrings`` collector would emit names).
_SOM_TYPE_INTS = {0: "site", 1: "domain", 2: "ou"}
_SOM_TYPE_NAMES = {
    "site": "site",
    "domain": "domain",
    "ou": "ou",
    "organizationalunit": "ou",
}


def _normalize_container_type(raw: object) -> str:
    if isinstance(raw, bool):  # guard: bool is an int subclass
        return ""
    if isinstance(raw, int):
        return _SOM_TYPE_INTS.get(raw, "")
    if isinstance(raw, str):
        s = raw.strip()
        if s.isdigit():
            return _SOM_TYPE_INTS.get(int(s), "")
        return _SOM_TYPE_NAMES.get(s.lower(), s.lower())
    return ""


def parse_inheritance(json_path: str | Path) -> list[Som]:
    """Parse GPInheritance dump into a list of ``Som``."""
    data = load_json(json_path)
    if not isinstance(data, list):
        data = [data]
    soms: list[Som] = []
    for record in data:
        path = record.get("Path", "")
        name = record.get("Name", "")
        container_type = _normalize_container_type(record.get("ContainerType", ""))
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


def augment_blocked_registry_from_pol(gpos: list[Gpo]) -> None:
    """Resolve ``<Blocked/>`` Registry extensions from the binary ``Registry.pol``.

    The GPO report sometimes renders the Registry CSE as ``<Blocked/>`` (the
    GPMC could not read it). When that happens the affected side carries a
    single placeholder setting with ``source_state="blocked"`` and no values.
    The authoritative values live in ``Machine/Registry.pol`` /
    ``User/Registry.pol`` (PReg binary format). Where that file exists, this
    replaces the blocked placeholder with the real settings, tagged
    ``source_state="registry_pol"``. Where it is absent, the placeholder is
    kept (we cannot fabricate values).

    Read-only and deterministic. Does not touch report-rendered Registry
    settings (those are kept as-is).
    """
    _SIDE_DIR = {"Computer": "Machine", "User": "User"}
    for gpo in gpos:
        if not gpo.sysvol_path:
            continue
        base = Path(gpo.sysvol_path)
        blocked_idxs = [
            i for i, s in enumerate(gpo.settings)
            if s.source_state == "blocked"
            and "registr" in s.cse.lower()
        ]
        if not blocked_idxs:
            continue
        # Group blocked placeholders by side; one placeholder per blocked side.
        blocked_sides = {gpo.settings[i].side for i in blocked_idxs}
        resolved_any = False
        additions: list[Setting] = []
        for side in blocked_sides:
            # Side dir casing varies on a real SYSVOL (default GPOs use MACHINE);
            # resolve case-insensitively for a case-sensitive analysis host.
            pol = ci_path(base, _SIDE_DIR.get(side, side), "Registry.pol")
            if pol is None:
                continue
            try:
                records = parse_registry_pol(pol.read_bytes())
            except (OSError, ValueError):
                continue
            if not records:
                continue
            resolved_any = True
            for rec in records:
                identity = (
                    f"{rec.key}:{rec.value_name}"
                    if (rec.key and rec.value_name)
                    else (rec.key or rec.value_name)
                )
                additions.append(Setting(
                    gpo_id=gpo.id,
                    side=side,
                    cse="Registry",
                    identity=identity,
                    display_name=rec.value_name or rec.key,
                    display_value=rec.display_value,
                    raw={
                        "key": rec.key,
                        "value_name": rec.value_name,
                        "type_code": rec.type_code,
                        "type_name": rec.type_name,
                        "size": rec.size,
                        "source": "registry_pol",
                    },
                    from_disabled_side=False,
                    source_state="registry_pol",
                ))
        if resolved_any:
            # Drop the blocked placeholders for the sides we resolved; keep the
            # real settings. Unresolved sides keep their placeholder.
            gpo.settings = [
                s for i, s in enumerate(gpo.settings) if i not in set(blocked_idxs)
            ]
            gpo.settings.extend(additions)


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


def parse_principals(json_path: str | Path) -> dict[str, ResolvedPrincipal]:
    """Parse ``principals.json`` into a ``{sid: ResolvedPrincipal}`` map.

    The file is optional (Plan 020 A.2); callers should only invoke this when
    the file exists. SIDs are canonicalized to lowercase. Each entry carries
    ``name``, ``sam``, ``type``, and ``domain`` from the collector's
    point-in-time directory lookup.
    """
    data = load_json(json_path)
    if not isinstance(data, dict):
        return {}
    raw_principals = data.get("principals")
    if not isinstance(raw_principals, dict):
        if isinstance(data, dict) and any(
            k.lower().startswith("s-1-") for k in data
        ):
            warnings.warn(
                "principals.json appears to be a flat SID map (no 'principals' "
                "wrapper key); expected {\"principals\": {\"<sid>\": ...}} format",
                stacklevel=2,
            )
        return {}
    out: dict[str, ResolvedPrincipal] = {}
    for sid_raw, entry in raw_principals.items():
        if not isinstance(entry, dict):
            continue
        sid = sid_raw.strip().lower()
        if not sid:
            continue
        name = entry.get("name") or sid
        sam = entry.get("sam") or ""
        ptype = entry.get("type") or "Unresolved"
        domain = entry.get("domain") or ""
        resolved = ptype != "Unresolved" and bool(name) and name != sid
        out[sid] = ResolvedPrincipal(
            sid=sid,
            name=name,
            sam=sam,
            principal_type=ptype,
            domain=domain,
            resolved=resolved,
        )
    return out


def parse_group_members(json_path: str | Path) -> dict[str, GroupMembership]:
    """Parse ``group-members.json`` into a ``{sid: GroupMembership}`` map.

    The file is optional (Plan 020 B); callers should only invoke this when
    the file exists. SIDs are canonicalized to lowercase. Each entry carries
    ``name``, ``members`` (a tuple of direct-member SIDs), and ``member_count``.
    Well-known groups with no enumerable membership carry an ``implicit`` note.
    """
    data = load_json(json_path)
    if not isinstance(data, dict):
        return {}
    raw_groups = data.get("groups")
    if not isinstance(raw_groups, dict):
        if isinstance(data, dict) and any(
            k.lower().startswith("s-1-") for k in data
        ):
            warnings.warn(
                "group-members.json appears to be a flat SID map (no 'groups' "
                "wrapper key); expected {\"groups\": {\"<sid>\": ...}} format",
                stacklevel=2,
            )
        return {}
    out: dict[str, GroupMembership] = {}
    for sid_raw, entry in raw_groups.items():
        if not isinstance(entry, dict):
            continue
        sid = sid_raw.strip().lower()
        if not sid:
            continue
        name = entry.get("name") or sid
        members_raw = entry.get("members")
        if not isinstance(members_raw, list):
            members_raw = []
        members = tuple(
            m.strip().lower() for m in members_raw
            if isinstance(m, str) and m.strip()
        )
        member_count = entry.get("member_count")
        if not isinstance(member_count, int):
            member_count = len(members)
        implicit = entry.get("implicit") or ""
        out[sid] = GroupMembership(
            sid=sid,
            name=name,
            members=members,
            member_count=member_count,
            implicit=implicit,
        )
    return out


# gPLink segment: ``[LDAP://CN={guid},...;flags]``. flags bit 0 = link
# disabled, bit 1 = enforced (NoOverride).
_GPLINK_RE = re.compile(r"\[LDAP://[Cc][Nn]=(\{[^}]+\}|[^,;]+),[^;]*;(\d+)\]")


def _parse_gplink(raw: str | None, target_dn: str) -> list[SomLink]:
    """Parse a raw ``gPLink`` attribute into ordered :class:`SomLink` entries.

    Order is the segment position (1-based) as written. Invalid GUID segments
    are skipped rather than raising.
    """
    links: list[SomLink] = []
    if not raw:
        return links
    for order, match in enumerate(_GPLINK_RE.finditer(raw), start=1):
        guid_raw, flags_raw = match.group(1), match.group(2)
        try:
            gpo_id = canonical_guid(guid_raw)
        except ValueError:
            continue
        flags = int(flags_raw)
        links.append(
            SomLink(
                gpo_id=gpo_id,
                order=order,
                enabled=(flags & 1) == 0,
                enforced=(flags & 2) != 0,
                target=target_dn,
            )
        )
    return links


def parse_sites(json_path: str | Path) -> list[Som]:
    """Parse ``sites.json`` into site scope-of-management nodes.

    Each AD site becomes a :class:`Som` with ``container_type="site"`` carrying
    its *direct* gPLink GPOs. Sites are a parallel scoping axis (not OU
    ancestors); their per-machine application (IP subnet -> site) is
    intentionally not resolved here.
    """
    data = load_json(json_path)
    if not isinstance(data, list):
        data = [data]
    sites: list[Som] = []
    for record in data:
        dn = record.get("DistinguishedName", "")
        name = record.get("Name", "")
        som = Som(
            path=dn,
            name=name,
            container_type="site",
            inheritance_blocked=False,
        )
        som.links = _parse_gplink(record.get("gPLink"), dn)
        sites.append(som)
    return sites


def parse_coverage_gaps(
    inventory_path: Path, errors_path: Path, gpos: list[Gpo]
) -> list[CoverageGap]:
    """Reconcile the authoritative inventory + collector failures against the export.

    A GPO present in ``gpo-inventory.json`` (ideally produced by a privileged
    run) but absent from the ingested GPOs is an inaccessible coverage gap. A
    GPO named in ``collection-errors.json`` that also did not make it into the
    export is a collection failure. Both are named, never silently dropped.
    Either file being absent is fine (older exports reconcile to no gaps).
    """
    known = {g.id for g in gpos}
    seen: set[str] = set()
    gaps: list[CoverageGap] = []

    if inventory_path.exists():
        inv = load_json(inventory_path)
        if not isinstance(inv, list):
            inv = [inv]
        for rec in inv:
            raw = rec.get("Id") or rec.get("id") or ""
            try:
                gid = canonical_guid(raw)
            except ValueError:
                continue
            if gid in known or gid in seen:
                continue
            gaps.append(CoverageGap(
                gpo_id=gid,
                display_name=rec.get("DisplayName") or rec.get("displayName"),
                kind="inaccessible",
                detail="In the GPO inventory but absent from the export "
                       "(the collection account could not read it)",
            ))
            seen.add(gid)

    if errors_path.exists():
        errs = load_json(errors_path)
        if not isinstance(errs, list):
            errs = [errs]
        for rec in errs:
            raw = rec.get("GpoId") or rec.get("gpo_id") or ""
            if not raw:
                continue
            try:
                gid = canonical_guid(raw)
            except ValueError:
                continue
            if gid in known or gid in seen:
                continue
            gaps.append(CoverageGap(
                gpo_id=gid,
                display_name=rec.get("DisplayName") or rec.get("display_name"),
                kind="collection_error",
                detail=rec.get("Error") or rec.get("Stage")
                       or "the collector reported a read failure",
            ))
            seen.add(gid)

    return gaps


def _scan_sysvol_coverage(gpos: list[Gpo]) -> list[CoverageGap]:
    """Detect GPOs whose SYSVOL Preferences directories are unreadable.

    A Windows-produced zip extracted on Linux often drops the traversal (``x``)
    bit on subdirectories. The parser skips these silently (correct — it must
    not crash), but the charter demands coverage honesty: if GPP content is
    invisible, surface it as a coverage_gap so the user knows the estate view
    is partial and can fix permissions (``chmod -R +rX SYSVOL-Policies``).
    """
    gaps: list[CoverageGap] = []
    for gpo in gpos:
        if not gpo.sysvol_path:
            continue
        base = Path(gpo.sysvol_path)
        unreadable: list[str] = []
        for side_dir in ("Machine", "User"):
            side = ci_child(base, side_dir)
            if side is None:
                continue
            prefs = ci_child(side, "Preferences")
            if prefs is None:
                continue
            try:
                for entry in sorted(prefs.iterdir()):
                    if entry.is_dir():
                        list(entry.iterdir())
            except OSError as exc:
                unreadable.append(
                    f"{side_dir}/Preferences ({exc.__class__.__name__})"
                )
        if unreadable:
            gaps.append(CoverageGap(
                gpo_id=gpo.id,
                display_name=gpo.name,
                kind="unreadable_sysvol",
                detail=(
                    f"GPP content in {', '.join(unreadable)} is invisible. "
                    f"If this is a zip extraction, run: chmod -R +rX on the "
                    f"SYSVOL-Policies directory."
                ),
            ))
    return gaps


def load_estate(sample_dir: str | Path) -> Estate:
    """Orchestrate loading a full estate from a sample directory."""
    src = Path(sample_dir)
    report_path = src / "AllGPOs.xml"
    if not report_path.exists():
        raise FileNotFoundError(f"AllGPOs.xml not found in {src}")
    gpos: list[Gpo] = []
    try:
        gpos = parse_report(report_path)
    except (ET.ParseError, OSError, UnicodeDecodeError) as exc:
        warnings.warn(f"Skipping AllGPOs.xml: {exc}", stacklevel=1)
    domain = gpos[0].domain if gpos else ""

    inheritance_path = src / "gp-inheritance.json"
    soms: list[Som] = []
    if inheritance_path.exists():
        try:
            soms = parse_inheritance(inheritance_path)
        except (OSError, ValueError) as exc:
            warnings.warn(f"Skipping gp-inheritance.json: {exc}", stacklevel=1)

    # AD sites are a parallel scoping axis; append them as container_type="site"
    # SOMs. Absent sites.json (older exports) changes nothing.
    sites_path = src / "sites.json"
    if sites_path.exists():
        try:
            soms.extend(parse_sites(sites_path))
        except (OSError, ValueError) as exc:
            warnings.warn(f"Skipping sites.json: {exc}", stacklevel=1)

    metadata_path = src / "gpo-metadata.json"
    if metadata_path.exists():
        try:
            merge_metadata(metadata_path, gpos)
        except (OSError, ValueError) as exc:
            warnings.warn(f"Skipping gpo-metadata.json: {exc}", stacklevel=1)

    sysvol_dir = src / "SYSVOL-Policies"
    if sysvol_dir.exists():
        attach_sysvol_paths(sysvol_dir, gpos)
    else:
        alt = src / "SYSVOL" / "Policies"
        if alt.exists():
            attach_sysvol_paths(alt, gpos)

    # Resolve <Blocked/> Registry extensions from the binary Registry.pol where
    # SYSVOL is present. No-op when SYSVOL wasn't copied or nothing is blocked.
    augment_blocked_registry_from_pol(gpos)

    wmi_filters: list[WmiFilter] = []
    wmi_path = src / "wmi-filters.json"
    if wmi_path.exists():
        try:
            wmi_filters = parse_wmi_filters(wmi_path)
        except (OSError, ValueError) as exc:
            warnings.warn(f"Skipping wmi-filters.json: {exc}", stacklevel=1)

    ou_tree: list[OuRecord] = []
    ou_tree_path = src / "ou-tree.json"
    if ou_tree_path.exists():
        try:
            ou_tree = parse_ou_tree(ou_tree_path)
        except (OSError, ValueError) as exc:
            warnings.warn(f"Skipping ou-tree.json: {exc}", stacklevel=1)

    coverage_gaps = parse_coverage_gaps(
        src / "gpo-inventory.json", src / "collection-errors.json", gpos
    )

    coverage_gaps.extend(_scan_sysvol_coverage(gpos))

    principals: dict[str, ResolvedPrincipal] = {}
    principals_path = src / "principals.json"
    if principals_path.exists():
        try:
            principals = parse_principals(principals_path)
        except (OSError, ValueError) as exc:
            warnings.warn(f"Skipping principals.json: {exc}", stacklevel=1)

    group_members: dict[str, GroupMembership] = {}
    group_members_path = src / "group-members.json"
    if group_members_path.exists():
        try:
            group_members = parse_group_members(group_members_path)
        except (OSError, ValueError) as exc:
            warnings.warn(f"Skipping group-members.json: {exc}", stacklevel=1)

    return Estate(
        domain=domain, gpos=gpos, soms=soms,
        wmi_filters=wmi_filters, ou_tree=ou_tree,
        coverage_gaps=coverage_gaps,
        principals=principals,
        group_members=group_members,
    )
