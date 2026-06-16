"""Scrubbed golden estate fixture generator.

Produces a **committed, CI-gated** fixture that mirrors the REAL on-disk SYSVOL
shape: uppercase side dirs (``MACHINE``/``USER``), nested per-CSE subfolders
(e.g. ``MACHINE/Preferences/ScheduledTasks/ScheduledTasks.xml``), a V2 scheduled
task, a cpassword positive, a ``<Blocked/>`` Registry extension with a real
PReg binary, a security-filtered GPO with a coverage-gap companion, drive
mappings with UNC paths (exercising the broken_refs scanner), a Printers
preference, and ILT (FilterOrgUnit) targeting.

Run with ``python tests/golden_estate/build_golden.py`` — idempotent and
safe to re-run.  All identifiers are synthetic; no work-domain data is present.

Why this exists
~~~~~~~~~~~~~~~
The existing ``tests/fixtures/`` uses a FLAT layout and title-case side dirs.
That mismatch hid two real bugs (Registry.pol parser and GPP nested-subfolder
walker) that shipped green-but-broken.  This fixture closes the gap — CI runs
against a shape-realistic estate.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path
from xml.sax.saxutils import escape as _xe

GOLDEN_DIR = Path(__file__).resolve().parent

# ---------------------------------------------------------------------------
# Domain & identifiers — all synthetic, no work-domain data
# ---------------------------------------------------------------------------

DOMAIN = "GOLDEN.local"
ROOT_DN = f"dc={DOMAIN.replace('.', ',dc=')}"

# fmt: off
GUID_V2TASK    = "{AAAAAAAA-0001-0001-0001-AAAAAAAAAAAA}"
GUID_CPASSWORD = "{AAAAAAAA-0002-0002-0002-AAAAAAAAAAAA}"
GUID_BLOCKED   = "{AAAAAAAA-0003-0003-0003-AAAAAAAAAAAA}"
GUID_SECFILT   = "{AAAAAAAA-0004-0004-0004-AAAAAAAAAAAA}"
GUID_WMIFILT   = "{AAAAAAAA-0005-0005-0005-AAAAAAAAAAAA}"
GUID_INVONLY   = "{AAAAAAAA-0006-0006-0006-AAAAAAAAAAAA}"  # inventory-only (coverage gap)
GUID_COLLERR   = "{AAAAAAAA-0007-0007-0007-AAAAAAAAAAAA}"  # collection-error (coverage gap)
GUID_DRIVES    = "{AAAAAAAA-0008-0008-0008-AAAAAAAAAAAA}"  # drive mappings + printers + ILT
# fmt: on

TS = "2025-06-01T00:00:00"

# Well-known test cpassword (MS14-025 documentation sample; detector only
# checks for the attribute's presence — it does not decrypt).
WELL_KNOWN_CPASSWORD = (
    "edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLf"
    "CuNH8p/5sZlXhq2jl0nxG6TBn1J0aKbuUAGHHKgLDRPGtiAIYOTaiwOUjJT4lAYGr"
    "BpDJ9dUKEGq9Pz0nSFTSSmYkP1yd5NQdj5pL0Ebjp+5oZt8ye6wAQUbc"
)


# ---------------------------------------------------------------------------
# PReg binary helpers — produce a valid Registry.pol file in Python
# ---------------------------------------------------------------------------

_PREG_HEADER = b"PReg\x01\x00\x00\x00"
_OPEN  = "\x5b".encode("utf-16-le")   # '['
_CLOSE = "\x5d".encode("utf-16-le")   # ']'
_SEP   = "\x3b".encode("utf-16-le")   # ';'


def _preg_null_term(s: str) -> bytes:
    """Encode *s* as a UTF-16LE null-terminated string."""
    return s.encode("utf-16-le") + b"\x00\x00"


def _make_preg_record(key: str, value_name: str, reg_type: int, data: bytes) -> bytes:
    """Build one ``[key;value;type;size;data]`` PReg record."""
    return (
        _OPEN
        + _preg_null_term(key)
        + _SEP
        + _preg_null_term(value_name)
        + _SEP
        + struct.pack("<I", reg_type)
        + _SEP
        + struct.pack("<I", len(data))
        + _SEP
        + data
        + _CLOSE
    )


def _make_dword_data(value: int) -> bytes:
    """Pack a DWORD value for a PReg record."""
    return struct.pack("<I", value)


def _make_sz_data(value: str) -> bytes:
    """Encode a REG_SZ value (UTF-16LE, null-terminated) for a PReg record."""
    return value.encode("utf-16-le") + b"\x00\x00"


# ---------------------------------------------------------------------------
# XML generation helpers
# ---------------------------------------------------------------------------

AUTH_USERS_READ = [
    {
        "trustee": "Authenticated Users",
        "sid": "S-1-5-11",
        "standard": "Read",
        "type": "Allow",
    },
]

SEC_FILTERED_DELEGATION = [
    {
        "trustee": "Helpdesk Operators",
        "sid": "S-1-5-21-999999999-999999999-999999999-1000",
        "standard": "Apply Group Policy",
        "type": "Allow",
    },
    {
        "trustee": "Domain Admins",
        "sid": "S-1-5-21-999999999-999999999-999999999-512",
        "standard": "Edit settings, delete, modify security",
        "type": "Allow",
    },
]


def _make_delegation_xml(entries: list[dict]) -> str:
    lines = ["    <SecurityDescriptor>", "      <Permissions>"]
    for e in entries:
        lines.append("        <TrusteePermissions>")
        lines.append("          <Trustee>")
        lines.append(f"            <Name>{_xe(e['trustee'])}</Name>")
        lines.append(f"            <SID>{_xe(e['sid'])}</SID>")
        lines.append("          </Trustee>")
        lines.append(
            "          <Standard>"
            f"<GPOGroupedAccessEnum>{_xe(e['standard'])}</GPOGroupedAccessEnum>"
            "</Standard>"
        )
        lines.append(
            f"          <Type><PermissionType>{_xe(e['type'])}</PermissionType></Type>"
        )
        lines.append("        </TrusteePermissions>")
    lines.append("      </Permissions>")
    lines.append("    </SecurityDescriptor>")
    return "\n".join(lines)


def _make_gpo_xml(
    *,
    guid: str,
    name: str,
    computer_enabled: bool = True,
    user_enabled: bool = True,
    comp_ver_ds: int = 1,
    comp_ver_sysvol: int = 1,
    user_ver_ds: int = 1,
    user_ver_sysvol: int = 1,
    computer_ext: str = "",
    user_ext: str = "",
    delegation: list[dict] | None = None,
    links: list[tuple[str, str, bool, bool]] | None = None,
    description: str = "",
) -> str:
    """Build a single <GPO> element.

    *computer_ext* and *user_ext* are inner XML fragments for the
    ``<ExtensionData>`` block on the respective side. Pass an empty string
    for no extension data.
    """
    lines = [
        "  <GPO>",
        "    <Identifier>",
        f"      <Identifier>{guid}</Identifier>",
        f"      <Domain>{DOMAIN}</Domain>",
        "    </Identifier>",
        f"    <Name>{_xe(name)}</Name>",
    ]
    if description:
        lines.append(f"    <Description>{_xe(description)}</Description>")
    lines.extend([
        f"    <CreatedTime>{TS}</CreatedTime>",
        f"    <ModifiedTime>{TS}</ModifiedTime>",
        f"    <ReadTime>{TS}</ReadTime>",
        "    <Computer>",
        f"      <Enabled>{str(computer_enabled).lower()}</Enabled>",
        f"      <VersionDirectory>{comp_ver_ds}</VersionDirectory>",
        f"      <VersionSysvol>{comp_ver_sysvol}</VersionSysvol>",
    ])
    if computer_ext:
        lines.append(computer_ext)
    lines.extend([
        "    </Computer>",
        "    <User>",
        f"      <Enabled>{str(user_enabled).lower()}</Enabled>",
        f"      <VersionDirectory>{user_ver_ds}</VersionDirectory>",
        f"      <VersionSysvol>{user_ver_sysvol}</VersionSysvol>",
    ])
    if user_ext:
        lines.append(user_ext)
    lines.append("    </User>")
    if delegation:
        lines.append(_make_delegation_xml(delegation))
    if links:
        for som_name, som_path, enabled, enforced in links:
            lines.append("    <LinksTo>")
            lines.append(f"      <SOMName>{_xe(som_name)}</SOMName>")
            lines.append(f"      <SOMPath>{_xe(som_path)}</SOMPath>")
            lines.append(f"      <Enabled>{str(enabled).lower()}</Enabled>")
            lines.append(f"      <NoOverride>{str(enforced).lower()}</NoOverride>")
            lines.append("    </LinksTo>")
    lines.append("    <FilterDataAvailable>false</FilterDataAvailable>")
    lines.append("  </GPO>")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# GPO definitions
# ---------------------------------------------------------------------------

def _build_v2task_gpo() -> str:
    """GPO 1: V2 scheduled task with nested <Exec> command + a V1 task."""
    computer_ext = (
        "      <ExtensionData>"
        "        <Name>Scheduled Tasks</Name>"
        "        <Extension>"
        '          <Task clsid="{00000000-0000-0000-0000-000000000000}"'
        ' name="Legacy App Install" changed="2025-01-01">'
        '            <Properties action="CREATE"'
        ' appName="%SystemRoot%\\System32\\legacy.exe"'
        ' arguments="--install" runAs="NT AUTHORITY\\SYSTEM"/>'
        "          </Task>"
        "        </Extension>"
        "      </ExtensionData>"
    )
    return _make_gpo_xml(
        guid=GUID_V2TASK,
        name="golden-v2-task",
        computer_ext=computer_ext,
        delegation=AUTH_USERS_READ,
        links=[(DOMAIN, ROOT_DN, True, False)],
    )


def _build_cpassword_gpo() -> str:
    """GPO 2: cpassword in nested Groups.xml + local group mod."""
    computer_ext = (
        "      <ExtensionData>"
        "        <Name>Security</Name>"
        "        <Extension>"
        '          <Security Name="Audit policy" Type="Policy">'
        "            <SettingBoolean>true</SettingBoolean>"
        "          </Security>"
        "        </Extension>"
        "      </ExtensionData>"
    )
    return _make_gpo_xml(
        guid=GUID_CPASSWORD,
        name="golden-cpassword",
        description="Domain baseline with embedded local-admin password (MS14-025).",
        computer_ext=computer_ext,
        delegation=AUTH_USERS_READ,
        links=[(DOMAIN, ROOT_DN, True, False)],
    )


def _build_blocked_reg_gpo() -> str:
    """GPO 3: <Blocked/> Registry extension — resolved by Registry.pol."""
    computer_ext = (
        "      <ExtensionData>"
        "        <Name>Registry</Name>"
        "        <Extension>"
        "          <Blocked/>"
        "        </Extension>"
        "      </ExtensionData>"
    )
    return _make_gpo_xml(
        guid=GUID_BLOCKED,
        name="golden-blocked-registry",
        computer_ext=computer_ext,
        delegation=AUTH_USERS_READ,
        links=[(DOMAIN, ROOT_DN, True, False)],
    )


def _build_secfilt_gpo() -> str:
    """GPO 4: Security-filtered (no Authenticated Users Read)."""
    return _make_gpo_xml(
        guid=GUID_SECFILT,
        name="golden-security-filtered",
        delegation=SEC_FILTERED_DELEGATION,
        links=[(DOMAIN, ROOT_DN, True, False)],
    )


def _build_wmifilt_gpo() -> str:
    """GPO 5: WMI-filtered GPO with a Registry setting."""
    computer_ext = (
        "      <ExtensionData>"
        "        <Name>Registry</Name>"
        "        <Extension>"
        '          <Registry KeyName="HKLM\\Software\\GoldenPolicies"'
        ' ValueName="EnableWmiSetting">1</Registry>'
        "        </Extension>"
        "      </ExtensionData>"
    )
    return _make_gpo_xml(
        guid=GUID_WMIFILT,
        name="golden-wmi-filter",
        computer_ext=computer_ext,
        delegation=AUTH_USERS_READ,
        links=[(DOMAIN, ROOT_DN, True, False)],
    )


def _build_drives_gpo() -> str:
    """GPO 7: Drive mappings with UNC paths + a Printers preference.

    User-side Drive Maps extension with UNC paths to exercise the
    broken_refs scanner and drive_mapping_unc detection.  One drive
    carries an ILT FilterOrgUnit to exercise scan_ilt.
    """
    user_ext = (
        "      <ExtensionData>"
        "        <Name>Drive Maps</Name>"
        "        <Extension>"
        '          <Drive driveLetter="P:"'
        ' path="\\\\GOLDEN.local\\shares\\public" label="Public"/>'
        '          <Drive driveLetter="Q:"'
        ' path="\\\\oldserver.golden.local\\deprecated\\share" label="Deprecated"/>'
        '          <Drive driveLetter="Z:"'
        ' path="\\\\missing-server\\share" label="Missing"/>'
        "        </Extension>"
        "      </ExtensionData>"
        "      <ExtensionData>"
        "        <Name>Printers</Name>"
        "        <Extension>"
        '          <SharedPrinter path="\\\\printserver\\lab-printer"'
        ' default="1" port="\\\\printserver\\lab-printer"/>'
        "        </Extension>"
        "      </ExtensionData>"
    )
    return _make_gpo_xml(
        guid=GUID_DRIVES,
        name="golden-drive-mappings",
        computer_enabled=False,
        user_ext=user_ext,
        delegation=AUTH_USERS_READ,
        links=[(DOMAIN, ROOT_DN, True, False)],
    )


# ---------------------------------------------------------------------------
# AllGPOs.xml
# ---------------------------------------------------------------------------

def build_all_gpos_xml() -> str:
    body = "\n\n".join([
        _build_v2task_gpo(),
        _build_cpassword_gpo(),
        _build_blocked_reg_gpo(),
        _build_secfilt_gpo(),
        _build_wmifilt_gpo(),
        _build_drives_gpo(),
    ])
    return '<?xml version="1.0" encoding="utf-8"?>\n<AllGPOs>\n' + body + "\n</AllGPOs>\n"


# ---------------------------------------------------------------------------
# gpo-metadata.json
# ---------------------------------------------------------------------------

def build_metadata() -> list[dict]:
    return [
        {
            "Id": GUID_V2TASK,
            "ComputerVersionDirectory": 1,
            "ComputerVersionSysvol": 1,
            "UserVersionDirectory": 1,
            "UserVersionSysvol": 1,
            "WmiFilter": None,
        },
        {
            "Id": GUID_CPASSWORD,
            "ComputerVersionDirectory": 1,
            "ComputerVersionSysvol": 1,
            "UserVersionDirectory": 1,
            "UserVersionSysvol": 1,
            "WmiFilter": None,
        },
        {
            "Id": GUID_BLOCKED,
            "ComputerVersionDirectory": 2,
            "ComputerVersionSysvol": 2,
            "UserVersionDirectory": 1,
            "UserVersionSysvol": 1,
            "WmiFilter": None,
        },
        {
            "Id": GUID_SECFILT,
            "ComputerVersionDirectory": 1,
            "ComputerVersionSysvol": 1,
            "UserVersionDirectory": 1,
            "UserVersionSysvol": 1,
            "WmiFilter": None,
        },
        {
            "Id": GUID_WMIFILT,
            "ComputerVersionDirectory": 1,
            "ComputerVersionSysvol": 1,
            "UserVersionDirectory": 1,
            "UserVersionSysvol": 1,
            "WmiFilter": "Golden WMI Filter",
        },
        {
            "Id": GUID_DRIVES,
            "ComputerVersionDirectory": 0,
            "ComputerVersionSysvol": 0,
            "UserVersionDirectory": 1,
            "UserVersionSysvol": 1,
            "WmiFilter": None,
        },
    ]


# ---------------------------------------------------------------------------
# ou-tree.json
# ---------------------------------------------------------------------------

def build_ou_tree() -> list[dict]:
    gplink = (
        f"[LDAP://CN={GUID_V2TASK},CN=Policies,CN=System,{ROOT_DN.upper()};0]"
        f"[LDAP://CN={GUID_CPASSWORD},CN=Policies,CN=System,{ROOT_DN.upper()};0]"
        f"[LDAP://CN={GUID_BLOCKED},CN=Policies,CN=System,{ROOT_DN.upper()};0]"
        f"[LDAP://CN={GUID_SECFILT},CN=Policies,CN=System,{ROOT_DN.upper()};0]"
        f"[LDAP://CN={GUID_WMIFILT},CN=Policies,CN=System,{ROOT_DN.upper()};0]"
        f"[LDAP://CN={GUID_DRIVES},CN=Policies,CN=System,{ROOT_DN.upper()};0]"
    )
    return [
        {
            "DistinguishedName": ROOT_DN,
            "Name": DOMAIN,
            "gPLink": gplink,
            "gPOptions": 0,
        },
    ]


# ---------------------------------------------------------------------------
# gp-inheritance.json
# ---------------------------------------------------------------------------

def build_gp_inheritance() -> list[dict]:
    links = []
    for order, guid in enumerate(
        [GUID_V2TASK, GUID_CPASSWORD, GUID_BLOCKED, GUID_SECFILT, GUID_WMIFILT, GUID_DRIVES],
        start=1,
    ):
        links.append({
            "GpoId": guid,
            "Order": order,
            "Enabled": True,
            "Enforced": False,
            "Target": ROOT_DN,
        })
    return [
        {
            "Path": ROOT_DN,
            "Name": DOMAIN,
            "ContainerType": "domain",
            "GpoInheritanceBlocked": False,
            "InheritedGpoLinks": links,
        },
    ]


# ---------------------------------------------------------------------------
# wmi-filters.json
# ---------------------------------------------------------------------------

def build_wmi_filters() -> list[dict]:
    return [
        {
            "Name": "Golden WMI Filter",
            "Query": "SELECT * FROM Win32_OperatingSystem WHERE ProductType = 1",
        },
    ]


# ---------------------------------------------------------------------------
# gpo-inventory.json — includes the inaccessible GPO for coverage-gap testing
# ---------------------------------------------------------------------------

def build_gpo_inventory() -> list[dict]:
    return [
        # All six GPOs that are in AllGPOs.xml (so they are NOT gaps)
        {"Id": GUID_V2TASK, "DisplayName": "golden-v2-task"},
        {"Id": GUID_CPASSWORD, "DisplayName": "golden-cpassword"},
        {"Id": GUID_BLOCKED, "DisplayName": "golden-blocked-registry"},
        {"Id": GUID_SECFILT, "DisplayName": "golden-security-filtered"},
        {"Id": GUID_WMIFILT, "DisplayName": "golden-wmi-filter"},
        {"Id": GUID_DRIVES, "DisplayName": "golden-drive-mappings"},
        # This one is NOT in AllGPOs.xml — triggers an "inaccessible" coverage gap
        {"Id": GUID_INVONLY, "DisplayName": "golden-inaccessible"},
    ]


def build_collection_errors() -> list[dict]:
    return [
        {
            "GpoId": GUID_COLLERR,
            "DisplayName": "golden-collection-error",
            "Error": "Access Denied",
            "Stage": "Backup-Gpo",
        },
    ]


# ---------------------------------------------------------------------------
# SYSVOL file generation — REAL nested layout with UPPERCASE side dirs
# ---------------------------------------------------------------------------

def _sysvol_dir(guid: str, *parts: str) -> Path:
    """Return the path ``SYSVOL-Policies/{GUID}/{parts}`` creating as needed."""
    bare = guid.strip("{}").upper()
    p = GOLDEN_DIR / "SYSVOL-Policies" / f"{{{bare}}}"
    for part in parts:
        p = p / part
    p.mkdir(parents=True, exist_ok=True)
    return p


def _write_sysvol_file(guid: str, *parts: str, content: str) -> None:
    """Write *content* to ``SYSVOL-Policies/{GUID}/{parts}``."""
    *dir_parts, filename = parts
    d = _sysvol_dir(guid, *dir_parts)
    (d / filename).write_text(content, encoding="utf-8")


def _write_sysvol_binary(guid: str, *parts: str, data: bytes) -> None:
    """Write binary *data* to ``SYSVOL-Policies/{GUID}/{parts}``."""
    *dir_parts, filename = parts
    d = _sysvol_dir(guid, *dir_parts)
    (d / filename).write_bytes(data)


def _build_v2task_sysvol() -> None:
    """GPO 1 SYSVOL: nested ScheduledTasks/ScheduledTasks.xml with V2 task."""
    xml = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<ScheduledTasks clsid="{3A9C9A85-A59E-484F-9CC8-1B1B7AF1AAA1}">\n'
        '  <Task clsid="{00000000-0000-0000-0000-000000000001}"'
        ' name="Legacy App Install" changed="2025-01-01">\n'
        '    <Properties action="CREATE"'
        ' appName="%SystemRoot%\\System32\\legacy.exe"'
        ' arguments="--install" runAs="NT AUTHORITY\\SYSTEM"/>\n'
        '  </Task>\n'
        '  <ImmediateTaskV2 clsid="{00000000-0000-0000-0000-000000000002}"'
        ' name="Set Timezone" changed="2025-01-01">\n'
        '    <Properties action="UPDATE">\n'
        '      <Task>\n'
        '        <Actions Context="Author">\n'
        '          <Exec>\n'
        '            <Command>tzutil.exe</Command>\n'
        '            <Arguments>/s "UTC"</Arguments>\n'
        '          </Exec>\n'
        '        </Actions>\n'
        '        <Principals>\n'
        '          <Principal id="Author">\n'
        '            <UserId>NT AUTHORITY\\SYSTEM</UserId>\n'
        '          </Principal>\n'
        '        </Principals>\n'
        '      </Task>\n'
        '    </Properties>\n'
        '  </ImmediateTaskV2>\n'
        '</ScheduledTasks>\n'
    )
    _write_sysvol_file(
        GUID_V2TASK,
        "MACHINE", "Preferences", "ScheduledTasks",
        "ScheduledTasks.xml",
        content=xml,
    )


def _build_cpassword_sysvol() -> None:
    """GPO 2 SYSVOL: nested Groups/Groups.xml with cpassword + LocalUsersAndGroups."""
    groups_xml = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D66F83}">\n'
        '  <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}"'
        ' name="LocalAdmin">\n'
        '    <Properties cpassword="' + WELL_KNOWN_CPASSWORD + '"'
        ' fullName="Local Admin" description="" changeLogon="0" noChange="0"'
        ' neverExpires="0" acctDisabled="0" userName="Administrator" />\n'
        '  </User>\n'
        '</Groups>\n'
    )
    _write_sysvol_file(
        GUID_CPASSWORD,
        "MACHINE", "Preferences", "Groups",
        "Groups.xml",
        content=groups_xml,
    )

    lug_xml = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D66F83}">\n'
        '  <Group clsid="{00000000-0000-0000-0000-000000000003}"'
        ' name="Administrators (local)" changed="2025-01-01">\n'
        '    <Properties action="UPDATE" groupName="Administrators"'
        ' groupSid="S-1-5-32-544" removePolicy="0">\n'
        '      <Members>\n'
        '        <Member name="GOLDEN\\ServerAdmins" action="ADD"'
        ' sid="S-1-5-21-999999999-999999999-999999999-1101"/>\n'
        '        <Member name="GOLDEN\\LegacyAdmin" action="REMOVE"'
        ' sid="S-1-5-21-999999999-999999999-999999999-1102"/>\n'
        '      </Members>\n'
        '    </Properties>\n'
        '  </Group>\n'
        '</Groups>\n'
    )
    _write_sysvol_file(
        GUID_CPASSWORD,
        "MACHINE", "Preferences", "LocalUsersAndGroups",
        "LocalUsersAndGroups.xml",
        content=lug_xml,
    )


def _build_blocked_reg_sysvol() -> None:
    """GPO 3 SYSVOL: MACHINE/Registry.pol (PReg binary) for <Blocked/> resolution."""
    # Build a Registry.pol with two records:
    #   1. HKLM\Software\GoldenPolicies\EnableAudit = REG_DWORD 1
    #   2. HKLM\Software\GoldenPolicies\LogPath = REG_SZ "C:\Logs\GPAudit.log"
    record1 = _make_preg_record(
        key=r"Software\GoldenPolicies",
        value_name="EnableAudit",
        reg_type=4,  # REG_DWORD
        data=_make_dword_data(1),
    )
    record2 = _make_preg_record(
        key=r"Software\GoldenPolicies",
        value_name="LogPath",
        reg_type=1,  # REG_SZ
        data=_make_sz_data(r"C:\Logs\GPAudit.log"),
    )
    pol_data = _PREG_HEADER + record1 + record2
    _write_sysvol_binary(
        GUID_BLOCKED,
        "MACHINE",
        "Registry.pol",
        data=pol_data,
    )


# A minimal but real GPT.INI. Every GPO's SYSVOL root has one; emitting it for
# otherwise-content-less GPOs keeps their folder non-empty so git tracks it (git
# cannot commit an empty directory — a bare MACHINE dir vanishes on a fresh CI
# clone, leaving attach_sysvol_paths unable to match the GUID).
_GPT_INI = "[General]\r\nVersion=0\r\n"


def _build_secfilt_sysvol() -> None:
    """GPO 4 SYSVOL: no settings content, but a real GPT.INI at the root so the
    folder is tracked by git and attach_sysvol_paths can match the GUID."""
    _write_sysvol_file(GUID_SECFILT, "GPT.INI", content=_GPT_INI)


def _build_wmifilt_sysvol() -> None:
    """GPO 5 SYSVOL: no settings content (WMI filter is the interesting
    attribute), but a real GPT.INI so the folder is tracked."""
    _write_sysvol_file(GUID_WMIFILT, "GPT.INI", content=_GPT_INI)


def _build_drives_sysvol() -> None:
    """GPO 7 SYSVOL: USER-side Drives.xml (with ILT) + Printers.xml.

    * Drives.xml: 3 <Drive> elements with UNC paths.  The first carries
      an <FilterOrgUnit> ILT filter inside <Properties>/<Filters>.
    * Printers.xml: 1 <Printer> element with a UNC path.
    """
    drives_xml = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<Drives clsid="{8FDDCC1A-B1A6-4c9c-A3B5-D6B7F7C0A4D1}">\n'
        '  <Drive clsid="{AAAAAAAA-0008-0008-0008-AAAAAAAA0001}"'
        ' name="P: -> \\\\GOLDEN.local\\shares\\public" changed="2025-01-01">\n'
        '    <Properties action="CREATE" driveLetter="P:"'
        ' path="\\\\GOLDEN.local\\shares\\public" label="Public"'
        ' persistent="1" useLetter="1">\n'
        '      <Filters>\n'
        '        <FilterOrgUnit name="OU=Workstations,DC=GOLDEN,DC=local" not="0"/>\n'
        '      </Filters>\n'
        '    </Properties>\n'
        '  </Drive>\n'
        '  <Drive clsid="{AAAAAAAA-0008-0008-0008-AAAAAAAA0002}"'
        ' name="Q: -> \\\\oldserver.golden.local\\deprecated\\share" changed="2025-01-01">\n'
        '    <Properties action="CREATE" driveLetter="Q:"'
        ' path="\\\\oldserver.golden.local\\deprecated\\share" label="Deprecated"'
        ' persistent="1" useLetter="1"/>\n'
        '  </Drive>\n'
        '  <Drive clsid="{AAAAAAAA-0008-0008-0008-AAAAAAAA0003}"'
        ' name="Z: -> \\\\missing-server\\share" changed="2025-01-01">\n'
        '    <Properties action="CREATE" driveLetter="Z:"'
        ' path="\\\\missing-server\\share" label="Missing"'
        ' persistent="1" useLetter="1"/>\n'
        '  </Drive>\n'
        '</Drives>\n'
    )
    _write_sysvol_file(
        GUID_DRIVES,
        "USER", "Preferences", "Drives",
        "Drives.xml",
        content=drives_xml,
    )

    printers_xml = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<Printers clsid="{A5B2CF1A-1A9E-4f0c-A39D-6AC0223C8A23}">\n'
        '  <SharedPrinter clsid="{AAAAAAAA-0008-0008-0008-BBBBBBBB0001}"'
        ' name="\\\\printserver\\lab-printer" changed="2025-01-01">\n'
        '    <Properties action="UPDATE" path="\\\\printserver\\lab-printer"'
        ' default="1" port="\\\\printserver\\lab-printer"/>\n'
        '  </SharedPrinter>\n'
        '</Printers>\n'
    )
    _write_sysvol_file(
        GUID_DRIVES,
        "USER", "Preferences", "Printers",
        "Printers.xml",
        content=printers_xml,
    )


def _build_inaccessible_sysvol() -> None:
    """GPO 6 SYSVOL: empty directory — present on disk but not in AllGPOs.xml.

    This exercises the coverage-gap path: the GPO exists in gpo-inventory.json
    and has a bare SYSVOL folder, but is absent from the AllGPOs.xml report.
    For CI portability we use an empty directory (not chmod 000).
    """
    _sysvol_dir(GUID_INVONLY, "MACHINE")


# ---------------------------------------------------------------------------
# Top-level build
# ---------------------------------------------------------------------------

def write_all(target: Path = GOLDEN_DIR) -> None:
    """Generate the entire golden estate fixture (idempotent)."""
    target.mkdir(parents=True, exist_ok=True)

    # --- AllGPOs.xml ---
    (target / "AllGPOs.xml").write_text(build_all_gpos_xml(), encoding="utf-8")

    # --- gpo-metadata.json (with BOM to exercise BOM-tolerant loading) ---
    meta = json.dumps(build_metadata(), indent=2) + "\n"
    (target / "gpo-metadata.json").write_bytes(
        b"\xef\xbb\xbf" + meta.encode("utf-8")
    )

    # --- ou-tree.json (with BOM) ---
    ou_tree = json.dumps(build_ou_tree(), indent=2) + "\n"
    (target / "ou-tree.json").write_bytes(
        b"\xef\xbb\xbf" + ou_tree.encode("utf-8")
    )

    # --- gp-inheritance.json ---
    (target / "gp-inheritance.json").write_text(
        json.dumps(build_gp_inheritance(), separators=(",", ":")) + "\n",
        encoding="utf-8",
    )

    # --- wmi-filters.json ---
    (target / "wmi-filters.json").write_text(
        json.dumps(build_wmi_filters(), separators=(",", ":")) + "\n",
        encoding="utf-8",
    )

    # --- gpo-inventory.json (includes the inaccessible GPO) ---
    (target / "gpo-inventory.json").write_text(
        json.dumps(build_gpo_inventory(), separators=(",", ":")) + "\n",
        encoding="utf-8",
    )

    # --- collection-errors.json (exercises collection_error coverage gap) ---
    (target / "collection-errors.json").write_text(
        json.dumps(build_collection_errors(), separators=(",", ":")) + "\n",
        encoding="utf-8",
    )

    # --- SYSVOL-Policies/{GUID}/... (nested layout, UPPERCASE side dirs) ---
    _build_v2task_sysvol()
    _build_cpassword_sysvol()
    _build_blocked_reg_sysvol()
    _build_secfilt_sysvol()
    _build_wmifilt_sysvol()
    _build_inaccessible_sysvol()
    _build_drives_sysvol()


if __name__ == "__main__":
    write_all()
