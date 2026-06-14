"""Declarative fixture generator for the synthetic test estate.

Run with ``python tests/fixtures/build_fixture.py`` to regenerate all fixture
files from pure-Python declarations.  Keeps the fixtures honest: any new field
consumed by ``_parse_single_gpo`` must be represented here, or the generator
can no longer produce the committed output and the ``test_fixtures`` round-trip
will fail.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from xml.sax.saxutils import escape as _xe

FIXTURE_DIR = Path(__file__).resolve().parent

DOMAIN = "fakefixture.local"
ROOT_DN = f"dc={DOMAIN.replace('.', ',dc=')}"
CHILD_DN = f"ou=child,{ROOT_DN}"

# fmt: off
GUID_A = "{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}"
GUID_B = "{BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB}"
GUID_C = "{CCCCCCCC-CCCC-CCCC-CCCC-CCCCCCCCCCCC}"
GUID_D = "{DDDDDDDD-DDDD-DDDD-DDDD-DDDDDDDDDDDD}"
GUID_E = "{EEEEEEEE-EEEE-EEEE-EEEE-EEEEEEEEEEEE}"
GUID_F = "{FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF}"
GUID_G = "{11111111-1111-1111-1111-111111111111}"
GUID_H = "{22222222-2222-2222-2222-222222222222}"
GUID_I = "{33333333-3333-3333-3333-333333333333}"
GUID_J = "{44444444-4444-4444-4444-444444444444}"
GUID_K = "{55555555-5555-5555-5555-555555555555}"
GUID_L = "{66666666-6666-6666-6666-666666666666}"
GUID_M = "{77777777-7777-7777-7777-777777777777}"
GUID_N = "{88888888-8888-8888-8888-888888888888}"
# fmt: on

TS = "2025-06-01T00:00:00"
TS_STALE = "2022-01-01T00:00:00"

AUTH_USERS_READ = {
    "trustee": "Authenticated Users",
    "sid": "S-1-5-11",
    "standard": "Read",
    "type": "Allow",
}

SECURITY_FILTERED_DELEGATION = [
    {
        "trustee": "Helpdesk Operators",
        "sid": "S-1-5-21-1234567890-1234567890-1234567890-1000",
        "standard": "Apply Group Policy",
        "type": "Allow",
    },
    {
        "trustee": "Domain Admins",
        "sid": "S-1-5-21-1234567890-1234567890-1234567890-512",
        "standard": "Edit settings, delete, modify security",
        "type": "Allow",
    },
]


@dataclass
class LinkDef:
    som_name: str
    som_path: str
    enabled: bool = True
    enforced: bool = False


@dataclass
class SideDef:
    enabled: bool = True
    ver_ds: int = 1
    ver_sysvol: int = 1
    data: list[dict] = field(default_factory=list)
    blocked: bool = False


@dataclass
class GpoDef:
    guid: str
    name: str
    computer: SideDef = field(default_factory=SideDef)
    user: SideDef = field(default_factory=SideDef)
    links: list[LinkDef] = field(default_factory=list)
    delegation: list[dict] = field(default_factory=list)
    modified: str = TS


def _make_link(
    som_name: str, som_path: str, enabled: bool = True, enforced: bool = False
) -> LinkDef:
    return LinkDef(som_name=som_name, som_path=som_path, enabled=enabled, enforced=enforced)


def _block_xml(cse: str, block: dict) -> str:
    if cse == "Security":
        attrs = f'Name="{_xe(block["name"])}" Type="{_xe(block["type"])}"'
        tag = block.get("tag", "SettingBoolean")
        val = block["value"]
        return (
            f"          <Security {attrs}>\n"
            f"            <{tag}>{_xe(val)}</{tag}>\n"
            "          </Security>"
        )
    if cse == "Registry":
        key = block.get("KeyName", "")
        val_name = block.get("ValueName", "")
        if "children" in block:
            child_lines = "\n".join(
                f"            <{k}>{_xe(v)}</{k}>" for k, v in block["children"]
            )
            return (
                f'          <Registry KeyName="{_xe(key)}"'
                f' ValueName="{_xe(val_name)}">\n'
                f"{child_lines}\n"
                "          </Registry>"
            )
        val = block["value"]
        return (
            f'          <Registry KeyName="{_xe(key)}"'
            f' ValueName="{_xe(val_name)}">{_xe(val)}</Registry>'
        )
    raise ValueError(f"unknown cse {cse}")


def _make_side_xml(side: SideDef) -> str:
    lines = [
        f"      <Enabled>{str(side.enabled).lower()}</Enabled>",
        f"      <VersionDirectory>{side.ver_ds}</VersionDirectory>",
        f"      <VersionSysvol>{side.ver_sysvol}</VersionSysvol>",
    ]
    if side.data or side.blocked:
        lines.append("      <ExtensionData>")
        if side.blocked:
            lines.append("        <Name>Registry</Name>")
            lines.append("        <Extension>")
            lines.append("          <Blocked/>")
            lines.append("        </Extension>")
        for entry in side.data:
            cse = entry["cse"]
            lines.append(f"        <Name>{cse}</Name>")
            lines.append("        <Extension>")
            for block in entry["blocks"]:
                lines.append(_block_xml(cse, block))
            lines.append("        </Extension>")
        lines.append("      </ExtensionData>")
    return "\n".join(lines)


def _make_delegation_xml(entries: list[dict], compact: bool = False) -> str:
    lines = ["    <SecurityDescriptor>", "      <Permissions>"]
    for e in entries:
        lines.append("        <TrusteePermissions>")
        if compact:
            lines.append(
                f"          <Trustee>"
                f"<Name>{_xe(e['trustee'])}</Name><SID>{_xe(e['sid'])}</SID>"
                f"</Trustee>"
            )
        else:
            lines.append("          <Trustee>")
            lines.append(f"            <Name>{_xe(e['trustee'])}</Name>")
            lines.append(f"            <SID>{_xe(e['sid'])}</SID>")
            lines.append("          </Trustee>")
        lines.append(
            "          <Standard>"
            f"<GPOGroupedAccessEnum>{_xe(e['standard'])}</GPOGroupedAccessEnum>"
            "</Standard>"
        )
        lines.append(f"          <Type><PermissionType>{_xe(e['type'])}</PermissionType></Type>")
        lines.append("        </TrusteePermissions>")
    lines.append("      </Permissions>")
    lines.append("    </SecurityDescriptor>")
    return "\n".join(lines)


def gpo_to_xml(g: GpoDef) -> str:
    lines = [
        "  <GPO>",
        "    <Identifier>",
        f"      <Identifier>{g.guid}</Identifier>",
        f"      <Domain>{DOMAIN}</Domain>",
        "    </Identifier>",
        f"    <Name>{_xe(g.name)}</Name>",
        f"    <CreatedTime>{TS}</CreatedTime>",
        f"    <ModifiedTime>{g.modified}</ModifiedTime>",
        f"    <ReadTime>{TS}</ReadTime>",
        "    <Computer>",
        _make_side_xml(g.computer),
        "    </Computer>",
        "    <User>",
        _make_side_xml(g.user),
        "    </User>",
    ]
    if g.delegation:
        compact = g.guid in (GUID_F, GUID_G, GUID_H)
        lines.append(_make_delegation_xml(g.delegation, compact=compact))
    for link in g.links:
        lines.append("    <LinksTo>")
        lines.append(f"      <SOMName>{_xe(link.som_name)}</SOMName>")
        lines.append(f"      <SOMPath>{_xe(link.som_path)}</SOMPath>")
        lines.append(f"      <Enabled>{str(link.enabled).lower()}</Enabled>")
        lines.append(f"      <NoOverride>{str(link.enforced).lower()}</NoOverride>")
        lines.append("    </LinksTo>")
    lines.append("    <FilterDataAvailable>false</FilterDataAvailable>")
    lines.append("  </GPO>")
    return "\n".join(lines)


GPO_DEFS = [
    GpoDef(
        guid=GUID_A,
        name="gpo-cpassword",
        computer=SideDef(
            data=[
                {
                    "cse": "Security",
                    "blocks": [
                        {"name": "Audit policy", "type": "Policy", "value": "true"},
                    ],
                }
            ],
        ),
        links=[_make_link(DOMAIN, ROOT_DN)],
        delegation=[AUTH_USERS_READ],
    ),
    GpoDef(
        guid=GUID_B,
        name="gpo-ms16-072-vuln",
        links=[_make_link(DOMAIN, ROOT_DN)],
        delegation=[
            {
                "trustee": "Domain Admins",
                "sid": "S-1-5-21-1234567890-1234567890-1234567890-512",
                "standard": "Edit settings, delete, modify security",
                "type": "Allow",
            }
        ],
    ),
    GpoDef(
        guid=GUID_C,
        name="gpo-version-skew",
        computer=SideDef(
            enabled=False,
            ver_ds=3,
            ver_sysvol=5,
            data=[
                {
                    "cse": "Registry",
                    "blocks": [
                        {"KeyName": r"HKLM\Software\Fake", "ValueName": "FakeValue", "value": "1"},
                    ],
                }
            ],
        ),
        links=[_make_link(DOMAIN, ROOT_DN, enforced=True)],
        delegation=[AUTH_USERS_READ],
    ),
    GpoDef(
        guid=GUID_D,
        name="gpo-broken-unc",
        computer=SideDef(
            data=[
                {
                    "cse": "Registry",
                    "blocks": [
                        {
                            "KeyName": r"HKLM\Software\Fake",
                            "ValueName": "BadValue",
                            "value": r"\\oldserver\share",
                        },
                    ],
                }
            ],
        ),
        links=[_make_link("child", CHILD_DN)],
        delegation=[AUTH_USERS_READ],
    ),
    GpoDef(
        guid=GUID_E,
        name="gpo-loopback",
        computer=SideDef(
            data=[
                {
                    "cse": "Security",
                    "blocks": [
                        {
                            "name": "Configure user group policy loopback processing mode",
                            "type": "Policy",
                            "value": "Replace",
                            "tag": "SettingString",
                        },
                    ],
                }
            ],
        ),
        links=[_make_link(DOMAIN, ROOT_DN)],
        delegation=[AUTH_USERS_READ],
    ),
    GpoDef(
        guid=GUID_I,
        name="gpo-loopback-merge",
        computer=SideDef(
            data=[
                {
                    "cse": "Security",
                    "blocks": [
                        {
                            "name": "Configure user group policy loopback processing mode",
                            "type": "Policy",
                            "value": "Merge",
                            "tag": "SettingString",
                        },
                    ],
                }
            ],
        ),
        links=[_make_link(DOMAIN, ROOT_DN)],
        delegation=[AUTH_USERS_READ],
    ),
    GpoDef(
        guid=GUID_J,
        name="gpo-loopback-unknown",
        computer=SideDef(
            data=[
                {
                    "cse": "Security",
                    "blocks": [
                        {
                            "name": "Configure user group policy loopback processing mode",
                            "type": "Policy",
                            "value": "Enabled: Custom Loopback Mode",
                            "tag": "SettingString",
                        },
                    ],
                }
            ],
        ),
        links=[_make_link(DOMAIN, ROOT_DN)],
        delegation=[AUTH_USERS_READ],
    ),
    GpoDef(
        guid=GUID_F,
        name="gpo-blocked-ext",
        computer=SideDef(blocked=True),
        links=[_make_link(DOMAIN, ROOT_DN)],
        delegation=[AUTH_USERS_READ],
    ),
    GpoDef(
        guid=GUID_G,
        name="gpo-user-disabled",
        user=SideDef(
            enabled=False,
            data=[
                {
                    "cse": "Security",
                    "blocks": [
                        {
                            "name": "Minimum password age",
                            "type": "Account",
                            "value": "1",
                            "tag": "SettingNumber",
                        },
                    ],
                }
            ],
        ),
        links=[_make_link(DOMAIN, ROOT_DN)],
        delegation=[AUTH_USERS_READ],
    ),
    GpoDef(
        guid=GUID_H,
        name="gpo-conflict",
        computer=SideDef(
            data=[
                {
                    "cse": "Registry",
                    "blocks": [
                        {
                            "KeyName": r"HKLM\Software\Fake",
                            "ValueName": "BadValue",
                            "value": "different_value",
                            "children": [("Value", "different_value")],
                        },
                    ],
                }
            ],
        ),
        links=[_make_link(DOMAIN, ROOT_DN)],
        delegation=[AUTH_USERS_READ],
    ),
    GpoDef(
        guid=GUID_K,
        name="gpo-security-filtered",
        computer=SideDef(
            data=[
                {
                    "cse": "Registry",
                    "blocks": [
                        {"KeyName": r"HKLM\Software\Fake",
                         "ValueName": "SecFiltered", "value": "1"},
                    ],
                }
            ]
        ),
        links=[_make_link(DOMAIN, ROOT_DN)],
        delegation=SECURITY_FILTERED_DELEGATION,
    ),
    GpoDef(
        guid=GUID_L,
        name="gpo-wmi-broken-ref",
        computer=SideDef(
            data=[
                {
                    "cse": "Registry",
                    "blocks": [
                        {"KeyName": r"HKLM\Software\Fake", "ValueName": "WmiRef", "value": "1"},
                    ],
                }
            ]
        ),
        links=[_make_link(DOMAIN, ROOT_DN)],
        delegation=[AUTH_USERS_READ],
    ),
    GpoDef(
        guid=GUID_M,
        name="gpo-gpp-ilt",
        user=SideDef(
            data=[
                {
                    "cse": "Registry",
                    "blocks": [
                        {"KeyName": r"HKCU\Software\Fake", "ValueName": "IltSetting", "value": "1"},
                    ],
                }
            ]
        ),
        links=[_make_link(DOMAIN, ROOT_DN)],
        delegation=[AUTH_USERS_READ],
    ),
    GpoDef(
        guid=GUID_N,
        name="gpo-stale",
        modified=TS_STALE,
        computer=SideDef(
            data=[
                {
                    "cse": "Registry",
                    "blocks": [
                        {"KeyName": r"HKLM\Software\Fake", "ValueName": "StaleValue", "value": "1"},
                    ],
                }
            ]
        ),
        links=[_make_link(DOMAIN, ROOT_DN)],
        delegation=[AUTH_USERS_READ],
    ),
]


def build_all_gpos_xml() -> str:
    body = "\n\n".join(gpo_to_xml(g) for g in GPO_DEFS)
    return '<?xml version="1.0" encoding="utf-8"?>\n<AllGPOs>\n' + body + "\n</AllGPOs>\n"


def build_ou_tree() -> list[dict]:
    gplink_root = (
        f"[LDAP://CN={GUID_A},CN=Policies,CN=System,{ROOT_DN.upper()};0]"
        f"[LDAP://CN={GUID_B},CN=Policies,CN=System,{ROOT_DN.upper()};0]"
        f"[LDAP://CN={GUID_C},CN=Policies,CN=System,{ROOT_DN.upper()};2]"
        f"[LDAP://CN={GUID_E},CN=Policies,CN=System,{ROOT_DN.upper()};0]"
        f"[LDAP://CN={GUID_F},CN=Policies,CN=System,{ROOT_DN.upper()};0]"
        f"[LDAP://CN={GUID_G},CN=Policies,CN=System,{ROOT_DN.upper()};0]"
        f"[LDAP://CN={GUID_H},CN=Policies,CN=System,{ROOT_DN.upper()};0]"
        f"[LDAP://CN={GUID_I},CN=Policies,CN=System,{ROOT_DN.upper()};0]"
        f"[LDAP://CN={GUID_J},CN=Policies,CN=System,{ROOT_DN.upper()};0]"
        f"[LDAP://CN={GUID_K},CN=Policies,CN=System,{ROOT_DN.upper()};0]"
        f"[LDAP://CN={GUID_L},CN=Policies,CN=System,{ROOT_DN.upper()};0]"
        f"[LDAP://CN={GUID_M},CN=Policies,CN=System,{ROOT_DN.upper()};0]"
        f"[LDAP://CN={GUID_N},CN=Policies,CN=System,{ROOT_DN.upper()};0]"
    )
    gplink_child = f"[LDAP://CN={GUID_D},CN=Policies,CN=System,{ROOT_DN.upper()};0]"
    return [
        {
            "DistinguishedName": ROOT_DN,
            "Name": DOMAIN,
            "gPLink": gplink_root,
            "gPOptions": 0,
        },
        {
            "DistinguishedName": CHILD_DN,
            "Name": "child",
            "gPLink": gplink_child,
            "gPOptions": 1,
        },
    ]


def build_gp_inheritance() -> list[dict]:
    root_links = []
    for order, guid in enumerate(
        [GUID_A, GUID_B, GUID_C, GUID_E, GUID_F, GUID_G, GUID_H, GUID_I, GUID_J,
         GUID_K, GUID_L, GUID_M, GUID_N],
        start=1,
    ):
        root_links.append(
            {
                "GpoId": guid,
                "Order": order,
                "Enabled": True,
                "Enforced": guid == GUID_C,
                "Target": ROOT_DN,
            }
        )
    root_links.append(
        {
            "GpoId": GUID_D,
            "Order": 10,
            "Enabled": True,
            "Enforced": False,
            "Target": CHILD_DN,
        }
    )
    return [
        {
            "Path": ROOT_DN,
            "Name": DOMAIN,
            "ContainerType": "domain",
            "GpoInheritanceBlocked": False,
            "InheritedGpoLinks": root_links,
        },
        {
            "Path": CHILD_DN,
            "Name": "child",
            "ContainerType": "ou",
            "GpoInheritanceBlocked": True,
            "InheritedGpoLinks": [
                {
                    "GpoId": GUID_C,
                    "Order": 1,
                    "Enabled": True,
                    "Enforced": True,
                    "Target": ROOT_DN,
                },
                {
                    "GpoId": GUID_D,
                    "Order": 2,
                    "Enabled": True,
                    "Enforced": False,
                    "Target": CHILD_DN,
                },
            ],
        },
    ]


def build_metadata() -> list[dict]:
    rows = []
    for g in GPO_DEFS:
        rows.append(
            {
                "Id": g.guid,
                "ComputerVersionDirectory": g.computer.ver_ds,
                "ComputerVersionSysvol": g.computer.ver_sysvol,
                "UserVersionDirectory": g.user.ver_ds,
                "UserVersionSysvol": g.user.ver_sysvol,
                "WmiFilter": "Fake WMI Filter" if g.guid == GUID_E
                else "Nonexistent WMI Filter" if g.guid == GUID_L
                else None,
            }
        )
    return rows


def build_wmi_filters() -> list[dict]:
    return [
        {
            "Name": "Fake WMI Filter",
            "Query": "SELECT * FROM Win32_OperatingSystem WHERE Version LIKE '10.%'",
        },
        {
            "Name": "Orphaned WMI Filter",
            "Query": "SELECT * FROM Win32_Processor WHERE Architecture = 9",
        },
    ]


def build_sites() -> list[dict]:
    """AD site GPO links (Configuration partition).

    One unlinked site and one site with an *enforced* link to an existing GPO,
    so the site caveat and precedence note are exercised.
    """
    config_nc = f"CN=Configuration,{ROOT_DN.upper()}"
    return [
        {
            "DistinguishedName": f"CN=Default-First-Site-Name,CN=Sites,{config_nc}",
            "Name": "Default-First-Site-Name",
            "gPLink": "",
            "gPOptions": 0,
        },
        {
            "DistinguishedName": f"CN=Branch-Office,CN=Sites,{config_nc}",
            "Name": "Branch-Office",
            # Enforced (;2) link to an existing GPO.
            "gPLink": f"[LDAP://CN={GUID_H},CN=Policies,CN=System,{ROOT_DN.upper()};2]",
            "gPOptions": 0,
        },
    ]


def write_all(target: Path = FIXTURE_DIR) -> None:
    target.mkdir(parents=True, exist_ok=True)

    (target / "AllGPOs.xml").write_text(build_all_gpos_xml(), encoding="utf-8")

    ou_tree = build_ou_tree()
    ou_tree_data = json.dumps(ou_tree, indent=2) + "\n"
    (target / "ou-tree.json").write_bytes(b"\xef\xbb\xbf" + ou_tree_data.encode("utf-8"))

    inheritance = build_gp_inheritance()
    (target / "gp-inheritance.json").write_text(
        json.dumps(inheritance, separators=(",", ":")) + "\n", encoding="utf-8"
    )

    meta = build_metadata()
    (target / "gpo-metadata.json").write_text(
        json.dumps(meta, separators=(",", ":")) + "\n", encoding="utf-8"
    )

    wmi = build_wmi_filters()
    (target / "wmi-filters.json").write_text(
        json.dumps(wmi, separators=(",", ":")) + "\n", encoding="utf-8"
    )

    sites = build_sites()
    sites_data = json.dumps(sites, indent=2) + "\n"
    (target / "sites.json").write_bytes(b"\xef\xbb\xbf" + sites_data.encode("utf-8"))

    sysvol = (
        target
        / "SYSVOL-Policies"
        / f"{{{GUID_A.strip('{}').upper()}}}"
        / "Machine"
        / "Preferences"
    )
    sysvol.mkdir(parents=True, exist_ok=True)
    groups_xml = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D66F83}">\n'
        '  <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="Administrator">\n'
        '    <Properties cpassword="'
        'AzV93mAPDnE3UNvYggAjKSIi6wN6h/TnRqUyF+5Z0wWmS6D0mN8Y5g=='
        '" fullName="Admin" description="" changeLogon="0" noChange="0"'
        ' neverExpires="0" acctDisabled="0" userName="Administrator" />\n'
        "  </User>\n"
        "</Groups>\n"
    )
    (sysvol / "Groups.xml").write_text(groups_xml, encoding="utf-8")

    ilt_sysvol = (
        target
        / "SYSVOL-Policies"
        / f"{{{GUID_M.strip('{}').upper()}}}"
        / "User"
        / "Preferences"
    )
    ilt_sysvol.mkdir(parents=True, exist_ok=True)
    ilt_xml = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<Registry clsid="{9CDCCB0F-DE08-463b-B39D-646F54292F80}">\n'
        '  <Registry clsid="{9CDCCB0F-DE08-463b-B39D-646F54292F80}"'
        ' name="IltSetting" status="IltSetting"'
        ' changed="2025-06-01" uid="{00000000-0000-0000-0000-000000000000}">\n'
        '    <Filters>\n'
        '      <FilterGroup bool="AND" not="0"'
        ' name="FAKEFIXTURE\\SecurityGroup"'
        ' sid="S-1-5-21-1234567890-1234567890-1234567890-1001"'
        ' userContext="1" primaryGroup="0" localGroup="0"/>\n'
        '    </Filters>\n'
        '    <Properties action="U" displayDecimal="0" default="0"'
        ' hive="HKEY_CURRENT_USER" key="Software\\Fake"'
        ' name="IltSetting" type="REG_SZ" value="1"/>\n'
        '  </Registry>\n'
        '</Registry>\n'
    )
    (ilt_sysvol / "Registry.xml").write_text(ilt_xml, encoding="utf-8")


if __name__ == "__main__":
    write_all()
