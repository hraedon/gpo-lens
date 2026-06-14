"""Unit tests for scope-honesty features in topology.py.

Covers scope_caveats, effective_scope, and scan_ilt edge cases.
Does NOT assert on is_security_filtered's empty-delegation behavior
or Everyone/S-1-1-0 handling (concurrent changes in progress).
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from gpo_lens.detection import scan_ilt
from gpo_lens.model import (
    DelegationEntry,
    Estate,
    Gpo,
    Setting,
    Som,
    SomLink,
    WmiFilter,
)
from gpo_lens.topology import effective_scope, scope_caveats


def _make_gpo(**kwargs) -> Gpo:
    defaults = {
        "id": "31b2f340-016d-11d2-945f-00c04fb984f9",
        "name": "Test GPO",
        "domain": "test.local",
        "created": None,
        "modified": None,
        "read": None,
        "computer_enabled": True,
        "user_enabled": True,
        "computer_ver_ds": None,
        "computer_ver_sysvol": None,
        "user_ver_ds": None,
        "user_ver_sysvol": None,
        "sddl": None,
        "owner": None,
        "filter_data_available": False,
        "wmi_filter": None,
        "sysvol_path": None,
    }
    defaults.update(kwargs)
    return Gpo(**defaults)


def _make_som(path: str, links: list[SomLink], **kwargs) -> Som:
    defaults = {
        "name": "TestOU",
        "container_type": "ou",
        "inheritance_blocked": False,
    }
    defaults.update(kwargs)
    return Som(path=path, links=links, **defaults)


# ---------------------------------------------------------------------------
# scope_caveats
# ---------------------------------------------------------------------------


class TestScopeCaveats:
    def test_loopback_gpo_yields_loopback_caveat(self) -> None:
        gpo = _make_gpo(
            id="gpo-lb",
            name="Loopback GPO",
            settings=[
                Setting(
                    gpo_id="gpo-lb",
                    side="Computer",
                    cse="Security",
                    identity="Configure user Group Policy loopback processing mode",
                    display_name="Loopback",
                    display_value="Replace",
                    raw={},
                    from_disabled_side=False,
                ),
            ],
            delegation=[
                DelegationEntry(
                    gpo_id="gpo-lb",
                    trustee="Authenticated Users",
                    trustee_sid="S-1-5-11",
                    permission="Read",
                    allowed=True,
                ),
            ],
        )
        som = _make_som(
            path="ou=ws,dc=test,dc=local",
            links=[
                SomLink(
                    gpo_id="gpo-lb",
                    order=1,
                    enabled=True,
                    enforced=False,
                    target="ou=ws,dc=test,dc=local",
                ),
            ],
        )
        estate = Estate(gpos=[gpo], soms=[som])
        caveats = scope_caveats(estate, "ou=ws,dc=test,dc=local")
        assert any("loopback" in c.lower() for c in caveats)

    def test_wmi_filtered_gpo_yields_wmi_caveat(self) -> None:
        gpo = _make_gpo(
            id="gpo-wmi",
            name="WMI GPO",
            wmi_filter="MyFilter",
            delegation=[
                DelegationEntry(
                    gpo_id="gpo-wmi",
                    trustee="Authenticated Users",
                    trustee_sid="S-1-5-11",
                    permission="Read",
                    allowed=True,
                ),
            ],
        )
        som = _make_som(
            path="ou=ws,dc=test,dc=local",
            links=[
                SomLink(
                    gpo_id="gpo-wmi",
                    order=1,
                    enabled=True,
                    enforced=False,
                    target="ou=ws,dc=test,dc=local",
                ),
            ],
        )
        estate = Estate(
            gpos=[gpo],
            soms=[som],
            wmi_filters=[WmiFilter(name="MyFilter", query="SELECT * FROM Win32_OperatingSystem")],
        )
        caveats = scope_caveats(estate, "ou=ws,dc=test,dc=local")
        assert any("wmi" in c.lower() for c in caveats)

    def test_nonexistent_som_returns_empty(self) -> None:
        estate = Estate(gpos=[], soms=[])
        caveats = scope_caveats(estate, "ou=missing,dc=test,dc=local")
        assert caveats == []

    def test_som_with_all_links_disabled_flags_caveat(self) -> None:
        # A SOM that exists but has every link disabled is a real, easily-missed
        # state: it should be flagged, not silently return no caveats.
        gpo = _make_gpo(id="gpo-1")
        som = _make_som(
            path="ou=ws,dc=test,dc=local",
            links=[
                SomLink(
                    gpo_id="gpo-1",
                    order=1,
                    enabled=False,
                    enforced=False,
                    target="ou=ws,dc=test,dc=local",
                ),
            ],
        )
        estate = Estate(gpos=[gpo], soms=[som])
        caveats = scope_caveats(estate, "ou=ws,dc=test,dc=local")
        assert any("disabled" in c.lower() for c in caveats)

    def test_security_filtered_gpo_yields_caveat(self) -> None:
        gpo = _make_gpo(
            id="gpo-sf",
            name="Filtered GPO",
            delegation=[
                DelegationEntry(
                    gpo_id="gpo-sf",
                    trustee="SomeGroup",
                    trustee_sid="S-1-5-21-999",
                    permission="Apply Group Policy",
                    allowed=True,
                ),
            ],
        )
        som = _make_som(
            path="ou=ws,dc=test,dc=local",
            links=[
                SomLink(
                    gpo_id="gpo-sf",
                    order=1,
                    enabled=True,
                    enforced=False,
                    target="ou=ws,dc=test,dc=local",
                ),
            ],
        )
        estate = Estate(gpos=[gpo], soms=[som])
        caveats = scope_caveats(estate, "ou=ws,dc=test,dc=local")
        assert any("security-filtered" in c.lower() for c in caveats)

    def test_ilt_gpo_yields_ilt_caveat(self, tmp_path: Path) -> None:
        gpo_dir = tmp_path / "gpo"
        prefs = gpo_dir / "User" / "Preferences"
        prefs.mkdir(parents=True)
        root = ET.Element("DriveMaps")
        drive = ET.SubElement(root, "DriveMap")
        filters = ET.SubElement(drive, "Filters")
        ET.SubElement(filters, "OrgUnit")
        ET.ElementTree(root).write(prefs / "DriveMaps.xml")

        gpo = _make_gpo(
            id="gpo-ilt",
            name="ILT GPO",
            sysvol_path=str(gpo_dir),
            delegation=[
                DelegationEntry(
                    gpo_id="gpo-ilt",
                    trustee="Authenticated Users",
                    trustee_sid="S-1-5-11",
                    permission="Read",
                    allowed=True,
                ),
            ],
        )
        som = _make_som(
            path="ou=ws,dc=test,dc=local",
            links=[
                SomLink(
                    gpo_id="gpo-ilt",
                    order=1,
                    enabled=True,
                    enforced=False,
                    target="ou=ws,dc=test,dc=local",
                ),
            ],
        )
        estate = Estate(gpos=[gpo], soms=[som])
        caveats = scope_caveats(estate, "ou=ws,dc=test,dc=local")
        assert any("item-level targeting" in c.lower() for c in caveats)

    def test_clean_gpo_no_caveats(self) -> None:
        gpo = _make_gpo(
            id="gpo-clean",
            name="Clean GPO",
            delegation=[
                DelegationEntry(
                    gpo_id="gpo-clean",
                    trustee="Authenticated Users",
                    trustee_sid="S-1-5-11",
                    permission="Read",
                    allowed=True,
                ),
            ],
        )
        som = _make_som(
            path="ou=ws,dc=test,dc=local",
            links=[
                SomLink(
                    gpo_id="gpo-clean",
                    order=1,
                    enabled=True,
                    enforced=False,
                    target="ou=ws,dc=test,dc=local",
                ),
            ],
        )
        estate = Estate(gpos=[gpo], soms=[som])
        caveats = scope_caveats(estate, "ou=ws,dc=test,dc=local")
        assert caveats == []


# ---------------------------------------------------------------------------
# effective_scope
# ---------------------------------------------------------------------------


class TestEffectiveScope:
    def test_resolves_by_id(self) -> None:
        gpo = _make_gpo(id="abc-123", name="My GPO", delegation=[])
        estate = Estate(gpos=[gpo])
        result = effective_scope(estate, "abc-123")
        assert result is not None
        assert result.gpo_id == "abc-123"
        assert result.gpo_name == "My GPO"

    def test_resolves_by_name(self) -> None:
        gpo = _make_gpo(id="abc-123", name="My GPO", delegation=[])
        estate = Estate(gpos=[gpo])
        result = effective_scope(estate, "My GPO")
        assert result is not None
        assert result.gpo_id == "abc-123"

    def test_resolves_by_name_case_insensitive(self) -> None:
        gpo = _make_gpo(id="abc-123", name="My GPO", delegation=[])
        estate = Estate(gpos=[gpo])
        result = effective_scope(estate, "my gpo")
        assert result is not None
        assert result.gpo_id == "abc-123"

    def test_returns_none_for_unknown(self) -> None:
        estate = Estate(gpos=[])
        assert effective_scope(estate, "nonexistent") is None

    def test_populates_caveats_list(self) -> None:
        gpo = _make_gpo(
            id="gpo-wmi",
            name="WMI GPO",
            wmi_filter="MyFilter",
            delegation=[
                DelegationEntry(
                    gpo_id="gpo-wmi",
                    trustee="Authenticated Users",
                    trustee_sid="S-1-5-11",
                    permission="Read",
                    allowed=True,
                ),
            ],
        )
        estate = Estate(
            gpos=[gpo],
            wmi_filters=[WmiFilter(name="MyFilter", query="SELECT * FROM Win32_OperatingSystem")],
        )
        result = effective_scope(estate, "gpo-wmi")
        assert result is not None
        assert len(result.caveats) > 0
        assert any("wmi" in c.lower() for c in result.caveats)

    def test_loopback_mode_populated(self) -> None:
        gpo = _make_gpo(
            id="gpo-lb",
            name="Loopback GPO",
            settings=[
                Setting(
                    gpo_id="gpo-lb",
                    side="Computer",
                    cse="Security",
                    identity="Configure user Group Policy loopback processing mode",
                    display_name="Loopback",
                    display_value="Merge",
                    raw={},
                    from_disabled_side=False,
                ),
            ],
            delegation=[
                DelegationEntry(
                    gpo_id="gpo-lb",
                    trustee="Authenticated Users",
                    trustee_sid="S-1-5-11",
                    permission="Read",
                    allowed=True,
                ),
            ],
        )
        estate = Estate(gpos=[gpo])
        result = effective_scope(estate, "gpo-lb")
        assert result is not None
        assert result.loopback_mode == "merge"
        assert any("loopback" in c.lower() for c in result.caveats)

    def test_no_links_yields_no_links_caveat(self) -> None:
        gpo = _make_gpo(
            id="gpo-unlinked",
            name="Unlinked GPO",
            links=[],
            delegation=[
                DelegationEntry(
                    gpo_id="gpo-unlinked",
                    trustee="Authenticated Users",
                    trustee_sid="S-1-5-11",
                    permission="Read",
                    allowed=True,
                ),
            ],
        )
        estate = Estate(gpos=[gpo])
        result = effective_scope(estate, "gpo-unlinked")
        assert result is not None
        assert any("no links" in c.lower() for c in result.caveats)

    def test_broken_wmi_filter_caveat(self) -> None:
        gpo = _make_gpo(
            id="gpo-bw",
            name="Broken WMI GPO",
            wmi_filter="MissingFilter",
            delegation=[
                DelegationEntry(
                    gpo_id="gpo-bw",
                    trustee="Authenticated Users",
                    trustee_sid="S-1-5-11",
                    permission="Read",
                    allowed=True,
                ),
            ],
        )
        estate = Estate(gpos=[gpo], wmi_filters=[])
        result = effective_scope(estate, "gpo-bw")
        assert result is not None
        assert any("broken" in c.lower() for c in result.caveats)

    def test_id_with_braces_stripped(self) -> None:
        gpo = _make_gpo(id="abc-123", name="Braced GPO", delegation=[])
        estate = Estate(gpos=[gpo])
        result = effective_scope(estate, "{abc-123}")
        assert result is not None
        assert result.gpo_id == "abc-123"


# ---------------------------------------------------------------------------
# scan_ilt
# ---------------------------------------------------------------------------


class TestScanIlt:
    def test_gpp_xml_with_filters_detected(self, tmp_path: Path) -> None:
        gpo_dir = tmp_path / "gpo"
        prefs = gpo_dir / "User" / "Preferences"
        prefs.mkdir(parents=True)
        root = ET.Element("DriveMaps")
        drive = ET.SubElement(root, "DriveMap")
        filters = ET.SubElement(drive, "Filters")
        ET.SubElement(filters, "OrgUnit")
        ET.SubElement(filters, "IpRange")
        ET.ElementTree(root).write(prefs / "DriveMaps.xml")

        gpo = _make_gpo(
            id="gpo-ilt",
            name="ILT GPO",
            sysvol_path=str(gpo_dir),
        )
        estate = Estate(gpos=[gpo])
        hits = scan_ilt(estate)
        assert len(hits) == 1
        assert hits[0].gpo_id == "gpo-ilt"
        assert "IpRange" in hits[0].filter_types
        assert "OrgUnit" in hits[0].filter_types

    def test_one_ilt_hit_per_gpo(self, tmp_path: Path) -> None:
        gpo_dir = tmp_path / "gpo"
        mach_prefs = gpo_dir / "Machine" / "Preferences"
        user_prefs = gpo_dir / "User" / "Preferences"
        mach_prefs.mkdir(parents=True)
        user_prefs.mkdir(parents=True)

        root1 = ET.Element("ScheduledTasks")
        task = ET.SubElement(root1, "Task")
        filters1 = ET.SubElement(task, "Filters")
        ET.SubElement(filters1, "Battery")
        ET.ElementTree(root1).write(mach_prefs / "ScheduledTasks.xml")

        root2 = ET.Element("DriveMaps")
        drive = ET.SubElement(root2, "DriveMap")
        filters2 = ET.SubElement(drive, "Filters")
        ET.SubElement(filters2, "OrgUnit")
        ET.ElementTree(root2).write(user_prefs / "DriveMaps.xml")

        gpo = _make_gpo(
            id="gpo-multi",
            name="Multi ILT GPO",
            sysvol_path=str(gpo_dir),
        )
        estate = Estate(gpos=[gpo])
        hits = scan_ilt(estate)
        assert len(hits) == 1
        assert hits[0].gpo_id == "gpo-multi"
        assert "Battery" in hits[0].filter_types
        assert "OrgUnit" in hits[0].filter_types

    def test_no_filters_no_hit(self, tmp_path: Path) -> None:
        gpo_dir = tmp_path / "gpo"
        prefs = gpo_dir / "User" / "Preferences"
        prefs.mkdir(parents=True)
        root = ET.Element("DriveMaps")
        ET.SubElement(root, "DriveMap")
        ET.ElementTree(root).write(prefs / "DriveMaps.xml")

        gpo = _make_gpo(
            id="gpo-no-ilt",
            name="No ILT GPO",
            sysvol_path=str(gpo_dir),
        )
        estate = Estate(gpos=[gpo])
        hits = scan_ilt(estate)
        assert hits == []

    def test_no_sysvol_path_no_hit(self) -> None:
        gpo = _make_gpo(id="gpo-nosysvol", name="No Sysvol GPO")
        estate = Estate(gpos=[gpo])
        assert scan_ilt(estate) == []

    def test_multiple_gpos_each_get_hit(self, tmp_path: Path) -> None:
        hits_expected = []
        gpos = []
        for i in range(3):
            gpo_dir = tmp_path / f"gpo-{i}"
            prefs = gpo_dir / "User" / "Preferences"
            prefs.mkdir(parents=True)
            root = ET.Element("DriveMaps")
            drive = ET.SubElement(root, "DriveMap")
            filters = ET.SubElement(drive, "Filters")
            ET.SubElement(filters, "OrgUnit")
            ET.ElementTree(root).write(prefs / "DriveMaps.xml")

            gid = f"gpo-ilt-{i}"
            gpos.append(_make_gpo(id=gid, name=f"ILT GPO {i}", sysvol_path=str(gpo_dir)))
            hits_expected.append(gid)

        estate = Estate(gpos=gpos)
        hits = scan_ilt(estate)
        assert len(hits) == 3
        assert {h.gpo_id for h in hits} == set(hits_expected)
