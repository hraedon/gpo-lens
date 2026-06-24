"""Unit tests for scope-honesty features in topology.py.

Covers scope_caveats, effective_scope, scan_ilt edge cases, and the
is_security_filtered / broad_trustee_key SID-matching rules (including the tightened
Domain Computers check that requires the S-1-5-21-* prefix).
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


# ---------------------------------------------------------------------------
# is_security_filtered / broad_trustee_key — SID matching
# ---------------------------------------------------------------------------


class TestBroadTrusteeSidMatching:
    """Domain Computers is S-1-5-21-{domain}-515. The -515 suffix check must
    be scoped to domain SIDs so a non-domain SID ending in 515 doesn't
    false-match (which would mask a real security-filtering finding)."""

    def test_dc_sid_with_domain_prefix_matches(self) -> None:
        from gpo_lens.authz import SCOPE_BROAD_TRUSTEES, broad_trustee_key

        result = broad_trustee_key("x", "S-1-5-21-123-456-515", SCOPE_BROAD_TRUSTEES)
        assert result == "domain_computers"

    def test_builtin_sid_ending_in_515_does_not_match(self) -> None:
        from gpo_lens.authz import SCOPE_BROAD_TRUSTEES, broad_trustee_key

        # S-1-5-32-515 is in the builtin domain, not a domain principal.
        assert broad_trustee_key("x", "S-1-5-32-515", SCOPE_BROAD_TRUSTEES) is None

    def test_arbitrary_sid_ending_in_515_does_not_match(self) -> None:
        from gpo_lens.authz import SCOPE_BROAD_TRUSTEES, broad_trustee_key

        assert broad_trustee_key("x", "S-1-2-3-515", SCOPE_BROAD_TRUSTEES) is None

    def test_name_match_still_works_without_sid(self) -> None:
        from gpo_lens.authz import SCOPE_BROAD_TRUSTEES, broad_trustee_key

        result = broad_trustee_key("Domain Computers", None, SCOPE_BROAD_TRUSTEES)
        assert result == "domain_computers"

    def test_is_security_filtered_flags_gpo_with_only_bogus_515_sid(self) -> None:
        """A GPO whose only 'broad' trustee is a non-domain SID ending in 515
        is genuinely filtered — the bogus SID must not count as Domain Computers."""
        gpo = _make_gpo(
            id="gpo-sf",
            delegation=[
                DelegationEntry(
                    gpo_id="gpo-sf",
                    trustee="NotDC",
                    trustee_sid="S-1-5-32-515",
                    permission="Read",
                    allowed=True,
                ),
            ],
        )
        from gpo_lens.topology import is_security_filtered

        assert is_security_filtered(gpo) is True

    def test_is_security_filtered_passes_with_real_dc_sid(self) -> None:
        gpo = _make_gpo(
            id="gpo-ok",
            delegation=[
                DelegationEntry(
                    gpo_id="gpo-ok",
                    trustee="DC",
                    trustee_sid="S-1-5-21-999-515",
                    permission="Apply Group Policy",
                    allowed=True,
                ),
            ],
        )
        from gpo_lens.topology import is_security_filtered

        assert is_security_filtered(gpo) is False


# ---------------------------------------------------------------------------
# is_security_filtered — Everyone, deny-ACE precedence, empty delegation
# ---------------------------------------------------------------------------


class TestIsSecurityFilteredEveryone:
    """Everyone (S-1-1-0) is a broad trustee. A GPO delegated to Everyone
    with Allow Read or Allow Apply is not security-filtered."""

    def test_everyone_allow_read_not_filtered(self) -> None:
        from gpo_lens.topology import is_security_filtered

        gpo = _make_gpo(
            id="gpo-everyone-read",
            delegation=[
                DelegationEntry(
                    gpo_id="gpo-everyone-read",
                    trustee="Everyone",
                    trustee_sid="S-1-1-0",
                    permission="Read",
                    allowed=True,
                ),
            ],
        )
        assert is_security_filtered(gpo) is False

    def test_everyone_allow_apply_not_filtered(self) -> None:
        from gpo_lens.topology import is_security_filtered

        gpo = _make_gpo(
            id="gpo-everyone-apply",
            delegation=[
                DelegationEntry(
                    gpo_id="gpo-everyone-apply",
                    trustee="Everyone",
                    trustee_sid="S-1-1-0",
                    permission="Apply Group Policy",
                    allowed=True,
                ),
            ],
        )
        assert is_security_filtered(gpo) is False

    def test_everyone_matched_by_sid_only(self) -> None:
        from gpo_lens.topology import is_security_filtered

        gpo = _make_gpo(
            id="gpo-everyone-sid",
            delegation=[
                DelegationEntry(
                    gpo_id="gpo-everyone-sid",
                    trustee="All Users",
                    trustee_sid="S-1-1-0",
                    permission="Read",
                    allowed=True,
                ),
            ],
        )
        assert is_security_filtered(gpo) is False

    def test_everyone_name_match_without_sid(self) -> None:
        from gpo_lens.topology import is_security_filtered

        gpo = _make_gpo(
            id="gpo-everyone-name",
            delegation=[
                DelegationEntry(
                    gpo_id="gpo-everyone-name",
                    trustee="Everyone",
                    trustee_sid=None,
                    permission="Read",
                    allowed=True,
                ),
            ],
        )
        assert is_security_filtered(gpo) is False


class TestIsSecurityFilteredDenyPrecedence:
    """Deny ACEs override allow ACEs for the same broad trustee. A broad
    trustee whose allow is countered by a deny on that same trustee does
    not count as broad application."""

    def test_au_allow_plus_au_deny_same_trustee(self) -> None:
        from gpo_lens.topology import is_security_filtered

        gpo = _make_gpo(
            id="gpo-au-deny",
            delegation=[
                DelegationEntry(
                    gpo_id="gpo-au-deny",
                    trustee="Authenticated Users",
                    trustee_sid="S-1-5-11",
                    permission="Read",
                    allowed=True,
                ),
                DelegationEntry(
                    gpo_id="gpo-au-deny",
                    trustee="Authenticated Users",
                    trustee_sid="S-1-5-11",
                    permission="Read",
                    allowed=False,
                ),
            ],
        )
        assert is_security_filtered(gpo) is True

    def test_au_allow_plus_da_deny_different_trustee(self) -> None:
        from gpo_lens.topology import is_security_filtered

        gpo = _make_gpo(
            id="gpo-au-allow-da-deny",
            delegation=[
                DelegationEntry(
                    gpo_id="gpo-au-allow-da-deny",
                    trustee="Authenticated Users",
                    trustee_sid="S-1-5-11",
                    permission="Read",
                    allowed=True,
                ),
                DelegationEntry(
                    gpo_id="gpo-au-allow-da-deny",
                    trustee="Domain Admins",
                    trustee_sid="S-1-5-21-999-512",
                    permission="Read",
                    allowed=False,
                ),
            ],
        )
        assert is_security_filtered(gpo) is False

    def test_everyone_allow_plus_everyone_deny(self) -> None:
        from gpo_lens.topology import is_security_filtered

        gpo = _make_gpo(
            id="gpo-everyone-both",
            delegation=[
                DelegationEntry(
                    gpo_id="gpo-everyone-both",
                    trustee="Everyone",
                    trustee_sid="S-1-1-0",
                    permission="Apply Group Policy",
                    allowed=True,
                ),
                DelegationEntry(
                    gpo_id="gpo-everyone-both",
                    trustee="Everyone",
                    trustee_sid="S-1-1-0",
                    permission="Apply Group Policy",
                    allowed=False,
                ),
            ],
        )
        assert is_security_filtered(gpo) is True

    def test_au_allow_plus_dc_deny_not_same_trustee(self) -> None:
        from gpo_lens.topology import is_security_filtered

        gpo = _make_gpo(
            id="gpo-au-allow-dc-deny",
            delegation=[
                DelegationEntry(
                    gpo_id="gpo-au-allow-dc-deny",
                    trustee="Authenticated Users",
                    trustee_sid="S-1-5-11",
                    permission="Read",
                    allowed=True,
                ),
                DelegationEntry(
                    gpo_id="gpo-au-allow-dc-deny",
                    trustee="Domain Computers",
                    trustee_sid="S-1-5-21-999-515",
                    permission="Read",
                    allowed=False,
                ),
            ],
        )
        assert is_security_filtered(gpo) is False


class TestIsSecurityFilteredEmptyDelegation:
    """Empty delegation → not filtered (absence of data is not evidence of
    filtering). Only non-broad trustees → filtered (narrowed)."""

    def test_empty_delegation_not_filtered(self) -> None:
        from gpo_lens.topology import is_security_filtered

        gpo = _make_gpo(id="gpo-no-deleg", delegation=[])
        assert is_security_filtered(gpo) is False

    def test_only_non_broad_trustee_is_filtered(self) -> None:
        from gpo_lens.topology import is_security_filtered

        gpo = _make_gpo(
            id="gpo-narrow-only",
            delegation=[
                DelegationEntry(
                    gpo_id="gpo-narrow-only",
                    trustee="Helpdesk Operators",
                    trustee_sid="S-1-5-21-999-1000",
                    permission="Apply Group Policy",
                    allowed=True,
                ),
            ],
        )
        assert is_security_filtered(gpo) is True

    def test_delegation_edit_settings_is_read_implying(self) -> None:
        """'Edit settings' includes Read per Microsoft's GPOGroupedAccessEnum,
        so a GPO with AU 'Edit settings' is NOT security-filtered (WI-047
        consolidated the permission predicate)."""
        from gpo_lens.topology import is_security_filtered

        gpo = _make_gpo(
            id="gpo-edit-only",
            delegation=[
                DelegationEntry(
                    gpo_id="gpo-edit-only",
                    trustee="Authenticated Users",
                    trustee_sid="S-1-5-11",
                    permission="Edit settings",
                    allowed=True,
                ),
            ],
        )
        assert is_security_filtered(gpo) is False


class TestIsSecurityFilteredSddlFallback:
    """When delegation is empty but SDDL is present, parse the SDDL DACL
    to check for broad trustees. This catches GPOs whose report carries
    SDDL but no Permissions sub-element."""

    def test_sddl_with_au_ga_not_filtered(self) -> None:
        from gpo_lens.topology import is_security_filtered

        gpo = _make_gpo(
            id="gpo-sddl-au",
            sddl="O:SYG:SYD:(A;;GA;;;S-1-5-11)",
            delegation=[],
        )
        assert is_security_filtered(gpo) is False

    def test_sddl_with_au_gr_not_filtered(self) -> None:
        from gpo_lens.topology import is_security_filtered

        gpo = _make_gpo(
            id="gpo-sddl-au-gr",
            sddl="O:SYG:SYD:(A;;GR;;;S-1-5-11)",
            delegation=[],
        )
        assert is_security_filtered(gpo) is False

    def test_sddl_with_everyone_ga_not_filtered(self) -> None:
        from gpo_lens.topology import is_security_filtered

        gpo = _make_gpo(
            id="gpo-sddl-everyone",
            sddl="O:SYG:SYD:(A;;GA;;;S-1-1-0)",
            delegation=[],
        )
        assert is_security_filtered(gpo) is False

    def test_sddl_with_dc_gr_not_filtered(self) -> None:
        from gpo_lens.topology import is_security_filtered

        gpo = _make_gpo(
            id="gpo-sddl-dc",
            sddl="O:SYG:SYD:(A;;GR;;;S-1-5-21-111-222-515)",
            delegation=[],
        )
        assert is_security_filtered(gpo) is False

    def test_sddl_with_only_narrow_trustee_filtered(self) -> None:
        from gpo_lens.topology import is_security_filtered

        gpo = _make_gpo(
            id="gpo-sddl-narrow",
            sddl="O:SYG:SYD:(A;;GA;;;S-1-5-21-111-222-1234)",
            delegation=[],
        )
        assert is_security_filtered(gpo) is True

    def test_sddl_with_au_deny_filtered(self) -> None:
        from gpo_lens.topology import is_security_filtered

        gpo = _make_gpo(
            id="gpo-sddl-deny",
            sddl="O:SYG:SYD:(D;;GA;;;S-1-5-11)",
            delegation=[],
        )
        assert is_security_filtered(gpo) is True

    def test_sddl_au_allow_plus_au_deny_same_trustee(self) -> None:
        from gpo_lens.topology import is_security_filtered

        gpo = _make_gpo(
            id="gpo-sddl-both",
            sddl="O:SYG:SYD:(A;;GA;;;S-1-5-11)(D;;GA;;;S-1-5-11)",
            delegation=[],
        )
        assert is_security_filtered(gpo) is True

    def test_sddl_au_allow_plus_da_deny_different_trustee(self) -> None:
        from gpo_lens.topology import is_security_filtered

        gpo = _make_gpo(
            id="gpo-sddl-cross",
            sddl="O:SYG:SYD:(A;;GA;;;S-1-5-11)(D;;GA;;;S-1-5-21-111-222-512)",
            delegation=[],
        )
        assert is_security_filtered(gpo) is False

    def test_sddl_no_delegation_no_sddl_not_filtered(self) -> None:
        from gpo_lens.topology import is_security_filtered

        gpo = _make_gpo(id="gpo-none", sddl=None, delegation=[])
        assert is_security_filtered(gpo) is False

    def test_sddl_delegation_takes_precedence_over_sddl(self) -> None:
        from gpo_lens.topology import is_security_filtered

        gpo = _make_gpo(
            id="gpo-both-paths",
            sddl="O:SYG:SYD:(A;;GA;;;S-1-5-11)",
            delegation=[
                DelegationEntry(
                    gpo_id="gpo-both-paths",
                    trustee="Helpdesk",
                    trustee_sid="S-1-5-21-999-1000",
                    permission="Apply Group Policy",
                    allowed=True,
                ),
            ],
        )
        assert is_security_filtered(gpo) is True

    def test_sddl_detail_has_au_read(self) -> None:
        from gpo_lens.topology import security_filtering_detail

        gpo = _make_gpo(
            id="gpo-sddl-detail-au",
            sddl="O:SYG:SYD:(A;;GR;;;S-1-5-11)",
            delegation=[],
        )
        detail = security_filtering_detail(gpo)
        assert detail.has_au_read is True
        assert detail.has_dc_read is False
        assert detail.is_filtered is False

    def test_sddl_detail_has_dc_read(self) -> None:
        from gpo_lens.topology import security_filtering_detail

        gpo = _make_gpo(
            id="gpo-sddl-detail-dc",
            sddl="O:SYG:SYD:(A;;GR;;;S-1-5-21-111-222-515)",
            delegation=[],
        )
        detail = security_filtering_detail(gpo)
        assert detail.has_au_read is False
        assert detail.has_dc_read is True
        assert detail.is_filtered is False

    def test_sddl_default_dacl_concatenated_rights_not_filtered(self) -> None:
        from gpo_lens.topology import is_security_filtered

        gpo = _make_gpo(
            id="gpo-sddl-default-dacl",
            sddl="O:SYG:SYD:(A;;RPWPCCDCLCSWRCWDWOGA;;;S-1-5-11)",
            delegation=[],
        )
        assert is_security_filtered(gpo) is False

    def test_sddl_object_deny_treated_as_deny(self) -> None:
        from gpo_lens.topology import is_security_filtered

        gpo = _make_gpo(
            id="gpo-sddl-oden",
            sddl="O:SYG:SYD:(A;;GA;;;S-1-5-11)(OD;;GA;;;S-1-5-11)",
            delegation=[],
        )
        assert is_security_filtered(gpo) is True

    def test_sddl_object_allow_treated_as_allow(self) -> None:
        from gpo_lens.topology import is_security_filtered

        gpo = _make_gpo(
            id="gpo-sddl-oallow",
            sddl="O:SYG:SYD:(OA;;GA;;;S-1-5-11)",
            delegation=[],
        )
        assert is_security_filtered(gpo) is False

    def test_sddl_empty_string_not_filtered(self) -> None:
        from gpo_lens.topology import is_security_filtered

        gpo = _make_gpo(id="gpo-sddl-empty", sddl="", delegation=[])
        assert is_security_filtered(gpo) is False

    def test_sddl_malformed_not_filtered(self) -> None:
        from gpo_lens.topology import is_security_filtered

        gpo = _make_gpo(id="gpo-sddl-bad", sddl="not-an-sddl", delegation=[])
        assert is_security_filtered(gpo) is False

    def test_sddl_sacl_only_not_filtered(self) -> None:
        from gpo_lens.topology import is_security_filtered

        gpo = _make_gpo(
            id="gpo-sddl-sacl",
            sddl="O:SYG:SYS:(AU;SA;GA;;;S-1-5-11)",
            delegation=[],
        )
        assert is_security_filtered(gpo) is False

    def test_sddl_detail_default_dacl_has_au_read(self) -> None:
        from gpo_lens.topology import security_filtering_detail

        gpo = _make_gpo(
            id="gpo-sddl-detail-default",
            sddl="O:SYG:SYD:(A;;RPWPCCDCLCSWRCWDWOGA;;;S-1-5-11)",
            delegation=[],
        )
        detail = security_filtering_detail(gpo)
        assert detail.has_au_read is True
        assert detail.is_filtered is False


class TestIsSecurityFilteredMixed:
    """Mixed scenarios with multiple broad trustees and deny ACEs."""

    def test_au_allow_dc_allow_narrow_deny(self) -> None:
        from gpo_lens.topology import is_security_filtered

        gpo = _make_gpo(
            id="gpo-mixed-1",
            delegation=[
                DelegationEntry(
                    gpo_id="gpo-mixed-1",
                    trustee="Authenticated Users",
                    trustee_sid="S-1-5-11",
                    permission="Read",
                    allowed=True,
                ),
                DelegationEntry(
                    gpo_id="gpo-mixed-1",
                    trustee="Domain Computers",
                    trustee_sid="S-1-5-21-999-515",
                    permission="Read",
                    allowed=True,
                ),
                DelegationEntry(
                    gpo_id="gpo-mixed-1",
                    trustee="Helpdesk Operators",
                    trustee_sid="S-1-5-21-999-1000",
                    permission="Read",
                    allowed=False,
                ),
            ],
        )
        assert is_security_filtered(gpo) is False

    def test_two_broad_one_allowed_one_denied(self) -> None:
        from gpo_lens.topology import is_security_filtered

        gpo = _make_gpo(
            id="gpo-mixed-2",
            delegation=[
                DelegationEntry(
                    gpo_id="gpo-mixed-2",
                    trustee="Authenticated Users",
                    trustee_sid="S-1-5-11",
                    permission="Read",
                    allowed=True,
                ),
                DelegationEntry(
                    gpo_id="gpo-mixed-2",
                    trustee="Domain Computers",
                    trustee_sid="S-1-5-21-999-515",
                    permission="Read",
                    allowed=False,
                ),
            ],
        )
        assert is_security_filtered(gpo) is False

    def test_au_denied_but_everyone_allowed(self) -> None:
        from gpo_lens.topology import is_security_filtered

        gpo = _make_gpo(
            id="gpo-mixed-3",
            delegation=[
                DelegationEntry(
                    gpo_id="gpo-mixed-3",
                    trustee="Authenticated Users",
                    trustee_sid="S-1-5-11",
                    permission="Read",
                    allowed=False,
                ),
                DelegationEntry(
                    gpo_id="gpo-mixed-3",
                    trustee="Everyone",
                    trustee_sid="S-1-1-0",
                    permission="Read",
                    allowed=True,
                ),
            ],
        )
        assert is_security_filtered(gpo) is False


# ---------------------------------------------------------------------------
# is_security_filtered — golden behavior-preservation matrix
# ---------------------------------------------------------------------------


class TestSecurityFilteringGolden:
    """Synthetic cases that pin the current scope-honesty semantics.

    These exist to detect behavior drift during the authz refactor; they must
    pass both before and after the shared substrate is extracted.
    """

    def test_broad_read_not_filtered(self) -> None:
        from gpo_lens.topology import is_security_filtered

        gpo = _make_gpo(
            id="gpo-au-read",
            delegation=[
                DelegationEntry(
                    gpo_id="gpo-au-read",
                    trustee="Authenticated Users",
                    trustee_sid="S-1-5-11",
                    permission="Read",
                    allowed=True,
                ),
            ],
        )
        assert is_security_filtered(gpo) is False

    def test_broad_apply_not_filtered(self) -> None:
        from gpo_lens.topology import is_security_filtered

        gpo = _make_gpo(
            id="gpo-au-apply",
            delegation=[
                DelegationEntry(
                    gpo_id="gpo-au-apply",
                    trustee="Authenticated Users",
                    trustee_sid="S-1-5-11",
                    permission="Apply Group Policy",
                    allowed=True,
                ),
            ],
        )
        assert is_security_filtered(gpo) is False

    def test_everyone_not_filtered(self) -> None:
        from gpo_lens.topology import is_security_filtered

        gpo = _make_gpo(
            id="gpo-everyone",
            delegation=[
                DelegationEntry(
                    gpo_id="gpo-everyone",
                    trustee="Everyone",
                    trustee_sid="S-1-1-0",
                    permission="Read",
                    allowed=True,
                ),
            ],
        )
        assert is_security_filtered(gpo) is False

    def test_edit_settings_is_not_filtered(self) -> None:
        """'Edit settings' includes Read per GPOGroupedAccessEnum, so a GPO
        with AU 'Edit settings' is NOT security-filtered (WI-047)."""
        from gpo_lens.topology import is_security_filtered

        gpo = _make_gpo(
            id="gpo-edit",
            delegation=[
                DelegationEntry(
                    gpo_id="gpo-edit",
                    trustee="Authenticated Users",
                    trustee_sid="S-1-5-11",
                    permission="Edit settings",
                    allowed=True,
                ),
            ],
        )
        assert is_security_filtered(gpo) is False

    def test_sddl_only_with_object_allow_not_filtered(self) -> None:
        from gpo_lens.topology import is_security_filtered

        gpo = _make_gpo(
            id="gpo-sddl-object-allow",
            sddl="O:SYG:SYD:(OA;;GR;;;S-1-5-11)",
            delegation=[],
        )
        assert is_security_filtered(gpo) is False

    def test_sddl_only_with_object_deny_filtered(self) -> None:
        from gpo_lens.topology import is_security_filtered

        gpo = _make_gpo(
            id="gpo-sddl-object-deny",
            sddl="O:SYG:SYD:(OD;;GR;;;S-1-5-11)",
            delegation=[],
        )
        assert is_security_filtered(gpo) is True

    def test_sddl_concatenated_rights_not_filtered(self) -> None:
        from gpo_lens.topology import is_security_filtered

        gpo = _make_gpo(
            id="gpo-sddl-concat",
            sddl="O:SYG:SYD:(A;;RPWPCCDCLCSWRCWDWOGA;;;S-1-5-21-111-222-515)",
            delegation=[],
        )
        assert is_security_filtered(gpo) is False

    def test_sddl_malformed_is_filtered_false(self) -> None:
        from gpo_lens.topology import is_security_filtered

        gpo = _make_gpo(
            id="gpo-sddl-bad",
            sddl="ThisIsNotSDDL",
            delegation=[],
        )
        assert is_security_filtered(gpo) is False

    def test_delegation_with_deny_override_filtered(self) -> None:
        from gpo_lens.topology import is_security_filtered

        gpo = _make_gpo(
            id="gpo-deny-overrides",
            delegation=[
                DelegationEntry(
                    gpo_id="gpo-deny-overrides",
                    trustee="Domain Computers",
                    trustee_sid="S-1-5-21-999-515",
                    permission="Read",
                    allowed=True,
                ),
                DelegationEntry(
                    gpo_id="gpo-deny-overrides",
                    trustee="Domain Computers",
                    trustee_sid="S-1-5-21-999-515",
                    permission="Read",
                    allowed=False,
                ),
            ],
        )
        assert is_security_filtered(gpo) is True

    def test_narrow_trustee_with_apply_is_filtered(self) -> None:
        from gpo_lens.topology import is_security_filtered

        gpo = _make_gpo(
            id="gpo-narrow",
            delegation=[
                DelegationEntry(
                    gpo_id="gpo-narrow",
                    trustee="Helpdesk Operators",
                    trustee_sid="S-1-5-21-999-1000",
                    permission="Apply Group Policy",
                    allowed=True,
                ),
            ],
        )
        assert is_security_filtered(gpo) is True

    def test_security_filtering_detail_au_apply_sets_read_and_apply(self) -> None:
        from gpo_lens.topology import security_filtering_detail

        gpo = _make_gpo(
            id="gpo-detail-apply",
            delegation=[
                DelegationEntry(
                    gpo_id="gpo-detail-apply",
                    trustee="Authenticated Users",
                    trustee_sid="S-1-5-11",
                    permission="Apply Group Policy",
                    allowed=True,
                ),
            ],
        )
        detail = security_filtering_detail(gpo)
        # Apply Group Policy contributes to has_au_read in the detail view.
        assert detail.has_au_read is True
        assert detail.is_filtered is False
        assert "Authenticated Users" in detail.apply_trustees


# ---- principal resolution in SDDL fallback (Plan 020 A.4) ------------------


class TestSddlFallbackPrincipalResolution:
    def test_sddl_fallback_resolves_broad_trustee_to_name(self) -> None:
        """SDDL fallback populates apply_trustees with resolved names."""
        from gpo_lens.topology import security_filtering_detail

        gpo = _make_gpo(
            id="gpo-sddl-resolve",
            sddl="O:SYG:SYD:(A;;GA;;;S-1-5-11)",
            delegation=[],
        )
        estate = Estate(gpos=[gpo])
        detail = security_filtering_detail(gpo, estate)
        assert "Authenticated Users" in detail.apply_trustees

    def test_sddl_fallback_without_estate_degrades_gracefully(self) -> None:
        """Without estate, the SDDL fallback still resolves well-known SIDs."""
        from gpo_lens.topology import security_filtering_detail

        gpo = _make_gpo(
            id="gpo-sddl-no-estate",
            sddl="O:SYG:SYD:(A;;GA;;;S-1-5-11)",
            delegation=[],
        )
        detail = security_filtering_detail(gpo)
        assert detail.has_au_read is True
        assert detail.is_filtered is False

    def test_sddl_fallback_verdict_invariant_with_estate(self) -> None:
        """AC-5: is_filtered is identical with/without estate."""
        from gpo_lens.topology import security_filtering_detail

        gpo = _make_gpo(
            id="gpo-sddl-invariant",
            sddl="O:SYG:SYD:(A;;GA;;;S-1-5-11)",
            delegation=[],
        )
        estate = Estate(gpos=[gpo])
        bare = security_filtering_detail(gpo)
        resolved = security_filtering_detail(gpo, estate)
        assert bare.is_filtered == resolved.is_filtered
        assert bare.has_au_read == resolved.has_au_read
        assert bare.has_dc_read == resolved.has_dc_read

    def test_delegation_path_keeps_existing_names(self) -> None:
        """Delegation already provides names — estate resolution is not needed."""
        from gpo_lens.topology import security_filtering_detail

        gpo = _make_gpo(
            id="gpo-deleg-name",
            delegation=[
                DelegationEntry(
                    gpo_id="gpo-deleg-name",
                    trustee="Custom Filter Group",
                    trustee_sid="S-1-5-21-100-200-300-9999",
                    permission="Apply Group Policy",
                    allowed=True,
                ),
            ],
        )
        estate = Estate(gpos=[gpo])
        detail = security_filtering_detail(gpo, estate)
        assert "Custom Filter Group" in detail.apply_trustees
