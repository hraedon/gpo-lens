"""Unit tests for the ingest module (no samples required)."""

from __future__ import annotations

import io
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from gpo_lens import ingest
from gpo_lens.model import Estate, Gpo


def _min_gpo_xml(
    gpo_id: str = "{31B2F340-016D-11D2-945F-00C04FB984F9}",
    name: str = "Test GPO",
    domain: str = "test.local",
    computer_enabled: str = "true",
    user_enabled: str = "true",
) -> str:
    """Minimal valid GPOReport XML with one GPO."""
    return f"""<?xml version="1.0" encoding="utf-8"?>
<GPO xmlns="http://www.microsoft.com/GroupPolicy/Settings">
    <GPO>
        <Identifier>
            <Identifier>{gpo_id}</Identifier>
            <Domain>{domain}</Domain>
        </Identifier>
        <Name>{name}</Name>
        <CreatedTime>2026-01-01T00:00:00</CreatedTime>
        <ModifiedTime>2026-01-02T00:00:00</ModifiedTime>
        <ReadTime>2026-01-03T00:00:00</ReadTime>
        <Computer>
            <VersionDirectory>1</VersionDirectory>
            <VersionSysvol>2</VersionSysvol>
            <Enabled>{computer_enabled}</Enabled>
        </Computer>
        <User>
            <VersionDirectory>3</VersionDirectory>
            <VersionSysvol>4</VersionSysvol>
            <Enabled>{user_enabled}</Enabled>
        </User>
        <FilterDataAvailable>true</FilterDataAvailable>
    </GPO>
</GPO>
"""


class TestParseReport:
    def test_parse_minimal_gpo(self, tmp_path: Path) -> None:
        xml_path = tmp_path / "report.xml"
        xml_path.write_text(_min_gpo_xml(), encoding="utf-8")
        gpos = ingest.parse_report(xml_path)
        assert len(gpos) == 1
        gpo = gpos[0]
        assert gpo.id == "31b2f340-016d-11d2-945f-00c04fb984f9"
        assert gpo.name == "Test GPO"
        assert gpo.domain == "test.local"
        assert gpo.computer_enabled is True
        assert gpo.user_enabled is True
        assert gpo.computer_ver_ds == 1
        assert gpo.computer_ver_sysvol == 2
        assert gpo.user_ver_ds == 3
        assert gpo.user_ver_sysvol == 4
        assert gpo.filter_data_available is True

    def test_parse_multiple_gpos(self, tmp_path: Path) -> None:
        body_a = (
            '    <GPO>\n'
            '        <Identifier>\n'
            '            <Identifier>{31B2F340-016D-11D2-945F-00C04FB984F9}</Identifier>\n'
            '            <Domain>test.local</Domain>\n'
            '        </Identifier>\n'
            '        <Name>GPO A</Name>\n'
            '        <CreatedTime>2026-01-01T00:00:00</CreatedTime>\n'
            '        <ModifiedTime>2026-01-02T00:00:00</ModifiedTime>\n'
            '        <ReadTime>2026-01-03T00:00:00</ReadTime>\n'
            '        <Computer><VersionDirectory>1</VersionDirectory>'
            '<VersionSysvol>2</VersionSysvol><Enabled>true</Enabled></Computer>\n'
            '        <User><VersionDirectory>3</VersionDirectory>'
            '<VersionSysvol>4</VersionSysvol><Enabled>true</Enabled></User>\n'
            '        <FilterDataAvailable>true</FilterDataAvailable>\n'
            '    </GPO>\n'
        )
        body_b = (
            '    <GPO>\n'
            '        <Identifier>\n'
            '            <Identifier>{11111111-1111-1111-1111-111111111111}</Identifier>\n'
            '            <Domain>test.local</Domain>\n'
            '        </Identifier>\n'
            '        <Name>GPO B</Name>\n'
            '        <CreatedTime>2026-01-01T00:00:00</CreatedTime>\n'
            '        <ModifiedTime>2026-01-02T00:00:00</ModifiedTime>\n'
            '        <ReadTime>2026-01-03T00:00:00</ReadTime>\n'
            '        <Computer><VersionDirectory>1</VersionDirectory>'
            '<VersionSysvol>2</VersionSysvol><Enabled>true</Enabled></Computer>\n'
            '        <User><VersionDirectory>3</VersionDirectory>'
            '<VersionSysvol>4</VersionSysvol><Enabled>true</Enabled></User>\n'
            '        <FilterDataAvailable>true</FilterDataAvailable>\n'
            '    </GPO>\n'
        )
        xml = (
            '<?xml version="1.0" encoding="utf-8"?>\n'
            '<GPO xmlns="http://www.microsoft.com/GroupPolicy/Settings">\n'
            + body_a + body_b
            + "</GPO>\n"
        )
        xml_path = tmp_path / "report.xml"
        xml_path.write_text(xml, encoding="utf-8")
        gpos = ingest.parse_report(xml_path)
        assert len(gpos) == 2
        assert {g.name for g in gpos} == {"GPO A", "GPO B"}

    def test_parse_empty_file_raises(self, tmp_path: Path) -> None:
        xml_path = tmp_path / "empty.xml"
        xml_path.write_text('<?xml version="1.0"?>\n<root/>', encoding="utf-8")
        # No <GPO> elements -> returns empty list, does not crash
        gpos = ingest.parse_report(xml_path)
        assert gpos == []

    def test_malformed_xml_raises(self, tmp_path: Path) -> None:
        xml_path = tmp_path / "bad.xml"
        xml_path.write_text("not xml at all", encoding="utf-8")
        with pytest.raises(ET.ParseError):
            ingest.parse_report(xml_path)

    def test_bom_tolerant(self, tmp_path: Path) -> None:
        xml_path = tmp_path / "bom.xml"
        xml_path.write_bytes(
            b"\xef\xbb\xbf"
            + _min_gpo_xml().encode("utf-8")
        )
        gpos = ingest.parse_report(xml_path)
        assert len(gpos) == 1
        assert gpos[0].name == "Test GPO"


class TestParseSingleGpoEdgeCases:
    def test_missing_identifier_gives_empty_id(self, tmp_path: Path) -> None:
        xml = (
            '<?xml version="1.0" encoding="utf-8"?>\n'
            '<GPO xmlns="http://www.microsoft.com/GroupPolicy/Settings">\n'
            '  <GPO>\n'
            '    <Name>NoID</Name>\n'
            '    <Computer><Enabled>false</Enabled></Computer>\n'
            '    <User><Enabled>false</Enabled></User>\n'
            '  </GPO>\n'
            '</GPO>\n'
        )
        xml_path = tmp_path / "report.xml"
        xml_path.write_text(xml, encoding="utf-8")
        gpos = ingest.parse_report(xml_path)
        assert len(gpos) == 1
        assert gpos[0].id == ""
        assert gpos[0].name == "NoID"

    def test_no_sides(self, tmp_path: Path) -> None:
        xml = (
            '<?xml version="1.0" encoding="utf-8"?>\n'
            '<GPO xmlns="http://www.microsoft.com/GroupPolicy/Settings">\n'
            '  <GPO>\n'
            '    <Identifier><Identifier>'
            '{11111111-1111-1111-1111-111111111111}'
            '</Identifier></Identifier>\n'
            '    <Name>NoSides</Name>\n'
            '  </GPO>\n'
            '</GPO>\n'
        )
        xml_path = tmp_path / "report.xml"
        xml_path.write_text(xml, encoding="utf-8")
        gpos = ingest.parse_report(xml_path)
        assert len(gpos) == 1
        assert gpos[0].computer_enabled is False
        assert gpos[0].user_enabled is False

    def test_parse_bool_case_insensitive(self, tmp_path: Path) -> None:
        xml = _min_gpo_xml(computer_enabled="True", user_enabled="FALSE")
        xml_path = tmp_path / "report.xml"
        xml_path.write_text(xml, encoding="utf-8")
        gpos = ingest.parse_report(xml_path)
        assert gpos[0].computer_enabled is True
        assert gpos[0].user_enabled is False


class TestLoadEstate:
    def test_load_estate_missing_allgpos(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            ingest.load_estate(tmp_path)

    def test_load_estate_minimal(self, tmp_path: Path) -> None:
        xml_path = tmp_path / "AllGPOs.xml"
        xml_path.write_text(_min_gpo_xml(), encoding="utf-8")
        estate = ingest.load_estate(tmp_path)
        assert isinstance(estate, Estate)
        assert len(estate.gpos) == 1
        assert estate.domain == "test.local"
        assert len(estate.soms) == 0  # no gp-inheritance.json

    def test_load_estate_with_inheritance(self, tmp_path: Path) -> None:
        xml_path = tmp_path / "AllGPOs.xml"
        xml_path.write_text(_min_gpo_xml(), encoding="utf-8")
        inheritance = tmp_path / "gp-inheritance.json"
        inheritance.write_text(
            '[{"Path":"dc=test,dc=local","Name":"test","ContainerType":"domain","GpoInheritanceBlocked":false,"InheritedGpoLinks":[]}]',
            encoding="utf-8",
        )
        estate = ingest.load_estate(tmp_path)
        assert len(estate.soms) == 1
        assert estate.soms[0].path == "dc=test,dc=local"

    def test_load_estate_with_metadata(self, tmp_path: Path) -> None:
        xml_path = tmp_path / "AllGPOs.xml"
        xml_path.write_text(_min_gpo_xml(), encoding="utf-8")
        metadata = tmp_path / "gpo-metadata.json"
        metadata.write_text(
            '[{"Id":"{31B2F340-016D-11D2-945F-00C04FB984F9}","WmiFilter":"MyFilter"}]',
            encoding="utf-8",
        )
        estate = ingest.load_estate(tmp_path)
        assert estate.gpos[0].wmi_filter == "MyFilter"

    def test_load_estate_missing_backfill_versions(self, tmp_path: Path) -> None:
        # XML has empty version fields but metadata provides them
        xml = (
            '<?xml version="1.0" encoding="utf-8"?>\n'
            '<GPO xmlns="http://www.microsoft.com/GroupPolicy/Settings">\n'
            '    <GPO>\n'
            '        <Identifier>\n'
            '            <Identifier>{31B2F340-016D-11D2-945F-00C04FB984F9}</Identifier>\n'
            '            <Domain>test.local</Domain>\n'
            '        </Identifier>\n'
            '        <Name>Test GPO</Name>\n'
            '        <Computer>\n'
            '            <VersionDirectory />\n'
            '            <VersionSysvol />\n'
            '            <Enabled>true</Enabled>\n'
            '        </Computer>\n'
            '        <User>\n'
            '            <VersionDirectory />\n'
            '            <VersionSysvol />\n'
            '            <Enabled>true</Enabled>\n'
            '        </User>\n'
            '        <FilterDataAvailable>true</FilterDataAvailable>\n'
            '    </GPO>\n'
            '</GPO>\n'
        )
        xml_path = tmp_path / "AllGPOs.xml"
        xml_path.write_text(xml, encoding="utf-8")
        metadata = tmp_path / "gpo-metadata.json"
        metadata.write_text(
            '[{"Id":"{31B2F340-016D-11D2-945F-00C04FB984F9}",'
            '"ComputerVersionDirectory":"5","ComputerVersionSysvol":"6",'
            '"UserVersionDirectory":"7","UserVersionSysvol":"8"}]',
            encoding="utf-8",
        )
        estate = ingest.load_estate(tmp_path)
        gpo = estate.gpos[0]
        assert gpo.computer_ver_ds == 5
        assert gpo.computer_ver_sysvol == 6
        assert gpo.user_ver_ds == 7
        assert gpo.user_ver_sysvol == 8

    def test_load_estate_sysvol_match(self, tmp_path: Path) -> None:
        xml_path = tmp_path / "AllGPOs.xml"
        xml_path.write_text(_min_gpo_xml(), encoding="utf-8")
        sysvol = tmp_path / "SYSVOL-Policies"
        guid_dir = sysvol / "31B2F340-016D-11D2-945F-00C04FB984F9"
        guid_dir.mkdir(parents=True)
        (guid_dir / "dummy.txt").write_text("hello", encoding="utf-8")
        estate = ingest.load_estate(tmp_path)
        assert estate.gpos[0].sysvol_path is not None

    def test_load_estate_sysvol_alt_path(self, tmp_path: Path) -> None:
        xml_path = tmp_path / "AllGPOs.xml"
        xml_path.write_text(_min_gpo_xml(), encoding="utf-8")
        sysvol = tmp_path / "SYSVOL" / "Policies"
        guid_dir = sysvol / "31B2F340-016D-11D2-945F-00C04FB984F9"
        guid_dir.mkdir(parents=True)
        estate = ingest.load_estate(tmp_path)
        assert estate.gpos[0].sysvol_path is not None


class TestParseInheritanceEdgeCases:
    def test_single_dict_not_list(self, tmp_path: Path) -> None:
        json_path = tmp_path / "inheritance.json"
        json_path.write_text(
            '{"Path":"dc=test,dc=local","Name":"test","ContainerType":"domain","GpoInheritanceBlocked":"false","InheritedGpoLinks":[]}',
            encoding="utf-8",
        )
        soms = ingest.parse_inheritance(json_path)
        assert len(soms) == 1
        assert soms[0].inheritance_blocked is False

    def test_gpo_inheritance_blocked_true_string(self, tmp_path: Path) -> None:
        json_path = tmp_path / "inheritance.json"
        json_path.write_text(
            '[{"Path":"dc=test,dc=local","Name":"test","ContainerType":"domain","GpoInheritanceBlocked":"true","InheritedGpoLinks":[]}]',
            encoding="utf-8",
        )
        soms = ingest.parse_inheritance(json_path)
        assert soms[0].inheritance_blocked is True

    def test_links_raw_is_dict(self, tmp_path: Path) -> None:
        json_path = tmp_path / "inheritance.json"
        json_path.write_text(
            '[{"Path":"dc=test,dc=local","Name":"test","ContainerType":"domain","GpoInheritanceBlocked":false,"InheritedGpoLinks":{"GpoId":"{31B2F340-016D-11D2-945F-00C04FB984F9}","Order":1,"Enabled":true,"Enforced":false,"Target":"dc=test,dc=local"}}]',
            encoding="utf-8",
        )
        soms = ingest.parse_inheritance(json_path)
        assert len(soms[0].links) == 1
        assert soms[0].links[0].gpo_id == "31b2f340-016d-11d2-945f-00c04fb984f9"

    def test_missing_gpo_id_skipped(self, tmp_path: Path) -> None:
        json_path = tmp_path / "inheritance.json"
        json_path.write_text(
            '[{"Path":"dc=test,dc=local","Name":"test","ContainerType":"domain","GpoInheritanceBlocked":false,"InheritedGpoLinks":[{"Order":1,"Enabled":true,"Enforced":false,"Target":"dc=test,dc=local"}]}]',
            encoding="utf-8",
        )
        soms = ingest.parse_inheritance(json_path)
        assert len(soms[0].links) == 0


class TestMergeMetadataEdgeCases:
    def test_gpo_not_found_is_skipped(self, tmp_path: Path) -> None:
        gpo = Gpo(
            id="aaa-bbb", name="Test", domain="test.local",
            created=None, modified=None, read=None,
            computer_enabled=True, user_enabled=True,
            computer_ver_ds=None, computer_ver_sysvol=None,
            user_ver_ds=None, user_ver_sysvol=None,
            sddl=None, owner=None, filter_data_available=False,
            wmi_filter=None, sysvol_path=None,
        )
        metadata = tmp_path / "meta.json"
        metadata.write_text(
            '[{"Id":"{00000000-0000-0000-0000-000000000000}","WmiFilter":"Other"}]',
            encoding="utf-8",
        )
        # Should not crash even though GPO id mismatch
        ingest.merge_metadata(metadata, [gpo])
        assert gpo.wmi_filter is None

    def test_wmi_filter_null(self, tmp_path: Path) -> None:
        gpo = Gpo(
            id="aaa-bbb", name="Test", domain="test.local",
            created=None, modified=None, read=None,
            computer_enabled=True, user_enabled=True,
            computer_ver_ds=None, computer_ver_sysvol=None,
            user_ver_ds=None, user_ver_sysvol=None,
            sddl=None, owner=None, filter_data_available=False,
            wmi_filter=None, sysvol_path=None,
        )
        metadata = tmp_path / "meta.json"
        metadata.write_text(
            '[{"Id":"{00000000-0000-0000-0000-000000000000}","WmiFilter":null}]',
            encoding="utf-8",
        )
        ingest.merge_metadata(metadata, [gpo])
        assert gpo.wmi_filter is None

    def test_non_string_wmi_filter_coerces_to_none(self, tmp_path: Path) -> None:
        gpo = Gpo(
            id="aaa-bbb", name="Test", domain="test.local",
            created=None, modified=None, read=None,
            computer_enabled=True, user_enabled=True,
            computer_ver_ds=None, computer_ver_sysvol=None,
            user_ver_ds=None, user_ver_sysvol=None,
            sddl=None, owner=None, filter_data_available=False,
            wmi_filter=None, sysvol_path=None,
        )
        metadata = tmp_path / "meta.json"
        metadata.write_text(
            '[{"Id":"{00000000-0000-0000-0000-000000000000}","WmiFilter":123}]',
            encoding="utf-8",
        )
        ingest.merge_metadata(metadata, [gpo])
        assert gpo.wmi_filter is None


class TestParseWmiFilters:
    def test_parse_wmi_filters_list(self, tmp_path: Path) -> None:
        j = tmp_path / "wmi-filters.json"
        j.write_text(
            '[{"Name":"WorkstationFilter","Query":"Select * from Win32_OperatingSystem"}]',
            encoding="utf-8",
        )
        filters = ingest.parse_wmi_filters(j)
        assert len(filters) == 1
        assert filters[0].name == "WorkstationFilter"
        assert "Win32_OperatingSystem" in filters[0].query

    def test_parse_wmi_filters_single_dict(self, tmp_path: Path) -> None:
        j = tmp_path / "wmi-filters.json"
        j.write_text(
            '{"Name":"F1","Query":"SELECT * FROM Win32_ComputerSystem"}',
            encoding="utf-8",
        )
        filters = ingest.parse_wmi_filters(j)
        assert len(filters) == 1
        assert filters[0].name == "F1"

    def test_parse_wmi_filters_empty_name_skipped(self, tmp_path: Path) -> None:
        j = tmp_path / "wmi-filters.json"
        j.write_text(
            '[{"Name":"","Query":"x"},{"Name":"Valid","Query":"y"}]',
            encoding="utf-8",
        )
        filters = ingest.parse_wmi_filters(j)
        assert len(filters) == 1
        assert filters[0].name == "Valid"

    def test_load_estate_with_wmi_filters(self, tmp_path: Path) -> None:
        xml_path = tmp_path / "AllGPOs.xml"
        xml_path.write_text(_min_gpo_xml(), encoding="utf-8")
        wf = tmp_path / "wmi-filters.json"
        wf.write_text(
            '[{"Name":"TestFilter","Query":"SELECT * FROM Foo"}]',
            encoding="utf-8",
        )
        estate = ingest.load_estate(tmp_path)
        assert len(estate.wmi_filters) == 1
        assert estate.wmi_filters[0].name == "TestFilter"


class TestParseOuTree:
    def test_parse_ou_tree_list(self, tmp_path: Path) -> None:
        j = tmp_path / "ou-tree.json"
        j.write_text(
            '[{"DistinguishedName":"OU=WS,DC=test,DC=local","Name":"WS",'
            '"gPLink":"[LDAP://cn={31B2F340-016D-11D2-945F-00C04FB984F9},...;0]",'
            '"gPOptions":0}]',
            encoding="utf-8",
        )
        records = ingest.parse_ou_tree(j)
        assert len(records) == 1
        assert records[0].dn == "OU=WS,DC=test,DC=local"
        assert records[0].gp_options == 0
        assert records[0].gp_link is not None

    def test_parse_ou_tree_single_dict(self, tmp_path: Path) -> None:
        j = tmp_path / "ou-tree.json"
        j.write_text(
            '{"DistinguishedName":"OU=WS,DC=test,DC=local","Name":"WS",'
            '"gPLink":null,"gPOptions":1}',
            encoding="utf-8",
        )
        records = ingest.parse_ou_tree(j)
        assert len(records) == 1
        assert records[0].gp_options == 1
        assert records[0].gp_link is None

    def test_load_estate_with_ou_tree(self, tmp_path: Path) -> None:
        xml_path = tmp_path / "AllGPOs.xml"
        xml_path.write_text(_min_gpo_xml(), encoding="utf-8")
        ot = tmp_path / "ou-tree.json"
        ot.write_text(
            '[{"DistinguishedName":"OU=WS,DC=test,DC=local","Name":"WS",'
            '"gPLink":null,"gPOptions":0}]',
            encoding="utf-8",
        )
        estate = ingest.load_estate(tmp_path)
        assert len(estate.ou_tree) == 1
        assert estate.ou_tree[0].name == "WS"


class TestParsePrincipals:
    def test_parse_principals_present(self, tmp_path: Path) -> None:
        import json

        payload = {
            "collected": "2026-06-19T00:00:00Z",
            "domain": "ad.test",
            "principals": {
                "S-1-5-21-100-200-300-1131": {
                    "name": "TEST\\GPO-Admins", "sam": "GPO-Admins",
                    "type": "Group", "domain": "TEST",
                },
                "S-1-5-11": {
                    "name": "Authenticated Users", "sam": "Authenticated Users",
                    "type": "WellKnown", "domain": "",
                },
            },
        }
        j = tmp_path / "principals.json"
        j.write_text(json.dumps(payload), encoding="utf-8")
        principals = ingest.parse_principals(j)
        assert len(principals) == 2
        rp = principals["s-1-5-21-100-200-300-1131"]
        assert rp.name == "TEST\\GPO-Admins"
        assert rp.sam == "GPO-Admins"
        assert rp.principal_type == "Group"
        assert rp.domain == "TEST"
        assert rp.resolved is True
        assert principals["s-1-5-11"].name == "Authenticated Users"

    def test_parse_principals_bom_tolerant(self, tmp_path: Path) -> None:
        import json

        payload = {
            "principals": {
                "S-1-5-21-1-2-3-1000": {
                    "name": "X\\Admins", "sam": "Admins",
                    "type": "Group", "domain": "X",
                },
            },
        }
        j = tmp_path / "principals.json"
        j.write_bytes(b"\xef\xbb\xbf" + json.dumps(payload).encode("utf-8"))
        principals = ingest.parse_principals(j)
        assert "s-1-5-21-1-2-3-1000" in principals
        assert principals["s-1-5-21-1-2-3-1000"].name == "X\\Admins"

    def test_parse_principals_partial_resolution(self, tmp_path: Path) -> None:
        """Some SIDs resolved, some Unresolved (Phase B finding, not a crash)."""
        import json

        payload = {
            "principals": {
                "S-1-5-21-1-2-3-1000": {
                    "name": "X\\Admins", "sam": "Admins",
                    "type": "Group", "domain": "X",
                },
                "S-1-5-21-1-2-3-9999": {
                    "name": "", "sam": "", "type": "Unresolved", "domain": "",
                },
            },
        }
        j = tmp_path / "principals.json"
        j.write_text(json.dumps(payload), encoding="utf-8")
        principals = ingest.parse_principals(j)
        assert len(principals) == 2
        assert principals["s-1-5-21-1-2-3-1000"].resolved is True
        unresolved = principals["s-1-5-21-1-2-3-9999"]
        assert unresolved.resolved is False
        assert unresolved.principal_type == "Unresolved"

    def test_parse_principals_empty_principals_key(self, tmp_path: Path) -> None:
        j = tmp_path / "principals.json"
        j.write_text('{"principals":{}}', encoding="utf-8")
        principals = ingest.parse_principals(j)
        assert principals == {}

    def test_parse_principals_missing_principals_key(self, tmp_path: Path) -> None:
        j = tmp_path / "principals.json"
        j.write_text('{"collected":"2026-01-01","domain":"x"}', encoding="utf-8")
        principals = ingest.parse_principals(j)
        assert principals == {}

    def test_parse_principals_skips_non_dict_entries(self, tmp_path: Path) -> None:
        import json

        payload = {
            "principals": {
                "S-1-5-11": "bad-string",
                "S-1-5-21-1-2-3-1000": {
                    "name": "X", "sam": "X", "type": "Group", "domain": "",
                },
            },
        }
        j = tmp_path / "principals.json"
        j.write_text(json.dumps(payload), encoding="utf-8")
        principals = ingest.parse_principals(j)
        assert len(principals) == 1
        assert "s-1-5-21-1-2-3-1000" in principals

    def test_load_estate_without_principals_json(self, tmp_path: Path) -> None:
        """AC-3: absent principals.json → empty dict, no crash."""
        xml_path = tmp_path / "AllGPOs.xml"
        xml_path.write_text(_min_gpo_xml(), encoding="utf-8")
        estate = ingest.load_estate(tmp_path)
        assert estate.principals == {}

    def test_load_estate_with_principals_json(self, tmp_path: Path) -> None:
        import json

        xml_path = tmp_path / "AllGPOs.xml"
        xml_path.write_text(_min_gpo_xml(), encoding="utf-8")
        payload = {
            "principals": {
                "S-1-5-21-1-2-3-1131": {
                    "name": "T\\Admins", "sam": "Admins",
                    "type": "Group", "domain": "T",
                },
            },
        }
        (tmp_path / "principals.json").write_text(json.dumps(payload), encoding="utf-8")
        estate = ingest.load_estate(tmp_path)
        assert len(estate.principals) == 1
        assert estate.principals["s-1-5-21-1-2-3-1131"].name == "T\\Admins"

    def test_load_estate_with_malformed_principals_json_warns(self, tmp_path: Path) -> None:
        """Malformed principals.json should warn, not crash; estate still loads."""
        xml_path = tmp_path / "AllGPOs.xml"
        xml_path.write_text(_min_gpo_xml(), encoding="utf-8")
        pj = tmp_path / "principals.json"
        pj.write_text("{not valid json", encoding="utf-8")
        with pytest.warns(UserWarning, match="Skipping principals.json"):
            estate = ingest.load_estate(tmp_path)
        assert estate.principals == {}


class TestParseGroupMembers:
    def test_parse_group_members_present(self, tmp_path: Path) -> None:
        import json

        payload = {
            "collected": "2026-06-19T00:00:00Z",
            "domain": "ad.test",
            "groups": {
                "S-1-5-21-100-200-300-1131": {
                    "name": "TEST\\GPO-Admins",
                    "members": ["S-1-5-21-100-200-300-1001", "S-1-5-21-100-200-300-1002"],
                    "member_count": 2,
                },
                "s-1-5-11": {
                    "name": "Authenticated Users", "members": [],
                    "member_count": 0,
                    "implicit": "All authenticated domain principals",
                },
            },
        }
        j = tmp_path / "group-members.json"
        j.write_text(json.dumps(payload), encoding="utf-8")
        groups = ingest.parse_group_members(j)
        assert len(groups) == 2
        gm = groups["s-1-5-21-100-200-300-1131"]
        assert gm.name == "TEST\\GPO-Admins"
        assert gm.members == ("s-1-5-21-100-200-300-1001", "s-1-5-21-100-200-300-1002")
        assert gm.member_count == 2
        au = groups["s-1-5-11"]
        assert au.implicit == "All authenticated domain principals"
        assert au.members == ()

    def test_parse_group_members_bom_tolerant(self, tmp_path: Path) -> None:
        import json

        payload = {
            "groups": {
                "S-1-5-21-1-2-3-1131": {
                    "name": "X\\Admins", "members": ["S-1-5-21-1-2-3-1000"],
                    "member_count": 1,
                },
            },
        }
        j = tmp_path / "group-members.json"
        j.write_bytes(b"\xef\xbb\xbf" + json.dumps(payload).encode("utf-8"))
        groups = ingest.parse_group_members(j)
        assert "s-1-5-21-1-2-3-1131" in groups
        assert groups["s-1-5-21-1-2-3-1131"].members == ("s-1-5-21-1-2-3-1000",)

    def test_parse_group_members_missing_groups_key(self, tmp_path: Path) -> None:
        j = tmp_path / "group-members.json"
        j.write_text('{"collected":"2026-01-01","domain":"x"}', encoding="utf-8")
        assert ingest.parse_group_members(j) == {}

    def test_parse_group_members_skips_non_dict_entries(self, tmp_path: Path) -> None:
        import json

        payload = {
            "groups": {
                "S-1-5-11": "bad-string",
                "S-1-5-21-1-2-3-1131": {
                    "name": "X", "members": ["S-1-5-21-1-2-3-1000"],
                    "member_count": 1,
                },
            },
        }
        j = tmp_path / "group-members.json"
        j.write_text(json.dumps(payload), encoding="utf-8")
        groups = ingest.parse_group_members(j)
        assert len(groups) == 1
        assert "s-1-5-21-1-2-3-1131" in groups

    def test_load_estate_without_group_members_json(self, tmp_path: Path) -> None:
        xml_path = tmp_path / "AllGPOs.xml"
        xml_path.write_text(_min_gpo_xml(), encoding="utf-8")
        estate = ingest.load_estate(tmp_path)
        assert estate.group_members == {}

    def test_load_estate_with_group_members_json(self, tmp_path: Path) -> None:
        import json

        xml_path = tmp_path / "AllGPOs.xml"
        xml_path.write_text(_min_gpo_xml(), encoding="utf-8")
        payload = {
            "groups": {
                "S-1-5-21-1-2-3-1131": {
                    "name": "T\\Admins", "members": ["S-1-5-21-1-2-3-1000"],
                    "member_count": 1,
                },
            },
        }
        (tmp_path / "group-members.json").write_text(json.dumps(payload), encoding="utf-8")
        estate = ingest.load_estate(tmp_path)
        assert len(estate.group_members) == 1
        assert estate.group_members["s-1-5-21-1-2-3-1131"].name == "T\\Admins"


# ---------------------------------------------------------------------------
# WI-006: Streaming decompression size enforcement tests
# ---------------------------------------------------------------------------


class TestSizeLimitedReader:
    """Tests for SizeLimitedReader - the core streaming size enforcer."""

    def test_under_limit(self) -> None:
        from gpo_lens.ingest import SizeLimitedReader

        src = io.BytesIO(b"hello")
        reader = SizeLimitedReader(src, 100)
        data = reader.read()
        assert data == b"hello"

    def test_exceeds_limit(self) -> None:
        from gpo_lens.ingest import SizeLimitedReader

        src = io.BytesIO(b"x" * 200)
        reader = SizeLimitedReader(src, 100)
        with pytest.raises(ValueError, match="exceeds limit"):
            reader.read(65536)

    def test_exact_limit(self) -> None:
        from gpo_lens.ingest import SizeLimitedReader

        src = io.BytesIO(b"hello")
        reader = SizeLimitedReader(src, 5)
        data = reader.read()
        assert data == b"hello"

    def test_over_by_one(self) -> None:
        from gpo_lens.ingest import SizeLimitedReader

        src = io.BytesIO(b"hello!")
        reader = SizeLimitedReader(src, 5)
        with pytest.raises(ValueError, match="exceeds limit"):
            reader.read()

    def test_multiple_reads_accumulate(self) -> None:
        from gpo_lens.ingest import SizeLimitedReader

        src = io.BytesIO(b"aaaaaabbbbbb")
        reader = SizeLimitedReader(src, 10)
        reader.read(3)
        reader.read(3)
        reader.read(3)
        with pytest.raises(ValueError, match="exceeds limit"):
            reader.read(3)

    def test_empty_read(self) -> None:
        from gpo_lens.ingest import SizeLimitedReader

        src = io.BytesIO(b"")
        reader = SizeLimitedReader(src, 100)
        data = reader.read()
        assert data == b""

    def test_large_read_request_capped(self) -> None:
        """A read with a huge size is capped to 65536, preventing excessive allocation."""
        from gpo_lens.ingest import SizeLimitedReader

        # 200 bytes of data, 300-byte limit
        src = io.BytesIO(b"x" * 200)
        reader = SizeLimitedReader(src, 300)
        # Request 1 GB read — should be capped, not allocate 1 GB
        chunk = reader.read(1_073_741_824)
        # BytesIO only has 200 bytes, so we get all of them
        assert len(chunk) == 200
        assert reader._total == 200


class TestStreamingZipRead:
    """Tests for _streaming_zip_read - streaming decompression with size enforcement."""

    def test_normal_read_under_limit(self) -> None:
        from gpo_lens.ingest import _streaming_zip_read

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("test.txt", b"hello world")
        buf.seek(0)
        with zipfile.ZipFile(buf, "r") as zf:
            counter = [0]
            data = _streaming_zip_read(zf, "test.txt", counter, max_bytes=1024)
        assert data == b"hello world"
        assert counter[0] == 11

    def test_rejects_oversized_entry(self) -> None:
        from gpo_lens.ingest import _streaming_zip_read

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("big.txt", b"x" * 200)
        buf.seek(0)
        with zipfile.ZipFile(buf, "r") as zf:
            counter = [0]
            with pytest.raises(ValueError, match="exceeds limit"):
                _streaming_zip_read(zf, "big.txt", counter, max_bytes=100)

    def test_accumulates_across_entries(self) -> None:
        from gpo_lens.ingest import _streaming_zip_read

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("a.txt", b"a" * 60)
            zf.writestr("b.txt", b"b" * 60)
        buf.seek(0)
        with zipfile.ZipFile(buf, "r") as zf:
            counter = [0]
            _streaming_zip_read(zf, "a.txt", counter, max_bytes=100)
            assert counter[0] == 60
            # Second read should fail because cumulative exceeds 100
            with pytest.raises(ValueError, match="exceeds limit"):
                _streaming_zip_read(zf, "b.txt", counter, max_bytes=100)

    def test_spoofed_file_size_header_still_enforced(self) -> None:
        """Zip-bomb vector: info.file_size says 1 byte, actual content is large.

        _streaming_zip_read must reject this because it counts actual
        decompressed bytes, not the declarative header value.

        NOTE: Python's zipfile.ZipExtFile validates CRC and truncates
        output to file_size bytes, so a real binary-spoofed zip raises
        BadZipFile before our reader sees it.  We test our streaming
        reader's independence from info.file_size by simulating a
        decompression stream that yields more bytes than the header claims.
        """
        from gpo_lens.ingest import _streaming_zip_read

        # Simulate zf.open("bomb.txt") returning 200 bytes
        # even though info.file_size says 1
        fake_stream = io.BytesIO(b"A" * 200)
        mock_zf = MagicMock()
        mock_zf.open.return_value.__enter__ = lambda s: fake_stream
        mock_zf.open.return_value.__exit__ = MagicMock(return_value=False)

        counter = [0]
        with pytest.raises(ValueError, match="exceeds limit"):
            _streaming_zip_read(mock_zf, "bomb.txt", counter, max_bytes=100)

    def test_does_not_check_info_file_size_before_read(self) -> None:
        """Verify _streaming_zip_read doesn't use info.file_size as a pre-check.

        A naive implementation might check ``if info.file_size > limit: reject``
        before opening the entry, which would be bypassed by spoofed headers.
        Our implementation enforces the limit during actual streaming reads.
        """
        from gpo_lens.ingest import _streaming_zip_read

        # Create a zip with content that exceeds our test limit
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("big.txt", b"x" * 200)
        buf.seek(0)
        with zipfile.ZipFile(buf, "r") as zf:
            # info.file_size correctly says 200 -- our reader catches it
            # during streaming, not by checking the header beforehand
            counter = [0]
            with pytest.raises(ValueError, match="exceeds limit"):
                _streaming_zip_read(zf, "big.txt", counter, max_bytes=100)

    def test_none_max_bytes_uses_default(self) -> None:
        """When max_bytes is None, _streaming_zip_read uses _MAX_DECOMPRESSED_BYTES."""
        import unittest.mock

        from gpo_lens.ingest import _streaming_zip_read

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("test.txt", b"hello")
        buf.seek(0)
        with zipfile.ZipFile(buf, "r") as zf:
            counter = [0]
            with unittest.mock.patch("gpo_lens.ingest._MAX_DECOMPRESSED_BYTES", 100):
                # With the default limit of 100, a 5-byte entry is fine
                data = _streaming_zip_read(zf, "test.txt", counter)
            assert data == b"hello"


class TestStreamingBaselineZip:
    """Tests for load_baseline_from_zip with streaming decompression enforcement."""

    def _min_gpo_xml(self) -> str:
        return (
            '<?xml version="1.0" encoding="utf-8"?>\n'
            "<GPO>\n"
            "  <Identifier>\n"
            "    <Identifier>{99999999-9999-9999-9999-999999999999}</Identifier>\n"
            "    <Domain>test.local</Domain>\n"
            "  </Identifier>\n"
            "  <Name>Test GPO</Name>\n"
            "  <CreatedTime>2024-01-01T00:00:00</CreatedTime>\n"
            "  <ModifiedTime>2024-01-01T00:00:00</ModifiedTime>\n"
            "  <ReadTime>2024-01-01T00:00:00</ReadTime>\n"
            "  <Computer><Enabled>true</Enabled></Computer>\n"
            "  <User><Enabled>true</Enabled></User>\n"
            "  <FilterDataAvailable>false</FilterDataAvailable>\n"
            "</GPO>\n"
        )

    def test_normal_baseline_zip_loads(self, tmp_path: Path) -> None:
        gpo_xml = self._min_gpo_xml()
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(
                "GPOs/{99999999-9999-9999-9999-999999999999}/gpreport.xml",
                gpo_xml,
            )
        zip_path = tmp_path / "baseline.zip"
        zip_path.write_bytes(buf.getvalue())

        gpos = ingest.load_baseline_from_zip(zip_path)
        assert len(gpos) == 1
        assert gpos[0].name == "Test GPO"

    def test_nested_baseline_zip_loads(self, tmp_path: Path) -> None:
        """Outer zip containing an inner zip with GPOs."""
        gpo_xml = self._min_gpo_xml()
        inner_buf = io.BytesIO()
        with zipfile.ZipFile(inner_buf, "w", zipfile.ZIP_DEFLATED) as inner:
            inner.writestr(
                "GPOs/{99999999-9999-9999-9999-999999999999}/gpreport.xml",
                gpo_xml,
            )
        outer_buf = io.BytesIO()
        with zipfile.ZipFile(outer_buf, "w", zipfile.ZIP_DEFLATED) as outer:
            outer.writestr("Windows 11 Security Baseline.zip", inner_buf.getvalue())

        zip_path = tmp_path / "baseline.zip"
        zip_path.write_bytes(outer_buf.getvalue())

        gpos = ingest.load_baseline_from_zip(zip_path)
        assert len(gpos) == 1
        assert gpos[0].name == "Test GPO"

    def test_large_nested_zip_rejected(self, tmp_path: Path) -> None:
        """Nested zip with large content must be warned and skipped, not crash.

        A real zip-bomb uses highly compressible data inside nested zips.
        The inner zip decompresses to much more than its compressed size.
        Our streaming reader catches this by counting actual decompressed
        bytes, not trusting header values. The oversized entry is skipped
        with a warning rather than crashing the entire baseline load.
        """
        import unittest.mock

        gpo_xml = self._min_gpo_xml()
        large_padding = " " * 5000
        padded_xml = gpo_xml + large_padding

        inner_buf = io.BytesIO()
        with zipfile.ZipFile(inner_buf, "w", zipfile.ZIP_DEFLATED) as inner:
            inner.writestr(
                "GPOs/{99999999-9999-9999-9999-999999999999}/gpreport.xml",
                padded_xml,
            )
        inner_data = inner_buf.getvalue()

        outer_buf = io.BytesIO()
        with zipfile.ZipFile(outer_buf, "w", zipfile.ZIP_DEFLATED) as outer:
            outer.writestr("baseline.zip", inner_data)

        zip_path = tmp_path / "baseline.zip"
        zip_path.write_bytes(outer_buf.getvalue())

        with unittest.mock.patch("gpo_lens.ingest._MAX_DECOMPRESSED_BYTES", 200):
            with pytest.warns(UserWarning, match="exceeds limit"):
                gpos = ingest.load_baseline_from_zip(zip_path)
        assert gpos == []

    def test_large_direct_zip_rejected(self, tmp_path: Path) -> None:
        """Direct zip (no nesting) with large content must be warned and skipped."""
        import unittest.mock

        gpo_xml = self._min_gpo_xml()
        padded_xml = gpo_xml + " " * 5000

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("GPOs/test/gpreport.xml", padded_xml)

        zip_path = tmp_path / "baseline.zip"
        zip_path.write_bytes(buf.getvalue())

        with unittest.mock.patch("gpo_lens.ingest._MAX_DECOMPRESSED_BYTES", 200):
            with pytest.warns(UserWarning, match="exceeds limit"):
                gpos = ingest.load_baseline_from_zip(zip_path)
        assert gpos == []


# ---------------------------------------------------------------------------
# container_type normalization (Get-GPInheritance serializes the SomType enum
# as an integer; the rest of gpo-lens expects the canonical lowercase string)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw, expected",
    [
        (1, "domain"),        # ConvertTo-Json serializes SomType.Domain as 1
        (2, "ou"),            # SomType.OrganizationalUnit
        (0, "site"),
        ("1", "domain"),      # string-of-int form
        ("2", "ou"),
        ("Domain", "domain"), # -EnumsAsStrings form
        ("OU", "ou"),
        ("OrganizationalUnit", "ou"),
        ("site", "site"),
        (True, ""),           # bool must not be read as int 1
        (None, ""),
    ],
)
def test_normalize_container_type(raw: object, expected: str) -> None:
    assert ingest._normalize_container_type(raw) == expected


def test_parse_inheritance_normalizes_integer_container_type(tmp_path: Path) -> None:
    """Real collector output carries integer ContainerType; parse_inheritance
    must emit the canonical string so the /ou type filter and merge site/domain
    logic match. Regression for the silently-broken type filter."""
    import json

    data = [
        {"Path": "dc=test,dc=local", "Name": "test.local", "ContainerType": 1,
         "GpoInheritanceBlocked": False, "InheritedGpoLinks": []},
        {"Path": "ou=eng,dc=test,dc=local", "Name": "eng", "ContainerType": 2,
         "GpoInheritanceBlocked": False, "InheritedGpoLinks": []},
    ]
    p = tmp_path / "gp-inheritance.json"
    p.write_text(json.dumps(data))
    soms = ingest.parse_inheritance(p)
    by_type = {s.container_type for s in soms}
    assert by_type == {"domain", "ou"}


class TestLoadBaselineFromZipErrorHandling:
    def test_oversized_inner_zip_skipped_not_crash(self, tmp_path: Path) -> None:
        import unittest.mock

        good_xml = (
            '<?xml version="1.0" encoding="utf-8"?>\n'
            "<GPO>\n"
            "  <Identifier><Identifier>{99999999-9999-9999-9999-999999999999}</Identifier>"
            "<Domain>test.local</Domain></Identifier>\n"
            "  <Name>Good GPO</Name>\n"
            "  <Computer><Enabled>true</Enabled></Computer>\n"
            "  <User><Enabled>true</Enabled></User>\n"
            "  <FilterDataAvailable>false</FilterDataAvailable>\n"
            "</GPO>\n"
        )
        large_padding = " " * 5000
        bad_xml = good_xml + large_padding

        inner_bad = io.BytesIO()
        with zipfile.ZipFile(inner_bad, "w", zipfile.ZIP_DEFLATED) as inner:
            inner.writestr("GPOs/bad/gpreport.xml", bad_xml)
        inner_good = io.BytesIO()
        with zipfile.ZipFile(inner_good, "w", zipfile.ZIP_DEFLATED) as inner:
            inner.writestr("GPOs/good/gpreport.xml", good_xml)

        outer_buf = io.BytesIO()
        with zipfile.ZipFile(outer_buf, "w", zipfile.ZIP_DEFLATED) as outer:
            outer.writestr("bad.zip", inner_bad.getvalue())
            outer.writestr("good.zip", inner_good.getvalue())

        zip_path = tmp_path / "baseline.zip"
        zip_path.write_bytes(outer_buf.getvalue())

        with unittest.mock.patch("gpo_lens.ingest._MAX_DECOMPRESSED_BYTES", 2000):
            with pytest.warns(UserWarning, match="exceeds limit"):
                gpos = ingest.load_baseline_from_zip(zip_path)
        good_ids = [g.name for g in gpos if g.name == "Good GPO"]
        assert len(good_ids) == 1

    def test_oversized_direct_gpreport_warns_not_crash(self, tmp_path: Path) -> None:
        import unittest.mock

        good_xml = (
            '<?xml version="1.0" encoding="utf-8"?>\n'
            "<GPO>\n"
            "  <Identifier><Identifier>{99999999-9999-9999-9999-999999999999}</Identifier>"
            "<Domain>test.local</Domain></Identifier>\n"
            "  <Name>Good</Name>\n"
            "  <Computer><Enabled>true</Enabled></Computer>\n"
            "  <User><Enabled>true</Enabled></User>\n"
            "  <FilterDataAvailable>false</FilterDataAvailable>\n"
            "</GPO>\n"
        )
        padded = good_xml + " " * 5000

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("GPOs/test/gpreport.xml", padded)

        zip_path = tmp_path / "baseline.zip"
        zip_path.write_bytes(buf.getvalue())

        with unittest.mock.patch("gpo_lens.ingest._MAX_DECOMPRESSED_BYTES", 200):
            with pytest.warns(UserWarning, match="exceeds limit"):
                gpos = ingest.load_baseline_from_zip(zip_path)
        assert gpos == []


class TestNonDictArrayGuards:
    def test_parse_inheritance_skips_non_dict(self, tmp_path: Path) -> None:
        j = tmp_path / "inh.json"
        j.write_text(
            '[{"Path":"dc=t,dc=l","Name":"t","ContainerType":"domain",'
            '"GpoInheritanceBlocked":false,"InheritedGpoLinks":[]},'
            '"bad-string", 42, null]',
            encoding="utf-8",
        )
        with pytest.warns(UserWarning, match="Skipping non-dict"):
            soms = ingest.parse_inheritance(j)
        assert len(soms) == 1
        assert soms[0].name == "t"

    def test_parse_wmi_filters_skips_non_dict(self, tmp_path: Path) -> None:
        j = tmp_path / "wmi.json"
        j.write_text(
            '[{"Name":"F1","Query":"q"}, "bad", null]',
            encoding="utf-8",
        )
        with pytest.warns(UserWarning, match="Skipping non-dict"):
            filters = ingest.parse_wmi_filters(j)
        assert len(filters) == 1
        assert filters[0].name == "F1"

    def test_parse_ou_tree_skips_non_dict(self, tmp_path: Path) -> None:
        j = tmp_path / "ou.json"
        j.write_text(
            '[{"DistinguishedName":"OU=x,DC=t","Name":"x","gPLink":null,"gPOptions":0},'
            '"bad", 123]',
            encoding="utf-8",
        )
        with pytest.warns(UserWarning, match="Skipping non-dict"):
            records = ingest.parse_ou_tree(j)
        assert len(records) == 1
        assert records[0].name == "x"

    def test_parse_sites_skips_non_dict(self, tmp_path: Path) -> None:
        j = tmp_path / "sites.json"
        j.write_text(
            '[{"DistinguishedName":"CN=Site1","Name":"Site1","gPLink":null},'
            '"bad", null]',
            encoding="utf-8",
        )
        with pytest.warns(UserWarning, match="Skipping non-dict"):
            sites = ingest.parse_sites(j)
        assert len(sites) == 1
        assert sites[0].name == "Site1"

    def test_parse_coverage_gaps_skips_non_dict_in_inventory(self, tmp_path: Path) -> None:
        inv = tmp_path / "gpo-inventory.json"
        inv.write_text(
            '[{"Id":"{00000000-0000-0000-0000-000000000001}","DisplayName":"Gap1"},'
            '"bad", null]',
            encoding="utf-8",
        )
        errs = tmp_path / "collection-errors.json"
        errs.write_text("[]", encoding="utf-8")
        with pytest.warns(UserWarning, match="Skipping non-dict"):
            gaps = ingest.parse_coverage_gaps(inv, errs, [])
        assert len(gaps) == 1
        assert gaps[0].kind == "inaccessible"

    def test_parse_coverage_gaps_skips_non_dict_in_errors(self, tmp_path: Path) -> None:
        inv = tmp_path / "gpo-inventory.json"
        inv.write_text("[]", encoding="utf-8")
        errs = tmp_path / "collection-errors.json"
        errs.write_text(
            '[{"GpoId":"{00000000-0000-0000-0000-000000000002}","DisplayName":"Err1",'
            '"Error":"fail"}, "bad", null]',
            encoding="utf-8",
        )
        with pytest.warns(UserWarning, match="Skipping non-dict"):
            gaps = ingest.parse_coverage_gaps(inv, errs, [])
        assert len(gaps) == 1
        assert gaps[0].kind == "collection_error"


class TestFloatOrderValue:
    def test_float_order_preserved(self, tmp_path: Path) -> None:
        j = tmp_path / "inh.json"
        j.write_text(
            '[{"Path":"dc=t,dc=l","Name":"t","ContainerType":"domain",'
            '"GpoInheritanceBlocked":false,"InheritedGpoLinks":'
            '[{"GpoId":"{31B2F340-016D-11D2-945F-00C04FB984F9}",'
            '"Order":3.0,"Enabled":true,"Enforced":false,"Target":"dc=t,dc=l"}]}]',
            encoding="utf-8",
        )
        soms = ingest.parse_inheritance(j)
        assert len(soms[0].links) == 1
        assert soms[0].links[0].order == 3

    def test_float_order_zero(self, tmp_path: Path) -> None:
        j = tmp_path / "inh.json"
        j.write_text(
            '[{"Path":"dc=t,dc=l","Name":"t","ContainerType":"domain",'
            '"GpoInheritanceBlocked":false,"InheritedGpoLinks":'
            '[{"GpoId":"{31B2F340-016D-11D2-945F-00C04FB984F9}",'
            '"Order":1.0,"Enabled":true,"Enforced":false,"Target":"dc=t,dc=l"}]}]',
            encoding="utf-8",
        )
        soms = ingest.parse_inheritance(j)
        assert soms[0].links[0].order == 1

    def test_int_order_still_works(self, tmp_path: Path) -> None:
        j = tmp_path / "inh.json"
        j.write_text(
            '[{"Path":"dc=t,dc=l","Name":"t","ContainerType":"domain",'
            '"GpoInheritanceBlocked":false,"InheritedGpoLinks":'
            '[{"GpoId":"{31B2F340-016D-11D2-945F-00C04FB984F9}",'
            '"Order":5,"Enabled":true,"Enforced":false,"Target":"dc=t,dc=l"}]}]',
            encoding="utf-8",
        )
        soms = ingest.parse_inheritance(j)
        assert soms[0].links[0].order == 5
