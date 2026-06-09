"""Unit tests for Tier-1 queries (no samples required)."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from gpo_lens import queries
from gpo_lens.model import DelegationEntry, Estate, Gpo, OuRecord, Setting


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


# ---- version_skew ----------------------------------------------------------

def test_version_skew_none():
    estate = Estate(gpos=[_make_gpo()])
    assert queries.version_skew(estate) == []


def test_version_skew_computer():
    gpo = _make_gpo(computer_ver_ds=1, computer_ver_sysvol=2)
    estate = Estate(gpos=[gpo])
    assert queries.version_skew(estate) == [(gpo, "Computer")]


def test_version_skew_user():
    gpo = _make_gpo(user_ver_ds=1, user_ver_sysvol=2)
    estate = Estate(gpos=[gpo])
    assert queries.version_skew(estate) == [(gpo, "User")]


def test_version_skew_both_sides():
    gpo = _make_gpo(computer_ver_ds=1, computer_ver_sysvol=2, user_ver_ds=3, user_ver_sysvol=4)
    estate = Estate(gpos=[gpo])
    results = queries.version_skew(estate)
    assert len(results) == 2
    assert (gpo, "Computer") in results
    assert (gpo, "User") in results


def test_version_skew_equal_versions():
    gpo = _make_gpo(computer_ver_ds=5, computer_ver_sysvol=5)
    estate = Estate(gpos=[gpo])
    assert queries.version_skew(estate) == []


def test_version_skew_one_none():
    """If one version is None and the other is not, that counts as skew."""
    gpo = _make_gpo(computer_ver_ds=5, computer_ver_sysvol=None)
    estate = Estate(gpos=[gpo])
    assert queries.version_skew(estate) == [(gpo, "Computer")]


# ---- ms16_072 --------------------------------------------------------------

def test_ms16_072_empty_delegation():
    gpo = _make_gpo(delegation=[])
    estate = Estate(gpos=[gpo])
    assert queries.ms16_072_vulnerable(estate) == [gpo]


def test_ms16_072_has_au_read():
    """AU with Read is sufficient — Apply Group Policy is irrelevant to MS16-072."""
    gpo = _make_gpo(
        delegation=[
            DelegationEntry(
                gpo_id="x", trustee="Authenticated Users", trustee_sid=None,
                permission="Read", allowed=True,
            ),
        ]
    )
    estate = Estate(gpos=[gpo])
    assert queries.ms16_072_vulnerable(estate) == []


def test_ms16_072_has_dc_read():
    """DC with Read is sufficient — Apply Group Policy is irrelevant to MS16-072."""
    gpo = _make_gpo(
        delegation=[
            DelegationEntry(
                gpo_id="x", trustee="Domain Computers", trustee_sid="S-1-5-21-123-515",
                permission="Read", allowed=True,
            ),
        ]
    )
    estate = Estate(gpos=[gpo])
    assert queries.ms16_072_vulnerable(estate) == []


def test_ms16_072_missing_read():
    """Apply Group Policy alone is not enough — MS16-072 needs Read for SYSVOL."""
    gpo = _make_gpo(
        delegation=[
            DelegationEntry(
                gpo_id="x", trustee="Authenticated Users", trustee_sid=None,
                permission="Apply Group Policy", allowed=True,
            ),
        ]
    )
    estate = Estate(gpos=[gpo])
    assert queries.ms16_072_vulnerable(estate) == [gpo]


def test_ms16_072_denied_read():
    """Denied Read counts as missing."""
    gpo = _make_gpo(
        delegation=[
            DelegationEntry(
                gpo_id="x", trustee="Authenticated Users", trustee_sid=None,
                permission="Read", allowed=False,
            ),
        ]
    )
    estate = Estate(gpos=[gpo])
    assert queries.ms16_072_vulnerable(estate) == [gpo]


def test_ms16_072_case_insensitive():
    gpo = _make_gpo(
        delegation=[
            DelegationEntry(
                gpo_id="x", trustee="authenticated users", trustee_sid=None,
                permission="read", allowed=True,
            ),
        ]
    )
    estate = Estate(gpos=[gpo])
    assert queries.ms16_072_vulnerable(estate) == []


def test_ms16_072_dc_read_via_sid():
    """DC matched by SID ending in -515."""
    gpo = _make_gpo(
        delegation=[
            DelegationEntry(
                gpo_id="x", trustee="SomeGroup", trustee_sid="S-1-5-21-123-515",
                permission="Read", allowed=True,
            ),
        ]
    )
    estate = Estate(gpos=[gpo])
    assert queries.ms16_072_vulnerable(estate) == []


# ---- cpassword_scan --------------------------------------------------------

def test_cpassword_scan_no_sysvol_path(tmp_path):
    gpo = _make_gpo(sysvol_path=None)
    estate = Estate(gpos=[gpo])
    assert queries.cpassword_scan(estate) == []


def test_cpassword_scan_clean(tmp_path):
    gpo_dir = tmp_path / "gpo"
    gpo_dir.mkdir()
    prefs = gpo_dir / "Machine" / "Preferences"
    prefs.mkdir(parents=True)
    (prefs / "Groups.xml").write_text("<Groups/>")
    gpo = _make_gpo(sysvol_path=str(gpo_dir))
    estate = Estate(gpos=[gpo])
    assert queries.cpassword_scan(estate) == []


def test_cpassword_scan_finds_hit(tmp_path):
    gpo_dir = tmp_path / "gpo"
    gpo_dir.mkdir()
    prefs = gpo_dir / "Machine" / "Preferences"
    prefs.mkdir(parents=True)
    root = ET.Element("Groups")
    user = ET.SubElement(root, "User")
    user.set("cpassword", "ABCD1234")
    tree = ET.ElementTree(root)
    tree.write(prefs / "Groups.xml")
    gpo = _make_gpo(id="abc", name="GPO", sysvol_path=str(gpo_dir))
    estate = Estate(gpos=[gpo])
    hits = queries.cpassword_scan(estate)
    assert len(hits) == 1
    hit = hits[0]
    assert hit.gpo_id == "abc"
    assert hit.gpo_name == "GPO"
    assert Path(hit.file) == Path("Machine/Preferences/Groups.xml")
    assert hit.tag == "User"
    assert hit.cpassword == "ABCD1234"


def test_cpassword_scan_skips_broken_xml(tmp_path):
    gpo_dir = tmp_path / "gpo"
    gpo_dir.mkdir()
    prefs = gpo_dir / "Machine" / "Preferences"
    prefs.mkdir(parents=True)
    (prefs / "Groups.xml").write_text("not xml")
    gpo = _make_gpo(sysvol_path=str(gpo_dir))
    estate = Estate(gpos=[gpo])
    assert queries.cpassword_scan(estate) == []


# ---- topology queries ------------------------------------------------------

def test_som_effective_gpos():
    from gpo_lens.model import Som, SomLink

    gpo = _make_gpo(id="gpo-1", name="Test GPO")
    som = Som(
        path="ou=workstations,dc=test,dc=local",
        name="Workstations",
        container_type="ou",
        inheritance_blocked=False,
        links=[
            SomLink(
                gpo_id="gpo-1", order=1, enabled=True,
                enforced=False, target="ou=workstations,dc=test,dc=local",
            ),
        ],
    )
    estate = Estate(gpos=[gpo], soms=[som])
    result = queries.som_effective_gpos(estate, "ou=workstations,dc=test,dc=local")
    assert len(result) == 1
    assert result[0].gpo_id == "gpo-1"
    assert result[0].gpo_name == "Test GPO"


def test_som_effective_gpos_case_insensitive():
    from gpo_lens.model import Som, SomLink

    gpo = _make_gpo(id="gpo-1", name="Test GPO")
    som = Som(
        path="OU=Workstations,DC=test,DC=local",
        name="Workstations",
        container_type="ou",
        inheritance_blocked=False,
        links=[SomLink(gpo_id="gpo-1", order=1, enabled=True, enforced=False, target="")],
    )
    estate = Estate(gpos=[gpo], soms=[som])
    result = queries.som_effective_gpos(estate, "ou=workstations,dc=test,dc=local")
    assert len(result) == 1


def test_dangling_links():
    from gpo_lens.model import Som, SomLink

    som = Som(
        path="ou=workstations,dc=test,dc=local",
        name="Workstations",
        container_type="ou",
        inheritance_blocked=False,
        links=[SomLink(gpo_id="missing-gpo", order=1, enabled=True, enforced=False, target="")],
    )
    estate = Estate(gpos=[], soms=[som])
    result = queries.dangling_links(estate)
    assert len(result) == 1
    assert result[0][1].gpo_id == "missing-gpo"


def test_enforced_links():
    from gpo_lens.model import Som, SomLink

    gpo = _make_gpo(id="gpo-1")
    som = Som(
        path="ou=workstations,dc=test,dc=local",
        name="Workstations",
        container_type="ou",
        inheritance_blocked=False,
        links=[
            SomLink(gpo_id="gpo-1", order=1, enabled=True, enforced=True, target=""),
        ],
    )
    estate = Estate(gpos=[gpo], soms=[som])
    result = queries.enforced_links(estate)
    assert len(result) == 1
    assert result[0][1].enforced is True


def test_loopback_gpos_detects_loopback_setting():
    from gpo_lens.model import Setting

    gpo = _make_gpo(
        id="gpo-1",
        settings=[
            Setting(
                gpo_id="gpo-1", side="Computer", cse="Registry",
                identity="Configure user Group Policy loopback processing mode",
                display_name="Loopback", display_value="Enabled",
                raw={}, from_disabled_side=False,
            ),
        ],
    )
    estate = Estate(gpos=[gpo])
    result = queries.loopback_gpos(estate)
    assert len(result) == 1
    assert result[0][0].id == "gpo-1"


def test_wmi_filtered_gpos():
    gpo = _make_gpo(id="gpo-1", wmi_filter="MyFilter")
    estate = Estate(gpos=[gpo])
    result = queries.wmi_filtered_gpos(estate)
    assert len(result) == 1
    assert result[0].wmi_filter == "MyFilter"


# ---- Tier 2.5 chain-aware queries -----------------------------------------

def test_som_conflicts_empty_when_no_som():
    estate = Estate(gpos=[], soms=[])
    assert queries.som_conflicts(estate, "dc=test,dc=local") == []


def test_som_conflicts_empty_when_single_gpo():
    from gpo_lens.model import Setting, Som, SomLink

    gpo = _make_gpo(
        id="gpo-1",
        settings=[
            Setting(
                gpo_id="gpo-1", side="Computer", cse="Security",
                identity="Account:Foo", display_name="Foo",
                display_value="bar", raw={}, from_disabled_side=False,
            ),
        ],
    )
    som = Som(
        path="ou=ws,dc=test,dc=local",
        name="WS",
        container_type="ou",
        inheritance_blocked=False,
        links=[SomLink(gpo_id="gpo-1", order=1, enabled=True, enforced=False, target="")],
    )
    estate = Estate(gpos=[gpo], soms=[som])
    result = queries.som_conflicts(estate, "ou=ws,dc=test,dc=local")
    assert result == []


def test_som_conflicts_detects_value_mismatch():
    from gpo_lens.model import Setting, Som, SomLink

    gpo_a = _make_gpo(
        id="gpo-a", name="GPO A",
        settings=[
            Setting(
                gpo_id="gpo-a", side="Computer", cse="Security",
                identity="Account:LockoutBadCount",
                display_name="LockoutBadCount",
                display_value="5", raw={}, from_disabled_side=False,
            ),
        ],
    )
    gpo_b = _make_gpo(
        id="gpo-b", name="GPO B",
        settings=[
            Setting(
                gpo_id="gpo-b", side="Computer", cse="Security",
                identity="Account:LockoutBadCount",
                display_name="LockoutBadCount",
                display_value="10", raw={}, from_disabled_side=False,
            ),
        ],
    )
    som = Som(
        path="ou=ws,dc=test,dc=local",
        name="WS",
        container_type="ou",
        inheritance_blocked=False,
        links=[
            SomLink(gpo_id="gpo-a", order=1, enabled=True, enforced=False, target=""),
            SomLink(gpo_id="gpo-b", order=2, enabled=True, enforced=False, target=""),
        ],
    )
    estate = Estate(gpos=[gpo_a, gpo_b], soms=[som])
    result = queries.som_conflicts(estate, "ou=ws,dc=test,dc=local")
    assert len(result) == 1
    c = result[0]
    assert c.identity == "Account:LockoutBadCount"
    assert c.winner == "GPO B"
    assert len(c.entries) == 2


def test_som_conflicts_ignores_disabled_links():
    from gpo_lens.model import Setting, Som, SomLink

    gpo_a = _make_gpo(
        id="gpo-a",
        settings=[
            Setting(
                gpo_id="gpo-a", side="Computer", cse="Security",
                identity="Account:Foo", display_name="Foo",
                display_value="5", raw={}, from_disabled_side=False,
            ),
        ],
    )
    gpo_b = _make_gpo(
        id="gpo-b",
        settings=[
            Setting(
                gpo_id="gpo-b", side="Computer", cse="Security",
                identity="Account:Foo", display_name="Foo",
                display_value="10", raw={}, from_disabled_side=False,
            ),
        ],
    )
    som = Som(
        path="ou=ws,dc=test,dc=local",
        name="WS",
        container_type="ou",
        inheritance_blocked=False,
        links=[
            SomLink(gpo_id="gpo-a", order=1, enabled=True, enforced=False, target=""),
            SomLink(
                gpo_id="gpo-b", order=2, enabled=False,
                enforced=False, target="",
            ),
        ],
    )
    estate = Estate(gpos=[gpo_a, gpo_b], soms=[som])
    result = queries.som_conflicts(estate, "ou=ws,dc=test,dc=local")
    assert result == []


def test_precedence_conflicts_empty_when_clean():
    estate = Estate(gpos=[], soms=[])
    assert queries.precedence_conflicts(estate) == []


def test_broken_refs_detects_unc_in_display_value():
    from gpo_lens.model import Setting

    gpo = _make_gpo(
        id="gpo-1",
        settings=[
            Setting(
                gpo_id="gpo-1", side="Computer", cse="Registry",
                identity="InstallDir", display_name="Install Dir",
                display_value=r"\\server\share\app", raw={},
                from_disabled_side=False,
            ),
        ],
    )
    estate = Estate(gpos=[gpo])
    result = queries.broken_refs(estate)
    assert len(result) == 1
    assert result[0].ref_type == "unc_path"
    assert result[0].ref_value == r"\\server\share\app"


def test_broken_refs_empty_when_clean():
    gpo = _make_gpo(id="gpo-1", settings=[])
    estate = Estate(gpos=[gpo])
    assert queries.broken_refs(estate) == []


def test_broken_refs_detects_unc_in_raw_dict():
    from gpo_lens.model import Setting

    gpo = _make_gpo(
        id="gpo-1",
        settings=[
            Setting(
                gpo_id="gpo-1", side="Computer", cse="Registry",
                identity="InstallDir", display_name="Install Dir",
                display_value="local",
                raw={"children": [{"text": r"\\server\share\path"}]},
                from_disabled_side=False,
            ),
        ],
    )
    estate = Estate(gpos=[gpo])
    result = queries.broken_refs(estate)
    unc_refs = [r for r in result if r.ref_type == "unc_path"]
    assert len(unc_refs) >= 1
    assert r"\\server\share\path" in unc_refs[0].ref_value


def test_broken_refs_detects_missing_script(tmp_path):
    from gpo_lens.model import Setting

    gpo_dir = tmp_path / "gpo"
    gpo_dir.mkdir()
    gpo = _make_gpo(
        id="gpo-1",
        sysvol_path=str(gpo_dir),
        settings=[
            Setting(
                gpo_id="gpo-1", side="Computer", cse="Scripts",
                identity="StartupScript", display_name="StartupScript",
                display_value="missing.bat",
                raw={}, from_disabled_side=False,
            ),
        ],
    )
    estate = Estate(gpos=[gpo])
    result = queries.broken_refs(estate)
    missing = [r for r in result if r.ref_type == "missing_script"]
    assert len(missing) == 1
    assert "missing.bat" in missing[0].ref_value


def test_broken_refs_script_found_in_sysvol(tmp_path):
    from gpo_lens.model import Setting

    gpo_dir = tmp_path / "gpo"
    scripts_dir = gpo_dir / "Machine" / "Scripts" / "Startup"
    scripts_dir.mkdir(parents=True)
    (scripts_dir / "exists.bat").write_text("@echo off", encoding="utf-8")

    gpo = _make_gpo(
        id="gpo-1",
        sysvol_path=str(gpo_dir),
        settings=[
            Setting(
                gpo_id="gpo-1", side="Computer", cse="Scripts",
                identity="StartupScript", display_name="StartupScript",
                display_value="exists.bat",
                raw={}, from_disabled_side=False,
            ),
        ],
    )
    estate = Estate(gpos=[gpo])
    result = queries.broken_refs(estate)
    missing = [r for r in result if r.ref_type == "missing_script"]
    assert missing == []


def test_broken_refs_deduplicates():
    from gpo_lens.model import Setting

    gpo = _make_gpo(
        id="gpo-1",
        settings=[
            Setting(
                gpo_id="gpo-1", side="Computer", cse="Registry",
                identity="X", display_name="X",
                display_value=r"\\server\share\path",
                raw={"text": r"\\server\share\path"},
                from_disabled_side=False,
            ),
        ],
    )
    estate = Estate(gpos=[gpo])
    result = queries.broken_refs(estate)
    unc_refs = [
        r for r in result
        if r.ref_type == "unc_path" and r.ref_value == r"\\server\share\path"
    ]
    assert len(unc_refs) == 1


# ---- estate_summary ---------------------------------------------------------

def test_estate_summary():
    gpo = _make_gpo(
        id="gpo-1",
        settings=[
            Setting(
                gpo_id="gpo-1", side="Computer", cse="Security",
                identity="X", display_name="X", display_value="1",
                raw={}, from_disabled_side=False,
            ),
        ],
    )
    estate = Estate(domain="test.local", gpos=[gpo])
    s = queries.estate_summary(estate)
    assert s.domain == "test.local"
    assert s.gpo_count == 1
    assert s.total_settings == 1
    assert s.unlinked_count == 1  # no links
    assert s.empty_count == 0
    assert s.conflict_count == 0
    assert s.ms16_072_vulnerable_count == 1  # no delegation entries


# ---- existing queries still pass smoke --------------------------------------

def test_empty_gpos():
    gpo = _make_gpo(settings=[])
    estate = Estate(gpos=[gpo])
    assert queries.empty_gpos(estate) == [gpo]


def test_unlinked_gpos():
    gpo = _make_gpo(links=[])
    estate = Estate(gpos=[gpo])
    assert queries.unlinked_gpos(estate) == [gpo]


# ---- disabled_but_populated --------------------------------------------------


def test_disabled_but_populated_computer_side():
    gpo = _make_gpo(
        computer_enabled=False,
        settings=[
            Setting(
                gpo_id="gpo-1", side="Computer", cse="Security",
                identity="X", display_name="X", display_value="1",
                raw={}, from_disabled_side=True,
            ),
        ],
    )
    estate = Estate(gpos=[gpo])
    result = queries.disabled_but_populated(estate)
    assert result == [(gpo, "Computer")]


def test_disabled_but_populated_user_side():
    gpo = _make_gpo(
        user_enabled=False,
        settings=[
            Setting(
                gpo_id="gpo-1", side="User", cse="Registry",
                identity="Y", display_name="Y", display_value="2",
                raw={}, from_disabled_side=True,
            ),
        ],
    )
    estate = Estate(gpos=[gpo])
    result = queries.disabled_but_populated(estate)
    assert result == [(gpo, "User")]


def test_disabled_but_populated_both_sides():
    gpo = _make_gpo(
        computer_enabled=False,
        user_enabled=False,
        settings=[
            Setting(
                gpo_id="gpo-1", side="Computer", cse="Security",
                identity="X", display_name="X", display_value="1",
                raw={}, from_disabled_side=True,
            ),
            Setting(
                gpo_id="gpo-1", side="User", cse="Registry",
                identity="Y", display_name="Y", display_value="2",
                raw={}, from_disabled_side=True,
            ),
        ],
    )
    estate = Estate(gpos=[gpo])
    result = queries.disabled_but_populated(estate)
    assert len(result) == 2
    assert (gpo, "Computer") in result
    assert (gpo, "User") in result


def test_disabled_but_populated_enabled_side_ignored():
    gpo = _make_gpo(
        computer_enabled=True,
        settings=[
            Setting(
                gpo_id="gpo-1", side="Computer", cse="Security",
                identity="X", display_name="X", display_value="1",
                raw={}, from_disabled_side=False,
            ),
        ],
    )
    estate = Estate(gpos=[gpo])
    assert queries.disabled_but_populated(estate) == []


# ---- settings_at_som --------------------------------------------------------

def test_settings_at_som_empty_when_no_som():
    estate = Estate(gpos=[], soms=[])
    assert queries.settings_at_som(estate, "dc=test,dc=local") == []


def test_settings_at_som_empty_when_single_gpo():
    from gpo_lens.model import Setting, Som, SomLink

    gpo = _make_gpo(
        id="gpo-1",
        settings=[
            Setting(
                gpo_id="gpo-1", side="Computer", cse="Security",
                identity="Account:Foo", display_name="Foo",
                display_value="bar", raw={}, from_disabled_side=False,
            ),
        ],
    )
    som = Som(
        path="ou=ws,dc=test,dc=local",
        name="WS",
        container_type="ou",
        inheritance_blocked=False,
        links=[SomLink(gpo_id="gpo-1", order=1, enabled=True, enforced=False, target="")],
    )
    estate = Estate(gpos=[gpo], soms=[som])
    result = queries.settings_at_som(estate, "ou=ws,dc=test,dc=local")
    assert len(result) == 1
    assert result[0].identity == "Account:Foo"
    assert result[0].display_value == "bar"
    assert result[0].winner_gpo_id == "gpo-1"
    assert result[0].overridden_by == []
    assert result[0].enforced is False


def test_settings_at_som_last_gpo_wins():
    from gpo_lens.model import Setting, Som, SomLink

    gpo_a = _make_gpo(
        id="gpo-a", name="GPO A",
        settings=[
            Setting(
                gpo_id="gpo-a", side="Computer", cse="Security",
                identity="Account:LockoutBadCount",
                display_name="LockoutBadCount",
                display_value="5", raw={}, from_disabled_side=False,
            ),
        ],
    )
    gpo_b = _make_gpo(
        id="gpo-b", name="GPO B",
        settings=[
            Setting(
                gpo_id="gpo-b", side="Computer", cse="Security",
                identity="Account:LockoutBadCount",
                display_name="LockoutBadCount",
                display_value="10", raw={}, from_disabled_side=False,
            ),
        ],
    )
    som = Som(
        path="ou=ws,dc=test,dc=local",
        name="WS",
        container_type="ou",
        inheritance_blocked=False,
        links=[
            SomLink(gpo_id="gpo-a", order=1, enabled=True, enforced=False, target=""),
            SomLink(gpo_id="gpo-b", order=2, enabled=True, enforced=False, target=""),
        ],
    )
    estate = Estate(gpos=[gpo_a, gpo_b], soms=[som])
    result = queries.settings_at_som(estate, "ou=ws,dc=test,dc=local")
    assert len(result) == 1
    es = result[0]
    assert es.identity == "Account:LockoutBadCount"
    assert es.display_value == "10"
    assert es.winner_gpo_name == "GPO B"
    assert es.overridden_by == [("GPO A", "5")]


def test_settings_at_som_ignores_disabled_links():
    from gpo_lens.model import Setting, Som, SomLink

    gpo_a = _make_gpo(
        id="gpo-a", name="GPO A",
        settings=[
            Setting(
                gpo_id="gpo-a", side="Computer", cse="Security",
                identity="Account:Foo", display_name="Foo",
                display_value="5", raw={}, from_disabled_side=False,
            ),
        ],
    )
    gpo_b = _make_gpo(
        id="gpo-b", name="GPO B",
        settings=[
            Setting(
                gpo_id="gpo-b", side="Computer", cse="Security",
                identity="Account:Foo", display_name="Foo",
                display_value="10", raw={}, from_disabled_side=False,
            ),
        ],
    )
    som = Som(
        path="ou=ws,dc=test,dc=local",
        name="WS",
        container_type="ou",
        inheritance_blocked=False,
        links=[
            SomLink(gpo_id="gpo-a", order=1, enabled=True, enforced=False, target=""),
            SomLink(
                gpo_id="gpo-b", order=2, enabled=False,
                enforced=False, target="",
            ),
        ],
    )
    estate = Estate(gpos=[gpo_a, gpo_b], soms=[som])
    result = queries.settings_at_som(estate, "ou=ws,dc=test,dc=local")
    assert len(result) == 1
    assert result[0].display_value == "5"
    assert result[0].overridden_by == []


def test_settings_at_som_enforced_flag():
    from gpo_lens.model import Setting, Som, SomLink

    gpo = _make_gpo(
        id="gpo-1", name="GPO One",
        settings=[
            Setting(
                gpo_id="gpo-1", side="Computer", cse="Security",
                identity="Account:Foo", display_name="Foo",
                display_value="5", raw={}, from_disabled_side=False,
            ),
        ],
    )
    som = Som(
        path="ou=ws,dc=test,dc=local",
        name="WS",
        container_type="ou",
        inheritance_blocked=False,
        links=[
            SomLink(gpo_id="gpo-1", order=1, enabled=True, enforced=True, target=""),
        ],
    )
    estate = Estate(gpos=[gpo], soms=[som])
    result = queries.settings_at_som(estate, "ou=ws,dc=test,dc=local")
    assert len(result) == 1
    assert result[0].enforced is True


def test_settings_at_som_multiple_identities():
    from gpo_lens.model import Setting, Som, SomLink

    gpo = _make_gpo(
        id="gpo-1", name="GPO One",
        settings=[
            Setting(
                gpo_id="gpo-1", side="Computer", cse="Security",
                identity="Account:Foo", display_name="Foo",
                display_value="A", raw={}, from_disabled_side=False,
            ),
            Setting(
                gpo_id="gpo-1", side="User", cse="Registry",
                identity="Bar", display_name="Bar",
                display_value="B", raw={}, from_disabled_side=False,
            ),
        ],
    )
    som = Som(
        path="ou=ws,dc=test,dc=local",
        name="WS",
        container_type="ou",
        inheritance_blocked=False,
        links=[
            SomLink(gpo_id="gpo-1", order=1, enabled=True, enforced=False, target=""),
        ],
    )
    estate = Estate(gpos=[gpo], soms=[som])
    result = queries.settings_at_som(estate, "ou=ws,dc=test,dc=local")
    # Should be stable sorted: by (cse, side, identity)
    # Registry (User) sorts before Security (Computer)
    assert len(result) == 2
    assert result[0].cse == "Registry"
    assert result[0].side == "User"
    assert result[0].identity == "Bar"
    assert result[1].cse == "Security"
    assert result[1].side == "Computer"
    assert result[1].identity == "Account:Foo"


# ---- topology_crosscheck ----------------------------------------------------

def test_topology_crosscheck_no_tree():
    estate = Estate(gpos=[], soms=[], ou_tree=[])
    assert queries.topology_crosscheck(estate) == []


def test_topology_crosscheck_block_mismatch():
    from gpo_lens.model import Som

    som = Som(
        path="ou=ws,dc=test,dc=local",
        name="WS",
        container_type="ou",
        inheritance_blocked=False,
        links=[],
    )
    ou = OuRecord(
        dn="OU=WS,DC=test,DC=local",
        name="WS",
        gp_link=None,
        gp_options=1,
    )
    estate = Estate(soms=[som], ou_tree=[ou])
    result = queries.topology_crosscheck(estate)
    assert len(result) == 1
    assert result[0].kind == "block_mismatch"


def test_topology_crosscheck_block_match():
    from gpo_lens.model import Som

    som = Som(
        path="ou=ws,dc=test,dc=local",
        name="WS",
        container_type="ou",
        inheritance_blocked=True,
        links=[],
    )
    ou = OuRecord(
        dn="OU=WS,DC=test,DC=local",
        name="WS",
        gp_link=None,
        gp_options=1,
    )
    estate = Estate(soms=[som], ou_tree=[ou])
    result = queries.topology_crosscheck(estate)
    assert result == []


def test_topology_crosscheck_ou_missing_from_soms():
    ou = OuRecord(
        dn="OU=Missing,DC=test,DC=local",
        name="Missing",
        gp_link="[LDAP://cn={AAA};0]",
        gp_options=0,
    )
    estate = Estate(soms=[], ou_tree=[ou])
    result = queries.topology_crosscheck(estate)
    assert len(result) == 1
    assert result[0].kind == "ou_missing_from_soms"


def test_topology_crosscheck_ou_no_gplink_not_flagged():
    ou = OuRecord(
        dn="OU=Empty,DC=test,DC=local",
        name="Empty",
        gp_link=None,
        gp_options=0,
    )
    estate = Estate(soms=[], ou_tree=[ou])
    result = queries.topology_crosscheck(estate)
    assert result == []
