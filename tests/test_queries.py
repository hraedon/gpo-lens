"""Unit tests for Tier-1 queries (no samples required)."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from gpo_lens.model import DelegationEntry, Estate, Gpo
from gpo_lens import queries


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


# ---- existing queries still pass smoke --------------------------------------

def test_empty_gpos():
    gpo = _make_gpo(settings=[])
    estate = Estate(gpos=[gpo])
    assert queries.empty_gpos(estate) == [gpo]


def test_unlinked_gpos():
    gpo = _make_gpo(links=[])
    estate = Estate(gpos=[gpo])
    assert queries.unlinked_gpos(estate) == [gpo]
