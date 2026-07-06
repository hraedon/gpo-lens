"""Direct tests for snapshot_diff.py edge cases.

These import snapshot_diff directly (not through the queries facade) to
cover paths that the existing query-level tests may not reach.
"""

from __future__ import annotations

import sqlite3

from _helpers import _make_gpo

from gpo_lens import store
from gpo_lens.model import Estate, Setting
from gpo_lens.snapshot_diff import (
    snapshot_changelog,
    snapshot_diff,
    snapshot_settings_diff,
)

# ---------------------------------------------------------------------------
# snapshot_changelog: gpo_removed entry
# ---------------------------------------------------------------------------


def test_snapshot_changelog_gpo_removed_direct(tmp_path):
    db = tmp_path / "removed.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)

    gpo_a = _make_gpo(id="gpo-alpha", name="Alpha")
    gpo_b = _make_gpo(id="gpo-beta", name="Beta")
    sid_a = store.save_estate(conn, Estate(domain="test.local", gpos=[gpo_a, gpo_b]))
    sid_b = store.save_estate(conn, Estate(domain="test.local", gpos=[gpo_a]))

    entries = snapshot_changelog(conn, sid_a, sid_b)
    conn.close()

    removed = [e for e in entries if e.kind == "gpo_removed"]
    assert len(removed) == 1
    assert removed[0].gpo_id == "gpo-beta"
    assert removed[0].gpo_name == "Beta"


# ---------------------------------------------------------------------------
# snapshot_changelog: version change with None old/new rows
# ---------------------------------------------------------------------------


def test_snapshot_changelog_no_changes_direct(tmp_path):
    """Identical snapshots produce zero changelog entries."""
    db = tmp_path / "nochange.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)

    gpo = _make_gpo(id="gpo-alpha", name="Alpha",
                    computer_ver_ds=1, computer_ver_sysvol=1)
    sid_a = store.save_estate(conn, Estate(domain="test.local", gpos=[gpo]))
    sid_b = store.save_estate(conn, Estate(domain="test.local", gpos=[gpo]))

    entries = snapshot_changelog(conn, sid_a, sid_b)
    conn.close()
    assert len(entries) == 0


# ---------------------------------------------------------------------------
# snapshot_settings_diff: added/removed settings
# ---------------------------------------------------------------------------


def test_snapshot_settings_diff_setting_added_direct(tmp_path):
    db = tmp_path / "added.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)

    gpo_a = _make_gpo(id="gpo-alpha", name="Alpha")
    sid_a = store.save_estate(conn, Estate(domain="test.local", gpos=[gpo_a]))

    gpo_b = _make_gpo(id="gpo-alpha", name="Alpha", settings=[
        Setting(gpo_id="gpo-alpha", side="Computer", cse="Registry",
                identity="HKLM\\X", display_name="X", display_value="1",
                raw={}, from_disabled_side=False),
    ])
    sid_b = store.save_estate(conn, Estate(domain="test.local", gpos=[gpo_b]))

    changes = snapshot_settings_diff(conn, sid_a, sid_b)
    conn.close()

    assert len(changes) == 1
    assert changes[0].change_type == "added"
    assert changes[0].identity == "HKLM\\X"


def test_snapshot_settings_diff_setting_removed_direct(tmp_path):
    db = tmp_path / "removed_setting.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)

    gpo_a = _make_gpo(id="gpo-alpha", name="Alpha", settings=[
        Setting(gpo_id="gpo-alpha", side="Computer", cse="Registry",
                identity="HKLM\\X", display_name="X", display_value="1",
                raw={}, from_disabled_side=False),
    ])
    sid_a = store.save_estate(conn, Estate(domain="test.local", gpos=[gpo_a]))

    gpo_b = _make_gpo(id="gpo-alpha", name="Alpha")
    sid_b = store.save_estate(conn, Estate(domain="test.local", gpos=[gpo_b]))

    changes = snapshot_settings_diff(conn, sid_a, sid_b)
    conn.close()

    assert len(changes) == 1
    assert changes[0].change_type == "removed"
    assert changes[0].identity == "HKLM\\X"


# ---------------------------------------------------------------------------
# snapshot_settings_diff: filtered by gpo_id, side, cse
# ---------------------------------------------------------------------------


def test_snapshot_settings_diff_filter_by_gpo_id_direct(tmp_path):
    db = tmp_path / "filter_gpo.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)

    gpo_a = _make_gpo(id="gpo-alpha", name="Alpha", settings=[
        Setting(gpo_id="gpo-alpha", side="Computer", cse="Registry",
                identity="HKLM\\X", display_name="X", display_value="old",
                raw={}, from_disabled_side=False),
    ])
    gpo_b = _make_gpo(id="gpo-beta", name="Beta", settings=[
        Setting(gpo_id="gpo-beta", side="Computer", cse="Registry",
                identity="HKLM\\Y", display_name="Y", display_value="old",
                raw={}, from_disabled_side=False),
    ])
    sid_a = store.save_estate(conn, Estate(domain="test.local", gpos=[gpo_a, gpo_b]))

    gpo_a2 = _make_gpo(id="gpo-alpha", name="Alpha", settings=[
        Setting(gpo_id="gpo-alpha", side="Computer", cse="Registry",
                identity="HKLM\\X", display_name="X", display_value="new",
                raw={}, from_disabled_side=False),
    ])
    gpo_b2 = _make_gpo(id="gpo-beta", name="Beta", settings=[
        Setting(gpo_id="gpo-beta", side="Computer", cse="Registry",
                identity="HKLM\\Y", display_name="Y", display_value="new",
                raw={}, from_disabled_side=False),
    ])
    sid_b = store.save_estate(conn, Estate(domain="test.local", gpos=[gpo_a2, gpo_b2]))

    all_changes = snapshot_settings_diff(conn, sid_a, sid_b)
    assert len(all_changes) == 2

    filtered = snapshot_settings_diff(conn, sid_a, sid_b, gpo_id="gpo-alpha")
    assert len(filtered) == 1
    assert filtered[0].gpo_id == "gpo-alpha"

    conn.close()


def test_snapshot_settings_diff_filter_by_side_direct(tmp_path):
    db = tmp_path / "filter_side.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)

    gpo = _make_gpo(id="gpo-alpha", name="Alpha", settings=[
        Setting(gpo_id="gpo-alpha", side="Computer", cse="Registry",
                identity="HKLM\\X", display_name="X", display_value="old",
                raw={}, from_disabled_side=False),
        Setting(gpo_id="gpo-alpha", side="User", cse="Registry",
                identity="HKCU\\Y", display_name="Y", display_value="old",
                raw={}, from_disabled_side=False),
    ])
    sid_a = store.save_estate(conn, Estate(domain="test.local", gpos=[gpo]))

    gpo2 = _make_gpo(id="gpo-alpha", name="Alpha", settings=[
        Setting(gpo_id="gpo-alpha", side="Computer", cse="Registry",
                identity="HKLM\\X", display_name="X", display_value="new",
                raw={}, from_disabled_side=False),
        Setting(gpo_id="gpo-alpha", side="User", cse="Registry",
                identity="HKCU\\Y", display_name="Y", display_value="new",
                raw={}, from_disabled_side=False),
    ])
    sid_b = store.save_estate(conn, Estate(domain="test.local", gpos=[gpo2]))

    comp_only = snapshot_settings_diff(conn, sid_a, sid_b, side="Computer")
    assert len(comp_only) == 1
    assert comp_only[0].side == "Computer"

    user_only = snapshot_settings_diff(conn, sid_a, sid_b, side="User")
    assert len(user_only) == 1
    assert user_only[0].side == "User"

    conn.close()


def test_snapshot_settings_diff_filter_by_cse_direct(tmp_path):
    db = tmp_path / "filter_cse.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)

    gpo = _make_gpo(id="gpo-alpha", name="Alpha", settings=[
        Setting(gpo_id="gpo-alpha", side="Computer", cse="Registry",
                identity="HKLM\\X", display_name="X", display_value="old",
                raw={}, from_disabled_side=False),
        Setting(gpo_id="gpo-alpha", side="Computer", cse="Security",
                identity="Security:X", display_name="X", display_value="old",
                raw={}, from_disabled_side=False),
    ])
    sid_a = store.save_estate(conn, Estate(domain="test.local", gpos=[gpo]))

    gpo2 = _make_gpo(id="gpo-alpha", name="Alpha", settings=[
        Setting(gpo_id="gpo-alpha", side="Computer", cse="Registry",
                identity="HKLM\\X", display_name="X", display_value="new",
                raw={}, from_disabled_side=False),
        Setting(gpo_id="gpo-alpha", side="Computer", cse="Security",
                identity="Security:X", display_name="X", display_value="new",
                raw={}, from_disabled_side=False),
    ])
    sid_b = store.save_estate(conn, Estate(domain="test.local", gpos=[gpo2]))

    reg_only = snapshot_settings_diff(conn, sid_a, sid_b, cse="Registry")
    assert len(reg_only) == 1
    assert reg_only[0].cse == "Registry"

    conn.close()


# ---------------------------------------------------------------------------
# snapshot_diff: no common GPOs
# ---------------------------------------------------------------------------


def test_snapshot_diff_no_common_gpos_direct(tmp_path):
    db = tmp_path / "nocommon.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)

    gpo_a = _make_gpo(id="gpo-alpha", name="Alpha")
    sid_a = store.save_estate(conn, Estate(domain="test.local", gpos=[gpo_a]))

    gpo_b = _make_gpo(id="gpo-beta", name="Beta")
    sid_b = store.save_estate(conn, Estate(domain="test.local", gpos=[gpo_b]))

    diff = snapshot_diff(conn, sid_a, sid_b)
    conn.close()

    assert diff.gpos_added == ["gpo-beta"]
    assert diff.gpos_removed == ["gpo-alpha"]
    assert diff.settings_changed == []
    assert diff.links_changed == []
    assert diff.delegation_changed == []


# ---------------------------------------------------------------------------
# snapshot_diff: version skew change
# ---------------------------------------------------------------------------


def test_snapshot_diff_version_skew_appears_direct(tmp_path):
    db = tmp_path / "skew.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)

    gpo_a = _make_gpo(id="gpo-alpha", name="Alpha",
                      computer_ver_ds=1, computer_ver_sysvol=1)
    sid_a = store.save_estate(conn, Estate(domain="test.local", gpos=[gpo_a]))

    gpo_b = _make_gpo(id="gpo-alpha", name="Alpha",
                      computer_ver_ds=1, computer_ver_sysvol=2)
    sid_b = store.save_estate(conn, Estate(domain="test.local", gpos=[gpo_b]))

    diff = snapshot_diff(conn, sid_a, sid_b)
    conn.close()

    assert "gpo-alpha" in diff.version_skew_changed


def test_snapshot_diff_version_skew_resolved_direct(tmp_path):
    db = tmp_path / "skew_resolved.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)

    gpo_a = _make_gpo(id="gpo-alpha", name="Alpha",
                      computer_ver_ds=1, computer_ver_sysvol=2)
    sid_a = store.save_estate(conn, Estate(domain="test.local", gpos=[gpo_a]))

    gpo_b = _make_gpo(id="gpo-alpha", name="Alpha",
                      computer_ver_ds=2, computer_ver_sysvol=2)
    sid_b = store.save_estate(conn, Estate(domain="test.local", gpos=[gpo_b]))

    diff = snapshot_diff(conn, sid_a, sid_b)
    conn.close()

    assert "gpo-alpha" in diff.version_skew_changed


# ---------------------------------------------------------------------------
# snapshot_diff: metadata changes (name, domain, sddl, owner)
# ---------------------------------------------------------------------------


def test_snapshot_diff_name_change_direct(tmp_path):
    db = tmp_path / "name.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)

    gpo_a = _make_gpo(id="gpo-alpha", name="Old Name")
    sid_a = store.save_estate(conn, Estate(domain="test.local", gpos=[gpo_a]))

    gpo_b = _make_gpo(id="gpo-alpha", name="New Name")
    sid_b = store.save_estate(conn, Estate(domain="test.local", gpos=[gpo_b]))

    diff = snapshot_diff(conn, sid_a, sid_b)
    conn.close()

    names = [c for c in diff.metadata_changes if c.field == "name"]
    assert len(names) == 1
    assert names[0].old_value == "Old Name"
    assert names[0].new_value == "New Name"


def test_snapshot_diff_sddl_change_direct(tmp_path):
    db = tmp_path / "sddl.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)

    gpo_a = _make_gpo(id="gpo-alpha", name="Alpha", sddl="D:(A;;GA;;;S-1-5-11)")
    sid_a = store.save_estate(conn, Estate(domain="test.local", gpos=[gpo_a]))

    gpo_b = _make_gpo(id="gpo-alpha", name="Alpha", sddl="D:(A;;GA;;;S-1-5-32-544)")
    sid_b = store.save_estate(conn, Estate(domain="test.local", gpos=[gpo_b]))

    diff = snapshot_diff(conn, sid_a, sid_b)
    conn.close()

    sddl_changes = [c for c in diff.metadata_changes if c.field == "sddl"]
    assert len(sddl_changes) == 1


def test_snapshot_diff_owner_change_direct(tmp_path):
    db = tmp_path / "owner.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)

    gpo_a = _make_gpo(id="gpo-alpha", name="Alpha", owner="DOMAIN\\Admin1")
    sid_a = store.save_estate(conn, Estate(domain="test.local", gpos=[gpo_a]))

    gpo_b = _make_gpo(id="gpo-alpha", name="Alpha", owner="DOMAIN\\Admin2")
    sid_b = store.save_estate(conn, Estate(domain="test.local", gpos=[gpo_b]))

    diff = snapshot_diff(conn, sid_a, sid_b)
    conn.close()

    owner_changes = [c for c in diff.metadata_changes if c.field == "owner"]
    assert len(owner_changes) == 1


def test_snapshot_diff_domain_change_direct(tmp_path):
    db = tmp_path / "domain.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)

    gpo_a = _make_gpo(id="gpo-alpha", name="Alpha", domain="old.local")
    sid_a = store.save_estate(conn, Estate(domain="old.local", gpos=[gpo_a]))

    gpo_b = _make_gpo(id="gpo-alpha", name="Alpha", domain="new.local")
    sid_b = store.save_estate(conn, Estate(domain="new.local", gpos=[gpo_b]))

    diff = snapshot_diff(conn, sid_a, sid_b)
    conn.close()

    domain_changes = [c for c in diff.metadata_changes if c.field == "domain"]
    assert len(domain_changes) == 1


# ---------------------------------------------------------------------------
# snapshot_diff: enabled flips
# ---------------------------------------------------------------------------


def test_snapshot_diff_computer_enabled_flip_direct(tmp_path):
    db = tmp_path / "enabled.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)

    gpo_a = _make_gpo(id="gpo-alpha", name="Alpha", computer_enabled=True)
    sid_a = store.save_estate(conn, Estate(domain="test.local", gpos=[gpo_a]))

    gpo_b = _make_gpo(id="gpo-alpha", name="Alpha", computer_enabled=False)
    sid_b = store.save_estate(conn, Estate(domain="test.local", gpos=[gpo_b]))

    diff = snapshot_diff(conn, sid_a, sid_b)
    conn.close()

    flips = [c for c in diff.enabled_flips if c.field == "computer_enabled"]
    assert len(flips) == 1
    assert flips[0].old_value == "True"
    assert flips[0].new_value == "False"


# ---------------------------------------------------------------------------
# snapshot_diff: wmi_filter changes
# ---------------------------------------------------------------------------


def test_snapshot_diff_wmi_filter_added_direct(tmp_path):
    db = tmp_path / "wmi_added.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)

    gpo_a = _make_gpo(id="gpo-alpha", name="Alpha", wmi_filter=None)
    sid_a = store.save_estate(conn, Estate(domain="test.local", gpos=[gpo_a]))

    gpo_b = _make_gpo(id="gpo-alpha", name="Alpha", wmi_filter="NewFilter")
    sid_b = store.save_estate(conn, Estate(domain="test.local", gpos=[gpo_b]))

    diff = snapshot_diff(conn, sid_a, sid_b)
    conn.close()

    assert len(diff.wmi_filter_changes) == 1
    assert diff.wmi_filter_changes[0].old_value == ""
    assert diff.wmi_filter_changes[0].new_value == "NewFilter"


def test_snapshot_diff_wmi_filter_removed_direct(tmp_path):
    db = tmp_path / "wmi_removed.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)

    gpo_a = _make_gpo(id="gpo-alpha", name="Alpha", wmi_filter="OldFilter")
    sid_a = store.save_estate(conn, Estate(domain="test.local", gpos=[gpo_a]))

    gpo_b = _make_gpo(id="gpo-alpha", name="Alpha", wmi_filter=None)
    sid_b = store.save_estate(conn, Estate(domain="test.local", gpos=[gpo_b]))

    diff = snapshot_diff(conn, sid_a, sid_b)
    conn.close()

    assert len(diff.wmi_filter_changes) == 1
    assert diff.wmi_filter_changes[0].old_value == "OldFilter"
    assert diff.wmi_filter_changes[0].new_value == ""


# ---------------------------------------------------------------------------
# snapshot_diff: links changed
# ---------------------------------------------------------------------------


def test_snapshot_diff_links_changed_direct(tmp_path):
    db = tmp_path / "links.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)

    from gpo_lens.model import GpoLink

    gpo_a = _make_gpo(id="gpo-alpha", name="Alpha", links=[
        GpoLink(gpo_id="gpo-alpha", som_name="test",
                som_path="dc=test,dc=local", link_enabled=True, enforced=False),
    ])
    sid_a = store.save_estate(conn, Estate(domain="test.local", gpos=[gpo_a]))

    gpo_b = _make_gpo(id="gpo-alpha", name="Alpha", links=[
        GpoLink(gpo_id="gpo-alpha", som_name="test",
                som_path="dc=test,dc=local", link_enabled=False, enforced=False),
    ])
    sid_b = store.save_estate(conn, Estate(domain="test.local", gpos=[gpo_b]))

    diff = snapshot_diff(conn, sid_a, sid_b)
    conn.close()

    assert "gpo-alpha" in diff.links_changed


# ---------------------------------------------------------------------------
# snapshot_diff: delegation changed
# ---------------------------------------------------------------------------


def test_snapshot_diff_delegation_changed_direct(tmp_path):
    db = tmp_path / "deleg.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)

    from gpo_lens.model import DelegationEntry

    gpo_a = _make_gpo(id="gpo-alpha", name="Alpha", delegation=[
        DelegationEntry(gpo_id="gpo-alpha", trustee="Authenticated Users",
                        trustee_sid="S-1-5-11",
                        permission="Apply Group Policy", allowed=True),
    ])
    sid_a = store.save_estate(conn, Estate(domain="test.local", gpos=[gpo_a]))

    gpo_b = _make_gpo(id="gpo-alpha", name="Alpha", delegation=[
        DelegationEntry(gpo_id="gpo-alpha", trustee="Authenticated Users",
                        trustee_sid="S-1-5-11",
                        permission="Read", allowed=True),
    ])
    sid_b = store.save_estate(conn, Estate(domain="test.local", gpos=[gpo_b]))

    diff = snapshot_diff(conn, sid_a, sid_b)
    conn.close()

    assert "gpo-alpha" in diff.delegation_changed


# ---------------------------------------------------------------------------
# _load_row_sets: allow-list guards (module-level extraction)
# ---------------------------------------------------------------------------


def test_load_row_sets_rejects_disallowed_table(tmp_path):
    import pytest

    from gpo_lens.snapshot_diff import _load_row_sets

    db = tmp_path / "guard_table.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)
    with pytest.raises(ValueError, match="unexpected table"):
        _load_row_sets(conn, "evil_table", "side, cse, identity, display_value",
                        1, [])
    conn.close()


def test_load_row_sets_rejects_disallowed_colset(tmp_path):
    import pytest

    from gpo_lens.snapshot_diff import _load_row_sets

    db = tmp_path / "guard_cols.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)
    with pytest.raises(ValueError, match="unexpected column set"):
        _load_row_sets(conn, "setting", "side, cse, identity, EVIL", 1, [])
    conn.close()


# ---------------------------------------------------------------------------
# snapshot_diff: chunking path (>500 common GPOs → multiple chunks)
# ---------------------------------------------------------------------------


def test_snapshot_diff_chunking_path(tmp_path, monkeypatch):
    """Exercise the chunked-query path with a small chunk size so the
    merge-across-chunks logic is tested without 501+ GPOs."""
    import gpo_lens.snapshot_diff as sd_mod

    monkeypatch.setattr(sd_mod, "_CHUNK_SIZE", 2)

    chunk_calls: list[int] = []
    original_chunked_ids = sd_mod._chunked_ids

    def _spied_chunked_ids(common_list: list[str]) -> list[list[str]]:
        chunks = list(original_chunked_ids(common_list))
        chunk_calls.extend(len(c) for c in chunks)
        return chunks

    monkeypatch.setattr(sd_mod, "_chunked_ids", _spied_chunked_ids)

    db = tmp_path / "chunk.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)

    gpos_a = [
        _make_gpo(id=f"gpo-{i:03d}", name=f"GPO-{i}",
                  settings=[
                      Setting(gpo_id=f"gpo-{i:03d}", side="Computer",
                              cse="Registry", identity="HKLM\\X",
                              display_name="X", display_value="old",
                              raw={}, from_disabled_side=False),
                  ])
        for i in range(5)
    ]
    sid_a = store.save_estate(conn, Estate(domain="test.local", gpos=gpos_a))

    gpos_b = [
        _make_gpo(id=f"gpo-{i:03d}", name=f"GPO-{i}",
                  settings=[
                      Setting(gpo_id=f"gpo-{i:03d}", side="Computer",
                              cse="Registry", identity="HKLM\\X",
                              display_name="X", display_value="new",
                              raw={}, from_disabled_side=False),
                  ])
        for i in range(5)
    ]
    sid_b = store.save_estate(conn, Estate(domain="test.local", gpos=gpos_b))

    diff = snapshot_diff(conn, sid_a, sid_b)
    conn.close()

    assert sorted(diff.settings_changed) == [
        "gpo-000", "gpo-001", "gpo-002", "gpo-003", "gpo-004",
    ]
    assert len(chunk_calls) >= 3, (
        f"chunking path not exercised: expected >=3 chunks, got {chunk_calls}"
    )
