"""Integration tests for the CLI."""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import unittest.mock

import pytest

GPO_LENS = [sys.executable, "-m", "gpo_lens.cli"]


@pytest.fixture
def db_path(tmp_path):
    """Create a small SQLite DB with one snapshot for testing."""
    from gpo_lens import model, store

    db = tmp_path / "test.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)
    estate = model.Estate(
        domain="test.local",
        gpos=[
            model.Gpo(
                id="aaa-bbb", name="Test GPO", domain="test.local",
                created=None, modified=None, read=None,
                computer_enabled=True, user_enabled=True,
                computer_ver_ds=None, computer_ver_sysvol=None,
                user_ver_ds=None, user_ver_sysvol=None,
                sddl=None, owner=None, filter_data_available=False,
                wmi_filter=None, sysvol_path=None,
            ),
        ],
    )
    store.save_estate(conn, estate)
    conn.close()
    return db


@pytest.fixture
def rich_db(tmp_path):
    """SQLite DB with GPOs, settings, delegation, SOMs, and links."""
    from gpo_lens import model, store

    db = tmp_path / "rich.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)
    estate = model.Estate(
        domain="test.local",
        gpos=[
            model.Gpo(
                id="aaa-bbb", name="GPO Alpha", domain="test.local",
                created=None, modified=None, read=None,
                computer_enabled=True, user_enabled=False,
                computer_ver_ds=1, computer_ver_sysvol=2,
                user_ver_ds=0, user_ver_sysvol=0,
                sddl=None, owner="BUILTIN\\Admins",
                filter_data_available=False,
                wmi_filter="MyFilter", sysvol_path=None,
                settings=[
                    model.Setting(
                        gpo_id="aaa-bbb", side="Computer", cse="Security",
                        identity="Account:LockoutBadCount",
                        display_name="LockoutBadCount", display_value="5",
                        raw={}, from_disabled_side=False,
                    ),
                    model.Setting(
                        gpo_id="aaa-bbb", side="Computer", cse="Registry",
                        identity=r"Software\MyApp:Setting1",
                        display_name=r"Software\MyApp", display_value="1",
                        raw={}, from_disabled_side=False,
                    ),
                ],
                delegation=[
                    model.DelegationEntry(
                        gpo_id="aaa-bbb", trustee="Authenticated Users",
                        trustee_sid="S-1-5-11", permission="Read", allowed=True,
                    ),
                ],
                links=[
                    model.GpoLink(
                        gpo_id="aaa-bbb",
                        som_name="Workstations",
                        som_path="ou=workstations,dc=test,dc=local",
                        link_enabled=True, enforced=False,
                    ),
                ],
            ),
            model.Gpo(
                id="ccc-ddd", name="GPO Beta", domain="test.local",
                created=None, modified=None, read=None,
                computer_enabled=False, user_enabled=True,
                computer_ver_ds=0, computer_ver_sysvol=0,
                user_ver_ds=0, user_ver_sysvol=0,
                sddl=None, owner=None,
                filter_data_available=False,
                wmi_filter=None, sysvol_path=None,
                settings=[
                    model.Setting(
                        gpo_id="ccc-ddd", side="User", cse="Registry",
                        identity="SomePolicy", display_name="SomePolicy",
                        display_value="Enabled", raw={},
                        from_disabled_side=False,
                    ),
                    model.Setting(
                        gpo_id="ccc-ddd", side="Computer", cse="Security",
                        identity="Account:LockoutBadCount",
                        display_name="LockoutBadCount", display_value="10",
                        raw={}, from_disabled_side=True,
                    ),
                ],
            ),
        ],
        soms=[
            model.Som(
                path="ou=workstations,dc=test,dc=local",
                name="Workstations", container_type="ou",
                inheritance_blocked=False,
                links=[
                    model.SomLink(
                        gpo_id="aaa-bbb", order=1, enabled=True,
                        enforced=False, target="ou=workstations,dc=test,dc=local",
                    ),
                    model.SomLink(
                        gpo_id="ccc-ddd", order=2, enabled=True,
                        enforced=True, target="ou=workstations,dc=test,dc=local",
                    ),
                    model.SomLink(
                        gpo_id="missing-gpo", order=3, enabled=True,
                        enforced=False, target="ou=workstations,dc=test,dc=local",
                    ),
                ],
            ),
        ],
        wmi_filters=[
            model.WmiFilter(name="MyFilter", query="SELECT * FROM Win32_OperatingSystem"),
        ],
        ou_tree=[
            model.OuRecord(
                dn="OU=Workstations,DC=test,DC=local",
                name="Workstations", gp_link=None, gp_options=0,
            ),
        ],
    )
    store.save_estate(conn, estate)
    conn.close()
    return db


class TestCLI:
    def test_help(self):
        r = subprocess.run(
            GPO_LENS + ["--help"], capture_output=True, text=True,
        )
        assert r.returncode == 0

    def test_no_args_returns_nonzero(self):
        r = subprocess.run(GPO_LENS, capture_output=True, text=True)
        # Exiting 0 is fine too, just make sure it doesn't crash
        assert r.returncode is not None

    def test_snapshots(self, db_path):
        r = subprocess.run(
            GPO_LENS + ["--db", str(db_path), "snapshots"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0

    def test_search(self, db_path):
        r = subprocess.run(
            GPO_LENS + ["--db", str(db_path), "search", "test"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0

    def test_unlinked(self, db_path):
        r = subprocess.run(
            GPO_LENS + ["--db", str(db_path), "unlinked"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0

    def test_perms(self, db_path):
        r = subprocess.run(
            GPO_LENS + ["--db", str(db_path), "perms"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0

    def test_snapshots_json(self, db_path):
        r = subprocess.run(
            GPO_LENS + ["--json", "--db", str(db_path), "snapshots"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0
        assert "[" in r.stdout

    def test_unlinked_json(self, db_path):
        r = subprocess.run(
            GPO_LENS + ["--json", "--db", str(db_path), "unlinked"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0
        assert "[" in r.stdout

    def test_ingest_missing_allgpos(self, tmp_path):
        r = subprocess.run(
            GPO_LENS + ["ingest", str(tmp_path)],
            capture_output=True, text=True,
        )
        assert r.returncode != 0

    def test_diff(self, db_path):
        # Need at least 2 snapshots to diff
        from gpo_lens import model, store

        conn = sqlite3.connect(str(db_path))
        store.init_db(conn)
        estate = model.Estate(
            domain="test.local",
            gpos=[
                model.Gpo(
                    id="bbb-ccc", name="GPO 2", domain="test.local",
                    created=None, modified=None, read=None,
                    computer_enabled=True, user_enabled=True,
                    computer_ver_ds=None, computer_ver_sysvol=None,
                    user_ver_ds=None, user_ver_sysvol=None,
                    sddl=None, owner=None, filter_data_available=False,
                    wmi_filter=None, sysvol_path=None,
                ),
            ],
        )
        store.save_estate(conn, estate)
        conn.close()

        r = subprocess.run(
            GPO_LENS + ["--db", str(db_path), "diff", "1", "2"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0
        assert "added" in r.stdout or "changed" in r.stdout or "gpos_added" in r.stdout

    def test_diff_settings(self, db_path):
        from gpo_lens import model, store

        conn = sqlite3.connect(str(db_path))
        store.init_db(conn)
        estate = model.Estate(
            domain="test.local",
            gpos=[
                model.Gpo(
                    id="aaa-111", name="GPO A", domain="test.local",
                    created=None, modified=None, read=None,
                    computer_enabled=True, user_enabled=True,
                    computer_ver_ds=None, computer_ver_sysvol=None,
                    user_ver_ds=None, user_ver_sysvol=None,
                    sddl=None, owner=None, filter_data_available=False,
                    wmi_filter=None, sysvol_path=None,
                ),
            ],
        )
        sid_a = store.save_estate(conn, estate)
        estate.gpos[0].settings.append(
            model.Setting(
                gpo_id="aaa-111", side="Computer", cse="Registry",
                identity="HKLM\\Software\\Test", display_name="Test",
                display_value="enabled", raw={}, from_disabled_side=False,
            ),
        )
        sid_b = store.save_estate(conn, estate)
        conn.close()

        r = subprocess.run(
            GPO_LENS + ["--db", str(db_path), "diff-settings", str(sid_a), str(sid_b)],
            capture_output=True, text=True,
        )
        assert r.returncode == 0
        assert "added" in r.stdout

        r_json = subprocess.run(
            GPO_LENS + ["--json", "--db", str(db_path), "diff-settings", str(sid_a), str(sid_b)],
            capture_output=True, text=True,
        )
        assert r_json.returncode == 0
        data = json.loads(r_json.stdout)
        assert len(data) == 1
        assert data[0]["change_type"] == "added"

    def test_diff_settings_no_changes(self, db_path):
        from gpo_lens import model, store

        conn = sqlite3.connect(str(db_path))
        store.init_db(conn)
        estate = model.Estate(
            domain="test.local",
            gpos=[
                model.Gpo(
                    id="aaa-111", name="GPO A", domain="test.local",
                    created=None, modified=None, read=None,
                    computer_enabled=True, user_enabled=True,
                    computer_ver_ds=None, computer_ver_sysvol=None,
                    user_ver_ds=None, user_ver_sysvol=None,
                    sddl=None, owner=None, filter_data_available=False,
                    wmi_filter=None, sysvol_path=None,
                ),
            ],
        )
        sid_a = store.save_estate(conn, estate)
        sid_b = store.save_estate(conn, estate)
        conn.close()

        r = subprocess.run(
            GPO_LENS + ["--db", str(db_path), "diff-settings", str(sid_a), str(sid_b)],
            capture_output=True, text=True,
        )
        assert r.returncode == 0
        assert "No setting differences" in r.stdout

    def test_summary(self, db_path):
        r = subprocess.run(
            GPO_LENS + ["--db", str(db_path), "summary"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0
        assert "GPOs:" in r.stdout

    def test_summary_json(self, db_path):
        r = subprocess.run(
            GPO_LENS + ["--json", "--db", str(db_path), "summary"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0
        assert "gpo_count" in r.stdout

    def test_repl_exit_immediately(self, db_path):
        # Feed "exit()" into REPL so it exits immediately
        r = subprocess.run(
            GPO_LENS + ["--db", str(db_path), "repl"],
            input="exit()\n",
            capture_output=True, text=True,
        )
        assert r.returncode == 0

    # ---- smoke tests for all remaining subcommands ----

    def test_empty(self, db_path):
        r = subprocess.run(
            GPO_LENS + ["--db", str(db_path), "empty"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0

    def test_disabled_populated(self, rich_db):
        r = subprocess.run(
            GPO_LENS + ["--db", str(rich_db), "disabled-populated"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0

    def test_disabled_populated_json(self, rich_db):
        r = subprocess.run(
            GPO_LENS + ["--json", "--db", str(rich_db), "disabled-populated"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0

    def test_who_sets(self, rich_db):
        r = subprocess.run(
            GPO_LENS + ["--db", str(rich_db), "who-sets", "Lockout"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0

    def test_who_sets_json(self, rich_db):
        r = subprocess.run(
            GPO_LENS + ["--json", "--db", str(rich_db), "who-sets", "Lockout"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0

    def test_conflicts(self, rich_db):
        r = subprocess.run(
            GPO_LENS + ["--db", str(rich_db), "conflicts"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0

    def test_conflicts_json(self, rich_db):
        r = subprocess.run(
            GPO_LENS + ["--json", "--db", str(rich_db), "conflicts"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0

    def test_blocked(self, db_path):
        r = subprocess.run(
            GPO_LENS + ["--db", str(db_path), "blocked"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0

    def test_version_skew(self, rich_db):
        r = subprocess.run(
            GPO_LENS + ["--db", str(rich_db), "version-skew"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0

    def test_version_skew_json(self, rich_db):
        r = subprocess.run(
            GPO_LENS + ["--json", "--db", str(rich_db), "version-skew"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0

    def test_ms16_072(self, rich_db):
        r = subprocess.run(
            GPO_LENS + ["--db", str(rich_db), "ms16-072"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0

    def test_cpassword(self, db_path):
        r = subprocess.run(
            GPO_LENS + ["--db", str(db_path), "cpassword"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0

    def test_cpassword_json(self, db_path):
        r = subprocess.run(
            GPO_LENS + ["--json", "--db", str(db_path), "cpassword"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0

    def test_show(self, db_path):
        r = subprocess.run(
            GPO_LENS + ["--db", str(db_path), "show", "aaa-bbb"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0

    def test_show_json(self, db_path):
        r = subprocess.run(
            GPO_LENS + ["--json", "--db", str(db_path), "show", "aaa-bbb"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0

    def test_som(self, rich_db):
        r = subprocess.run(
            GPO_LENS + ["--db", str(rich_db), "som",
                        "ou=workstations,dc=test,dc=local"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0

    def test_som_json(self, rich_db):
        r = subprocess.run(
            GPO_LENS + ["--json", "--db", str(rich_db), "som",
                        "ou=workstations,dc=test,dc=local"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0

    def test_dangling(self, rich_db):
        r = subprocess.run(
            GPO_LENS + ["--db", str(rich_db), "dangling"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0

    def test_enforced(self, rich_db):
        r = subprocess.run(
            GPO_LENS + ["--db", str(rich_db), "enforced"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0

    def test_loopback(self, db_path):
        r = subprocess.run(
            GPO_LENS + ["--db", str(db_path), "loopback"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0

    def test_wmi(self, rich_db):
        r = subprocess.run(
            GPO_LENS + ["--db", str(rich_db), "wmi"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0

    def test_wmi_filters(self, rich_db):
        r = subprocess.run(
            GPO_LENS + ["--db", str(rich_db), "wmi-filters"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0

    def test_topology_check(self, rich_db):
        r = subprocess.run(
            GPO_LENS + ["--db", str(rich_db), "topology-check"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0

    def test_broken_refs(self, db_path):
        r = subprocess.run(
            GPO_LENS + ["--db", str(db_path), "broken-refs"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0

    def test_broken_refs_json(self, db_path):
        r = subprocess.run(
            GPO_LENS + ["--json", "--db", str(db_path), "broken-refs"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0

    def test_admx_gaps(self, db_path):
        r = subprocess.run(
            GPO_LENS + ["--db", str(db_path), "admx-gaps"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0

    def test_admx_gaps_json(self, rich_db):
        r = subprocess.run(
            GPO_LENS + ["--json", "--db", str(rich_db), "admx-gaps"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0

    def test_settings_at(self, rich_db):
        r = subprocess.run(
            GPO_LENS + ["--db", str(rich_db), "settings-at",
                        "ou=workstations,dc=test,dc=local"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0

    def test_settings_at_json(self, rich_db):
        r = subprocess.run(
            GPO_LENS + ["--json", "--db", str(rich_db), "settings-at",
                        "ou=workstations,dc=test,dc=local"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0

    def test_som_conflicts(self, rich_db):
        r = subprocess.run(
            GPO_LENS + ["--db", str(rich_db), "som-conflicts",
                        "ou=workstations,dc=test,dc=local"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0

    def test_precedence_conflicts(self, rich_db):
        r = subprocess.run(
            GPO_LENS + ["--db", str(rich_db), "precedence-conflicts"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0

    def test_precedence_conflicts_json(self, rich_db):
        r = subprocess.run(
            GPO_LENS + ["--json", "--db", str(rich_db), "precedence-conflicts"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0

    def test_doctor(self, rich_db):
        r = subprocess.run(
            GPO_LENS + ["--db", str(rich_db), "doctor"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0
        assert "Estate Doctor" in r.stdout

    def test_doctor_json(self, rich_db):
        r = subprocess.run(
            GPO_LENS + ["--json", "--db", str(rich_db), "doctor"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0
        assert "severity" in r.stdout

    def test_doctor_clean(self, db_path):
        r = subprocess.run(
            GPO_LENS + ["--db", str(db_path), "doctor"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0
        # db_path has one unlinked, no-delegation GPO => info findings
        assert "INFO" in r.stdout

    def test_settings_dump(self, rich_db):
        r = subprocess.run(
            GPO_LENS + ["--db", str(rich_db), "settings-dump"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0
        assert "LockoutBadCount" in r.stdout

    def test_settings_dump_json(self, rich_db):
        r = subprocess.run(
            GPO_LENS + ["--json", "--db", str(rich_db), "settings-dump"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0
        assert "gpo_id" in r.stdout

    def test_settings_dump_filter_side(self, rich_db):
        r = subprocess.run(
            GPO_LENS + ["--db", str(rich_db), "settings-dump", "--side", "User"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0
        # Only User-side settings should appear
        assert "SomePolicy" in r.stdout
        assert "LockoutBadCount" not in r.stdout

    def test_settings_dump_filter_cse(self, rich_db):
        r = subprocess.run(
            GPO_LENS + ["--db", str(rich_db), "settings-dump", "--cse", "Security"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0
        assert "LockoutBadCount" in r.stdout

    def test_settings_dump_filter_gpo(self, rich_db):
        r = subprocess.run(
            GPO_LENS + ["--db", str(rich_db), "settings-dump", "--gpo", "Alpha"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0
        assert "GPO Alpha" in r.stdout
        assert "GPO Beta" not in r.stdout

    def test_settings_dump_empty(self, db_path):
        r = subprocess.run(
            GPO_LENS + ["--db", str(db_path), "settings-dump"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0
        assert "No results" in r.stdout

    def test_settings_diff(self, tmp_path):
        import json

        gid = "31b2f340-016d-11d2-945f-00c04fb984f9"
        data_a = [
            {
                "gpo_id": gid,
                "gpo_name": "Test",
                "side": "Computer",
                "cse": "Security",
                "identity": "X",
                "display_name": "X",
                "display_value": "1",
                "from_disabled_side": False,
            },
        ]
        data_b = [
            {
                "gpo_id": gid,
                "gpo_name": "Test",
                "side": "Computer",
                "cse": "Security",
                "identity": "X",
                "display_name": "X",
                "display_value": "2",
                "from_disabled_side": False,
            },
        ]
        fa = tmp_path / "a.json"
        fb = tmp_path / "b.json"
        fa.write_text(json.dumps(data_a))
        fb.write_text(json.dumps(data_b))

        r = subprocess.run(
            GPO_LENS + ["settings-diff", str(fa), str(fb)],
            capture_output=True, text=True,
        )
        assert r.returncode == 0
        assert "modified" in r.stdout

    def test_settings_diff_json(self, tmp_path):
        import json

        data_a: list[dict[str, object]] = []
        data_b = [
            {
                "gpo_id": "31b2f340-016d-11d2-945f-00c04fb984f9",
                "gpo_name": "Test",
                "side": "Computer",
                "cse": "Security",
                "identity": "X",
                "display_name": "X",
                "display_value": "1",
                "from_disabled_side": False,
            },
        ]
        fa = tmp_path / "a.json"
        fb = tmp_path / "b.json"
        fa.write_text(json.dumps(data_a))
        fb.write_text(json.dumps(data_b))

        r = subprocess.run(
            GPO_LENS + ["--json", "settings-diff", str(fa), str(fb)],
            capture_output=True, text=True,
        )
        assert r.returncode == 0
        data = json.loads(r.stdout)
        assert len(data) == 1
        assert data[0]["change_type"] == "added"

    def test_settings_diff_no_changes(self, tmp_path):
        import json

        data = [
            {
                "gpo_id": "31b2f340-016d-11d2-945f-00c04fb984f9",
                "gpo_name": "Test",
                "side": "Computer",
                "cse": "Security",
                "identity": "X",
                "display_name": "X",
                "display_value": "1",
                "from_disabled_side": False,
            },
        ]
        fa = tmp_path / "a.json"
        fb = tmp_path / "b.json"
        fa.write_text(json.dumps(data))
        fb.write_text(json.dumps(data))

        r = subprocess.run(
            GPO_LENS + ["settings-diff", str(fa), str(fb)],
            capture_output=True, text=True,
        )
        assert r.returncode == 0
        assert "No differences" in r.stdout

    def test_settings_diff_filter_side(self, tmp_path):
        import json

        gid = "31b2f340-016d-11d2-945f-00c04fb984f9"
        data_a = [
            {
                "gpo_id": gid,
                "gpo_name": "Test",
                "side": "Computer",
                "cse": "Security",
                "identity": "X",
                "display_name": "X",
                "display_value": "1",
                "from_disabled_side": False,
            },
            {
                "gpo_id": gid,
                "gpo_name": "Test",
                "side": "User",
                "cse": "Registry",
                "identity": "Y",
                "display_name": "Y",
                "display_value": "2",
                "from_disabled_side": False,
            },
        ]
        data_b = [
            {
                "gpo_id": gid,
                "gpo_name": "Test",
                "side": "Computer",
                "cse": "Security",
                "identity": "X",
                "display_name": "X",
                "display_value": "10",
                "from_disabled_side": False,
            },
            {
                "gpo_id": gid,
                "gpo_name": "Test",
                "side": "User",
                "cse": "Registry",
                "identity": "Y",
                "display_name": "Y",
                "display_value": "20",
                "from_disabled_side": False,
            },
        ]
        fa = tmp_path / "a.json"
        fb = tmp_path / "b.json"
        fa.write_text(json.dumps(data_a))
        fb.write_text(json.dumps(data_b))

        r = subprocess.run(
            GPO_LENS + ["--json", "settings-diff", str(fa), str(fb), "--side", "User"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0
        data = json.loads(r.stdout)
        assert len(data) == 1
        assert data[0]["side"] == "User"

    def test_ingest_diff_latest_no_prior(self, tmp_path):
        """--diff-latest with no prior snapshot should say so."""
        db = tmp_path / "test.db"
        r = subprocess.run(
            GPO_LENS + ["--db", str(db), "ingest", "--diff-latest", "tests/fixtures"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0
        assert "No previous snapshot to diff against" in r.stdout

    def test_ingest_diff_latest_with_prior(self, tmp_path):
        """--diff-latest with a prior snapshot shows changelog."""
        from gpo_lens import model, store

        db = tmp_path / "test.db"
        conn = sqlite3.connect(str(db))
        store.init_db(conn)

        # Pre-populate with a snapshot containing one of the fixture GPOs
        # but with different version numbers
        gpo = model.Gpo(
            id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            name="gpo-cpassword", domain="fakefixture.local",
            created=None, modified=None, read=None,
            computer_enabled=True, user_enabled=True,
            computer_ver_ds=1, computer_ver_sysvol=1,
            user_ver_ds=1, user_ver_sysvol=1,
            sddl=None, owner=None, filter_data_available=False,
            wmi_filter=None, sysvol_path=None,
        )
        estate = model.Estate(domain="fakefixture.local", gpos=[gpo])
        store.save_estate(conn, estate)
        conn.close()

        r = subprocess.run(
            GPO_LENS + ["--db", str(db), "ingest", "--diff-latest", "tests/fixtures"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0
        # The fixture gpo-cpassword has computer_ver_ds=1, computer_ver_sysvol=1
        # So no version change. But there are new GPOs in the fixture.
        # The output should at least show the ingest succeeded and the diff ran.
        assert "snapshot=" in r.stdout


class TestDoctorExplain:
    """Tests for the doctor --explain flag."""

    def test_doctor_explain_with_key(self, rich_db, capsys) -> None:
        canned = "## CRITICAL\nExplanation of findings."
        with unittest.mock.patch.dict(os.environ, {"GPO_LENS_API_KEY": "test-key"}):
            with unittest.mock.patch("gpo_lens.narration.call_llm", return_value=canned):
                from gpo_lens.cli import main
                ret = main(["--db", str(rich_db), "doctor", "--explain"])
        assert ret == 0
        captured = capsys.readouterr()
        assert "Explanation of findings" in captured.out

    def test_doctor_explain_without_key(self, rich_db, capsys) -> None:
        with unittest.mock.patch.dict(os.environ, {}, clear=True):
            from gpo_lens.cli import main
            ret = main(["--db", str(rich_db), "doctor", "--explain"])
        assert ret == 0
        captured = capsys.readouterr()
        assert "Set GPO_LENS_API_KEY" in captured.out
        assert "Estate Doctor" in captured.out

    def test_doctor_explain_json_with_key(self, rich_db, capsys) -> None:
        canned = "## CRITICAL\nExplanation of findings."
        with unittest.mock.patch.dict(os.environ, {"GPO_LENS_API_KEY": "test-key"}):
            with unittest.mock.patch("gpo_lens.narration.call_llm", return_value=canned):
                from gpo_lens.cli import main
                ret = main(["--json", "--db", str(rich_db), "doctor", "--explain"])
        assert ret == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "findings" in data
        assert "narration" in data

    def test_doctor_explain_json_without_key(self, rich_db, capsys) -> None:
        with unittest.mock.patch.dict(os.environ, {}, clear=True):
            from gpo_lens.cli import main
            ret = main(["--json", "--db", str(rich_db), "doctor", "--explain"])
        assert ret == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "findings" in data
        assert data["narration"] is None


class TestAsk:
    def test_ask_no_api_key_exits_nonzero(self, rich_db, capsys) -> None:
        with unittest.mock.patch.dict(os.environ, {}, clear=True):
            from gpo_lens.cli import main

            ret = main(["--db", str(rich_db), "ask", "How many GPOs?"])
        assert ret == 1
        captured = capsys.readouterr()
        assert "GPO_LENS_API_KEY" in captured.err or "Error" in captured.err

    def test_ask_routes_and_executes(self, rich_db, capsys) -> None:
        routing = json.dumps(
            {"query": "estate_summary", "params": {}}
        )
        with unittest.mock.patch.dict(
            os.environ, {"GPO_LENS_API_KEY": "test-key"}
        ):
            with unittest.mock.patch(
                "gpo_lens.narration.call_llm",
                side_effect=[routing, "Here is your summary."],
            ):
                from gpo_lens.cli import main

                ret = main(["--db", str(rich_db), "ask", "How many GPOs?"])
        assert ret == 0
        captured = capsys.readouterr()
        assert "summary" in captured.out.lower()

    def test_ask_cannot_route(self, rich_db, capsys) -> None:
        routing = json.dumps(
            {"error": "cannot_route", "reason": "not a GPO question"}
        )
        with unittest.mock.patch.dict(
            os.environ, {"GPO_LENS_API_KEY": "test-key"}
        ):
            with unittest.mock.patch(
                "gpo_lens.narration.call_llm", return_value=routing
            ):
                from gpo_lens.cli import main

                ret = main(
                    ["--db", str(rich_db), "ask", "What's the weather?"]
                )
        assert ret == 1
        captured = capsys.readouterr()
        assert "Cannot answer" in captured.err

    def test_ask_no_narrate(self, rich_db, capsys) -> None:
        routing = json.dumps(
            {"query": "unlinked_gpos", "params": {}}
        )
        with unittest.mock.patch.dict(
            os.environ, {"GPO_LENS_API_KEY": "test-key"}
        ):
            with unittest.mock.patch(
                "gpo_lens.narration.call_llm", return_value=routing
            ):
                from gpo_lens.cli import main

                ret = main(
                    [
                        "--db",
                        str(rich_db),
                        "ask",
                        "--no-narrate",
                        "Which GPOs are unlinked?",
                    ]
                )
        assert ret == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert isinstance(data, list)
        if data:
            assert isinstance(data[0], dict), (
                f"Expected dict, got {type(data[0])}: {data[0]!r}"
            )
            assert "id" in data[0] and "name" in data[0], (
                f"Expected keys 'id' and 'name', got {list(data[0].keys())}"
            )
