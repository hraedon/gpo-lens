"""CLI-level tests for the 'scope' subcommand.

Mirrors the subprocess pattern from tests/test_cli.py.
"""

from __future__ import annotations

import sqlite3
import subprocess
import sys

import pytest

from gpo_lens import model, store

GPO_LENS = [sys.executable, "-m", "gpo_lens.cli"]


@pytest.fixture
def scope_db(tmp_path):
    """SQLite DB with a GPO that has security filtering, WMI, and a link."""
    db = tmp_path / "scope.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)
    estate = model.Estate(
        domain="test.local",
        gpos=[
            model.Gpo(
                id="scope-gpo-1",
                name="Scope Test GPO",
                domain="test.local",
                created=None,
                modified=None,
                read=None,
                computer_enabled=True,
                user_enabled=True,
                computer_ver_ds=None,
                computer_ver_sysvol=None,
                user_ver_ds=None,
                user_ver_sysvol=None,
                sddl=None,
                owner=None,
                filter_data_available=False,
                wmi_filter="MyFilter",
                sysvol_path=None,
                settings=[],
                delegation=[
                    model.DelegationEntry(
                        gpo_id="scope-gpo-1",
                        trustee="Authenticated Users",
                        trustee_sid="S-1-5-11",
                        permission="Read",
                        allowed=True,
                    ),
                ],
                links=[
                    model.GpoLink(
                        gpo_id="scope-gpo-1",
                        som_name="Workstations",
                        som_path="ou=workstations,dc=test,dc=local",
                        link_enabled=True,
                        enforced=False,
                    ),
                ],
            ),
        ],
        soms=[
            model.Som(
                path="ou=workstations,dc=test,dc=local",
                name="Workstations",
                container_type="ou",
                inheritance_blocked=False,
                links=[
                    model.SomLink(
                        gpo_id="scope-gpo-1",
                        order=1,
                        enabled=True,
                        enforced=False,
                        target="ou=workstations,dc=test,dc=local",
                    ),
                ],
            ),
        ],
        wmi_filters=[
            model.WmiFilter(name="MyFilter", query="SELECT * FROM Win32_OperatingSystem"),
        ],
    )
    store.save_estate(conn, estate)
    conn.close()
    return db


class TestScopeCLI:
    def test_scope_by_id(self, scope_db) -> None:
        r = subprocess.run(
            GPO_LENS + ["--db", str(scope_db), "scope", "scope-gpo-1"],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        assert "Scope Test GPO" in r.stdout

    def test_scope_by_name(self, scope_db) -> None:
        r = subprocess.run(
            GPO_LENS + ["--db", str(scope_db), "scope", "Scope Test GPO"],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        assert "Scope Test GPO" in r.stdout

    def test_scope_json(self, scope_db) -> None:
        import json

        r = subprocess.run(
            GPO_LENS + ["--json", "--db", str(scope_db), "scope", "scope-gpo-1"],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        data = json.loads(r.stdout)["data"]
        assert data["gpo_id"] == "scope-gpo-1"
        assert data["gpo_name"] == "Scope Test GPO"
        assert "caveats" in data

    def test_scope_not_found(self, scope_db) -> None:
        r = subprocess.run(
            GPO_LENS + ["--db", str(scope_db), "scope", "nonexistent"],
            capture_output=True,
            text=True,
        )
        # Not-found is an error: nonzero exit, message on stderr, clean stdout.
        assert r.returncode == 1
        assert r.stdout == ""
        assert "not found" in r.stderr.lower()

    def test_scope_shows_wmi_caveat(self, scope_db) -> None:
        r = subprocess.run(
            GPO_LENS + ["--db", str(scope_db), "scope", "scope-gpo-1"],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        assert "WMI" in r.stdout


class TestScopeCLIDetail:
    """Additional coverage for scope detail views: security-filtered GPOs,
    normal GPOs, and the SOM-level scope view via settings-at."""

    @pytest.fixture
    def multi_gpo_db(self, tmp_path):
        """DB with a security-filtered GPO, a normal GPO, and a WMI-filtered GPO."""
        db = tmp_path / "scope_multi.db"
        conn = sqlite3.connect(str(db))
        store.init_db(conn)
        sf_gpo = model.Gpo(
            id="sf-gpo",
            name="Security Filtered GPO",
            domain="test.local",
            created=None,
            modified=None,
            read=None,
            computer_enabled=True,
            user_enabled=True,
            computer_ver_ds=None,
            computer_ver_sysvol=None,
            user_ver_ds=None,
            user_ver_sysvol=None,
            sddl=None,
            owner=None,
            filter_data_available=False,
            wmi_filter=None,
            sysvol_path=None,
            settings=[
                model.Setting(
                    gpo_id="sf-gpo",
                    side="Computer",
                    cse="Registry",
                    identity="HKLM\\Software\\Test:Value1",
                    display_name="Value1",
                    display_value="1",
                    raw={},
                    from_disabled_side=False,
                ),
            ],
            delegation=[
                model.DelegationEntry(
                    gpo_id="sf-gpo",
                    trustee="Helpdesk Operators",
                    trustee_sid="S-1-5-21-999-1000",
                    permission="Apply Group Policy",
                    allowed=True,
                ),
            ],
            links=[
                model.GpoLink(
                    gpo_id="sf-gpo",
                    som_name="Workstations",
                    som_path="ou=workstations,dc=test,dc=local",
                    link_enabled=True,
                    enforced=False,
                ),
            ],
        )
        normal_gpo = model.Gpo(
            id="normal-gpo",
            name="Normal GPO",
            domain="test.local",
            created=None,
            modified=None,
            read=None,
            computer_enabled=True,
            user_enabled=True,
            computer_ver_ds=None,
            computer_ver_sysvol=None,
            user_ver_ds=None,
            user_ver_sysvol=None,
            sddl=None,
            owner=None,
            filter_data_available=False,
            wmi_filter=None,
            sysvol_path=None,
            settings=[
                model.Setting(
                    gpo_id="normal-gpo",
                    side="Computer",
                    cse="Registry",
                    identity="HKLM\\Software\\Test:Value2",
                    display_name="Value2",
                    display_value="2",
                    raw={},
                    from_disabled_side=False,
                ),
            ],
            delegation=[
                model.DelegationEntry(
                    gpo_id="normal-gpo",
                    trustee="Authenticated Users",
                    trustee_sid="S-1-5-11",
                    permission="Read",
                    allowed=True,
                ),
            ],
            links=[
                model.GpoLink(
                    gpo_id="normal-gpo",
                    som_name="Workstations",
                    som_path="ou=workstations,dc=test,dc=local",
                    link_enabled=True,
                    enforced=False,
                ),
            ],
        )
        estate = model.Estate(
            domain="test.local",
            gpos=[sf_gpo, normal_gpo],
            soms=[
                model.Som(
                    path="ou=workstations,dc=test,dc=local",
                    name="Workstations",
                    container_type="ou",
                    inheritance_blocked=False,
                    links=[
                        model.SomLink(
                            gpo_id="sf-gpo",
                            order=1,
                            enabled=True,
                            enforced=False,
                            target="ou=workstations,dc=test,dc=local",
                        ),
                        model.SomLink(
                            gpo_id="normal-gpo",
                            order=2,
                            enabled=True,
                            enforced=False,
                            target="ou=workstations,dc=test,dc=local",
                        ),
                    ],
                ),
            ],
            wmi_filters=[],
        )
        store.save_estate(conn, estate)
        conn.close()
        return db

    def test_scope_shows_security_filtered(self, multi_gpo_db) -> None:
        r = subprocess.run(
            GPO_LENS + ["--db", str(multi_gpo_db), "scope", "sf-gpo"],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        assert "Security Filtered GPO" in r.stdout
        assert "FILTERED" in r.stdout

    def test_scope_normal_gpo_not_filtered(self, multi_gpo_db) -> None:
        r = subprocess.run(
            GPO_LENS + ["--db", str(multi_gpo_db), "scope", "normal-gpo"],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        assert "Normal GPO" in r.stdout
        assert "Not filtered" in r.stdout

    def test_scope_security_filtered_json(self, multi_gpo_db) -> None:
        import json

        r = subprocess.run(
            GPO_LENS + ["--json", "--db", str(multi_gpo_db), "scope", "sf-gpo"],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        data = json.loads(r.stdout)["data"]
        assert data["security_filtering"]["is_filtered"] is True
        assert data["caveats"]

    def test_settings_at_shows_caveats(self, multi_gpo_db) -> None:
        r = subprocess.run(
            GPO_LENS + ["--db", str(multi_gpo_db), "settings-at",
                        "ou=workstations,dc=test,dc=local"],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        assert "CAVEATS" in r.stdout or "caveats" in r.stdout.lower()

    def test_settings_at_json_includes_caveats(self, multi_gpo_db) -> None:
        import json

        r = subprocess.run(
            GPO_LENS + ["--json", "--db", str(multi_gpo_db), "settings-at",
                        "ou=workstations,dc=test,dc=local"],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        data = json.loads(r.stdout)["data"]
        assert "caveats" in data
