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
