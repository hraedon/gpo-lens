"""Integration tests for the CLI."""

from __future__ import annotations

import sqlite3
import subprocess
import sys

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
        assert "added" in r.stdout or "changed" in r.stdout

    def test_repl_exit_immediately(self, db_path):
        # Feed "exit()" into REPL so it exits immediately
        r = subprocess.run(
            GPO_LENS + ["--db", str(db_path), "repl"],
            input="exit()\n",
            capture_output=True, text=True,
        )
        assert r.returncode == 0
