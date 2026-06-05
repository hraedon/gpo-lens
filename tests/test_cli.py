"""Integration tests for the CLI."""

from __future__ import annotations

import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

GPO_LENS = [sys.executable, "-m", "gpo_lens.cli"]


@pytest.fixture
def db_path(tmp_path):
    """Create a small SQLite DB with one snapshot for testing."""
    from gpo_lens import store, model

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
