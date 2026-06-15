"""Tests for the SQLite persistence layer (store.py).

Covers DB-file permission hardening and deterministic load_estate ordering —
both are correctness/reproducibility properties that the snapshot-diff and
--json contract depend on.
"""

from __future__ import annotations

import os
import sqlite3
import stat

from gpo_lens import store
from gpo_lens.model import Estate, Gpo, Setting


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


# ---------------------------------------------------------------------------
# DB file permissions
# ---------------------------------------------------------------------------


def test_init_db_restricts_file_permissions_to_owner_only(tmp_path):
    db = tmp_path / "perms.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)
    conn.close()

    mode = stat.S_IMODE(os.stat(db).st_mode)
    # Owner-only (0o600). On shared hosts the DB holds the full estate — it
    # must not be world/group readable regardless of the process umask.
    assert mode == 0o600


def test_init_db_retightens_permissions_on_existing_db(tmp_path):
    """A pre-existing DB with loose perms is re-tightened by init_db."""
    db = tmp_path / "loose.db"
    db.write_bytes(b"")
    os.chmod(db, 0o644)

    conn = sqlite3.connect(str(db))
    store.init_db(conn)
    conn.close()

    mode = stat.S_IMODE(os.stat(db).st_mode)
    assert mode == 0o600


# ---------------------------------------------------------------------------
# load_estate determinism
# ---------------------------------------------------------------------------


def test_load_estate_returns_gpos_in_stable_order(tmp_path):
    """GPOs loaded from the DB must come back in a stable (id) order,
    independent of insertion order — snapshot diffs depend on this."""
    db = tmp_path / "order.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)

    gpo_b = _make_gpo(id="gpo-b", name="Beta")
    gpo_a = _make_gpo(id="gpo-a", name="Alpha")
    gpo_c = _make_gpo(id="gpo-c", name="Charlie")
    estate_in = Estate(domain="test.local", gpos=[gpo_b, gpo_a, gpo_c])
    sid = store.save_estate(conn, estate_in)

    estate_out = store.load_estate(conn, sid)
    conn.close()

    ids = [g.id for g in estate_out.gpos]
    assert ids == sorted(ids)
    assert ids == ["gpo-a", "gpo-b", "gpo-c"]


def test_load_estate_round_trip_is_stable(tmp_path):
    """Two loads of the same snapshot must produce identical Estates."""
    db = tmp_path / "rt.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)

    gpo = _make_gpo(
        id="gpo-1",
        name="RoundTrip",
        settings=[
            Setting(
                gpo_id="gpo-1", side="Computer", cse="Security",
                identity="X", display_name="X", display_value="1",
                raw={}, from_disabled_side=False,
            ),
        ],
    )
    sid = store.save_estate(conn, Estate(domain="test.local", gpos=[gpo]))

    first = store.load_estate(conn, sid)
    second = store.load_estate(conn, sid)
    conn.close()

    assert [g.id for g in first.gpos] == [g.id for g in second.gpos]
    assert first.gpos[0].settings == second.gpos[0].settings


def test_description_round_trips_through_db(tmp_path):
    db = tmp_path / "desc.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)

    gpo = _make_gpo(id="gpo-1", name="WithDesc", description="Audit baseline; frozen.")
    sid = store.save_estate(conn, Estate(domain="test.local", gpos=[gpo]))
    loaded = store.load_estate(conn, sid)
    conn.close()

    assert loaded.gpos[0].description == "Audit baseline; frozen."


def test_description_survives_migration_from_old_schema(tmp_path):
    """A DB created before the description column must be migrated (additive
    ALTER TABLE) rather than rejected. init_db adds the column on open."""
    db = tmp_path / "old.db"
    conn = sqlite3.connect(str(db))
    # Hand-build a pre-description schema (no description column).
    conn.execute(
        "CREATE TABLE snapshot (id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "domain TEXT NOT NULL, taken_at TEXT NOT NULL)"
    )
    conn.execute(
        "CREATE TABLE gpo ("
        "snapshot_id INTEGER NOT NULL, id TEXT NOT NULL, name TEXT NOT NULL, "
        "domain TEXT NOT NULL, computer_enabled INTEGER NOT NULL, "
        "user_enabled INTEGER NOT NULL, filter_data_available INTEGER NOT NULL, "
        "PRIMARY KEY (snapshot_id, id))"
    )
    conn.commit()
    conn.close()

    # init_db on the old DB should add the column without error.
    conn = sqlite3.connect(str(db))
    store.init_db(conn)
    cols = {r[1] for r in conn.execute("PRAGMA table_info(gpo)").fetchall()}
    assert "description" in cols
    conn.close()
