"""SQLite persistence for ``Estate`` snapshots."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone

from gpo_lens.events import init_events_table
from gpo_lens.model import (
    DelegationEntry,
    Estate,
    Gpo,
    GpoLink,
    OuRecord,
    Setting,
    Som,
    SomLink,
    WmiFilter,
)


def init_db(conn: sqlite3.Connection) -> None:
    """Create tables (idempotent, ``IF NOT EXISTS``)."""
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS snapshot (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            taken_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS gpo (
            snapshot_id INTEGER NOT NULL REFERENCES snapshot(id) ON DELETE CASCADE,
            id TEXT NOT NULL,
            name TEXT NOT NULL,
            domain TEXT NOT NULL,
            created TEXT,
            modified TEXT,
            read TEXT,
            computer_enabled INTEGER NOT NULL,
            user_enabled INTEGER NOT NULL,
            computer_ver_ds INTEGER,
            computer_ver_sysvol INTEGER,
            user_ver_ds INTEGER,
            user_ver_sysvol INTEGER,
            sddl TEXT,
            owner TEXT,
            filter_data_available INTEGER NOT NULL,
            wmi_filter TEXT,
            sysvol_path TEXT,
            PRIMARY KEY (snapshot_id, id)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS gpo_link (
            snapshot_id INTEGER NOT NULL REFERENCES snapshot(id) ON DELETE CASCADE,
            gpo_id TEXT NOT NULL,
            som_name TEXT NOT NULL,
            som_path TEXT NOT NULL,
            link_enabled INTEGER NOT NULL,
            enforced INTEGER NOT NULL,
            PRIMARY KEY (snapshot_id, gpo_id, som_name, som_path)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS setting (
            snapshot_id INTEGER NOT NULL REFERENCES snapshot(id) ON DELETE CASCADE,
            gpo_id TEXT NOT NULL,
            side TEXT NOT NULL,
            cse TEXT NOT NULL,
            identity TEXT NOT NULL,
            display_name TEXT NOT NULL,
            display_value TEXT NOT NULL,
            raw TEXT NOT NULL,
            from_disabled_side INTEGER NOT NULL,
            source_state TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS delegation (
            snapshot_id INTEGER NOT NULL REFERENCES snapshot(id) ON DELETE CASCADE,
            gpo_id TEXT NOT NULL,
            trustee TEXT NOT NULL,
            trustee_sid TEXT,
            permission TEXT NOT NULL,
            allowed INTEGER NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS som (
            snapshot_id INTEGER NOT NULL REFERENCES snapshot(id) ON DELETE CASCADE,
            path TEXT NOT NULL,
            name TEXT NOT NULL,
            container_type TEXT NOT NULL,
            inheritance_blocked INTEGER NOT NULL,
            PRIMARY KEY (snapshot_id, path)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS som_link (
            snapshot_id INTEGER NOT NULL REFERENCES snapshot(id) ON DELETE CASCADE,
            som_path TEXT NOT NULL,
            gpo_id TEXT NOT NULL,
            order_ INTEGER NOT NULL,
            enabled INTEGER NOT NULL,
            enforced INTEGER NOT NULL,
            target TEXT NOT NULL,
            PRIMARY KEY (snapshot_id, som_path, gpo_id, order_, target)
        )
        """
    )
    # Indexes for query performance
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_setting_snapshot_gpo
        ON setting(snapshot_id, gpo_id)
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_gpo_link_snapshot_gpo
        ON gpo_link(snapshot_id, gpo_id)
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_delegation_snapshot_gpo
        ON delegation(snapshot_id, gpo_id)
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_som_link_snapshot_som
        ON som_link(snapshot_id, som_path)
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_som_link_snapshot_gpo
        ON som_link(snapshot_id, gpo_id)
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS wmi_filter (
            snapshot_id INTEGER NOT NULL REFERENCES snapshot(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            query TEXT NOT NULL,
            PRIMARY KEY (snapshot_id, name)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS ou_tree (
            snapshot_id INTEGER NOT NULL REFERENCES snapshot(id) ON DELETE CASCADE,
            dn TEXT NOT NULL,
            name TEXT NOT NULL,
            gp_link TEXT,
            gp_options INTEGER,
            PRIMARY KEY (snapshot_id, dn)
        )
        """
    )
    init_events_table(conn)
    conn.commit()


def _dt_to_iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return dt.isoformat()


def _iso_to_dt(text: str | None) -> datetime | None:
    if text is None:
        return None
    return datetime.fromisoformat(text)


def save_estate(conn: sqlite3.Connection, estate: Estate, taken_at: datetime | None = None) -> int:
    """Save an estate as a new snapshot; returns the new ``snapshot_id``."""
    if taken_at is None:
        taken_at = datetime.now(timezone.utc)
    cursor = conn.execute(
        "INSERT INTO snapshot (domain, taken_at) VALUES (?, ?)",
        (estate.domain, taken_at.isoformat()),
    )
    snapshot_id = cursor.lastrowid
    assert snapshot_id is not None

    for g in estate.gpos:
        conn.execute(
            """
            INSERT INTO gpo (
                snapshot_id, id, name, domain, created, modified, read,
                computer_enabled, user_enabled, computer_ver_ds, computer_ver_sysvol,
                user_ver_ds, user_ver_sysvol, sddl, owner, filter_data_available,
                wmi_filter, sysvol_path
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                snapshot_id,
                g.id,
                g.name,
                g.domain,
                _dt_to_iso(g.created),
                _dt_to_iso(g.modified),
                _dt_to_iso(g.read),
                int(g.computer_enabled),
                int(g.user_enabled),
                g.computer_ver_ds,
                g.computer_ver_sysvol,
                g.user_ver_ds,
                g.user_ver_sysvol,
                g.sddl,
                g.owner,
                int(g.filter_data_available),
                g.wmi_filter,
                g.sysvol_path,
            ),
        )
        for link in g.links:
            conn.execute(
                """
                INSERT INTO gpo_link (
                    snapshot_id, gpo_id, som_name, som_path, link_enabled, enforced
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    snapshot_id,
                    link.gpo_id,
                    link.som_name,
                    link.som_path,
                    int(link.link_enabled),
                    int(link.enforced),
                ),
            )
        for s in g.settings:
            conn.execute(
                """
                INSERT INTO setting (
                    snapshot_id, gpo_id, side, cse, identity, display_name,
                    display_value, raw, from_disabled_side, source_state
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    snapshot_id,
                    s.gpo_id,
                    s.side,
                    s.cse,
                    s.identity,
                    s.display_name,
                    s.display_value,
                    json.dumps(s.raw, sort_keys=True),
                    int(s.from_disabled_side),
                    s.source_state,
                ),
            )
        for d in g.delegation:
            conn.execute(
                """
                INSERT INTO delegation (
                    snapshot_id, gpo_id, trustee, trustee_sid, permission, allowed
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    snapshot_id,
                    d.gpo_id,
                    d.trustee,
                    d.trustee_sid,
                    d.permission,
                    int(d.allowed),
                ),
            )

    for som in estate.soms:
        conn.execute(
            """
            INSERT INTO som (
                snapshot_id, path, name, container_type, inheritance_blocked
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                snapshot_id,
                som.path,
                som.name,
                som.container_type,
                int(som.inheritance_blocked),
            ),
        )
        for som_link in som.links:
            conn.execute(
                """
                INSERT INTO som_link (
                    snapshot_id, som_path, gpo_id, order_, enabled, enforced, target
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    snapshot_id,
                    som.path,
                    som_link.gpo_id,
                    som_link.order,
                    int(som_link.enabled),
                    int(som_link.enforced),
                    som_link.target,
                ),
            )

    for wf in estate.wmi_filters:
        conn.execute(
            "INSERT INTO wmi_filter (snapshot_id, name, query) VALUES (?, ?, ?)",
            (snapshot_id, wf.name, wf.query),
        )

    for ou in estate.ou_tree:
        conn.execute(
            "INSERT INTO ou_tree (snapshot_id, dn, name, gp_link, gp_options) "
            "VALUES (?, ?, ?, ?, ?)",
            (snapshot_id, ou.dn, ou.name, ou.gp_link, ou.gp_options),
        )

    conn.commit()
    return snapshot_id


def load_estate(conn: sqlite3.Connection, snapshot_id: int | None = None) -> Estate:
    """Reconstruct an ``Estate`` from a snapshot (default: most recent)."""
    if snapshot_id is None:
        row = conn.execute(
            "SELECT id, domain, taken_at FROM snapshot ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if row is None:
            raise ValueError("No snapshots found in database")
        snapshot_id = row[0]
    else:
        row = conn.execute(
            "SELECT id, domain, taken_at FROM snapshot WHERE id = ?", (snapshot_id,)
        ).fetchone()
        if row is None:
            raise ValueError(f"Snapshot {snapshot_id} not found")

    domain = row[1]

    # Load GPOs
    gpos: dict[str, Gpo] = {}
    for row in conn.execute(
        """
        SELECT id, name, domain, created, modified, read,
               computer_enabled, user_enabled, computer_ver_ds, computer_ver_sysvol,
               user_ver_ds, user_ver_sysvol, sddl, owner, filter_data_available,
               wmi_filter, sysvol_path
        FROM gpo WHERE snapshot_id = ?
        """,
        (snapshot_id,),
    ):
        gpo = Gpo(
            id=row[0],
            name=row[1],
            domain=row[2],
            created=_iso_to_dt(row[3]),
            modified=_iso_to_dt(row[4]),
            read=_iso_to_dt(row[5]),
            computer_enabled=bool(row[6]),
            user_enabled=bool(row[7]),
            computer_ver_ds=row[8],
            computer_ver_sysvol=row[9],
            user_ver_ds=row[10],
            user_ver_sysvol=row[11],
            sddl=row[12],
            owner=row[13],
            filter_data_available=bool(row[14]),
            wmi_filter=row[15],
            sysvol_path=row[16],
        )
        gpos[gpo.id] = gpo

    # Load links
    for row in conn.execute(
        """
        SELECT gpo_id, som_name, som_path, link_enabled, enforced
        FROM gpo_link WHERE snapshot_id = ?
        """,
        (snapshot_id,),
    ):
        gpo = gpos[row[0]]
        gpo.links.append(
            GpoLink(
                gpo_id=row[0],
                som_name=row[1],
                som_path=row[2],
                link_enabled=bool(row[3]),
                enforced=bool(row[4]),
            )
        )

    # Load settings
    for row in conn.execute(
        """
        SELECT gpo_id, side, cse, identity, display_name, display_value,
               raw, from_disabled_side, source_state
        FROM setting WHERE snapshot_id = ?
        """,
        (snapshot_id,),
    ):
        gpo = gpos[row[0]]
        gpo.settings.append(
            Setting(
                gpo_id=row[0],
                side=row[1],
                cse=row[2],
                identity=row[3],
                display_name=row[4],
                display_value=row[5],
                raw=json.loads(row[6]),
                from_disabled_side=bool(row[7]),
                source_state=row[8],
            )
        )

    # Load delegation
    for row in conn.execute(
        """
        SELECT gpo_id, trustee, trustee_sid, permission, allowed
        FROM delegation WHERE snapshot_id = ?
        """,
        (snapshot_id,),
    ):
        gpo = gpos[row[0]]
        gpo.delegation.append(
            DelegationEntry(
                gpo_id=row[0],
                trustee=row[1],
                trustee_sid=row[2],
                permission=row[3],
                allowed=bool(row[4]),
            )
        )

    # Load SOMs
    soms: dict[str, Som] = {}
    for row in conn.execute(
        "SELECT path, name, container_type, inheritance_blocked FROM som WHERE snapshot_id = ?",
        (snapshot_id,),
    ):
        som = Som(
            path=row[0],
            name=row[1],
            container_type=row[2],
            inheritance_blocked=bool(row[3]),
        )
        soms[som.path] = som

    for row in conn.execute(
        """
        SELECT som_path, gpo_id, order_, enabled, enforced, target
        FROM som_link WHERE snapshot_id = ?
        """,
        (snapshot_id,),
    ):
        som = soms[row[0]]
        som.links.append(
            SomLink(
                gpo_id=row[1],
                order=row[2],
                enabled=bool(row[3]),
                enforced=bool(row[4]),
                target=row[5],
            )
        )

    wmi_filters: list[WmiFilter] = []
    for row in conn.execute(
        "SELECT name, query FROM wmi_filter WHERE snapshot_id = ?",
        (snapshot_id,),
    ):
        wmi_filters.append(WmiFilter(name=row[0], query=row[1]))

    ou_tree: list[OuRecord] = []
    for row in conn.execute(
        "SELECT dn, name, gp_link, gp_options FROM ou_tree WHERE snapshot_id = ?",
        (snapshot_id,),
    ):
        ou_tree.append(OuRecord(dn=row[0], name=row[1], gp_link=row[2], gp_options=row[3]))

    return Estate(
        domain=domain,
        gpos=list(gpos.values()),
        soms=list(soms.values()),
        wmi_filters=wmi_filters,
        ou_tree=ou_tree,
    )


def list_snapshots(conn: sqlite3.Connection) -> list[tuple[int, str, datetime | None]]:
    """Return ``(id, domain, taken_at)`` newest first."""
    rows = conn.execute(
        "SELECT id, domain, taken_at FROM snapshot ORDER BY id DESC"
    ).fetchall()
    return [(row[0], row[1], _iso_to_dt(row[2])) for row in rows]
