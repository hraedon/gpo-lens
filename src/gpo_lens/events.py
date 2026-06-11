"""Append-only event store for tracking GPO estate changes."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import Any


def init_events_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            schema_version INTEGER NOT NULL DEFAULT 1,
            payload TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_events_timestamp
        ON events(timestamp)
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_events_event_type
        ON events(event_type)
        """
    )
    conn.commit()


def append_event(
    conn: sqlite3.Connection,
    event_type: str,
    payload: dict[str, Any],
    schema_version: int = 1,
) -> int:
    ts = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        "INSERT INTO events (timestamp, event_type, schema_version, payload) "
        "VALUES (?, ?, ?, ?)",
        (ts, event_type, schema_version, json.dumps(payload, sort_keys=True)),
    )
    conn.commit()
    return cursor.lastrowid  # type: ignore[return-value]


def append_events(
    conn: sqlite3.Connection,
    events: list[tuple[str, dict[str, Any]]],
) -> list[int]:
    ts = datetime.now(timezone.utc).isoformat()
    ids: list[int] = []
    for event_type, payload in events:
        cursor = conn.execute(
            "INSERT INTO events (timestamp, event_type, schema_version, payload) "
            "VALUES (?, ?, 1, ?)",
            (ts, event_type, json.dumps(payload, sort_keys=True)),
        )
        ids.append(cursor.lastrowid)  # type: ignore[arg-type]
    conn.commit()
    return ids


def query_events(
    conn: sqlite3.Connection,
    *,
    since: str | None = None,
    event_type: str | None = None,
    limit: int = 1000,
) -> list[dict[str, Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if since:
        clauses.append("timestamp >= ?")
        params.append(since)
    if event_type:
        clauses.append("event_type LIKE ?")
        params.append(f"%{event_type}%")
    where = " AND ".join(clauses) if clauses else "1=1"
    sql = (
        "SELECT id, timestamp, event_type, schema_version, payload "
        f"FROM events WHERE {where} ORDER BY id ASC LIMIT ?"
    )
    params.append(limit)
    rows = conn.execute(sql, params).fetchall()
    results: list[dict[str, Any]] = []
    for row in rows:
        results.append({
            "id": row[0],
            "timestamp": row[1],
            "event_type": row[2],
            "schema_version": row[3],
            "payload": json.loads(row[4]),
        })
    return results
