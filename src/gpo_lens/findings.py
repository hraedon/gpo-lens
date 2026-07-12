"""Finding identity and lifecycle (Plan 023 WI-4).

Findings (danger rules, conflicts, broken refs, delegation issues, ADMX gaps,
version skew) become durable objects with identity across snapshots, so the
tool can say **new / persisting / resolved** instead of re-reporting the world
every scan.

Stable finding key: ``(rule_id, subject_identity)`` where subject identity
reuses the normalized identities (GPO GUID, setting identity, trustee SID, …).
Keys are deterministic and stable across snapshot re-ingest of identical data.

This module is a core module — no ``narration`` or ``web`` imports.
"""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    pass


@dataclass(frozen=True)
class FindingRecord:
    """One finding's lifecycle state."""

    id: int
    finding_key: str
    rule_id: str
    subject_identity: str
    severity: str
    summary: str
    gpo_id: str
    gpo_name: str
    first_seen_snapshot: int
    last_seen_snapshot: int
    resolved_in_snapshot: int | None
    predecessor_id: int | None


@dataclass(frozen=True)
class FindingLifecycleResult:
    """Summary of what happened during a lifecycle update."""

    new_count: int
    persisting_count: int
    resolved_count: int
    regressed_count: int
    # Active findings that were absent from the current scan but whose absence
    # is *not* evidence of resolution because the collection was incomplete
    # (their subject GPO was not re-collected, or an estate-level detector
    # could not be trusted under a coverage gap).  These stay active.
    indeterminate_count: int = 0


def finding_key(rule_id: str, subject_identity: str, detail: str = "") -> str:
    """Compute a stable, deterministic finding key.

    The key is a SHA-256 hash of ``(rule_id, subject_identity, detail)``, all
    lowercased and stripped.  *detail* is a discriminator that prevents
    silent deduplication when a single GPO has multiple findings from the
    same rule (e.g. two dangerous registry values under the same check_id).

    This ensures:
    - Determinism: the same finding data always produces the same key.
    - Stability across re-ingest: identical export data → identical keys.
    - Invariance under export ordering: the key does not depend on the
      order findings are emitted by the scanners.
    """
    raw = "\x00".join([
        rule_id.strip().lower(),
        subject_identity.strip().lower(),
        detail.strip().lower(),
    ])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _finding_to_key_parts(finding: Any) -> tuple[str, str, str, str]:
    """Extract ``(rule_id, subject_identity, severity, detail)`` from a finding.

    Works for both :class:`DoctorFinding` and :class:`DangerFinding` —
    both carry ``category``/``check_id`` and ``gpo_id``.  The *detail*
    field prevents silent deduplication when one GPO has multiple findings
    from the same rule (e.g. two broken refs of the same type).
    """
    rule_id = getattr(finding, "category", "") or getattr(finding, "check_id", "")
    subject = getattr(finding, "gpo_id", "") or getattr(finding, "summary", "")
    severity = getattr(finding, "severity", "info")
    detail = getattr(finding, "detail", "") or getattr(finding, "summary", "")
    return rule_id, subject, severity, detail


def _absence_is_meaningful(
    gpo_id: str,
    collected_gpo_ids: set[str] | None,
    coverage_complete: bool,
) -> bool:
    """Decide whether a finding's absence from the current scan means resolved.

    Absence only implies resolution when the subject was actually re-evaluated.
    A partial collection (a denied SYSVOL subtree, a per-GPO collection error)
    must never mark a finding *resolved* just because the GPO it belongs to was
    not collected this time — that would silently report a real risk as fixed.

    - Complete collection (no coverage gaps): absence is meaningful — the
      condition was fixed or the GPO was deleted.  Resolve.
    - Partial collection: only resolve findings whose subject GPO was actually
      collected this run.  Findings on un-collected GPOs, and estate-level
      findings (empty ``gpo_id``), are indeterminate and stay active.
    """
    if coverage_complete:
        return True
    if gpo_id and collected_gpo_ids is not None and gpo_id in collected_gpo_ids:
        return True
    return False


def update_finding_lifecycle(
    conn: sqlite3.Connection,
    snapshot_id: int,
    findings: list[Any],
    *,
    collected_gpo_ids: set[str] | None = None,
    coverage_complete: bool = True,
) -> FindingLifecycleResult:
    """Diff current findings against the prior snapshot and update lifecycle.

    Called at ingest time (after ``save_estate``) with the estate doctor's
    findings for the new snapshot.  For each finding:

    - If an active (non-resolved) finding with the same key exists: update
      its ``last_seen_snapshot``.
    - If no active finding exists but a resolved one does: create a **new**
      finding row with ``predecessor_id`` linking to the resolved one
      (regression signal).
    - If no finding with the key exists at all: create a new finding.

    For each active finding not present in the current scan: mark it resolved
    (``resolved_in_snapshot = snapshot_id``) **only if its absence is
    meaningful** — see :func:`_absence_is_meaningful`.  Under an incomplete
    collection, findings whose subject was not re-evaluated stay active and are
    counted as ``indeterminate`` rather than being falsely resolved.

    *coverage_complete* is ``True`` when the estate has no coverage gaps;
    *collected_gpo_ids* is the set of GPO ids actually present in this scan.
    The defaults (complete coverage, no id set) preserve the plain
    "everything absent is resolved" behaviour for callers with no estate.

    Re-ingesting the same export twice creates no duplicate findings (the
    second pass finds all keys already active and just bumps
    ``last_seen_snapshot``).
    """
    current_keys: dict[str, Any] = {}
    for f in findings:
        rule_id, subject, _sev, detail = _finding_to_key_parts(f)
        key = finding_key(rule_id, subject, detail)
        current_keys[key] = f

    # Load all active (non-resolved) findings
    active_rows = conn.execute(
        "SELECT id, finding_key, rule_id, subject_identity, severity, summary, "
        "gpo_id, gpo_name, first_seen_snapshot, last_seen_snapshot, "
        "resolved_in_snapshot, predecessor_id "
        "FROM finding WHERE resolved_in_snapshot IS NULL"
    ).fetchall()

    active_by_key: dict[str, dict[str, Any]] = {}
    for row in active_rows:
        row_dict = {
            "id": row[0],
            "finding_key": row[1],
            "rule_id": row[2],
            "subject_identity": row[3],
            "severity": row[4],
            "summary": row[5],
            "gpo_id": row[6],
            "gpo_name": row[7],
            "first_seen_snapshot": row[8],
            "last_seen_snapshot": row[9],
            "resolved_in_snapshot": row[10],
            "predecessor_id": row[11],
        }
        active_by_key[row[1]] = row_dict

    new_count = 0
    persisting_count = 0
    regressed_count = 0

    try:
        # Update or create findings for current scan
        for key, finding in current_keys.items():
            rule_id, subject, severity, _detail = _finding_to_key_parts(finding)
            summary = getattr(finding, "summary", "") or getattr(finding, "title", "")
            gpo_id = getattr(finding, "gpo_id", "")
            gpo_name = getattr(finding, "gpo_name", "")

            if key in active_by_key:
                # Persisting: bump last_seen_snapshot
                existing = active_by_key[key]
                conn.execute(
                    "UPDATE finding SET last_seen_snapshot = ?, severity = ?, summary = ? "
                    "WHERE id = ?",
                    (snapshot_id, severity, summary, existing["id"]),
                )
                persisting_count += 1
            else:
                # Check for a resolved predecessor (regression)
                predecessor_row = conn.execute(
                    "SELECT id FROM finding WHERE finding_key = ? "
                    "AND resolved_in_snapshot IS NOT NULL "
                    "ORDER BY resolved_in_snapshot DESC LIMIT 1",
                    (key,),
                ).fetchone()

                predecessor_id = predecessor_row[0] if predecessor_row else None
                if predecessor_id is not None:
                    regressed_count += 1

                conn.execute(
                    "INSERT INTO finding "
                    "(finding_key, rule_id, subject_identity, severity, summary, "
                    "gpo_id, gpo_name, first_seen_snapshot, last_seen_snapshot, "
                    "resolved_in_snapshot, predecessor_id) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)",
                    (key, rule_id, subject, severity, summary,
                     gpo_id, gpo_name, snapshot_id, snapshot_id, predecessor_id),
                )
                new_count += 1

        # Resolve findings no longer present in the current scan — but only
        # when their absence is meaningful (the subject was actually
        # re-evaluated).  Under a partial collection, un-observed findings are
        # indeterminate and stay active rather than being falsely resolved.
        resolved_count = 0
        indeterminate_count = 0
        for key, existing in active_by_key.items():
            if key not in current_keys:
                if not _absence_is_meaningful(
                    existing["gpo_id"], collected_gpo_ids, coverage_complete
                ):
                    indeterminate_count += 1
                    continue
                conn.execute(
                    "UPDATE finding SET resolved_in_snapshot = ? WHERE id = ?",
                    (snapshot_id, existing["id"]),
                )
                resolved_count += 1

        conn.commit()
    except Exception:
        conn.rollback()
        raise

    return FindingLifecycleResult(
        new_count=new_count,
        persisting_count=persisting_count,
        resolved_count=resolved_count,
        regressed_count=regressed_count,
        indeterminate_count=indeterminate_count,
    )


def load_active_findings(conn: sqlite3.Connection) -> list[FindingRecord]:
    """Load all active (non-resolved) findings, newest first."""
    rows = conn.execute(
        "SELECT id, finding_key, rule_id, subject_identity, severity, summary, "
        "gpo_id, gpo_name, first_seen_snapshot, last_seen_snapshot, "
        "resolved_in_snapshot, predecessor_id "
        "FROM finding WHERE resolved_in_snapshot IS NULL "
        "ORDER BY last_seen_snapshot DESC"
    ).fetchall()
    return [
        FindingRecord(
            id=row[0], finding_key=row[1], rule_id=row[2],
            subject_identity=row[3], severity=row[4], summary=row[5],
            gpo_id=row[6], gpo_name=row[7],
            first_seen_snapshot=row[8], last_seen_snapshot=row[9],
            resolved_in_snapshot=row[10], predecessor_id=row[11],
        )
        for row in rows
    ]


def load_finding_triage(conn: sqlite3.Connection, finding_id: int) -> list[dict[str, Any]]:
    """Load triage history for a finding (append-only, oldest first)."""
    rows = conn.execute(
        "SELECT id, status, note, actor, timestamp "
        "FROM finding_triage WHERE finding_id = ? "
        "ORDER BY id ASC",
        (finding_id,),
    ).fetchall()
    return [
        {"id": r[0], "status": r[1], "note": r[2], "actor": r[3], "timestamp": r[4]}
        for r in rows
    ]


def triage_finding(
    conn: sqlite3.Connection,
    finding_id: int,
    status: str,
    note: str,
    actor: str,
) -> None:
    """Append a triage annotation to a finding.

    Triage is append-only (the provenance instinct applies to local state too):
    each ack/accept-risk/open transition is a new row, never an update-in-place.

    *status* must be one of ``open``, ``acknowledged``, ``accepted_risk``.
    *actor* is the authenticated principal name (from forwarded-user or token).
    """
    if status not in ("open", "acknowledged", "accepted_risk"):
        raise ValueError(f"invalid triage status: {status!r}")
    note = (note or "")[:2000]
    actor = (actor or "unknown")[:256]
    from datetime import UTC, datetime

    conn.execute(
        "INSERT INTO finding_triage (finding_id, status, note, actor, timestamp) "
        "VALUES (?, ?, ?, ?, ?)",
        (finding_id, status, note, actor, datetime.now(UTC).isoformat()),
    )
    conn.commit()


def load_finding_triage_map(
    conn: sqlite3.Connection,
) -> dict[int, dict[str, Any]]:
    """Load the latest triage state for each finding.

    Returns ``{finding_id: {status, note, actor, timestamp}}``.
    """
    rows = conn.execute(
        "SELECT ft.finding_id, ft.status, ft.note, ft.actor, ft.timestamp "
        "FROM finding_triage ft "
        "INNER JOIN (SELECT finding_id, MAX(id) AS max_id "
        "FROM finding_triage GROUP BY finding_id) latest "
        "ON ft.id = latest.max_id"
    ).fetchall()
    return {
        r[0]: {"status": r[1], "note": r[2], "actor": r[3], "timestamp": r[4]}
        for r in rows
    }
