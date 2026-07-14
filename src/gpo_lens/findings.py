"""Finding identity and lifecycle (Plan 023 WI-4, Plan 024).

Findings (danger rules, conflicts, broken refs, delegation issues, ADMX gaps,
version skew) become durable objects with identity across snapshots, so the
tool can say **new / persisting / resolved** instead of re-reporting the world
every scan.

Plan 024 extends this with:

- **Evaluation provenance** — ``evaluation_run`` records track which detector,
  rules, catalogue, comparator, snapshot, and software version produced each
  claim.
- **Occurrence/observation separation** — an occurrence is one continuous
  interval; an observation is presence/absence in one run.
- **Enhanced triage** — risk acceptance with expiry/revocation, deterministic
  fold, append-only events.
- **Core queries** — ``finding_inbox``, ``finding_history``, ``finding_delta``,
  ``accepted_risk_register``, ``evaluation_runs``.

Stable finding key: ``(rule_id, subject_identity)`` where subject identity
reuses the normalized identities (GPO GUID, setting identity, trustee SID, …).
Keys are deterministic and stable across snapshot re-ingest of identical data.

**Single estate per store (WI-1.5).** The lifecycle engine assumes one estate
(one domain's snapshot series) per SQLite database. Finding fingerprints do not
include an estate/domain dimension, so pointing two different domains at the
same ``--db`` would fold their findings into one lifecycle series. Multi-estate
comparison (WI-059) is a separate, post-1.0 concern with its own model.

This module is a core module — no ``narration`` or ``web`` imports.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from gpo_lens.finding_model import (
    FINGERPRINT_VERSION,
    ClaimLevel,
    EvidenceRef,
    FindingCandidate,
    FindingDelta,
    FindingHistory,
    FindingObservation,
    FindingOccurrence,
    FindingView,
    RiskAcceptance,
    TriageAction,
    TriageEvent,
    TriageStatus,
    compute_fingerprint,
    series_key,
)
from gpo_lens.normalize import parse_dt as _parse_dt

if TYPE_CHECKING:
    from gpo_lens.model import AdmxResolver, Estate


@dataclass(frozen=True)
class FindingRecord:
    """One finding's lifecycle state."""

    id: int
    finding_key: str
    rule_id: str
    subject_identity: str
    severity: str
    summary: str
    detail: str
    remediation: str
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

    When a finding declares an explicit ``subject_key`` (WI-089, Plan 024 §4),
    that tuple *is* the identity — prose and evidence (summary, detail,
    counts) are excluded so the finding does not churn identity every time
    its wording or evidence changes.  This is how GPO-less findings
    (topology discrepancies, excessive writers, orphaned WMI filters,
    coverage gaps) stay stable across snapshots.
    """
    rule_id = getattr(finding, "category", "") or getattr(finding, "check_id", "")
    severity = getattr(finding, "severity", "info")
    subject_key = getattr(finding, "subject_key", ()) or ()
    if subject_key:
        return rule_id, "|".join(subject_key), severity, ""
    subject = getattr(finding, "gpo_id", "") or getattr(finding, "summary", "")
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
        "detail, remediation, "
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
            "detail": row[6],
            "remediation": row[7],
            "gpo_id": row[8],
            "gpo_name": row[9],
            "first_seen_snapshot": row[10],
            "last_seen_snapshot": row[11],
            "resolved_in_snapshot": row[12],
            "predecessor_id": row[13],
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
            raw_detail = getattr(finding, "detail", "")
            raw_remediation = getattr(finding, "remediation", "")
            finding_detail = raw_detail[:16_000] if isinstance(raw_detail, str) else ""
            remediation = (
                raw_remediation[:8_000] if isinstance(raw_remediation, str) else ""
            )
            gpo_id = getattr(finding, "gpo_id", "")
            gpo_name = getattr(finding, "gpo_name", "")

            if key in active_by_key:
                # Persisting: bump last_seen_snapshot
                existing = active_by_key[key]
                conn.execute(
                    "UPDATE finding SET last_seen_snapshot = ?, severity = ?, summary = ?, "
                    "detail = ?, remediation = ? "
                    "WHERE id = ?",
                    (
                        snapshot_id, severity, summary, finding_detail,
                        remediation, existing["id"],
                    ),
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
                    "detail, remediation, gpo_id, gpo_name, "
                    "first_seen_snapshot, last_seen_snapshot, "
                    "resolved_in_snapshot, predecessor_id) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)",
                    (key, rule_id, subject, severity, summary, finding_detail, remediation,
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
        "detail, remediation, "
        "gpo_id, gpo_name, first_seen_snapshot, last_seen_snapshot, "
        "resolved_in_snapshot, predecessor_id "
        "FROM finding WHERE resolved_in_snapshot IS NULL "
        "ORDER BY last_seen_snapshot DESC"
    ).fetchall()
    return [
        FindingRecord(
            id=row[0], finding_key=row[1], rule_id=row[2],
            subject_identity=row[3], severity=row[4], summary=row[5],
            detail=row[6], remediation=row[7], gpo_id=row[8], gpo_name=row[9],
            first_seen_snapshot=row[10], last_seen_snapshot=row[11],
            resolved_in_snapshot=row[12], predecessor_id=row[13],
        )
        for row in rows
    ]


def evaluate_finding_lifecycle(
    conn: sqlite3.Connection,
    snapshot_id: int,
    estate: Estate,
    *,
    admx: AdmxResolver | None = None,
) -> FindingLifecycleResult:
    """Run the deterministic estate detectors and persist their lifecycle.

    This is the single ingest-time evaluation path used by both the CLI and
    web uploader. Keeping it in the core prevents either ingest surface from
    producing an empty/stale findings inbox.
    """
    from gpo_lens.danger import danger_findings
    from gpo_lens.queries import estate_doctor

    danger = danger_findings(estate, admx=admx)
    findings = estate_doctor(estate, admx=admx, danger=danger)
    return update_finding_lifecycle(
        conn,
        snapshot_id,
        findings,
        collected_gpo_ids={g.id for g in estate.gpos},
        coverage_complete=not estate.coverage_gaps,
    )


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


# ---------------------------------------------------------------------------
# Plan 024 — Evaluation provenance, lifecycle engine, enhanced triage,
# and core queries.
# ---------------------------------------------------------------------------

_VALID_TRIAGE_ACTIONS: frozenset[str] = frozenset({
    "commented", "acknowledged", "reopened",
    "accepted_risk", "risk_acceptance_expired", "risk_acceptance_revoked",
})


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


# ---------------------------------------------------------------------------
# Analysis input + evaluation run
# ---------------------------------------------------------------------------


def register_analysis_input(
    conn: sqlite3.Connection,
    kind: str,
    canonical_digest: str,
    version: str = "unknown",
    metadata: dict[str, Any] | None = None,
) -> int:
    """Register or reuse an analysis input (danger rules, ADMX catalogue, etc.).

    Returns the ``analysis_input.id``. If an input with the same kind + digest
    already exists, it is reused (idempotent).
    """
    meta_json = json.dumps(metadata or {}, sort_keys=True)
    conn.execute(
        "INSERT OR IGNORE INTO analysis_input "
        "(kind, canonical_digest, version, metadata_json, created_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (kind, canonical_digest, version, meta_json, _now_iso()),
    )
    row = conn.execute(
        "SELECT id FROM analysis_input WHERE kind = ? AND canonical_digest = ?",
        (kind, canonical_digest),
    ).fetchone()
    assert row is not None
    return int(row[0])


def create_evaluation_run(
    conn: sqlite3.Connection,
    snapshot_id: int,
    *,
    evaluation_kind: str = "intrinsic",
    detector_set_digest: str = "",
    comparator_input_id: int | None = None,
    application_version: str = "",
    status: str = "completed",
    error_summary: str = "",
) -> int:
    """Create an evaluation run record and return its ``id``.

    The run records *which* snapshot, detector set, comparator, and software
    version produced the findings in this evaluation. This is the provenance
    anchor for all observations and occurrence transitions.

    *status* must be one of ``completed``, ``failed``, ``partial``. Only
    ``completed`` runs resolve absent findings (Plan 024 §7).
    """
    if status not in ("completed", "failed", "partial"):
        raise ValueError(f"invalid run status: {status!r}")
    started = _now_iso()
    cursor = conn.execute(
        "INSERT INTO evaluation_run "
        "(snapshot_id, evaluation_kind, detector_set_digest, "
        "comparator_input_id, application_version, started_at, completed_at, "
        "status, error_summary) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (snapshot_id, evaluation_kind, detector_set_digest,
         comparator_input_id, application_version, started, started,
         status, error_summary),
    )
    assert cursor.lastrowid is not None
    conn.commit()
    return cursor.lastrowid


def complete_evaluation_run(
    conn: sqlite3.Connection,
    run_id: int,
    *,
    status: str = "completed",
    error_summary: str = "",
) -> None:
    """Mark an evaluation run as completed (or failed/partial)."""
    if status not in ("completed", "failed", "partial"):
        raise ValueError(f"invalid run status: {status!r}")
    conn.execute(
        "UPDATE evaluation_run SET completed_at = ?, status = ?, "
        "error_summary = ? WHERE id = ?",
        (_now_iso(), status, error_summary, run_id),
    )
    conn.commit()


def list_evaluation_runs(
    conn: sqlite3.Connection,
    *,
    snapshot_id: int | None = None,
    series: str | None = None,
) -> list[dict[str, Any]]:
    """List evaluation runs, optionally filtered by snapshot or series key."""
    sql = (
        "SELECT id, snapshot_id, evaluation_kind, detector_set_digest, "
        "comparator_input_id, application_version, started_at, completed_at, "
        "status, error_summary FROM evaluation_run"
    )
    params: list[Any] = []
    clauses: list[str] = []
    if snapshot_id is not None:
        clauses.append("snapshot_id = ?")
        params.append(snapshot_id)
    if series is not None:
        escaped = series.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        clauses.append("detector_set_digest LIKE ? ESCAPE '\\'")
        params.append(f"%{escaped}%")
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY id DESC"
    rows = conn.execute(sql, params).fetchall()
    return [
        {
            "id": r[0], "snapshot_id": r[1], "evaluation_kind": r[2],
            "detector_set_digest": r[3], "comparator_input_id": r[4],
            "application_version": r[5], "started_at": r[6],
            "completed_at": r[7], "status": r[8], "error_summary": r[9],
        }
        for r in rows
    ]


# ---------------------------------------------------------------------------
# Lifecycle engine (Plan 024 §7)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LifecycleResult:
    """Summary of what happened during a Plan 024 lifecycle update."""

    run_id: int
    new_count: int
    persisting_count: int
    resolved_count: int
    regressed_count: int
    indeterminate_count: int
    duplicate_fingerprint_count: int = 0


def _absence_is_meaningful_v2(
    gpo_id: str,
    collected_gpo_ids: set[str] | None,
    coverage_complete: bool,
) -> bool:
    """Same logic as ``_absence_is_meaningful`` — kept separate for clarity."""
    if coverage_complete:
        return True
    if gpo_id and collected_gpo_ids is not None and gpo_id in collected_gpo_ids:
        return True
    return False


def run_evaluation(
    conn: sqlite3.Connection,
    run_id: int,
    candidates: list[FindingCandidate],
    *,
    collected_gpo_ids: set[str] | None = None,
    coverage_complete: bool = True,
    run_status: str = "completed",
) -> LifecycleResult:
    """Process FindingCandidate records through the Plan 024 lifecycle engine.

    For each candidate (Plan 024 §7):

    1. Compute fingerprint.
    2. Reject duplicate fingerprints within one detector result (detector bug).
    3. Match candidates to open occurrences in the same series.
    4. Append observations and update ``last_seen_run_id``.
    5. Resolve unmatched open occurrences only if the detector completed
       successfully and coverage was sufficient for absence to be meaningful.
    6. Create new occurrences for unmatched candidates, linking a resolved
       predecessor with the same fingerprint as a regression.
    7. Commit evaluation, observations, occurrence transitions in one
       transaction.

    A failed or partial evaluation never resolves unseen findings (AC: "Failed
    or incomplete analysis never implies resolution").
    """
    if run_status not in ("completed", "failed", "partial"):
        raise ValueError(f"invalid run_status: {run_status!r}")

    # Step 1+2: Canonicalize and validate candidates, reject duplicates.
    fingerprint_map: dict[str, FindingCandidate] = {}
    duplicate_count = 0
    for c in candidates:
        fp = compute_fingerprint(c)
        if fp in fingerprint_map:
            duplicate_count += 1
            continue
        fingerprint_map[fp] = c

    # Load all active (non-resolved) occurrences.
    active_rows = conn.execute(
        "SELECT id, finding_key, fingerprint_version, series_key, "
        "detector_id, detector_version, rule_id, subject_type, "
        "subject_key_json, first_seen_run_id, last_seen_run_id, "
        "resolved_run_id, predecessor_id, gpo_id "
        "FROM finding WHERE resolved_run_id IS NULL "
        "AND resolved_in_snapshot IS NULL"
    ).fetchall()

    active_by_fp: dict[str, dict[str, Any]] = {}
    for row in active_rows:
        active_by_fp[row[1]] = {
            "id": row[0], "fingerprint": row[1],
            "fingerprint_version": row[2], "series_key": row[3],
            "detector_id": row[4], "detector_version": row[5],
            "category": row[6], "subject_type": row[7],
            "subject_key_json": row[8], "first_seen_run_id": row[9],
            "last_seen_run_id": row[10], "resolved_run_id": row[11],
            "predecessor_id": row[12], "gpo_id": row[13],
        }

    new_count = 0
    persisting_count = 0
    regressed_count = 0

    try:
        # Steps 3-6: Process each candidate.
        for fp, cand in fingerprint_map.items():
            sk = series_key(cand.detector_id, cand.comparator_series)
            subject_key_json = json.dumps(list(cand.subject_key))
            evidence_json = json.dumps(
                [
                    {
                        "snapshot_id": e.snapshot_id,
                        "gpo_id": e.gpo_id,
                        "source": e.source,
                        "field_path": e.field_path,
                        "safe_projection": e.safe_projection[:500],
                    }
                    for e in cand.evidence_refs
                ],
                sort_keys=True,
            )
            compliance_json = json.dumps(list(cand.compliance))
            gpo_id = cand.subject_key[0] if cand.subject_type == "gpo" and cand.subject_key else ""
            # Store the detector's real detail (WI-1.5); fall back to the
            # summary when a candidate carries none, and bound it like the
            # legacy path did so a pathological detector can't bloat the row.
            cand_detail = (cand.detail or cand.summary)[:16_000]

            if fp in active_by_fp:
                # Step 4: Persisting — append observation, update last_seen.
                existing = active_by_fp[fp]
                occ_id = existing["id"]
                conn.execute(
                    "UPDATE finding SET last_seen_run_id = ?, "
                    "last_seen_snapshot = (SELECT snapshot_id FROM "
                    "evaluation_run WHERE id = ?), "
                    "severity = ?, summary = ?, detail = ?, remediation = ? "
                    "WHERE id = ?",
                    (run_id, run_id, cand.severity, cand.summary,
                     cand_detail, cand.remediation, occ_id),
                )
                conn.execute(
                    "INSERT INTO finding_observation "
                    "(run_id, occurrence_id, severity, summary, evidence_json, "
                    "claim_level, remediation, compliance_json, gpo_id, gpo_name) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (run_id, occ_id, cand.severity, cand.summary,
                     evidence_json, cand.claim, cand.remediation,
                     compliance_json, gpo_id,
                     cand.gpo_name),
                )
                persisting_count += 1
            else:
                # Step 6: New occurrence — check for resolved predecessor.
                predecessor_row = conn.execute(
                    "SELECT id FROM finding WHERE finding_key = ? "
                    "AND (resolved_run_id IS NOT NULL "
                    "OR resolved_in_snapshot IS NOT NULL) "
                    "ORDER BY COALESCE(resolved_run_id, 0) DESC, "
                    "resolved_in_snapshot DESC LIMIT 1",
                    (fp,),
                ).fetchone()
                predecessor_id = predecessor_row[0] if predecessor_row else None
                if predecessor_id is not None:
                    regressed_count += 1

                # Get snapshot_id from the run.
                run_row = conn.execute(
                    "SELECT snapshot_id FROM evaluation_run WHERE id = ?",
                    (run_id,),
                ).fetchone()
                snapshot_id = run_row[0] if run_row else 0

                cursor = conn.execute(
                    "INSERT INTO finding "
                    "(finding_key, rule_id, subject_identity, severity, "
                    "summary, detail, remediation, gpo_id, gpo_name, "
                    "first_seen_snapshot, last_seen_snapshot, "
                    "resolved_in_snapshot, predecessor_id, "
                    "fingerprint_version, series_key, detector_id, "
                    "detector_version, subject_type, subject_key_json, "
                    "first_seen_run_id, last_seen_run_id, resolved_run_id) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, "
                    "?, ?, ?, ?, ?, ?, ?, ?, NULL)",
                    (fp, cand.detector_id, gpo_id, cand.severity,
                     cand.summary, cand_detail, cand.remediation,
                     gpo_id,
                     cand.gpo_name,
                     snapshot_id, snapshot_id, predecessor_id,
                     FINGERPRINT_VERSION, sk, cand.detector_id,
                     cand.detector_version, cand.subject_type,
                     subject_key_json, run_id, run_id),
                )
                occ_id = cursor.lastrowid
                conn.execute(
                    "INSERT INTO finding_observation "
                    "(run_id, occurrence_id, severity, summary, evidence_json, "
                    "claim_level, remediation, compliance_json, gpo_id, gpo_name) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (run_id, occ_id, cand.severity, cand.summary,
                     evidence_json, cand.claim, cand.remediation,
                     compliance_json, gpo_id,
                     cand.gpo_name),
                )
                new_count += 1

        # Step 5: Resolve unmatched open occurrences — but only when the
        # run completed successfully and absence is meaningful.
        resolved_count = 0
        indeterminate_count = 0

        if run_status == "completed":
            for fp, existing in active_by_fp.items():
                if fp in fingerprint_map:
                    continue
                if not _absence_is_meaningful_v2(
                    existing["gpo_id"], collected_gpo_ids, coverage_complete
                ):
                    indeterminate_count += 1
                    continue
                conn.execute(
                    "UPDATE finding SET resolved_run_id = ?, "
                    "resolved_in_snapshot = (SELECT snapshot_id FROM "
                    "evaluation_run WHERE id = ?) "
                    "WHERE id = ?",
                    (run_id, run_id, existing["id"]),
                )
                resolved_count += 1

        conn.commit()
    except Exception:
        conn.rollback()
        raise

    return LifecycleResult(
        run_id=run_id,
        new_count=new_count,
        persisting_count=persisting_count,
        resolved_count=resolved_count,
        regressed_count=regressed_count,
        indeterminate_count=indeterminate_count,
        duplicate_fingerprint_count=duplicate_count,
    )


# ---------------------------------------------------------------------------
# Enhanced triage (Plan 024 §8)
# ---------------------------------------------------------------------------


def append_triage_event(
    conn: sqlite3.Connection,
    occurrence_id: int,
    action: TriageAction,
    actor: str,
    *,
    note: str = "",
    rationale: str = "",
    expires_at: datetime | None = None,
    supersedes_event_id: int | None = None,
) -> int:
    """Append a triage event to a finding occurrence.

    Triage is append-only (Plan 024 §8). Each event is a new row; current
    status is a deterministic fold over events (see :func:`fold_triage`).

    *action* must be one of the :data:`TriageAction` literals.
    *actor* is the authenticated principal name.
    *rationale* is required for ``accepted_risk`` (Plan 024 §8: "Accepted risk
    requires actor, rationale, timestamp, and optional expiry").
    *expires_at* is the optional expiry for risk acceptance.
    """
    if action not in _VALID_TRIAGE_ACTIONS:
        raise ValueError(f"invalid triage action: {action!r}")
    if action == "accepted_risk" and not rationale.strip():
        raise ValueError("accepted_risk requires a non-empty rationale")

    note = (note or "")[:2000]
    rationale = (rationale or "")[:2000]
    actor = (actor or "unknown")[:256]
    expires_iso = expires_at.isoformat() if expires_at else None

    cursor = conn.execute(
        "INSERT INTO finding_triage_event "
        "(occurrence_id, action, actor, occurred_at, note, rationale, "
        "expires_at, supersedes_event_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (occurrence_id, action, actor, _now_iso(), note, rationale,
         expires_iso, supersedes_event_id),
    )
    assert cursor.lastrowid is not None
    conn.commit()
    return cursor.lastrowid


def fold_triage(events: list[TriageEvent]) -> TriageStatus:
    """Deterministically fold triage events into current status.

    Fold rules (Plan 024 §8):

    - Start: ``open``
    - ``commented`` → no status change (note-only)
    - ``acknowledged`` → ``acknowledged``
    - ``accepted_risk`` → ``accepted_risk`` (captures expiry + rationale)
    - ``reopened`` → ``open``
    - ``risk_acceptance_expired`` → ``open`` (if current was ``accepted_risk``)
    - ``risk_acceptance_revoked`` → ``open`` (if current was ``accepted_risk``)
    """
    status = "open"
    actor = ""
    note = ""
    updated_at = datetime.min.replace(tzinfo=UTC)
    expires_at: datetime | None = None
    rationale = ""

    for ev in events:
        updated_at = ev.occurred_at
        actor = ev.actor
        if ev.action == "commented":
            note = ev.note
            continue
        if ev.action == "acknowledged":
            status = "acknowledged"
            note = ev.note
            expires_at = None
            rationale = ""
        elif ev.action == "accepted_risk":
            status = "accepted_risk"
            note = ev.note
            rationale = ev.rationale
            expires_at = ev.expires_at
        elif ev.action == "reopened":
            status = "open"
            note = ev.note
            expires_at = None
            rationale = ""
        elif ev.action in ("risk_acceptance_expired", "risk_acceptance_revoked"):
            if status == "accepted_risk":
                status = "open"
                expires_at = None
                rationale = ""
            note = ev.note

    return TriageStatus(
        status=status, actor=actor, note=note,
        updated_at=updated_at, expires_at=expires_at, rationale=rationale,
    )


def load_triage_events(
    conn: sqlite3.Connection,
    occurrence_id: int,
) -> list[TriageEvent]:
    """Load all triage events for an occurrence (oldest first)."""
    rows = conn.execute(
        "SELECT id, occurrence_id, action, actor, occurred_at, note, "
        "rationale, expires_at, supersedes_event_id "
        "FROM finding_triage_event WHERE occurrence_id = ? "
        "ORDER BY id ASC",
        (occurrence_id,),
    ).fetchall()
    return [
        TriageEvent(
            id=r[0], occurrence_id=r[1], action=r[2], actor=r[3],
            occurred_at=_parse_dt(r[4]) or datetime.min.replace(tzinfo=UTC),
            note=r[5], rationale=r[6],
            expires_at=_parse_dt(r[7]),
            supersedes_event_id=r[8],
        )
        for r in rows
    ]


def get_triage_status(
    conn: sqlite3.Connection,
    occurrence_id: int,
) -> TriageStatus:
    """Get the current triage status for an occurrence (deterministic fold)."""
    events = load_triage_events(conn, occurrence_id)
    return fold_triage(events)


def load_triage_status_map(
    conn: sqlite3.Connection,
) -> dict[int, TriageStatus]:
    """Load the current triage status for all occurrences.

    Returns ``{occurrence_id: TriageStatus}``.
    """
    # Single scan of the event log, grouped in Python, instead of one
    # load_triage_events query per occurrence (WI-1.3: kills the N+1 that the
    # accepted-risk register and any status-map consumer paid on large estates).
    rows = conn.execute(
        "SELECT id, occurrence_id, action, actor, occurred_at, note, "
        "rationale, expires_at, supersedes_event_id "
        "FROM finding_triage_event ORDER BY occurrence_id, id ASC"
    ).fetchall()
    events_by_occ: dict[int, list[TriageEvent]] = {}
    for r in rows:
        events_by_occ.setdefault(r[1], []).append(
            TriageEvent(
                id=r[0], occurrence_id=r[1], action=r[2], actor=r[3],
                occurred_at=_parse_dt(r[4]) or datetime.min.replace(tzinfo=UTC),
                note=r[5], rationale=r[6],
                expires_at=_parse_dt(r[7]),
                supersedes_event_id=r[8],
            )
        )
    return {
        occ_id: fold_triage(events)
        for occ_id, events in events_by_occ.items()
    }


def expire_risk_acceptances(
    conn: sqlite3.Connection,
    *,
    now: datetime | None = None,
) -> int:
    """Expire risk acceptances whose expiry has passed.

    Appends a ``risk_acceptance_expired`` event to each occurrence whose
    current triage status is ``accepted_risk`` with an ``expires_at`` in the
    past. Returns the number of expirations processed.

    This is the sweep that makes expired risk acceptance re-enter the
    actionable inbox (Plan 024 §8, AC: "Expired risk acceptance re-enters the
    actionable inbox").
    """
    if now is None:
        now = datetime.now(UTC)

    status_map = load_triage_status_map(conn)
    expired_count = 0
    try:
        for occ_id, status in status_map.items():
            if status.status != "accepted_risk":
                continue
            if status.expires_at is None:
                continue
            if status.expires_at > now:
                continue
            conn.execute(
                "INSERT INTO finding_triage_event "
                "(occurrence_id, action, actor, occurred_at, note, rationale, "
                "expires_at, supersedes_event_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (occ_id, "risk_acceptance_expired", "system", _now_iso(),
                 f"Risk acceptance expired at {status.expires_at.isoformat()}",
                 "", None, None),
            )
            expired_count += 1
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return expired_count


# ---------------------------------------------------------------------------
# Core queries (Plan 024 §9)
# ---------------------------------------------------------------------------


def finding_inbox(
    conn: sqlite3.Connection,
    *,
    as_of_run: int | None = None,
    lifecycle_state: str | None = None,
    triage_status: str | None = None,
    category: str | None = None,
    severity: str | None = None,
    gpo_id: str | None = None,
    subject_type: str | None = None,
    claim_level: str | None = None,
    limit: int = 500,
) -> list[FindingView]:
    """Query the finding inbox with filters (Plan 024 §9).

    Returns active (non-resolved) findings by default, with their current
    triage status. Filters narrow by lifecycle state, triage status, category,
    severity, GPO, subject type, and claim level.

    *as_of_run* limits to findings observed in the given evaluation run.

    All filters — including ``claim_level`` and ``triage_status`` — are applied
    in SQL *before* ``LIMIT`` (WI-1.2), so a filtered page can never silently
    truncate: the ``limit`` bounds the matching set, not a pre-filter superset.
    """
    # Current triage status is a fold over the append-only event log, not a
    # stored column, so resolve it once (batched) and translate the requested
    # triage_status into a pre-LIMIT id-set predicate. "open" is the implicit
    # status of an occurrence with no events, so it filters by *excluding*
    # occurrences whose folded status is non-open.
    status_map = load_triage_status_map(conn)

    # Latest observation's claim level for an occurrence (observation-level, so
    # not a column on finding); used both as a filter and as a select column.
    latest_claim_sq = (
        "(SELECT claim_level FROM finding_observation o "
        "WHERE o.occurrence_id = f.id ORDER BY o.id DESC LIMIT 1)"
    )

    sql = (
        "SELECT f.id, f.finding_key, f.detector_id, f.rule_id, "
        "f.severity, f.summary, f.detail, f.remediation, "
        "f.gpo_id, f.gpo_name, f.subject_type, f.subject_key_json, "
        "f.first_seen_run_id, f.last_seen_run_id, f.resolved_run_id, "
        "f.predecessor_id, "
        f"COALESCE({latest_claim_sq}, 'confirmed') AS claim_level "
        "FROM finding f WHERE f.resolved_run_id IS NULL "
        "AND f.resolved_in_snapshot IS NULL "
        # WI-1.4: only rows with evaluation-run provenance are v2 findings.
        # Every deployed ingest path (CLI cmd_ingest, web _persist) runs the v2
        # engine, which always stamps first_seen_run_id; the legacy Plan 023
        # writer is test-only, so no deployed store holds provenance-less rows.
        # Excluding them keeps a hypothetical pre-lifecycle row from surfacing
        # as a spurious "new" finding with no run history — mixed-mode rows are
        # never silently blended into the v2 inbox.
        "AND f.first_seen_run_id IS NOT NULL"
    )
    params: list[Any] = []
    clauses: list[str] = []

    if as_of_run is not None:
        clauses.append("f.last_seen_run_id = ?")
        params.append(as_of_run)
    if category is not None:
        clauses.append("f.rule_id = ?")
        params.append(category)
    if severity is not None:
        clauses.append("f.severity = ?")
        params.append(severity)
    if gpo_id is not None:
        clauses.append("f.gpo_id = ?")
        params.append(gpo_id)
    if subject_type is not None:
        clauses.append("f.subject_type = ?")
        params.append(subject_type)
    if lifecycle_state == "new":
        clauses.append("f.first_seen_run_id = f.last_seen_run_id")
    elif lifecycle_state == "persisting":
        clauses.append("f.first_seen_run_id < f.last_seen_run_id")
    if claim_level is not None:
        clauses.append(f"COALESCE({latest_claim_sq}, 'confirmed') = ?")
        params.append(claim_level)
    if triage_status is not None:
        if triage_status == "open":
            non_open = [
                oid for oid, ts in status_map.items() if ts.status != "open"
            ]
            if non_open:
                ph = ",".join("?" * len(non_open))
                clauses.append(f"f.id NOT IN ({ph})")
                params.extend(non_open)
        else:
            matching = [
                oid for oid, ts in status_map.items()
                if ts.status == triage_status
            ]
            if matching:
                ph = ",".join("?" * len(matching))
                clauses.append(f"f.id IN ({ph})")
                params.extend(matching)
            else:
                # No occurrence holds this status → empty result set.
                clauses.append("0")

    if clauses:
        sql += " AND " + " AND ".join(clauses)
    sql += (
        " ORDER BY CASE f.severity WHEN 'critical' THEN 0"
        " WHEN 'high' THEN 1 WHEN 'medium' THEN 2"
        " WHEN 'low' THEN 3 ELSE 4 END, f.rule_id, f.id LIMIT ?"
    )
    params.append(limit)

    rows = conn.execute(sql, params).fetchall()

    views: list[FindingView] = []
    for r in rows:
        occ_id = r[0]
        c_level = r[16] or "confirmed"

        ts = status_map.get(occ_id)
        t_status = ts.status if ts else "open"
        t_actor = ts.actor if ts else ""
        t_note = ts.note if ts else ""
        t_expires = ts.expires_at if ts else None

        subject_key = tuple(json.loads(r[11])) if r[11] else ()

        first_run = r[12] or 0
        last_run = r[13] or 0
        if first_run == last_run:
            lc_state = "new"
        else:
            lc_state = "persisting"

        views.append(FindingView(
            occurrence_id=occ_id,
            fingerprint=r[1],
            detector_id=r[2] or r[1][:8],
            category=r[3],
            severity=r[4],
            summary=r[5],
            detail=r[6] or r[5],
            remediation=r[7] or "",
            gpo_id=r[8],
            gpo_name=r[9],
            subject_type=r[10] or "",
            subject_key=subject_key,
            claim_level=c_level,  # type: ignore[arg-type]
            lifecycle_state=lc_state,  # type: ignore[arg-type]
            triage_status=t_status,
            triage_actor=t_actor,
            triage_note=t_note,
            triage_expires_at=t_expires,
            first_seen_run_id=r[12] or 0,
            last_seen_run_id=r[13] or 0,
            resolved_run_id=r[14],
            predecessor_id=r[15],
            compliance=(),
        ))

    return views


def finding_history(
    conn: sqlite3.Connection,
    occurrence_id: int,
) -> FindingHistory:
    """Get the full history of a finding occurrence (Plan 024 §9).

    Returns the occurrence record, all observations, and all triage events.
    """
    row = conn.execute(
        "SELECT id, finding_key, fingerprint_version, series_key, "
        "detector_id, detector_version, rule_id, subject_type, "
        "subject_key_json, first_seen_run_id, last_seen_run_id, "
        "resolved_run_id, predecessor_id "
        "FROM finding WHERE id = ?",
        (occurrence_id,),
    ).fetchone()
    if row is None:
        raise ValueError(f"Occurrence {occurrence_id} not found")

    occurrence = FindingOccurrence(
        id=row[0], fingerprint=row[1], fingerprint_version=row[2],
        series_key=row[3], detector_id=row[4], detector_version=row[5],
        category=row[6], subject_type=row[7],
        subject_key=tuple(json.loads(row[8])) if row[8] else (),
        first_seen_run_id=row[9] or 0, last_seen_run_id=row[10] or 0,
        resolved_run_id=row[11], predecessor_id=row[12],
    )

    obs_rows = conn.execute(
        "SELECT run_id, occurrence_id, severity, summary, evidence_json, "
        "claim_level, remediation, compliance_json "
        "FROM finding_observation WHERE occurrence_id = ? "
        "ORDER BY id ASC",
        (occurrence_id,),
    ).fetchall()
    observations = tuple(
        FindingObservation(
            run_id=r[0], occurrence_id=r[1], severity=r[2],
            summary=r[3], evidence_json=r[4], claim_level=r[5],
            remediation=r[6], compliance_json=r[7],
        )
        for r in obs_rows
    )

    triage_events = tuple(load_triage_events(conn, occurrence_id))

    return FindingHistory(
        occurrence=occurrence,
        observations=observations,
        triage_events=triage_events,
    )


def finding_delta(
    conn: sqlite3.Connection,
    run_a: int,
    run_b: int,
) -> FindingDelta:
    """Compute the difference between two evaluation runs (Plan 024 §9).

    Returns fingerprints that are new, resolved, persisting, or regressed
    between run_a (earlier) and run_b (later).
    """
    # Occurrence IDs observed in each run.
    run_a_occ_ids = {
        r[0] for r in conn.execute(
            "SELECT occurrence_id FROM finding_observation WHERE run_id = ?",
            (run_a,),
        ).fetchall()
    }
    run_b_occ_ids = {
        r[0] for r in conn.execute(
            "SELECT occurrence_id FROM finding_observation WHERE run_id = ?",
            (run_b,),
        ).fetchall()
    }

    # Map occurrence_id → fingerprint.
    all_occ_ids = run_a_occ_ids | run_b_occ_ids
    if not all_occ_ids:
        return FindingDelta(
            new_fingerprints=(), resolved_fingerprints=(),
            persisting_fingerprints=(), regressed_fingerprints=(),
        )
    placeholders = ",".join("?" * len(all_occ_ids))
    fp_map = {
        r[0]: r[1] for r in conn.execute(
            f"SELECT id, finding_key FROM finding WHERE id IN ({placeholders})",
            list(all_occ_ids),
        ).fetchall()
    }

    a_fps = {fp_map[oid] for oid in run_a_occ_ids if oid in fp_map}
    b_fps = {fp_map[oid] for oid in run_b_occ_ids if oid in fp_map}

    new = tuple(sorted(b_fps - a_fps))
    resolved = tuple(sorted(a_fps - b_fps))
    persisting = tuple(sorted(a_fps & b_fps))

    # Regressed: new in run_b (not in run_a) but the occurrence has a
    # resolved predecessor — meaning it was resolved then reappeared.
    regressed: list[str] = []
    for oid in run_b_occ_ids:
        if oid not in fp_map:
            continue
        fp = fp_map[oid]
        if fp in a_fps:
            continue
        row = conn.execute(
            "SELECT predecessor_id FROM finding WHERE id = ?",
            (oid,),
        ).fetchone()
        if row and row[0] is not None:
            regressed.append(fp)

    return FindingDelta(
        new_fingerprints=new,
        resolved_fingerprints=resolved,
        persisting_fingerprints=persisting,
        regressed_fingerprints=tuple(sorted(regressed)),
    )


def accepted_risk_register(
    conn: sqlite3.Connection,
    *,
    as_of: datetime | None = None,
) -> list[RiskAcceptance]:
    """List all risk acceptances (active and expired) as of a point in time.

    Plan 024 §9: ``accepted_risk_register(as_of) -> list[RiskAcceptance]``.
    """
    if as_of is None:
        as_of = datetime.now(UTC)

    status_map = load_triage_status_map(conn)
    result: list[RiskAcceptance] = []

    for occ_id, status in status_map.items():
        if status.status != "accepted_risk":
            continue
        # Find the accepted_risk event.
        events = load_triage_events(conn, occ_id)
        accepted_ev = None
        revoked_ev = None
        for ev in events:
            if ev.action == "accepted_risk":
                accepted_ev = ev
            elif ev.action == "risk_acceptance_revoked":
                revoked_ev = ev

        if accepted_ev is None:
            continue

        # Get occurrence details.
        row = conn.execute(
            "SELECT finding_key, rule_id, severity, summary FROM finding WHERE id = ?",
            (occ_id,),
        ).fetchone()
        if row is None:
            continue

        is_expired = (
            accepted_ev.expires_at is not None
            and accepted_ev.expires_at <= as_of
        )

        result.append(RiskAcceptance(
            occurrence_id=occ_id,
            fingerprint=row[0],
            category=row[1],
            severity=row[2],
            summary=row[3] or row[2],
            actor=accepted_ev.actor,
            rationale=accepted_ev.rationale,
            accepted_at=accepted_ev.occurred_at,
            expires_at=accepted_ev.expires_at,
            is_expired=is_expired,
            revoked_at=revoked_ev.occurred_at if revoked_ev else None,
            revoked_by=revoked_ev.actor if revoked_ev else "",
        ))

    return result


def evaluation_runs(
    conn: sqlite3.Connection,
    *,
    snapshot_id: int | None = None,
    series_key: str | None = None,
) -> list[dict[str, Any]]:
    """List evaluation runs, optionally filtered (Plan 024 §9).

    ``evaluation_runs(snapshot_id | series_key) -> list[EvaluationRun]``.
    """
    return list_evaluation_runs(
        conn, snapshot_id=snapshot_id, series=series_key,
    )


# ---------------------------------------------------------------------------
# Detector adapter — convert existing detectors to FindingCandidate (Plan 024 §10)
# ---------------------------------------------------------------------------


def _doctor_finding_to_candidate(
    f: Any,
    snapshot_id: int,
) -> FindingCandidate:
    """Convert a ``DoctorFinding`` to a ``FindingCandidate``.

    The adapter maps the existing detector output to the Plan 024 protocol:

    - ``detector_id``: the finding category (e.g. ``cpassword``, ``ms16_072``)
    - ``subject_type``: ``"gpo"`` for GPO-scoped findings, ``"estate"`` for
      estate-level findings (empty ``gpo_id``)
    - ``subject_key``: ``(gpo_id,)`` for GPO findings, or the declared
      ``subject_key`` tuple for estate-level findings
    - ``dimensions``: identity-bearing fields that distinguish multiple
      findings on the same subject (e.g. side, ref_type, file path)
    - ``claim``: ``"confirmed"`` for directly observed findings,
      ``"probable"`` for inferred structural findings
    """
    gpo_id = getattr(f, "gpo_id", "") or ""
    declared_sk = getattr(f, "subject_key", ()) or ()

    # A GPO-scoped finding's subject is the GPO GUID; any extra identity
    # (a coverage gap's kind, etc.) rides in ``dimensions`` so ``gpo_id`` can
    # be recovered from ``subject_key[0]`` downstream. Estate-scoped findings
    # (no GPO) carry their full identity in the declared ``subject_key``.
    if gpo_id:
        subject_type = "gpo"
        subject_key: tuple[str, ...] = (gpo_id,)
    elif declared_sk:
        subject_type = "estate"
        subject_key = declared_sk
    else:
        subject_type = "estate"
        subject_key = (getattr(f, "summary", ""),)

    # Identity-bearing dimensions are declared by the detector as typed
    # key/value pairs (WI-1.1) — never parsed out of the prose summary/detail,
    # which can change between observations without changing identity.
    dims: list[tuple[str, str]] = [
        (str(k), str(v)) for k, v in (getattr(f, "dimensions", ()) or ())
    ]
    summary = getattr(f, "summary", "") or ""
    category = getattr(f, "category", "") or ""

    # Evidence reference (safe projection — no raw secrets).
    evidence = (
        EvidenceRef(
            snapshot_id=snapshot_id,
            gpo_id=gpo_id,
            source="estate_doctor",
            field_path=category,
            safe_projection=summary[:200],
        ),
    )

    compliance = getattr(f, "compliance", ()) or ()
    compliance_tuples = tuple(
        (c.framework, c.control_id) for c in compliance
    ) if compliance else ()

    # Claim level: directly observed = confirmed, inferred = probable.
    confirmed_categories = frozenset({
        "cpassword", "ms16_072", "version_skew", "dangling_link",
        "disabled_but_populated", "unlinked", "empty", "enforced_link",
        "coverage_gap", "broken_wmi_ref", "orphaned_wmi_filter",
        "ilt_gpo", "stale_gpo", "admx_gap",
    })
    probable_categories = frozenset({
        "deny_ace", "excessive_writer", "topology_discrepancy",
    })
    if category in confirmed_categories or category.startswith("broken_ref:"):
        claim: ClaimLevel = "confirmed"
    elif category in probable_categories:
        claim = "probable"
    elif category.startswith("danger:"):
        claim = "probable"
    else:
        claim = "possible"

    return FindingCandidate(
        detector_id=category,
        detector_version="1",
        category=category,
        severity=getattr(f, "severity", "info"),
        subject_type=subject_type,
        subject_key=subject_key,
        dimensions=tuple(dims),
        summary=summary,
        detail=getattr(f, "detail", "") or "",
        evidence_refs=evidence,
        claim=claim,
        remediation=getattr(f, "remediation", "") or "",
        compliance=compliance_tuples,
        gpo_name=getattr(f, "gpo_name", "") or "",
    )


def _danger_finding_to_candidate(
    f: Any,
    snapshot_id: int,
) -> FindingCandidate:
    """Convert a ``DangerFinding`` to a ``FindingCandidate``."""
    gpo_id = getattr(f, "gpo_id", "") or ""
    check_id = getattr(f, "check_id", "") or ""
    category = f"danger:{check_id}"

    if gpo_id:
        subject_type = "gpo"
        subject_key: tuple[str, ...] = (gpo_id,)
    else:
        subject_type = "estate"
        subject_key = (check_id,)

    title = getattr(f, "title", "") or ""

    # Identity-bearing dimensions are declared by the detector as typed
    # key/value pairs (WI-1.1) — e.g. the trustee/owner SID that distinguishes
    # multiple non-admin writers on one GPO — never parsed from prose.
    dims: list[tuple[str, str]] = [
        (str(k), str(v)) for k, v in (getattr(f, "dimensions", ()) or ())
    ]

    evidence = (
        EvidenceRef(
            snapshot_id=snapshot_id,
            gpo_id=gpo_id,
            source="danger_detector",
            field_path=check_id,
            safe_projection=title[:200],
        ),
    )

    compliance = getattr(f, "compliance", ()) or ()
    compliance_tuples = tuple(
        (c.framework, c.control_id) for c in compliance
    ) if compliance else ()

    return FindingCandidate(
        detector_id=category,
        detector_version="1",
        category=category,
        severity=getattr(f, "severity", "medium"),
        subject_type=subject_type,
        subject_key=subject_key,
        dimensions=tuple(dims),
        summary=title,
        detail=getattr(f, "detail", "") or "",
        evidence_refs=evidence,
        claim="probable",
        remediation=getattr(f, "remediation", "") or "",
        compliance=compliance_tuples,
        gpo_name=getattr(f, "gpo_name", "") or "",
    )


def candidates_from_estate(
    estate: Estate,
    *,
    snapshot_id: int = 0,
    admx: AdmxResolver | None = None,
) -> list[FindingCandidate]:
    """Run intrinsic detectors and convert to FindingCandidate records.

    This is the Plan 024 adapter for the existing intrinsic detector family
    (Plan 024 §10.2: "Adapt one narrow intrinsic detector family and qualify
    lifecycle behavior"). It runs the estate doctor + danger detectors and
    converts each finding to a ``FindingCandidate`` with declared identity
    dimensions.

    The adapter documents:

    - **Subject key:** GPO GUID for GPO-scoped findings; declared subject_key
      tuple for estate-level findings.
    - **Dimensions:** identity-bearing fields (side, ref_value, trustee SID)
      that distinguish multiple findings on the same subject.
    - **Rule versioning:** ``detector_version="1"`` for all intrinsic
      detectors. A future rule-semantics change bumps the version and must
      declare whether it continues the old lifecycle series or starts a new
      one.
    - **Evidence projection:** summary text truncated to 200 chars; no raw
      cpassword values, SDDL strings, or credentials stored.
    - **Coverage requirements:** absence is meaningful only when the subject
      GPO was actually re-collected (handled by ``run_evaluation``).
    """
    from gpo_lens.danger import danger_findings
    from gpo_lens.queries import estate_doctor

    danger = danger_findings(estate, admx=admx)
    doctor_findings = estate_doctor(estate, admx=admx, danger=danger)

    candidates: list[FindingCandidate] = []
    for doc_f in doctor_findings:
        candidates.append(_doctor_finding_to_candidate(doc_f, snapshot_id))
    for dang_f in danger:
        candidates.append(_danger_finding_to_candidate(dang_f, snapshot_id))

    return candidates


def evaluate_finding_lifecycle_v2(
    conn: sqlite3.Connection,
    snapshot_id: int,
    estate: Estate,
    *,
    admx: AdmxResolver | None = None,
    application_version: str = "",
) -> LifecycleResult:
    """Run the Plan 024 evaluation pipeline end-to-end.

    This is the single ingest-time evaluation path for the Plan 024 model.
    It:

    1. Creates an evaluation run (recording snapshot, detector set, version).
    2. Runs intrinsic detectors and converts to FindingCandidate records.
    3. Processes candidates through the lifecycle engine.
    4. Returns the lifecycle result.

    This coexists with the legacy ``evaluate_finding_lifecycle`` (Plan 023)
    which writes to the same ``finding`` table without evaluation-run
    provenance. The v2 path is additive — it writes both the old columns
    (for backward compatibility with the existing web UI) and the new
    columns (for Plan 024 queries).
    """
    candidates = candidates_from_estate(
        estate, snapshot_id=snapshot_id, admx=admx,
    )

    detector_set_digest = hashlib.sha256(
        "|".join(sorted({c.detector_id for c in candidates})).encode()
    ).hexdigest()[:16]

    run_id = create_evaluation_run(
        conn,
        snapshot_id,
        evaluation_kind="intrinsic",
        detector_set_digest=detector_set_digest,
        application_version=application_version,
        status="partial",
    )

    try:
        result = run_evaluation(
            conn,
            run_id,
            candidates,
            collected_gpo_ids={g.id for g in estate.gpos},
            coverage_complete=not estate.coverage_gaps,
        )
        complete_evaluation_run(conn, run_id)
    except Exception:
        complete_evaluation_run(
            conn, run_id, status="failed",
            error_summary="evaluation run failed",
        )
        raise
    return result
