"""Legacy Plan 023 finding lifecycle (test-only).

These functions are the original Plan 023 lifecycle writer, retained for
test compatibility.  Production code uses the Plan 024 ``run_evaluation``
path in :mod:`gpo_lens.findings`.
"""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from gpo_lens.findings import absence_is_meaningful


@runtime_checkable
class _FindingLike(Protocol):
    """Protocol for finding objects processed by the legacy lifecycle."""

    @property
    def gpo_id(self) -> str: ...
    @property
    def gpo_name(self) -> str: ...
    @property
    def severity(self) -> str: ...
    @property
    def detail(self) -> str: ...
    @property
    def remediation(self) -> str: ...
    # The remaining attributes are read by ``_finding_to_key_parts``; they are
    # declared here so the protocol is honest about what the function needs.
    @property
    def category(self) -> str: ...
    @property
    def check_id(self) -> str: ...
    @property
    def subject_key(self) -> tuple[str, ...]: ...
    @property
    def summary(self) -> str: ...


@dataclass(frozen=True)
class FindingLifecycleResult:
    """Summary of what happened during a lifecycle update."""

    new_count: int
    persisting_count: int
    resolved_count: int
    regressed_count: int
    indeterminate_count: int = 0


def finding_key(rule_id: str, subject_identity: str, detail: str = "") -> str:
    """Compute a stable, deterministic finding key.

    The key is a SHA-256 hash of ``(rule_id, subject_identity, detail)``, all
    lowercased and stripped.  *detail* is a discriminator that prevents
    silent deduplication when a single GPO has multiple findings from the
    same rule (e.g. two dangerous registry values under the same check_id).
    """
    raw = "\x00".join(
        [
            rule_id.strip().lower(),
            subject_identity.strip().lower(),
            detail.strip().lower(),
        ]
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _finding_to_key_parts(finding: _FindingLike) -> tuple[str, str, str, str]:
    """Extract ``(rule_id, subject_identity, severity, detail)`` from a finding."""
    rule_id = getattr(finding, "category", "") or getattr(finding, "check_id", "")
    severity = getattr(finding, "severity", "info")
    subject_key = getattr(finding, "subject_key", ()) or ()
    if subject_key:
        return rule_id, "|".join(subject_key), severity, ""
    subject = getattr(finding, "gpo_id", "") or getattr(finding, "summary", "")
    detail = getattr(finding, "detail", "") or getattr(finding, "summary", "")
    return rule_id, subject, severity, detail


def update_finding_lifecycle(
    conn: sqlite3.Connection,
    snapshot_id: int,
    findings: list[_FindingLike],
    *,
    collected_gpo_ids: set[str] | None = None,
    coverage_complete: bool = True,
) -> FindingLifecycleResult:
    """Diff current findings against the prior snapshot and update lifecycle."""
    current_keys: dict[str, _FindingLike] = {}
    for f in findings:
        rule_id, subject, _sev, detail = _finding_to_key_parts(f)
        key = finding_key(rule_id, subject, detail)
        current_keys[key] = f

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
        for key, finding in current_keys.items():
            rule_id, subject, severity, _detail = _finding_to_key_parts(finding)
            summary = getattr(finding, "summary", "") or getattr(finding, "title", "")
            raw_detail = getattr(finding, "detail", "")
            raw_remediation = getattr(finding, "remediation", "")
            finding_detail = raw_detail[:16_000] if isinstance(raw_detail, str) else ""
            remediation = raw_remediation[:8_000] if isinstance(raw_remediation, str) else ""
            gpo_id = getattr(finding, "gpo_id", "")
            gpo_name = getattr(finding, "gpo_name", "")

            if key in active_by_key:
                existing = active_by_key[key]
                conn.execute(
                    "UPDATE finding SET last_seen_snapshot = ?, severity = ?, summary = ?, "
                    "detail = ?, remediation = ? "
                    "WHERE id = ?",
                    (
                        snapshot_id,
                        severity,
                        summary,
                        finding_detail,
                        remediation,
                        existing["id"],
                    ),
                )
                persisting_count += 1
            else:
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
                    (
                        key,
                        rule_id,
                        subject,
                        severity,
                        summary,
                        finding_detail,
                        remediation,
                        gpo_id,
                        gpo_name,
                        snapshot_id,
                        snapshot_id,
                        predecessor_id,
                    ),
                )
                new_count += 1

        resolved_count = 0
        indeterminate_count = 0
        for key, existing in active_by_key.items():
            if key not in current_keys:
                if not absence_is_meaningful(
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
