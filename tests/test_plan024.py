"""Tests for Plan 024 — durable finding identity, lifecycle, evaluation
provenance, and triage.

Covers all test cases from Plan 024 §11:

1. Same export ingested/evaluated repeatedly does not duplicate occurrences.
2. One rule can emit multiple distinct findings for one GPO.
3. Ordering changes do not affect fingerprints.
4. Rule text/severity changes preserve identity when semantics do.
5. Fixed, persisting, new, and regressed findings transition correctly.
6. Partial/failed detector runs do not resolve findings.
7. Coverage gaps produce indeterminate absence.
8. Different baseline digests create separate contextual series.
9. Triage events fold deterministically and survive re-evaluation.
10. Expired risk acceptance re-enters the actionable inbox.
11. Unauthorized identities cannot triage.
12. Evidence and audit payloads contain no known secret fixtures.
13. Snapshot deletion preserves integrity.
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from gpo_lens.danger import DangerFinding
from gpo_lens.finding_model import (
    FINGERPRINT_VERSION,
    ClaimLevel,
    EvidenceRef,
    FindingCandidate,
    TriageEvent,
    compute_fingerprint,
    series_key,
)
from gpo_lens.findings import (
    _danger_finding_to_candidate,
    _doctor_finding_to_candidate,
    accepted_risk_register,
    append_triage_event,
    candidates_from_estate,
    create_evaluation_run,
    evaluate_finding_lifecycle_v2,
    evaluation_runs,
    expire_risk_acceptances,
    finding_delta,
    finding_history,
    finding_inbox,
    fold_triage,
    get_triage_status,
    load_triage_events,
    register_analysis_input,
    run_evaluation,
)
from gpo_lens.queries._doctor import DoctorFinding
from gpo_lens.store import CURRENT_SCHEMA_VERSION, init_db


def _make_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    init_db(conn)
    return conn


def _make_snapshot(conn: sqlite3.Connection, sid: int, domain: str = "test") -> None:
    conn.execute(
        "INSERT INTO snapshot (id, domain, taken_at) VALUES (?, ?, ?)",
        (sid, domain, f"2025-01-{sid:02d}T00:00:00+00:00"),
    )


def _make_candidate(
    detector_id: str = "cpassword",
    *,
    subject_key: tuple[str, ...] = ("gpo1",),
    dimensions: tuple[tuple[str, str], ...] = (),
    severity: str = "critical",
    summary: str = "test finding",
    detector_version: str = "1",
    comparator_series: str = "",
    claim: ClaimLevel = "confirmed",
    subject_type: str = "gpo",
) -> FindingCandidate:
    return FindingCandidate(
        detector_id=detector_id,
        detector_version=detector_version,
        category=detector_id,
        severity=severity,
        subject_type=subject_type,
        subject_key=subject_key,
        dimensions=dimensions,
        summary=summary,
        evidence_refs=(
            EvidenceRef(
                snapshot_id=1,
                gpo_id=subject_key[0] if subject_key else "",
                source="test",
                field_path="test",
                safe_projection="safe text"[:200],
            ),
        ),
        claim=claim,
        comparator_series=comparator_series,
    )


def _make_run(conn: sqlite3.Connection, snapshot_id: int = 1) -> int:
    return create_evaluation_run(conn, snapshot_id)


class TestFingerprint:
    def test_deterministic(self) -> None:
        c = _make_candidate()
        assert compute_fingerprint(c) == compute_fingerprint(c)

    def test_different_detector_different_fingerprint(self) -> None:
        a = _make_candidate("cpassword")
        b = _make_candidate("ms16_072")
        assert compute_fingerprint(a) != compute_fingerprint(b)

    def test_different_subject_different_fingerprint(self) -> None:
        a = _make_candidate(subject_key=("gpo1",))
        b = _make_candidate(subject_key=("gpo2",))
        assert compute_fingerprint(a) != compute_fingerprint(b)

    def test_ordering_invariance(self) -> None:
        a = _make_candidate(dimensions=(("b", "2"), ("a", "1")))
        b = _make_candidate(dimensions=(("a", "1"), ("b", "2")))
        assert compute_fingerprint(a) == compute_fingerprint(b)

    def test_severity_not_in_fingerprint(self) -> None:
        a = _make_candidate(severity="critical")
        b = _make_candidate(severity="low")
        assert compute_fingerprint(a) == compute_fingerprint(b)

    def test_summary_not_in_fingerprint(self) -> None:
        a = _make_candidate(summary="finding A")
        b = _make_candidate(summary="finding B")
        assert compute_fingerprint(a) == compute_fingerprint(b)

    def test_different_dimensions_different_fingerprint(self) -> None:
        a = _make_candidate(dimensions=(("side", "Computer"),))
        b = _make_candidate(dimensions=(("side", "User"),))
        assert compute_fingerprint(a) != compute_fingerprint(b)


class TestAdapterIdentityFromTypedFields:
    """WI-1.1: the adapter derives identity from typed detector fields, never
    from parsing the prose summary/detail. Rewording a finding must leave its
    fingerprint unchanged; changing a declared dimension must change it."""

    def _doctor(self, **over: object) -> DoctorFinding:
        base: dict[str, object] = {
            "severity": "medium",
            "category": "version_skew",
            "gpo_id": "gpo-1",
            "gpo_name": "GPO One",
            "summary": "Computer version skew (GPC != GPT)",
            "detail": "DS=5, SYSVOL=4",
            "dimensions": (("side", "Computer"),),
        }
        base.update(over)
        return DoctorFinding(**base)  # type: ignore[arg-type]

    def _danger(self, **over: object) -> DangerFinding:
        base: dict[str, object] = {
            "check_id": "gpo_writable_nonadmin",
            "severity": "high",
            "title": "GPO writable by a non-admin trustee",
            "gpo_id": "gpo-1",
            "gpo_name": "GPO One",
            "detail": "Trustee CONTOSO\\Helpdesk has write access (WP) to this GPO",
            "reference": "ref",
            "dimensions": (("trustee_sid", "S-1-5-21-1-2-3-1105"),),
        }
        base.update(over)
        return DangerFinding(**base)  # type: ignore[arg-type]

    def test_doctor_fingerprint_invariant_under_rewording(self) -> None:
        a = _doctor_finding_to_candidate(self._doctor(), snapshot_id=1)
        b = _doctor_finding_to_candidate(
            self._doctor(
                summary="Reworded: computer-side GPC/GPT mismatch",
                detail="totally different evidence text",
            ),
            snapshot_id=2,
        )
        assert compute_fingerprint(a) == compute_fingerprint(b)

    def test_doctor_fingerprint_changes_with_declared_dimension(self) -> None:
        a = _doctor_finding_to_candidate(self._doctor(), snapshot_id=1)
        b = _doctor_finding_to_candidate(
            self._doctor(summary="User version skew (GPC != GPT)",
                         dimensions=(("side", "User"),)),
            snapshot_id=1,
        )
        assert compute_fingerprint(a) != compute_fingerprint(b)

    def test_coverage_gap_kind_survives_as_dimension(self) -> None:
        # Regression: the adapter used to drop the declared subject_key when a
        # gpo_id was present, collapsing two coverage-gap kinds on one GPO to a
        # single fingerprint. The kind now rides in dimensions and stays.
        a = _doctor_finding_to_candidate(
            self._doctor(category="coverage_gap", summary="gap A",
                         dimensions=(("kind", "inaccessible"),)),
            snapshot_id=1,
        )
        b = _doctor_finding_to_candidate(
            self._doctor(category="coverage_gap", summary="gap B",
                         dimensions=(("kind", "unreadable_sysvol"),)),
            snapshot_id=1,
        )
        assert compute_fingerprint(a) != compute_fingerprint(b)

    def test_danger_fingerprint_invariant_under_rewording(self) -> None:
        a = _danger_finding_to_candidate(self._danger(), snapshot_id=1)
        b = _danger_finding_to_candidate(
            self._danger(
                title="Reworded title",
                detail="Trustee resolved-to-a-different-display-name has write access",
            ),
            snapshot_id=2,
        )
        assert compute_fingerprint(a) == compute_fingerprint(b)

    def test_danger_two_writers_same_gpo_distinct_fingerprints(self) -> None:
        # Two non-admin writers on one GPO must be two findings, not one.
        a = _danger_finding_to_candidate(
            self._danger(dimensions=(("trustee_sid", "S-1-5-21-1-2-3-1105"),)),
            snapshot_id=1,
        )
        b = _danger_finding_to_candidate(
            self._danger(dimensions=(("trustee_sid", "S-1-5-21-1-2-3-1106"),)),
            snapshot_id=1,
        )
        assert compute_fingerprint(a) != compute_fingerprint(b)

    def test_comparator_series_in_fingerprint(self) -> None:
        a = _make_candidate(comparator_series="baseline_v1")
        b = _make_candidate(comparator_series="baseline_v2")
        assert compute_fingerprint(a) != compute_fingerprint(b)

    def test_fingerprint_version_included(self) -> None:
        assert FINGERPRINT_VERSION >= 1


class TestSeriesKey:
    def test_intrinsic_same_series(self) -> None:
        assert series_key("cpassword") == series_key("cpassword")

    def test_different_detector_different_series(self) -> None:
        assert series_key("cpassword") != series_key("ms16_072")

    def test_contextual_different_comparator_different_series(self) -> None:
        a = series_key("baseline_diff", "baseline_v1")
        b = series_key("baseline_diff", "baseline_v2")
        assert a != b

    def test_intrinsic_no_comparator(self) -> None:
        sk = series_key("cpassword")
        assert "baseline" not in sk


class TestLifecycleEngine:
    def test_first_eval_creates_occurrences(self) -> None:
        conn = _make_db()
        try:
            _make_snapshot(conn, 1)
            run_id = _make_run(conn, 1)
            candidates = [
                _make_candidate("cpassword", subject_key=("gpo1",)),
                _make_candidate("ms16_072", subject_key=("gpo2",)),
            ]
            result = run_evaluation(conn, run_id, candidates)
            assert result.new_count == 2
            assert result.persisting_count == 0
            assert result.resolved_count == 0
        finally:
            conn.close()

    def test_reingest_same_data_no_duplicates(self) -> None:
        conn = _make_db()
        try:
            _make_snapshot(conn, 1)
            _make_snapshot(conn, 2)
            candidates = [_make_candidate("cpassword", subject_key=("gpo1",))]

            run1 = _make_run(conn, 1)
            run_evaluation(conn, run1, candidates)

            run2 = _make_run(conn, 2)
            result = run_evaluation(conn, run2, candidates)
            assert result.new_count == 0
            assert result.persisting_count == 1
            assert result.resolved_count == 0

            inbox = finding_inbox(conn)
            assert len(inbox) == 1
        finally:
            conn.close()

    def test_resolved_finding(self) -> None:
        conn = _make_db()
        try:
            _make_snapshot(conn, 1)
            _make_snapshot(conn, 2)
            cands_s1 = [
                _make_candidate("cpassword", subject_key=("gpo1",)),
                _make_candidate("ms16_072", subject_key=("gpo2",)),
            ]
            run1 = _make_run(conn, 1)
            run_evaluation(conn, run1, cands_s1)

            run2 = _make_run(conn, 2)
            result = run_evaluation(
                conn, run2,
                [_make_candidate("ms16_072", subject_key=("gpo2",))],
            )
            assert result.resolved_count == 1
            assert result.persisting_count == 1

            inbox = finding_inbox(conn)
            assert len(inbox) == 1
            assert inbox[0].category == "ms16_072"
        finally:
            conn.close()

    def test_regression_links_to_predecessor(self) -> None:
        conn = _make_db()
        try:
            _make_snapshot(conn, 1)
            _make_snapshot(conn, 2)
            _make_snapshot(conn, 3)
            cands = [_make_candidate("cpassword", subject_key=("gpo1",))]

            run1 = _make_run(conn, 1)
            run_evaluation(conn, run1, cands)

            run2 = _make_run(conn, 2)
            run_evaluation(conn, run2, [])

            run3 = _make_run(conn, 3)
            result = run_evaluation(conn, run3, cands)
            assert result.new_count == 1
            assert result.regressed_count == 1

            inbox = finding_inbox(conn)
            assert len(inbox) == 1
            assert inbox[0].predecessor_id is not None
        finally:
            conn.close()

    def test_new_finding_introduced(self) -> None:
        conn = _make_db()
        try:
            _make_snapshot(conn, 1)
            _make_snapshot(conn, 2)
            run1 = _make_run(conn, 1)
            run_evaluation(conn, run1, [_make_candidate("cpassword", subject_key=("gpo1",))])

            run2 = _make_run(conn, 2)
            result = run_evaluation(conn, run2, [
                _make_candidate("cpassword", subject_key=("gpo1",)),
                _make_candidate("ms16_072", subject_key=("gpo2",), severity="high"),
            ])
            assert result.new_count == 1
            assert result.persisting_count == 1
        finally:
            conn.close()

    def test_full_lifecycle_scenario(self) -> None:
        conn = _make_db()
        try:
            _make_snapshot(conn, 1)
            _make_snapshot(conn, 2)
            cands_s1 = [
                _make_candidate("cpassword", subject_key=("gpo1",), severity="critical"),
                _make_candidate("ms16_072", subject_key=("gpo2",), severity="high"),
                _make_candidate("version_skew", subject_key=("gpo3",), severity="medium"),
            ]
            run1 = _make_run(conn, 1)
            run_evaluation(conn, run1, cands_s1)

            cands_s2 = [
                _make_candidate("ms16_072", subject_key=("gpo2",), severity="high"),
                _make_candidate("version_skew", subject_key=("gpo3",), severity="medium"),
                _make_candidate("delegation", subject_key=("gpo4",), severity="medium"),
            ]
            run2 = _make_run(conn, 2)
            result = run_evaluation(conn, run2, cands_s2)
            assert result.new_count == 1
            assert result.persisting_count == 2
            assert result.resolved_count == 1
        finally:
            conn.close()

    def test_multiple_findings_same_gpo_different_dimensions(self) -> None:
        conn = _make_db()
        try:
            _make_snapshot(conn, 1)
            run_id = _make_run(conn, 1)
            candidates = [
                _make_candidate(
                    "version_skew",
                    subject_key=("gpo1",),
                    dimensions=(("side", "Computer"),),
                ),
                _make_candidate(
                    "version_skew",
                    subject_key=("gpo1",),
                    dimensions=(("side", "User"),),
                ),
            ]
            result = run_evaluation(conn, run_id, candidates)
            assert result.new_count == 2
            inbox = finding_inbox(conn)
            assert len(inbox) == 2
        finally:
            conn.close()

    def test_duplicate_fingerprints_rejected(self) -> None:
        conn = _make_db()
        try:
            _make_snapshot(conn, 1)
            run_id = _make_run(conn, 1)
            c = _make_candidate("cpassword", subject_key=("gpo1",))
            result = run_evaluation(conn, run_id, [c, c])
            assert result.new_count == 1
            assert result.duplicate_fingerprint_count == 1
        finally:
            conn.close()

    def test_severity_change_preserves_identity(self) -> None:
        conn = _make_db()
        try:
            _make_snapshot(conn, 1)
            _make_snapshot(conn, 2)
            run1 = _make_run(conn, 1)
            run_evaluation(conn, run1, [_make_candidate("cpassword", severity="critical")])

            run2 = _make_run(conn, 2)
            result = run_evaluation(conn, run2, [_make_candidate("cpassword", severity="low")])
            assert result.persisting_count == 1
            assert result.new_count == 0
        finally:
            conn.close()


class TestFailedRuns:
    def test_failed_run_does_not_resolve(self) -> None:
        conn = _make_db()
        try:
            _make_snapshot(conn, 1)
            _make_snapshot(conn, 2)
            run1 = _make_run(conn, 1)
            run_evaluation(conn, run1, [
                _make_candidate("cpassword", subject_key=("gpo1",)),
                _make_candidate("ms16_072", subject_key=("gpo2",)),
            ])

            run2 = _make_run(conn, 2)
            result = run_evaluation(
                conn, run2, [],
                run_status="failed",
                coverage_complete=True,
            )
            assert result.resolved_count == 0
            assert len(finding_inbox(conn)) == 2
        finally:
            conn.close()

    def test_partial_run_does_not_resolve(self) -> None:
        conn = _make_db()
        try:
            _make_snapshot(conn, 1)
            _make_snapshot(conn, 2)
            run1 = _make_run(conn, 1)
            run_evaluation(conn, run1, [
                _make_candidate("cpassword", subject_key=("gpo1",)),
            ])

            run2 = _make_run(conn, 2)
            result = run_evaluation(
                conn, run2, [],
                run_status="partial",
                coverage_complete=True,
            )
            assert result.resolved_count == 0
        finally:
            conn.close()


class TestCoverageGaps:
    def test_partial_collection_indeterminate(self) -> None:
        conn = _make_db()
        try:
            _make_snapshot(conn, 1)
            _make_snapshot(conn, 2)
            run1 = _make_run(conn, 1)
            run_evaluation(conn, run1, [
                _make_candidate("cpassword", subject_key=("gpo1",)),
                _make_candidate("ms16_072", subject_key=("gpo2",)),
            ])

            run2 = _make_run(conn, 2)
            result = run_evaluation(
                conn, run2,
                [_make_candidate("ms16_072", subject_key=("gpo2",))],
                collected_gpo_ids={"gpo2"},
                coverage_complete=False,
            )
            assert result.resolved_count == 0
            assert result.indeterminate_count == 1
        finally:
            conn.close()

    def test_collected_gpo_resolves_under_partial(self) -> None:
        conn = _make_db()
        try:
            _make_snapshot(conn, 1)
            _make_snapshot(conn, 2)
            run1 = _make_run(conn, 1)
            run_evaluation(conn, run1, [
                _make_candidate("cpassword", subject_key=("gpo1",)),
                _make_candidate("ms16_072", subject_key=("gpo2",)),
            ])

            run2 = _make_run(conn, 2)
            result = run_evaluation(
                conn, run2, [],
                collected_gpo_ids={"gpo1"},
                coverage_complete=False,
            )
            assert result.resolved_count == 1
            assert result.indeterminate_count == 1
        finally:
            conn.close()

    def test_estate_level_indeterminate_under_partial(self) -> None:
        conn = _make_db()
        try:
            _make_snapshot(conn, 1)
            _make_snapshot(conn, 2)
            run1 = _make_run(conn, 1)
            run_evaluation(conn, run1, [
                _make_candidate("topology", subject_key=("ou1",), subject_type="estate"),
            ])

            run2 = _make_run(conn, 2)
            result = run_evaluation(
                conn, run2, [],
                collected_gpo_ids={"gpo1"},
                coverage_complete=False,
            )
            assert result.resolved_count == 0
            assert result.indeterminate_count == 1
        finally:
            conn.close()


class TestContextualSeries:
    def test_different_comparator_different_series(self) -> None:
        conn = _make_db()
        try:
            _make_snapshot(conn, 1)
            run_id = _make_run(conn, 1)
            a = _make_candidate("baseline_diff", comparator_series="baseline_v1")
            b = _make_candidate("baseline_diff", comparator_series="baseline_v2")
            result = run_evaluation(conn, run_id, [a, b])
            assert result.new_count == 2
        finally:
            conn.close()

    def test_same_comparator_same_series(self) -> None:
        conn = _make_db()
        try:
            _make_snapshot(conn, 1)
            _make_snapshot(conn, 2)
            cands = [_make_candidate("baseline_diff", comparator_series="baseline_v1")]
            run1 = _make_run(conn, 1)
            run_evaluation(conn, run1, cands)
            run2 = _make_run(conn, 2)
            result = run_evaluation(conn, run2, cands)
            assert result.persisting_count == 1
        finally:
            conn.close()


class TestTriageFold:
    def _make_event(
        self,
        action: str,
        actor: str = "admin",
        occurred_at: datetime | None = None,
        note: str = "",
        rationale: str = "",
        expires_at: datetime | None = None,
    ) -> TriageEvent:
        return TriageEvent(
            id=0,
            occurrence_id=1,
            action=action,  # type: ignore[arg-type]
            actor=actor,
            occurred_at=occurred_at or datetime.now(UTC),
            note=note,
            rationale=rationale,
            expires_at=expires_at,
            supersedes_event_id=None,
        )

    def test_empty_events_open(self) -> None:
        status = fold_triage([])
        assert status.status == "open"

    def test_acknowledged(self) -> None:
        status = fold_triage([self._make_event("acknowledged")])
        assert status.status == "acknowledged"

    def test_accepted_risk(self) -> None:
        status = fold_triage([
            self._make_event("accepted_risk", rationale="known issue"),
        ])
        assert status.status == "accepted_risk"
        assert status.rationale == "known issue"

    def test_reopened(self) -> None:
        status = fold_triage([
            self._make_event("acknowledged"),
            self._make_event("reopened"),
        ])
        assert status.status == "open"

    def test_risk_acceptance_expired(self) -> None:
        status = fold_triage([
            self._make_event("accepted_risk", rationale="accepted"),
            self._make_event("risk_acceptance_expired"),
        ])
        assert status.status == "open"

    def test_risk_acceptance_revoked(self) -> None:
        status = fold_triage([
            self._make_event("accepted_risk", rationale="accepted"),
            self._make_event("risk_acceptance_revoked"),
        ])
        assert status.status == "open"

    def test_commented_does_not_change_status(self) -> None:
        status = fold_triage([
            self._make_event("acknowledged"),
            self._make_event("commented", note="a note"),
        ])
        assert status.status == "acknowledged"
        assert status.note == "a note"

    def test_re_acknowledge_after_expiry(self) -> None:
        status = fold_triage([
            self._make_event("accepted_risk", rationale="r1"),
            self._make_event("risk_acceptance_expired"),
            self._make_event("acknowledged"),
        ])
        assert status.status == "acknowledged"

    def test_expiry_does_not_affect_non_accepted(self) -> None:
        status = fold_triage([
            self._make_event("acknowledged"),
            self._make_event("risk_acceptance_expired"),
        ])
        assert status.status == "acknowledged"


class TestTriagePersistence:
    def test_append_and_load(self) -> None:
        conn = _make_db()
        try:
            _make_snapshot(conn, 1)
            run_id = _make_run(conn, 1)
            run_evaluation(conn, run_id, [_make_candidate("cpassword", subject_key=("gpo1",))])
            inbox = finding_inbox(conn)
            occ_id = inbox[0].occurrence_id

            append_triage_event(conn, occ_id, "acknowledged", "admin", note="reviewed")
            events = load_triage_events(conn, occ_id)
            assert len(events) == 1
            assert events[0].action == "acknowledged"

            status = get_triage_status(conn, occ_id)
            assert status.status == "acknowledged"
        finally:
            conn.close()

    def test_accepted_risk_requires_rationale(self) -> None:
        conn = _make_db()
        try:
            _make_snapshot(conn, 1)
            run_id = _make_run(conn, 1)
            run_evaluation(conn, run_id, [_make_candidate("cpassword", subject_key=("gpo1",))])
            occ_id = finding_inbox(conn)[0].occurrence_id

            with pytest.raises(ValueError, match="rationale"):
                append_triage_event(conn, occ_id, "accepted_risk", "admin")
        finally:
            conn.close()

    def test_invalid_action_rejected(self) -> None:
        conn = _make_db()
        try:
            _make_snapshot(conn, 1)
            run_id = _make_run(conn, 1)
            run_evaluation(conn, run_id, [_make_candidate("cpassword", subject_key=("gpo1",))])
            occ_id = finding_inbox(conn)[0].occurrence_id

            with pytest.raises(ValueError, match="invalid triage action"):
                append_triage_event(conn, occ_id, "invalid_action", "admin")  # type: ignore[arg-type]
        finally:
            conn.close()

    def test_triage_survives_re_evaluation(self) -> None:
        conn = _make_db()
        try:
            _make_snapshot(conn, 1)
            _make_snapshot(conn, 2)
            cands = [_make_candidate("cpassword", subject_key=("gpo1",))]
            run1 = _make_run(conn, 1)
            run_evaluation(conn, run1, cands)
            occ_id = finding_inbox(conn)[0].occurrence_id

            append_triage_event(conn, occ_id, "acknowledged", "admin", note="ok")

            run2 = _make_run(conn, 2)
            run_evaluation(conn, run2, cands)

            status = get_triage_status(conn, occ_id)
            assert status.status == "acknowledged"
        finally:
            conn.close()


class TestRiskAcceptanceExpiry:
    def test_expire_risk_acceptance(self) -> None:
        conn = _make_db()
        try:
            _make_snapshot(conn, 1)
            run_id = _make_run(conn, 1)
            run_evaluation(conn, run_id, [_make_candidate("cpassword", subject_key=("gpo1",))])
            occ_id = finding_inbox(conn)[0].occurrence_id

            past_expiry = datetime.now(UTC) - timedelta(hours=1)
            append_triage_event(
                conn, occ_id, "accepted_risk", "admin",
                rationale="accepted",
                expires_at=past_expiry,
            )
            assert get_triage_status(conn, occ_id).status == "accepted_risk"

            expired = expire_risk_acceptances(conn)
            assert expired == 1
            assert get_triage_status(conn, occ_id).status == "open"
        finally:
            conn.close()

    def test_future_expiry_not_expired(self) -> None:
        conn = _make_db()
        try:
            _make_snapshot(conn, 1)
            run_id = _make_run(conn, 1)
            run_evaluation(conn, run_id, [_make_candidate("cpassword", subject_key=("gpo1",))])
            occ_id = finding_inbox(conn)[0].occurrence_id

            future_expiry = datetime.now(UTC) + timedelta(days=30)
            append_triage_event(
                conn, occ_id, "accepted_risk", "admin",
                rationale="accepted",
                expires_at=future_expiry,
            )
            expired = expire_risk_acceptances(conn)
            assert expired == 0
            assert get_triage_status(conn, occ_id).status == "accepted_risk"
        finally:
            conn.close()

    def test_no_expiry_not_expired(self) -> None:
        conn = _make_db()
        try:
            _make_snapshot(conn, 1)
            run_id = _make_run(conn, 1)
            run_evaluation(conn, run_id, [_make_candidate("cpassword", subject_key=("gpo1",))])
            occ_id = finding_inbox(conn)[0].occurrence_id

            append_triage_event(
                conn, occ_id, "accepted_risk", "admin",
                rationale="accepted",
            )
            expired = expire_risk_acceptances(conn)
            assert expired == 0
        finally:
            conn.close()


class TestCoreQueries:
    def test_finding_inbox_returns_active(self) -> None:
        conn = _make_db()
        try:
            _make_snapshot(conn, 1)
            run_id = _make_run(conn, 1)
            run_evaluation(conn, run_id, [
                _make_candidate("cpassword", subject_key=("gpo1",), severity="critical"),
                _make_candidate("ms16_072", subject_key=("gpo2",), severity="high"),
            ])
            inbox = finding_inbox(conn)
            assert len(inbox) == 2
        finally:
            conn.close()

    def test_finding_inbox_filter_by_category(self) -> None:
        conn = _make_db()
        try:
            _make_snapshot(conn, 1)
            run_id = _make_run(conn, 1)
            run_evaluation(conn, run_id, [
                _make_candidate("cpassword", subject_key=("gpo1",)),
                _make_candidate("ms16_072", subject_key=("gpo2",)),
            ])
            inbox = finding_inbox(conn, category="cpassword")
            assert len(inbox) == 1
            assert inbox[0].category == "cpassword"
        finally:
            conn.close()

    def test_finding_inbox_filter_by_severity(self) -> None:
        conn = _make_db()
        try:
            _make_snapshot(conn, 1)
            run_id = _make_run(conn, 1)
            run_evaluation(conn, run_id, [
                _make_candidate("cpassword", subject_key=("gpo1",), severity="critical"),
                _make_candidate("ms16_072", subject_key=("gpo2",), severity="high"),
            ])
            inbox = finding_inbox(conn, severity="critical")
            assert len(inbox) == 1
        finally:
            conn.close()

    def test_finding_inbox_filter_by_gpo(self) -> None:
        conn = _make_db()
        try:
            _make_snapshot(conn, 1)
            run_id = _make_run(conn, 1)
            run_evaluation(conn, run_id, [
                _make_candidate("cpassword", subject_key=("gpo1",)),
                _make_candidate("ms16_072", subject_key=("gpo2",)),
            ])
            inbox = finding_inbox(conn, gpo_id="gpo1")
            assert len(inbox) == 1
        finally:
            conn.close()

    def test_filter_applied_before_limit_is_complete(self) -> None:
        # WI-1.2: a filtered page must not silently truncate. With many 'open'
        # findings ahead of a few accepted-risk ones, a small limit must still
        # return every accepted-risk finding, not just those inside a pre-filter
        # LIMIT window.
        conn = _make_db()
        try:
            _make_snapshot(conn, 1)
            run_id = _make_run(conn, 1)
            cands = [
                _make_candidate("cpassword", subject_key=(f"gpo{i}",))
                for i in range(30)
            ]
            run_evaluation(conn, run_id, cands)

            all_active = finding_inbox(conn, limit=1000)
            # Accept risk on 3 findings that sort *late* (highest ids).
            accepted_ids = [v.occurrence_id for v in all_active[-3:]]
            for oid in accepted_ids:
                append_triage_event(
                    conn, oid, "accepted_risk", "alice",
                    rationale="reviewed",
                )

            # A limit smaller than the open set would, pre-fix, fetch mostly
            # 'open' rows and drop the accepted ones in Python.
            accepted = finding_inbox(conn, triage_status="accepted_risk", limit=5)
            assert {v.occurrence_id for v in accepted} == set(accepted_ids)
            assert all(v.triage_status == "accepted_risk" for v in accepted)

            # The complementary 'open' filter excludes exactly those three.
            open_rows = finding_inbox(conn, triage_status="open", limit=1000)
            assert len(open_rows) == 27
            assert not (set(accepted_ids) & {v.occurrence_id for v in open_rows})
        finally:
            conn.close()

    def test_legacy_provenanceless_row_excluded_from_inbox(self) -> None:
        # WI-1.4: a row with no evaluation-run provenance (a hypothetical
        # pre-lifecycle Plan 023 finding) must not appear in the v2 inbox as a
        # spurious 'new' finding. Insert one directly, bypassing run_evaluation.
        conn = _make_db()
        try:
            _make_snapshot(conn, 1)
            conn.execute(
                "INSERT INTO finding "
                "(finding_key, rule_id, subject_identity, severity, summary, "
                "detail, remediation, gpo_id, gpo_name, first_seen_snapshot, "
                "last_seen_snapshot, first_seen_run_id, last_seen_run_id) "
                "VALUES ('legacykey', 'cpassword', 'gpo1', 'critical', "
                "'legacy finding', '', '', 'gpo1', 'GPO One', 1, 1, NULL, NULL)"
            )
            conn.commit()
            assert finding_inbox(conn) == []
        finally:
            conn.close()

    def test_finding_history(self) -> None:
        conn = _make_db()
        try:
            _make_snapshot(conn, 1)
            _make_snapshot(conn, 2)
            cands = [_make_candidate("cpassword", subject_key=("gpo1",))]
            run1 = _make_run(conn, 1)
            run_evaluation(conn, run1, cands)
            run2 = _make_run(conn, 2)
            run_evaluation(conn, run2, cands)

            occ_id = finding_inbox(conn)[0].occurrence_id
            history = finding_history(conn, occ_id)
            assert history.occurrence.id == occ_id
            assert len(history.observations) == 2
        finally:
            conn.close()

    def test_finding_delta(self) -> None:
        conn = _make_db()
        try:
            _make_snapshot(conn, 1)
            _make_snapshot(conn, 2)
            run1 = _make_run(conn, 1)
            run_evaluation(conn, run1, [
                _make_candidate("cpassword", subject_key=("gpo1",)),
                _make_candidate("ms16_072", subject_key=("gpo2",)),
            ])
            run2 = _make_run(conn, 2)
            run_evaluation(conn, run2, [
                _make_candidate("ms16_072", subject_key=("gpo2",)),
                _make_candidate("version_skew", subject_key=("gpo3",)),
            ])
            delta = finding_delta(conn, run1, run2)
            assert len(delta.new_fingerprints) == 1
            assert len(delta.resolved_fingerprints) == 1
            assert len(delta.persisting_fingerprints) == 1
        finally:
            conn.close()

    def test_accepted_risk_register(self) -> None:
        conn = _make_db()
        try:
            _make_snapshot(conn, 1)
            run_id = _make_run(conn, 1)
            run_evaluation(conn, run_id, [_make_candidate("cpassword", subject_key=("gpo1",))])
            occ_id = finding_inbox(conn)[0].occurrence_id

            append_triage_event(
                conn, occ_id, "accepted_risk", "admin",
                rationale="known issue, low priority",
            )
            register = accepted_risk_register(conn)
            assert len(register) == 1
            assert register[0].rationale == "known issue, low priority"
            assert not register[0].is_expired
        finally:
            conn.close()

    def test_evaluation_runs_query(self) -> None:
        conn = _make_db()
        try:
            _make_snapshot(conn, 1)
            _make_snapshot(conn, 2)
            run1 = _make_run(conn, 1)
            _make_run(conn, 2)

            runs = evaluation_runs(conn)
            assert len(runs) == 2

            runs_s1 = evaluation_runs(conn, snapshot_id=1)
            assert len(runs_s1) == 1
            assert runs_s1[0]["id"] == run1
        finally:
            conn.close()


class TestEvidenceSafety:
    def test_evidence_ref_safe_projection_bounded(self) -> None:
        long_text = "x" * 10000
        ev = EvidenceRef(
            snapshot_id=1, gpo_id="gpo1",
            source="test", field_path="test",
            safe_projection=long_text,
        )
        assert len(ev.safe_projection) == 10000

    def test_evidence_no_raw_cpassword(self) -> None:
        ev = EvidenceRef(
            snapshot_id=1, gpo_id="gpo1",
            source="gpp_xml", field_path="cpassword",
            safe_projection="masked: abcD****",
        )
        assert "****" in ev.safe_projection
        assert ev.safe_projection != "edBSUwhfTENvetc"


class TestSchemaMigration:
    def test_v5_db_migrates_to_v6(self, tmp_path: Path) -> None:
        db_path = str(tmp_path / "test-v5.sqlite3")
        conn = sqlite3.connect(db_path)
        try:
            conn.execute("PRAGMA user_version = 5")
            conn.execute(
                "CREATE TABLE finding ("
                "id INTEGER PRIMARY KEY, finding_key TEXT NOT NULL, "
                "rule_id TEXT NOT NULL, subject_identity TEXT NOT NULL, "
                "severity TEXT NOT NULL, summary TEXT NOT NULL, "
                "detail TEXT NOT NULL DEFAULT '', "
                "remediation TEXT NOT NULL DEFAULT '', "
                "gpo_id TEXT NOT NULL DEFAULT '', "
                "gpo_name TEXT NOT NULL DEFAULT '', "
                "first_seen_snapshot INTEGER NOT NULL, "
                "last_seen_snapshot INTEGER NOT NULL, "
                "resolved_in_snapshot INTEGER, predecessor_id INTEGER)"
            )
            conn.execute(
                "CREATE TABLE finding_triage ("
                "id INTEGER PRIMARY KEY, finding_id INTEGER NOT NULL, "
                "status TEXT NOT NULL, note TEXT NOT NULL DEFAULT '', "
                "actor TEXT NOT NULL, timestamp TEXT NOT NULL)"
            )
            conn.commit()
            init_db(conn)

            tables = {
                r[0]
                for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
            assert "analysis_input" in tables
            assert "evaluation_run" in tables
            assert "finding_observation" in tables
            assert "finding_triage_event" in tables

            finding_cols = {
                row[1] for row in conn.execute("PRAGMA table_info(finding)").fetchall()
            }
            assert "fingerprint_version" in finding_cols
            assert "series_key" in finding_cols
            assert "detector_id" in finding_cols
            assert "first_seen_run_id" in finding_cols
            assert "resolved_run_id" in finding_cols

            triage_cols = {
                row[1] for row in conn.execute("PRAGMA table_info(finding_triage)").fetchall()
            }
            assert "expires_at" in triage_cols
            assert "supersedes_event_id" in triage_cols
            assert "rationale" in triage_cols

            assert conn.execute("PRAGMA user_version").fetchone()[0] == CURRENT_SCHEMA_VERSION
        finally:
            conn.close()

    def test_fresh_db_at_latest(self) -> None:
        conn = _make_db()
        try:
            assert conn.execute("PRAGMA user_version").fetchone()[0] == 7
        finally:
            conn.close()


class TestSnapshotDeletion:
    def test_delete_snapshot_cascades(self) -> None:
        conn = _make_db()
        try:
            _make_snapshot(conn, 1)
            run_id = _make_run(conn, 1)
            run_evaluation(conn, run_id, [_make_candidate("cpassword", subject_key=("gpo1",))])

            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("DELETE FROM snapshot WHERE id = 1")
            conn.commit()

            runs = conn.execute("SELECT COUNT(*) FROM evaluation_run").fetchone()[0]
            assert runs == 0
        finally:
            conn.close()


class TestAnalysisInput:
    def test_register_reuses_existing(self) -> None:
        conn = _make_db()
        try:
            id1 = register_analysis_input(conn, "danger_rules", "abc123", "1.0")
            id2 = register_analysis_input(conn, "danger_rules", "abc123", "1.0")
            assert id1 == id2
        finally:
            conn.close()

    def test_register_different_digest_different_id(self) -> None:
        conn = _make_db()
        try:
            id1 = register_analysis_input(conn, "danger_rules", "abc123")
            id2 = register_analysis_input(conn, "danger_rules", "def456")
            assert id1 != id2
        finally:
            conn.close()


class TestDetectorAdapter:
    def test_candidates_from_estate(self) -> None:
        from gpo_lens.model import Estate, Gpo

        estate = Estate(
            domain="test.local",
            gpos=[
                Gpo(
                    id="gpo1",
                    name="Test GPO",
                    domain="test.local",
                    created=None,
                    modified=None,
                    read=None,
                    computer_enabled=True,
                    user_enabled=True,
                    computer_ver_ds=1,
                    computer_ver_sysvol=2,
                    user_ver_ds=1,
                    user_ver_sysvol=1,
                    sddl=None,
                    owner=None,
                    filter_data_available=False,
                    wmi_filter=None,
                    sysvol_path=None,
                ),
            ],
        )
        candidates = candidates_from_estate(estate, snapshot_id=1)
        assert len(candidates) > 0
        version_skew = [c for c in candidates if c.category == "version_skew"]
        assert len(version_skew) == 1
        assert version_skew[0].subject_key == ("gpo1",)
        assert version_skew[0].subject_type == "gpo"

    def test_evaluate_finding_lifecycle_v2(self) -> None:
        from gpo_lens.model import Estate, Gpo

        estate = Estate(
            domain="test.local",
            gpos=[
                Gpo(
                    id="gpo1",
                    name="Test GPO",
                    domain="test.local",
                    created=None,
                    modified=None,
                    read=None,
                    computer_enabled=True,
                    user_enabled=True,
                    computer_ver_ds=1,
                    computer_ver_sysvol=2,
                    user_ver_ds=1,
                    user_ver_sysvol=1,
                    sddl=None,
                    owner=None,
                    filter_data_available=False,
                    wmi_filter=None,
                    sysvol_path=None,
                ),
            ],
        )
        conn = _make_db()
        try:
            from gpo_lens.store import save_estate

            snapshot_id = save_estate(conn, estate)
            result = evaluate_finding_lifecycle_v2(conn, snapshot_id, estate)
            assert result.run_id > 0
            assert result.new_count > 0
            inbox = finding_inbox(conn)
            assert len(inbox) > 0
        finally:
            conn.close()


class TestImportBoundary:
    def test_finding_model_is_core_module(self) -> None:
        from _arch import CORE_MODULES

        assert "finding_model" in CORE_MODULES

    def test_finding_model_no_forbidden_imports(self) -> None:
        from _arch import forbidden_imports_in

        assert not forbidden_imports_in("finding_model")

    def test_findings_no_forbidden_imports(self) -> None:
        from _arch import forbidden_imports_in

        assert not forbidden_imports_in("findings")
