"""Tests for WI-4: finding identity and lifecycle."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from unittest.mock import MagicMock

from gpo_lens.findings import (
    finding_key,
    load_active_findings,
    update_finding_lifecycle,
)
from gpo_lens.store import init_db

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"


def _make_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    init_db(conn)
    return conn


def _make_finding(category: str, gpo_id: str, severity="medium", summary="test"):
    """Create a mock DoctorFinding-like object."""
    return MagicMock(
        category=category,
        gpo_id=gpo_id,
        gpo_name=f"GPO-{gpo_id[:8]}",
        severity=severity,
        summary=summary,
        detail="",
    )


class TestFindingKey:
    def test_deterministic(self) -> None:
        key1 = finding_key("cpassword", "abc123", "detail1")
        key2 = finding_key("cpassword", "abc123", "detail1")
        assert key1 == key2

    def test_different_rule_different_key(self) -> None:
        assert finding_key("cpassword", "abc", "d") != finding_key("ms16_072", "abc", "d")

    def test_different_subject_different_key(self) -> None:
        assert finding_key("cpassword", "abc", "d") != finding_key("cpassword", "xyz", "d")

    def test_different_detail_different_key(self) -> None:
        """Same rule + subject but different detail = different key (no silent dedup)."""
        assert finding_key("cpassword", "abc", "detail1") != finding_key(
            "cpassword", "abc", "detail2"
        )

    def test_case_insensitive(self) -> None:
        assert finding_key("Cpassword", "ABC", "Detail") == finding_key(
            "cpassword", "abc", "detail"
        )

    def test_whitespace_stripped(self) -> None:
        assert finding_key("  cpassword  ", "  abc  ", "  d  ") == finding_key(
            "cpassword", "abc", "d"
        )

    def test_invariant_under_ordering(self) -> None:
        """Property: finding keys don't depend on the order findings are emitted."""
        findings_a = [
            _make_finding("cpassword", "gpo1"),
            _make_finding("ms16_072", "gpo2"),
            _make_finding("version_skew", "gpo3"),
        ]
        findings_b = list(reversed(findings_a))
        keys_a = {finding_key(f.category, f.gpo_id, f.summary) for f in findings_a}
        keys_b = {finding_key(f.category, f.gpo_id, f.summary) for f in findings_b}
        assert keys_a == keys_b


class TestFindingLifecycle:
    def test_first_ingest_creates_findings(self) -> None:
        conn = _make_db()
        try:
            conn.execute(
                "INSERT INTO snapshot (id, domain, taken_at) VALUES (1, 'test', '2025-01-01')"
            )
            findings = [
                _make_finding("cpassword", "gpo1", "critical"),
                _make_finding("ms16_072", "gpo2", "high"),
            ]
            result = update_finding_lifecycle(conn, 1, findings)
            assert result.new_count == 2
            assert result.persisting_count == 0
            assert result.resolved_count == 0
            active = load_active_findings(conn)
            assert len(active) == 2
        finally:
            conn.close()

    def test_reingest_same_data_no_duplicates(self) -> None:
        conn = _make_db()
        try:
            conn.execute(
                "INSERT INTO snapshot (id, domain, taken_at) VALUES (1, 'test', '2025-01-01')"
            )
            findings = [_make_finding("cpassword", "gpo1")]
            update_finding_lifecycle(conn, 1, findings)

            conn.execute(
                "INSERT INTO snapshot (id, domain, taken_at) VALUES (2, 'test', '2025-01-02')"
            )
            result = update_finding_lifecycle(conn, 2, findings)
            assert result.new_count == 0
            assert result.persisting_count == 1
            assert result.resolved_count == 0

            active = load_active_findings(conn)
            assert len(active) == 1
        finally:
            conn.close()

    def test_resolved_finding(self) -> None:
        conn = _make_db()
        try:
            conn.execute(
                "INSERT INTO snapshot (id, domain, taken_at) VALUES (1, 'test', '2025-01-01')"
            )
            findings = [_make_finding("cpassword", "gpo1"), _make_finding("ms16_072", "gpo2")]
            update_finding_lifecycle(conn, 1, findings)

            conn.execute(
                "INSERT INTO snapshot (id, domain, taken_at) VALUES (2, 'test', '2025-01-02')"
            )
            # Second snapshot: cpassword is fixed (only ms16_072 remains)
            result = update_finding_lifecycle(conn, 2, [_make_finding("ms16_072", "gpo2")])
            assert result.new_count == 0
            assert result.persisting_count == 1
            assert result.resolved_count == 1

            active = load_active_findings(conn)
            assert len(active) == 1
            assert active[0].rule_id == "ms16_072"
        finally:
            conn.close()

    def test_regression_links_to_predecessor(self) -> None:
        conn = _make_db()
        try:
            conn.execute(
                "INSERT INTO snapshot (id, domain, taken_at) VALUES (1, 'test', '2025-01-01')"
            )
            findings = [_make_finding("cpassword", "gpo1")]
            update_finding_lifecycle(conn, 1, findings)

            # Snapshot 2: cpassword fixed
            conn.execute(
                "INSERT INTO snapshot (id, domain, taken_at) VALUES (2, 'test', '2025-01-02')"
            )
            update_finding_lifecycle(conn, 2, [])

            # Snapshot 3: cpassword reappears (regression)
            conn.execute(
                "INSERT INTO snapshot (id, domain, taken_at) VALUES (3, 'test', '2025-01-03')"
            )
            result = update_finding_lifecycle(conn, 3, [_make_finding("cpassword", "gpo1")])
            assert result.new_count == 1
            assert result.regressed_count == 1

            active = load_active_findings(conn)
            assert len(active) == 1
            assert active[0].predecessor_id is not None
        finally:
            conn.close()

    def test_new_finding_introduced(self) -> None:
        conn = _make_db()
        try:
            conn.execute(
                "INSERT INTO snapshot (id, domain, taken_at) VALUES (1, 'test', '2025-01-01')"
            )
            update_finding_lifecycle(conn, 1, [_make_finding("cpassword", "gpo1")])

            conn.execute(
                "INSERT INTO snapshot (id, domain, taken_at) VALUES (2, 'test', '2025-01-02')"
            )
            # New delegation issue introduced
            result = update_finding_lifecycle(conn, 2, [
                _make_finding("cpassword", "gpo1"),
                _make_finding("delegation", "gpo2", "medium"),
            ])
            assert result.new_count == 1
            assert result.persisting_count == 1
            assert result.resolved_count == 0
        finally:
            conn.close()

    def test_full_lifecycle_scenario(self) -> None:
        """AC: ingest of two snapshots yields exactly one resolved, one new, N persisting."""
        conn = _make_db()
        try:
            conn.execute(
                "INSERT INTO snapshot (id, domain, taken_at) VALUES (1, 'test', '2025-01-01')"
            )
            findings_s1 = [
                _make_finding("cpassword", "gpo1", "critical"),
                _make_finding("ms16_072", "gpo2", "high"),
                _make_finding("version_skew", "gpo3", "medium"),
            ]
            update_finding_lifecycle(conn, 1, findings_s1)

            conn.execute(
                "INSERT INTO snapshot (id, domain, taken_at) VALUES (2, 'test', '2025-01-02')"
            )
            # Snapshot 2: cpassword fixed, new delegation issue, others persist
            findings_s2 = [
                _make_finding("ms16_072", "gpo2", "high"),
                _make_finding("version_skew", "gpo3", "medium"),
                _make_finding("delegation", "gpo4", "medium"),
            ]
            result = update_finding_lifecycle(conn, 2, findings_s2)
            assert result.new_count == 1       # delegation
            assert result.persisting_count == 2  # ms16_072 + version_skew
            assert result.resolved_count == 1    # cpassword
        finally:
            conn.close()

    def test_finding_keys_invariant_under_export_ordering(self) -> None:
        """AC: property test — finding keys are invariant under export ordering."""
        findings_order_a = [
            _make_finding("cpassword", "gpo1"),
            _make_finding("ms16_072", "gpo2"),
            _make_finding("version_skew", "gpo3"),
            _make_finding("delegation", "gpo4"),
        ]
        findings_order_b = [
            _make_finding("delegation", "gpo4"),
            _make_finding("ms16_072", "gpo2"),
            _make_finding("cpassword", "gpo1"),
            _make_finding("version_skew", "gpo3"),
        ]
        conn = _make_db()
        try:
            conn.execute(
                "INSERT INTO snapshot (id, domain, taken_at) VALUES (1, 'test', '2025-01-01')"
            )
            update_finding_lifecycle(conn, 1, findings_order_a)
            active_a = {f.finding_key for f in load_active_findings(conn)}

            # Fresh DB, different order
            conn2 = _make_db()
            try:
                conn2.execute(
                    "INSERT INTO snapshot (id, domain, taken_at) VALUES (1, 'test', '2025-01-01')"
                )
                update_finding_lifecycle(conn2, 1, findings_order_b)
                active_b = {f.finding_key for f in load_active_findings(conn2)}

                assert active_a == active_b
            finally:
                conn2.close()
        finally:
            conn.close()


class TestCoverageAwareResolution:
    """A partial collection must never falsely mark a finding resolved.

    Regression guard for the false-resolve bug: absence of a finding from a
    scan only means "fixed" when the subject was actually re-evaluated.
    """

    def test_complete_coverage_resolves_as_before(self) -> None:
        conn = _make_db()
        try:
            conn.execute(
                "INSERT INTO snapshot (id, domain, taken_at) VALUES (1, 'test', '2025-01-01')"
            )
            update_finding_lifecycle(
                conn, 1,
                [_make_finding("cpassword", "gpo1"), _make_finding("ms16_072", "gpo2")],
            )
            conn.execute(
                "INSERT INTO snapshot (id, domain, taken_at) VALUES (2, 'test', '2025-01-02')"
            )
            # Complete re-scan (both GPOs collected) with cpassword gone → resolved.
            result = update_finding_lifecycle(
                conn, 2, [_make_finding("ms16_072", "gpo2")],
                collected_gpo_ids={"gpo1", "gpo2"},
                coverage_complete=True,
            )
            assert result.resolved_count == 1
            assert result.indeterminate_count == 0
        finally:
            conn.close()

    def test_partial_collection_does_not_resolve_uncollected_gpo(self) -> None:
        conn = _make_db()
        try:
            conn.execute(
                "INSERT INTO snapshot (id, domain, taken_at) VALUES (1, 'test', '2025-01-01')"
            )
            update_finding_lifecycle(
                conn, 1,
                [_make_finding("cpassword", "gpo1"), _make_finding("ms16_072", "gpo2")],
            )
            conn.execute(
                "INSERT INTO snapshot (id, domain, taken_at) VALUES (2, 'test', '2025-01-02')"
            )
            # Partial collection: gpo1 was NOT collected (coverage gap), so its
            # cpassword finding is absent — but that is NOT evidence it is fixed.
            result = update_finding_lifecycle(
                conn, 2, [_make_finding("ms16_072", "gpo2")],
                collected_gpo_ids={"gpo2"},
                coverage_complete=False,
            )
            assert result.resolved_count == 0
            assert result.indeterminate_count == 1
            # The cpassword finding must still be active, not silently resolved.
            active = {f.rule_id for f in load_active_findings(conn)}
            assert active == {"cpassword", "ms16_072"}
        finally:
            conn.close()

    def test_partial_collection_still_resolves_collected_gpo(self) -> None:
        conn = _make_db()
        try:
            conn.execute(
                "INSERT INTO snapshot (id, domain, taken_at) VALUES (1, 'test', '2025-01-01')"
            )
            update_finding_lifecycle(
                conn, 1,
                [_make_finding("cpassword", "gpo1"), _make_finding("ms16_072", "gpo2")],
            )
            conn.execute(
                "INSERT INTO snapshot (id, domain, taken_at) VALUES (2, 'test', '2025-01-02')"
            )
            # Partial elsewhere, but gpo1 WAS collected and its finding is gone →
            # genuinely resolved; gpo2 not collected → its finding stays active.
            result = update_finding_lifecycle(
                conn, 2, [],
                collected_gpo_ids={"gpo1"},
                coverage_complete=False,
            )
            assert result.resolved_count == 1
            assert result.indeterminate_count == 1
            active = {f.rule_id for f in load_active_findings(conn)}
            assert active == {"ms16_072"}
        finally:
            conn.close()

    def test_estate_level_finding_indeterminate_under_partial_coverage(self) -> None:
        conn = _make_db()
        try:
            conn.execute(
                "INSERT INTO snapshot (id, domain, taken_at) VALUES (1, 'test', '2025-01-01')"
            )
            # Estate-level finding (empty gpo_id), e.g. topology_discrepancy.
            update_finding_lifecycle(
                conn, 1, [_make_finding("topology_discrepancy", "", summary="ou mismatch")],
            )
            conn.execute(
                "INSERT INTO snapshot (id, domain, taken_at) VALUES (2, 'test', '2025-01-02')"
            )
            result = update_finding_lifecycle(
                conn, 2, [],
                collected_gpo_ids={"gpo1"},
                coverage_complete=False,
            )
            assert result.resolved_count == 0
            assert result.indeterminate_count == 1
        finally:
            conn.close()


class TestSchemaMigration:
    def test_v3_db_migrates_to_v4(self, tmp_path: Path) -> None:
        """A v3 DB should migrate to v4 with the new finding tables."""
        db_path = str(tmp_path / "test-v3.sqlite3")
        conn = sqlite3.connect(db_path)
        try:
            # Create a v3 schema manually
            conn.execute("PRAGMA user_version = 3")
            from gpo_lens.store import init_db

            # init_db creates all tables (IF NOT EXISTS) and calls _migrate_schema
            init_db(conn)
            # Verify tables exist
            tables = {
                r[0]
                for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
            assert "finding" in tables
            assert "finding_triage" in tables
            # Verify version bumped
            assert conn.execute("PRAGMA user_version").fetchone()[0] == 4
        finally:
            conn.close()
