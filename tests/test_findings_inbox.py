"""Tests for WI-5: triage annotations + findings inbox."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from gpo_lens.findings import (
    load_finding_triage,
    load_finding_triage_map,
    triage_finding,
    update_finding_lifecycle,
)
from gpo_lens.store import init_db

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"


def _make_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    init_db(conn)
    return conn


def _make_finding(category: str, gpo_id: str, severity="medium", summary="test"):
    return MagicMock(
        category=category,
        gpo_id=gpo_id,
        gpo_name=f"GPO-{gpo_id[:8]}",
        severity=severity,
        summary=summary,
        detail="",
        subject_key=(),
    )


class TestTriage:
    def test_triage_append_only(self) -> None:
        conn = _make_db()
        try:
            conn.execute(
                "INSERT INTO snapshot (id, domain, taken_at) VALUES (1, 'test', '2025-01-01')"
            )
            update_finding_lifecycle(conn, 1, [_make_finding("cpassword", "gpo1")])
            from gpo_lens.findings import load_active_findings

            active = load_active_findings(conn)
            finding_id = active[0].id

            triage_finding(conn, finding_id, "acknowledged", "looking into it", "alice")
            triage_finding(conn, finding_id, "accepted_risk", "approved by CISO", "bob")

            history = load_finding_triage(conn, finding_id)
            assert len(history) == 2
            assert history[0]["status"] == "acknowledged"
            assert history[0]["actor"] == "alice"
            assert history[1]["status"] == "accepted_risk"
            assert history[1]["actor"] == "bob"
        finally:
            conn.close()

    def test_triage_map_returns_latest(self) -> None:
        conn = _make_db()
        try:
            conn.execute(
                "INSERT INTO snapshot (id, domain, taken_at) VALUES (1, 'test', '2025-01-01')"
            )
            update_finding_lifecycle(conn, 1, [_make_finding("cpassword", "gpo1")])
            from gpo_lens.findings import load_active_findings

            finding_id = load_active_findings(conn)[0].id

            triage_finding(conn, finding_id, "acknowledged", "", "alice")
            triage_finding(conn, finding_id, "accepted_risk", "", "bob")

            triage_map = load_finding_triage_map(conn)
            assert finding_id in triage_map
            assert triage_map[finding_id]["status"] == "accepted_risk"
            assert triage_map[finding_id]["actor"] == "bob"
        finally:
            conn.close()

    def test_invalid_status_raises(self) -> None:
        conn = _make_db()
        try:
            conn.execute(
                "INSERT INTO snapshot (id, domain, taken_at) VALUES (1, 'test', '2025-01-01')"
            )
            update_finding_lifecycle(conn, 1, [_make_finding("cpassword", "gpo1")])
            from gpo_lens.findings import load_active_findings

            finding_id = load_active_findings(conn)[0].id
            try:
                triage_finding(conn, finding_id, "invalid_status", "", "alice")
                raise AssertionError("should have raised")
            except ValueError:
                pass
        finally:
            conn.close()

    def test_triage_survives_reingest(self) -> None:
        """Triage annotations survive re-ingest of the same estate."""
        conn = _make_db()
        try:
            conn.execute(
                "INSERT INTO snapshot (id, domain, taken_at) VALUES (1, 'test', '2025-01-01')"
            )
            update_finding_lifecycle(conn, 1, [_make_finding("cpassword", "gpo1")])
            from gpo_lens.findings import load_active_findings

            finding_id = load_active_findings(conn)[0].id
            triage_finding(conn, finding_id, "acknowledged", "noted", "alice")

            conn.execute(
                "INSERT INTO snapshot (id, domain, taken_at) VALUES (2, 'test', '2025-01-02')"
            )
            update_finding_lifecycle(conn, 2, [_make_finding("cpassword", "gpo1")])

            triage_map = load_finding_triage_map(conn)
            assert finding_id in triage_map
            assert triage_map[finding_id]["status"] == "acknowledged"
        finally:
            conn.close()


class TestFindingsInboxWeb:
    @pytest.fixture(autouse=True)
    def _auth_env(self, monkeypatch):
        # monkeypatch (not bare os.environ) so the token never leaks into
        # other tests in the same worker — a leaked token defeats the
        # no-token loopback bind guard and lets cmd_serve tests really
        # start uvicorn on 0.0.0.0 (observed as a suite hang / flaky
        # TestLoopbackGuard failure under xdist).
        monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "test-secret-token")

    @pytest.fixture(autouse=True)
    def _db_dir(self, tmp_path):
        # Each test gets its own scratch DB. A shared DB under
        # tests/fixtures/ raced across xdist workers (its transient
        # -shm/-wal sidecars broke copytree-based tests) and coupled
        # tests through leftover rows.
        self._db_path = str(tmp_path / "gpo-lens-test.sqlite3")

    @property
    def _client(self):
        from fastapi.testclient import TestClient

        from gpo_lens.web.app import create_app

        db_path = self._db_path
        from gpo_lens.ingest import load_estate
        from gpo_lens.store import init_db, save_estate

        estate = load_estate(FIXTURE_DIR)
        conn = sqlite3.connect(db_path)
        try:
            init_db(conn)
            save_estate(conn, estate)
        finally:
            conn.close()

        app = create_app(db_path)
        return TestClient(app)

    def test_findings_page_renders(self) -> None:
        client = self._client
        resp = client.get(
            "/findings",
            headers={"Authorization": "Bearer test-secret-token"},
        )
        assert resp.status_code == 200
        html = resp.text
        assert "Findings inbox" in html or "Findings" in html

    def test_findings_page_has_filter_bar(self) -> None:
        client = self._client
        resp = client.get(
            "/findings",
            headers={"Authorization": "Bearer test-secret-token"},
        )
        assert resp.status_code == 200
        html = resp.text
        assert "severity" in html.lower()
        assert "triage" in html.lower()

    def _seed_finding(self) -> None:
        # Create a finding so we can triage it. Requires the DB to exist:
        # build the client (which runs init_db + save_estate) first.
        conn = sqlite3.connect(self._db_path)
        try:
            from gpo_lens.store import list_snapshots

            snaps = list_snapshots(conn)
            if snaps:
                sid = snaps[0][0]
                from gpo_lens.findings import update_finding_lifecycle

                update_finding_lifecycle(
                    conn, sid,
                    [_make_finding("test_rule", "test_gpo", "medium", "test finding")]
                )
        finally:
            conn.close()

    def test_triage_post_allowed_with_triage_permission(self) -> None:
        client = self._client
        self._seed_finding()
        # TestClient follows redirects by default, so a successful triage
        # returns 200 (the findings page) after a 303 redirect
        resp = client.post(
            "/findings/1/triage",
            data={"status": "acknowledged", "note": "test"},
            headers={
                "Authorization": "Bearer test-secret-token",
                "Origin": "http://testserver",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 303

    def _client_as(self, permissions: frozenset) -> object:
        """A client whose principal has exactly *permissions* (WI-088)."""
        from gpo_lens.web.auth import Principal, get_principal

        client = self._client
        client.app.dependency_overrides[get_principal] = lambda: Principal(
            name="test-user", role="test", permissions=permissions
        )
        return client

    def test_triage_denied_with_ingest_but_no_triage_permission(self) -> None:
        # WI-088 / Plan 024 §8: triage is its own permission — holding
        # INGEST alone must no longer authorize finding triage.
        from gpo_lens.web.auth import Permission

        client = self._client_as(frozenset({Permission.VIEW, Permission.INGEST}))
        self._seed_finding()
        resp = client.post(
            "/findings/1/triage",
            data={"status": "acknowledged", "note": "test"},
            headers={"Origin": "http://testserver"},
            follow_redirects=False,
        )
        assert resp.status_code == 403

    def test_triage_allowed_without_ingest_permission(self) -> None:
        # The converse: a triage-only principal can acknowledge a finding
        # but must not be able to upload snapshots.
        from gpo_lens.web.auth import Permission

        client = self._client_as(frozenset({Permission.VIEW, Permission.TRIAGE}))
        self._seed_finding()
        resp = client.post(
            "/findings/1/triage",
            data={"status": "acknowledged", "note": "test"},
            headers={"Origin": "http://testserver"},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        resp = client.post(
            "/ingest",
            files={"file": ("export.zip", b"not-a-zip", "application/zip")},
            headers={"Origin": "http://testserver"},
            follow_redirects=False,
        )
        assert resp.status_code == 403
