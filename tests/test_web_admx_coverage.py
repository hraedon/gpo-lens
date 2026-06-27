"""Web route tests for /admx-coverage (WI-075)."""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from gpo_lens.web.app import create_app

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture
def fixture_db(tmp_path):
    from gpo_lens.ingest import load_estate as ingest_load_estate
    from gpo_lens.store import init_db, save_estate

    db = tmp_path / "admx_test.db"
    conn = sqlite3.connect(str(db))
    init_db(conn)
    estate = ingest_load_estate(FIXTURE_DIR)
    save_estate(conn, estate)
    conn.close()
    return str(db)


@pytest.fixture
def empty_db(tmp_path):
    db = tmp_path / "empty.db"
    conn = sqlite3.connect(str(db))
    from gpo_lens.store import init_db

    init_db(conn)
    conn.close()
    return str(db)


@pytest.fixture
def client(fixture_db, monkeypatch):
    monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "test-secret-token")
    app = create_app(fixture_db)
    return TestClient(
        app,
        headers={
            "origin": "http://localhost",
            "Authorization": "Bearer test-secret-token",
        },
    )


@pytest.fixture
def empty_client(empty_db, monkeypatch):
    monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "test-secret-token")
    app = create_app(empty_db)
    return TestClient(
        app,
        headers={
            "origin": "http://localhost",
            "Authorization": "Bearer test-secret-token",
        },
    )


class TestAdmxCoverageRoute:
    def test_get_returns_200_with_report(self, client) -> None:
        resp = client.get("/admx-coverage")
        assert resp.status_code == 200
        assert "ADMX Coverage" in resp.text
        assert "total policies" in resp.text.lower() or "total_policies" in resp.text

    def test_get_on_empty_db_returns_200(self, empty_client) -> None:
        resp = empty_client.get("/admx-coverage")
        assert resp.status_code == 200
        assert "ADMX Coverage" in resp.text
        assert "0" in resp.text

    def test_get_on_blank_file_db_returns_200(self, tmp_path, monkeypatch) -> None:
        db = tmp_path / "blank.db"
        db.touch()
        monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "test-secret-token")
        app = create_app(str(db))
        c = TestClient(
            app,
            headers={
                "origin": "http://localhost",
                "Authorization": "Bearer test-secret-token",
            },
        )
        resp = c.get("/admx-coverage")
        assert resp.status_code == 200
        assert "ADMX Coverage" in resp.text

    def test_report_shows_gap_section(self, client) -> None:
        resp = client.get("/admx-coverage")
        assert resp.status_code == 200
        assert "Gaps" in resp.text or "gaps" in resp.text.lower()
