"""Web route tests for /golden-diff (WI-075)."""
from __future__ import annotations

import io
import sqlite3
import zipfile
from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from gpo_lens.web.app import create_app

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"


def _make_golden_zip() -> bytes:
    gpreport = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        "<GPO>\n"
        "  <Identifier>\n"
        "    <Identifier>{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}</Identifier>\n"
        "    <Domain>golden.local</Domain>\n"
        "  </Identifier>\n"
        "  <Name>Test Policy</Name>\n"
        "  <CreatedTime>2024-01-01T00:00:00</CreatedTime>\n"
        "  <ModifiedTime>2024-01-01T00:00:00</ModifiedTime>\n"
        "  <ReadTime>2024-01-01T00:00:00</ReadTime>\n"
        "  <Computer>\n"
        "    <Enabled>true</Enabled>\n"
        "    <VersionDirectory>1</VersionDirectory>\n"
        "    <VersionSysvol>1</VersionSysvol>\n"
        "    <ExtensionData>\n"
        "      <Name>Registry</Name>\n"
        "      <Extension>\n"
        '        <Registry KeyName="HKLM\\Software\\Test" ValueName="Setting">1</Registry>\n'
        "      </Extension>\n"
        "    </ExtensionData>\n"
        "  </Computer>\n"
        "  <User>\n"
        "    <Enabled>true</Enabled>\n"
        "    <VersionDirectory>1</VersionDirectory>\n"
        "    <VersionSysvol>1</VersionSysvol>\n"
        "  </User>\n"
        "  <FilterDataAvailable>false</FilterDataAvailable>\n"
        "</GPO>\n"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "GPOs/{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}/gpreport.xml",
            gpreport,
        )
    return buf.getvalue()


@pytest.fixture
def fixture_db(tmp_path):
    from gpo_lens.ingest import load_estate as ingest_load_estate
    from gpo_lens.store import init_db, save_estate

    db = tmp_path / "golden_test.db"
    conn = sqlite3.connect(str(db))
    init_db(conn)
    estate = ingest_load_estate(FIXTURE_DIR)
    save_estate(conn, estate)
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


class TestGoldenDiffRoute:
    def test_get_returns_200_with_form(self, client) -> None:
        resp = client.get("/golden-diff")
        assert resp.status_code == 200
        assert "Golden Backup" in resp.text
        assert "drop" in resp.text.lower() or "browse" in resp.text.lower()

    def test_post_valid_zip_shows_summary(self, client) -> None:
        data = _make_golden_zip()
        resp = client.post(
            "/golden-diff",
            files={"file": ("golden.zip", data, "application/zip")},
        )
        assert resp.status_code == 200
        assert "Summary" in resp.text
        assert "GPOs matched" in resp.text or "gpos_matched" in resp.text

    def test_post_invalid_zip_shows_error(self, client) -> None:
        resp = client.post(
            "/golden-diff",
            files={"file": ("bad.zip", b"not a zip", "application/zip")},
        )
        assert resp.status_code == 200
        assert "Invalid golden zip" in resp.text

    def test_upload_exceeds_size_limit_returns_413(self, client) -> None:
        from unittest.mock import patch

        with patch("gpo_lens.web.app._MAX_UPLOAD_BYTES", 100):
            resp = client.post(
                "/golden-diff",
                files={"file": ("big.zip", b"x" * 200, "application/zip")},
            )
        assert resp.status_code == 413
        assert "Upload exceeds" in resp.text

    def test_get_on_empty_db_returns_200(self, tmp_path, monkeypatch) -> None:
        db = tmp_path / "empty.db"
        conn = sqlite3.connect(str(db))
        from gpo_lens.store import init_db

        init_db(conn)
        conn.close()
        monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "test-secret-token")
        app = create_app(str(db))
        c = TestClient(
            app,
            headers={
                "origin": "http://localhost",
                "Authorization": "Bearer test-secret-token",
            },
        )
        resp = c.get("/golden-diff")
        assert resp.status_code == 200
        assert "Golden Backup" in resp.text
