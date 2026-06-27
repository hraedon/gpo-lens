"""Web route tests for /delegation."""
from __future__ import annotations

import sqlite3

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from gpo_lens.web.app import create_app


@pytest.fixture
def empty_db(tmp_path):
    db = tmp_path / "test.db"
    conn = sqlite3.connect(str(db))
    from gpo_lens.store import init_db
    init_db(conn)
    conn.close()
    return str(db)


@pytest.fixture
def blank_file_db(tmp_path):
    db = tmp_path / "blank.db"
    db.touch()
    return str(db)


@pytest.fixture
def populated_db(tmp_path):
    from gpo_lens.model import DelegationEntry, Estate, Gpo
    from gpo_lens.store import init_db, save_estate

    db = tmp_path / "populated.db"
    conn = sqlite3.connect(str(db))
    init_db(conn)

    from gpo_lens.model import ResolvedPrincipal

    writer_sid = "S-1-5-21-100-200-300-5555"
    writer_sid_lower = writer_sid.lower()
    principals = {
        writer_sid_lower: ResolvedPrincipal(
            sid=writer_sid_lower, name="TEST\\Helpdesk", sam="Helpdesk",
            principal_type="Group", domain="TEST", resolved=True,
        ),
    }
    gpo = Gpo(
        id="11111111-1111-1111-1111-111111111111",
        name="gpo-writer",
        domain="test.local",
        created=None, modified=None, read=None,
        computer_enabled=True, user_enabled=True,
        computer_ver_ds=None, computer_ver_sysvol=None,
        user_ver_ds=None, user_ver_sysvol=None,
        sddl=f"O:BAG:BAD:(A;;GA;;;{writer_sid})",
        owner=None, filter_data_available=False,
        wmi_filter=None, sysvol_path=None,
        settings=[],
        delegation=[
            DelegationEntry(
                gpo_id="11111111-1111-1111-1111-111111111111",
                trustee="Helpdesk",
                trustee_sid=writer_sid,
                permission="Write",
                allowed=True,
            ),
            DelegationEntry(
                gpo_id="11111111-1111-1111-1111-111111111111",
                trustee="Authenticated Users",
                trustee_sid="S-1-5-11",
                permission="Read",
                allowed=True,
            ),
        ],
    )
    estate = Estate(domain="test.local", gpos=[gpo], principals=principals)
    save_estate(conn, estate)
    conn.close()
    return str(db)


@pytest.fixture
def auth_token(monkeypatch):
    monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "test-secret-token")
    return "test-secret-token"


class TestDelegationRoute:
    def _client(self, db_path: str, token: str):
        app = create_app(db_path)
        return TestClient(
            app,
            headers={
                "origin": "http://localhost",
                "Authorization": f"Bearer {token}",
            },
        )

    def test_empty_db_returns_200(self, empty_db, auth_token):
        client = self._client(empty_db, auth_token)
        response = client.get("/delegation")
        assert response.status_code == 200
        text = response.text
        assert "Delegation Rollup" in text or "delegation" in text.lower()
        assert "0" in text

    def test_uninitialized_db_returns_200(self, blank_file_db, auth_token):
        client = self._client(blank_file_db, auth_token)
        response = client.get("/delegation")
        assert response.status_code == 200
        text = response.text
        assert "Delegation Rollup" in text or "delegation" in text.lower()

    def test_populated_db_returns_200_with_data(self, populated_db, auth_token):
        client = self._client(populated_db, auth_token)
        response = client.get("/delegation")
        assert response.status_code == 200
        text = response.text
        assert "Helpdesk" in text
        assert "gpo-writer" in text
        assert "1" in text
