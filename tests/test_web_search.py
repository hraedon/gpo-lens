"""Web route tests for /search (WI-082 — estate-wide settings search)."""
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


def _gpo(gpo_id: str, name: str, settings):
    from gpo_lens.model import Gpo
    return Gpo(
        id=gpo_id, name=name, domain="test.local",
        created=None, modified=None, read=None,
        computer_enabled=True, user_enabled=True,
        computer_ver_ds=None, computer_ver_sysvol=None,
        user_ver_ds=None, user_ver_sysvol=None,
        sddl=None, owner=None, filter_data_available=False,
        wmi_filter=None, sysvol_path=None,
        settings=settings, delegation=[],
    )


def _setting(gpo_id, side, cse, identity, name, value):
    from gpo_lens.model import Setting
    return Setting(
        gpo_id=gpo_id, side=side, cse=cse, identity=identity,
        display_name=name, display_value=value, raw={},
        from_disabled_side=False,
    )


@pytest.fixture
def populated_db(tmp_path):
    from gpo_lens.model import Estate
    from gpo_lens.store import init_db, save_estate

    db = tmp_path / "populated.db"
    conn = sqlite3.connect(str(db))
    init_db(conn)

    g1 = "11111111-1111-1111-1111-111111111111"
    g2 = "22222222-2222-2222-2222-222222222222"
    gpos = [
        _gpo(g1, "gpo-kerberos", [
            _setting(g1, "Computer", "Security",
                     r"HKLM\System\MaxTokenSize", "MaxTokenSize", "48000"),
            _setting(g1, "Computer", "Registry",
                     r"HKLM\Software\Foo", "Foo policy", "1"),
        ]),
        _gpo(g2, "gpo-tokens", [
            _setting(g2, "User", "Registry",
                     r"HKCU\Software\MaxTokenSize", "MaxTokenSize", "65535"),
        ]),
    ]
    estate = Estate(domain="test.local", gpos=gpos, principals={})
    save_estate(conn, estate)
    conn.close()
    return str(db)


@pytest.fixture
def auth_token(monkeypatch):
    monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "test-secret-token")
    return "test-secret-token"


class TestSearchRoute:
    def _client(self, db_path: str, token: str):
        app = create_app(db_path)
        return TestClient(
            app,
            headers={
                "origin": "http://localhost",
                "Authorization": f"Bearer {token}",
            },
        )

    def test_empty_query_shows_prompt_not_results(self, populated_db, auth_token):
        client = self._client(populated_db, auth_token)
        r = client.get("/search")
        assert r.status_code == 200
        # no q -> prompt, and no GPO rows dumped
        assert "find every GPO that sets it" in r.text
        assert "gpo-kerberos" not in r.text

    def test_query_finds_both_gpos_grouped(self, populated_db, auth_token):
        client = self._client(populated_db, auth_token)
        r = client.get("/search", params={"q": "MaxTokenSize"})
        assert r.status_code == 200
        assert "gpo-kerberos" in r.text
        assert "gpo-tokens" in r.text
        # both GPOs set MaxTokenSize -> 2 GPOs in the summary
        assert "2" in r.text

    def test_cse_facet_narrows_results(self, populated_db, auth_token):
        client = self._client(populated_db, auth_token)
        r = client.get("/search", params={"q": "MaxTokenSize", "cse": "Security"})
        assert r.status_code == 200
        assert "gpo-kerberos" in r.text   # Security CSE hit
        assert "gpo-tokens" not in r.text  # Registry CSE filtered out

    def test_no_match_shows_empty_state(self, populated_db, auth_token):
        client = self._client(populated_db, auth_token)
        r = client.get("/search", params={"q": "zzz-no-such-setting"})
        assert r.status_code == 200
        assert "No settings match" in r.text
        assert "gpo-kerberos" not in r.text

    def test_empty_db_returns_200(self, empty_db, auth_token):
        client = self._client(empty_db, auth_token)
        r = client.get("/search", params={"q": "anything"})
        assert r.status_code == 200

    def test_uninitialized_db_returns_200(self, blank_file_db, auth_token):
        client = self._client(blank_file_db, auth_token)
        r = client.get("/search", params={"q": "anything"})
        assert r.status_code == 200

    def test_search_in_nav(self, populated_db, auth_token):
        client = self._client(populated_db, auth_token)
        r = client.get("/")
        assert r.status_code == 200
        assert "/search" in r.text
