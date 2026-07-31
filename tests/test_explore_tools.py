"""Web route tests for /explore and /tools (Plan 025 WI-3).

The directory pages organize existing destinations without removing routes.
The registry in ``gpo_lens.web.routes.explore`` resolves every entry through
``app.url_path_for`` at request time, so these tests are what turn a renamed
route into a loud failure instead of a dead link.
"""
from __future__ import annotations

import sqlite3

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from gpo_lens.web.app import create_app
from gpo_lens.web.routes.explore import EXPLORE_SECTIONS, TOOLS_SECTIONS


@pytest.fixture
def empty_db(tmp_path):
    db = tmp_path / "test.db"
    conn = sqlite3.connect(str(db))
    from gpo_lens.store import init_db
    init_db(conn)
    conn.close()
    return str(db)


@pytest.fixture
def auth_token(monkeypatch):
    monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "test-secret-token")
    return "test-secret-token"


def _client(db: str, token: str) -> TestClient:
    return TestClient(
        create_app(db),
        headers={"Authorization": f"Bearer {token}"},
    )


class TestDirectoryPages:
    def test_explore_renders(self, empty_db, auth_token):
        r = _client(empty_db, auth_token).get("/explore")
        assert r.status_code == 200
        assert "Explore" in r.text
        assert "Why is this setting what it is here?" in r.text

    def test_tools_renders(self, empty_db, auth_token):
        r = _client(empty_db, auth_token).get("/tools")
        assert r.status_code == 200
        assert "Tools" in r.text
        assert "What specialist operation do I need?" in r.text

    @pytest.mark.parametrize(
        ("path", "sections"),
        [("/explore", EXPLORE_SECTIONS), ("/tools", TOOLS_SECTIONS)],
    )
    def test_every_destination_resolves_and_is_linked(
        self, empty_db, auth_token, path, sections
    ):
        """No dead links: each registry entry resolves and appears as an href."""
        client = _client(empty_db, auth_token)
        app = client.app
        page = client.get(path).text
        for section in sections:
            assert section.title in page
            for dest in section.destinations:
                href = app.url_path_for(dest.route_name)  # raises if renamed
                assert f'href="{href}"' in page, (
                    f"{path} does not link {dest.route_name} ({href})"
                )
                assert dest.title in page

    def test_registry_routes_are_distinct(self):
        """The two pages organize different surfaces; overlap is a smell."""
        explore = {
            d.route_name for s in EXPLORE_SECTIONS for d in s.destinations
        }
        tools = {d.route_name for s in TOOLS_SECTIONS for d in s.destinations}
        assert not explore & tools

    @pytest.mark.parametrize("path", ["/explore", "/tools"])
    def test_requires_auth(self, empty_db, monkeypatch, path):
        monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "test-secret-token")
        client = TestClient(create_app(empty_db))
        assert client.get(path).status_code != 200

    @pytest.mark.parametrize("path", ["/explore", "/tools"])
    def test_renders_without_any_snapshot(self, empty_db, auth_token, path):
        """Directory pages read nothing from the estate — an empty database
        (no snapshot ever ingested) must render identically."""
        r = _client(empty_db, auth_token).get(path)
        assert r.status_code == 200
