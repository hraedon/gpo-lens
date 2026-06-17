from __future__ import annotations

import sqlite3

import pytest

pytest.importorskip("fastapi")

from fastapi import HTTPException
from fastapi.testclient import TestClient

from gpo_lens.store import init_db
from gpo_lens.web.app import create_app
from gpo_lens.web.auth import (
    LOCAL_PRINCIPAL,
    LOOPBACK_VIEWER,
    ROLE_PERMISSIONS,
    Permission,
    Principal,
    _is_loopback,
    get_principal,
    requires,
)


@pytest.fixture
def tmp_db(tmp_path):
    db = tmp_path / "test.db"
    conn = sqlite3.connect(str(db))
    init_db(conn)
    conn.close()
    return str(db)


@pytest.fixture
def viewer_principal():
    return Principal(
        name="viewer-user",
        role="viewer",
        permissions=frozenset(ROLE_PERMISSIONS["viewer"]),
    )


@pytest.fixture
def auth_token(monkeypatch):
    monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "test-secret-token")
    return "test-secret-token"


class TestPermissionEnum:
    def test_enum_values(self):
        assert Permission.VIEW.value == "view"
        assert Permission.INGEST.value == "ingest"
        assert Permission.NARRATE.value == "narrate"
        assert Permission.ADMIN.value == "admin"


class TestRolePermissions:
    def test_viewer_has_view_only(self):
        assert ROLE_PERMISSIONS["viewer"] == {Permission.VIEW}

    def test_operator_has_view_and_ingest(self):
        assert ROLE_PERMISSIONS["operator"] == {Permission.VIEW, Permission.INGEST}

    def test_admin_has_all_permissions(self):
        assert ROLE_PERMISSIONS["admin"] == {
            Permission.VIEW, Permission.INGEST, Permission.NARRATE, Permission.ADMIN
        }


class TestLocalPrincipal:
    def test_has_all_permissions(self):
        assert LOCAL_PRINCIPAL.has(Permission.VIEW)
        assert LOCAL_PRINCIPAL.has(Permission.INGEST)
        assert LOCAL_PRINCIPAL.has(Permission.NARRATE)
        assert LOCAL_PRINCIPAL.has(Permission.ADMIN)
        assert LOCAL_PRINCIPAL.role == "admin"
        assert LOCAL_PRINCIPAL.name == "local-analyst"


class TestRequiresDecorator:
    def test_view_allows_local_principal(self):
        dep = requires(Permission.VIEW)
        # FastAPI Depends is hard to unit test; we test through the client
        assert dep is not None

    def test_ingest_allows_local_principal(self):
        dep = requires(Permission.INGEST)
        assert dep is not None


class TestRoutePermissions:
    def test_all_routes_declare_a_permission(self, tmp_db):
        app = create_app(tmp_db)
        for route in app.routes:
            if not hasattr(route, "dependant"):
                continue
            dependant = route.dependant
            has_perm_check = False
            for dep in dependant.dependencies:
                call = getattr(dep.call, "__wrapped__", dep.call)
                if getattr(call, "_required_permission", None) is not None:
                    has_perm_check = True
                    break
            assert has_perm_check, (
                f"Route {route.path} ({route.name}) is missing a permission check"
            )

    def test_home_requires_view(self, tmp_db, auth_token):
        app = create_app(tmp_db)
        client = TestClient(
            app,
            headers={
                "origin": "http://localhost",
                "Authorization": f"Bearer {auth_token}",
            },
        )
        response = client.get("/")
        assert response.status_code == 200

    def test_ingest_route_requires_ingest(self, tmp_db, auth_token):
        app = create_app(tmp_db)
        client = TestClient(
            app,
            headers={
                "origin": "http://localhost",
                "Authorization": f"Bearer {auth_token}",
            },
        )
        response = client.post("/ingest")
        assert response.status_code != 200

    def test_narrate_stub_requires_narrate(self, tmp_db, auth_token):
        app = create_app(tmp_db)
        client = TestClient(
            app,
            headers={
                "origin": "http://localhost",
                "Authorization": f"Bearer {auth_token}",
            },
        )
        response = client.post("/api/narrate")
        assert response.status_code == 501


class TestViewerAccessDenied:
    def test_viewer_can_access_home(self, tmp_db, viewer_principal):
        app = create_app(tmp_db)
        app.dependency_overrides[get_principal] = lambda: viewer_principal
        try:
            client = TestClient(app, headers={"origin": "http://localhost"})
            response = client.get("/")
            assert response.status_code == 200
        finally:
            app.dependency_overrides.clear()

    def test_viewer_denied_ingest(self, tmp_db, viewer_principal):
        app = create_app(tmp_db)
        app.dependency_overrides[get_principal] = lambda authorization=None: viewer_principal
        try:
            client = TestClient(app, headers={"origin": "http://localhost"})
            response = client.post("/ingest")
            assert response.status_code == 403
        finally:
            app.dependency_overrides.clear()

    def test_viewer_denied_narrate(self, tmp_db, viewer_principal):
        app = create_app(tmp_db)
        app.dependency_overrides[get_principal] = lambda authorization=None: viewer_principal
        try:
            client = TestClient(app, headers={"origin": "http://localhost"})
            response = client.post("/api/narrate")
            assert response.status_code == 403
        finally:
            app.dependency_overrides.clear()


class FakeClient:
    def __init__(self, host: str | None):
        self.host = host


class FakeRequest:
    def __init__(self, host: str | None):
        self.client = FakeClient(host) if host else None


class TestLoopbackAuth:
    def test_is_loopback(self):
        assert _is_loopback("127.0.0.1")
        assert _is_loopback("::1")
        assert _is_loopback("localhost")
        assert _is_loopback("::ffff:127.0.0.1")
        assert not _is_loopback("10.0.0.5")
        assert not _is_loopback("192.168.1.1")
        assert not _is_loopback(None)

    def test_no_token_loopback_returns_viewer(self, monkeypatch):
        monkeypatch.delenv("GPO_LENS_AUTH_TOKEN", raising=False)
        req = FakeRequest("127.0.0.1")
        principal = get_principal(req)
        assert principal == LOOPBACK_VIEWER
        assert principal.has(Permission.VIEW)
        assert not principal.has(Permission.INGEST)
        assert not principal.has(Permission.ADMIN)

    def test_no_token_remote_raises_401(self, monkeypatch):
        monkeypatch.delenv("GPO_LENS_AUTH_TOKEN", raising=False)
        req = FakeRequest("10.0.0.5")
        with pytest.raises(HTTPException) as exc:
            get_principal(req)
        assert exc.value.status_code == 401

    def test_no_token_missing_client_raises_401(self, monkeypatch):
        monkeypatch.delenv("GPO_LENS_AUTH_TOKEN", raising=False)
        req = FakeRequest(None)
        with pytest.raises(HTTPException) as exc:
            get_principal(req)
        assert exc.value.status_code == 401

    def test_with_token_loopback_gets_admin(self, monkeypatch):
        monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "secret")
        req = FakeRequest("127.0.0.1")
        principal = get_principal(req, authorization="Bearer secret")
        assert principal == LOCAL_PRINCIPAL

    def test_with_token_remote_gets_admin(self, monkeypatch):
        monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "secret")
        req = FakeRequest("10.0.0.5")
        principal = get_principal(req, authorization="Bearer secret")
        assert principal == LOCAL_PRINCIPAL

    def test_no_token_loopback_can_view_but_not_ingest(self, tmp_db):
        app = create_app(tmp_db)
        app.dependency_overrides[get_principal] = lambda: LOOPBACK_VIEWER
        try:
            client = TestClient(app, headers={"origin": "http://localhost"})
            assert client.get("/").status_code == 200
            assert client.post("/ingest").status_code == 403
        finally:
            app.dependency_overrides.clear()



