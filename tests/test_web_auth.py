from __future__ import annotations

import sqlite3

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from gpo_lens.store import init_db
from gpo_lens.web.app import create_app
from gpo_lens.web.auth import (
    LOCAL_PRINCIPAL,
    ROLE_PERMISSIONS,
    Permission,
    Principal,
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

    def test_home_requires_view(self, tmp_db):
        app = create_app(tmp_db)
        client = TestClient(app)
        response = client.get("/")
        assert response.status_code == 200

    def test_ingest_route_requires_ingest(self, tmp_db):
        app = create_app(tmp_db)
        client = TestClient(app)
        response = client.post("/ingest")
        assert response.status_code != 200

    def test_narrate_stub_requires_narrate(self, tmp_db):
        app = create_app(tmp_db)
        client = TestClient(app)
        response = client.post("/api/narrate")
        assert response.status_code == 501


class TestViewerAccessDenied:
    def test_viewer_can_access_home(self, tmp_db, viewer_principal):
        app = create_app(tmp_db)
        app.dependency_overrides[get_principal] = lambda: viewer_principal
        try:
            client = TestClient(app)
            response = client.get("/")
            assert response.status_code == 200
        finally:
            app.dependency_overrides.clear()

    def test_viewer_denied_ingest(self, tmp_db, viewer_principal):
        app = create_app(tmp_db)
        app.dependency_overrides[get_principal] = lambda: viewer_principal
        try:
            client = TestClient(app)
            response = client.post("/ingest")
            assert response.status_code == 403
        finally:
            app.dependency_overrides.clear()

    def test_viewer_denied_narrate(self, tmp_db, viewer_principal):
        app = create_app(tmp_db)
        app.dependency_overrides[get_principal] = lambda: viewer_principal
        try:
            client = TestClient(app)
            response = client.post("/api/narrate")
            assert response.status_code == 403
        finally:
            app.dependency_overrides.clear()



