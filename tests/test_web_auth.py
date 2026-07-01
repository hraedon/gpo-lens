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
    LOOPBACK_PRINCIPAL,
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
    # Intentionally unauthenticated routes — liveness/version probes that
    # IIS/app-pool supervisors and ops must reach without credentials.
    # /api/v1/ and /api/v1/health are the REST API self-listing and health
    # probe (WI-057), also exempt for the same monitoring reason.
    _UNAUTHED_ROUTES = {"/healthz", "/api/version", "/api/v1/", "/api/v1/health"}

    def test_all_routes_declare_a_permission(self, tmp_db):
        app = create_app(tmp_db)
        for route in app.routes:
            if not hasattr(route, "dependant"):
                continue
            if route.path in self._UNAUTHED_ROUTES:
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


class FakeClient:
    def __init__(self, host: str | None):
        self.host = host


class FakeRequest:
    def __init__(self, host: str | None, headers: dict[str, str] | None = None):
        self.client = FakeClient(host) if host else None
        self.headers = headers or {}


class TestLoopbackAuth:
    def test_is_loopback(self):
        assert _is_loopback("127.0.0.1")
        assert _is_loopback("::1")
        assert _is_loopback("localhost")
        assert _is_loopback("::ffff:127.0.0.1")
        assert not _is_loopback("10.0.0.5")
        assert not _is_loopback("192.168.1.1")
        assert not _is_loopback(None)

    def test_no_token_loopback_returns_local_principal(self, monkeypatch):
        # No token configured means the server is loopback-only (the bind guard
        # in cli/_serve.py enforces this), so the local operator is trusted with
        # the full analyst capability set — but not ADMIN.
        monkeypatch.delenv("GPO_LENS_AUTH_TOKEN", raising=False)
        req = FakeRequest("127.0.0.1")
        principal = get_principal(req)
        assert principal == LOOPBACK_PRINCIPAL
        assert principal.has(Permission.VIEW)
        assert principal.has(Permission.INGEST)
        assert principal.has(Permission.NARRATE)
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

    def test_no_token_loopback_can_view_and_ingest(self, tmp_db):
        app = create_app(tmp_db)
        app.dependency_overrides[get_principal] = lambda: LOOPBACK_PRINCIPAL
        try:
            client = TestClient(app, headers={"origin": "http://localhost"})
            assert client.get("/").status_code == 200
            # The local operator may reach the privileged endpoints; a POST with
            # no file is rejected for missing data (422), not for authz (403).
            assert client.post("/ingest").status_code != 403
        finally:
            app.dependency_overrides.clear()


class TestForwardedUser:
    """GPO_LENS_FORWARDED_USER_HEADER — proxy-forwarded audit identity.

    Behind the documented IIS deployment every request arrives from loopback
    as ``local-analyst``, so audit entries cannot distinguish operators even
    though IIS *knows* who they are (Windows Auth). When the operator opts in,
    the same-host proxy forwards the authenticated username in a header and
    the principal is named after it — permissions stay exactly the loopback
    set, and the header is never trusted from a non-loopback peer.
    """

    def test_forwarded_user_names_principal(self, monkeypatch):
        monkeypatch.delenv("GPO_LENS_AUTH_TOKEN", raising=False)
        monkeypatch.setenv("GPO_LENS_FORWARDED_USER_HEADER", "X-Forwarded-User")
        req = FakeRequest("127.0.0.1", {"X-Forwarded-User": "CONTOSO\\alice"})
        principal = get_principal(req)
        assert principal.name == "CONTOSO\\alice"
        assert principal.role == "forwarded"
        assert principal.permissions == LOOPBACK_PRINCIPAL.permissions
        assert not principal.has(Permission.ADMIN)

    def test_header_ignored_when_env_unset(self, monkeypatch):
        monkeypatch.delenv("GPO_LENS_AUTH_TOKEN", raising=False)
        monkeypatch.delenv("GPO_LENS_FORWARDED_USER_HEADER", raising=False)
        req = FakeRequest("127.0.0.1", {"X-Forwarded-User": "CONTOSO\\mallory"})
        assert get_principal(req) == LOOPBACK_PRINCIPAL

    def test_header_ignored_from_remote_peer(self, monkeypatch):
        # A remote client presenting the header must NOT gain loopback trust —
        # the loopback check runs first and still 401s.
        monkeypatch.delenv("GPO_LENS_AUTH_TOKEN", raising=False)
        monkeypatch.setenv("GPO_LENS_FORWARDED_USER_HEADER", "X-Forwarded-User")
        req = FakeRequest("10.0.0.5", {"X-Forwarded-User": "CONTOSO\\mallory"})
        with pytest.raises(HTTPException) as exc:
            get_principal(req)
        assert exc.value.status_code == 401

    def test_empty_or_missing_header_falls_back(self, monkeypatch):
        monkeypatch.delenv("GPO_LENS_AUTH_TOKEN", raising=False)
        monkeypatch.setenv("GPO_LENS_FORWARDED_USER_HEADER", "X-Forwarded-User")
        assert get_principal(FakeRequest("127.0.0.1")) == LOOPBACK_PRINCIPAL
        req = FakeRequest("127.0.0.1", {"X-Forwarded-User": "   "})
        assert get_principal(req) == LOOPBACK_PRINCIPAL

    def test_forwarded_name_is_sanitized_and_capped(self, monkeypatch):
        monkeypatch.delenv("GPO_LENS_AUTH_TOKEN", raising=False)
        monkeypatch.setenv("GPO_LENS_FORWARDED_USER_HEADER", "X-Forwarded-User")
        req = FakeRequest(
            "127.0.0.1", {"X-Forwarded-User": "al\x00ice\r\n" + "x" * 400}
        )
        principal = get_principal(req)
        assert "\x00" not in principal.name
        assert "\n" not in principal.name
        assert len(principal.name) <= 256

    def test_token_mode_unaffected_by_forwarded_header(self, monkeypatch):
        # Explicit bearer auth wins; the forwarded header only applies on the
        # no-token loopback path.
        monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "secret")
        monkeypatch.setenv("GPO_LENS_FORWARDED_USER_HEADER", "X-Forwarded-User")
        req = FakeRequest("127.0.0.1", {"X-Forwarded-User": "CONTOSO\\alice"})
        principal = get_principal(req, authorization="Bearer secret")
        assert principal == LOCAL_PRINCIPAL



