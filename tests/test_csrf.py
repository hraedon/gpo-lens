"""Comprehensive direct tests for the CSRF origin/referer validation middleware.

WI-005: The CSRF middleware was hardened but lacked dedicated test coverage.
This file documents and verifies the exact behavior of the middleware.

CSRF Middleware Logic (app.py::_csrf_check):
  Only POST requests are checked. For POSTs:
    1. Origin present, NOT localhost   → 403 (blocked)
    2. No Origin, Referer NOT localhost → 403 (blocked)
    3. No Origin AND no Referer         → 403 (blocked)
    4. Otherwise                        → pass through

  Pass-through cases:
    - Origin present AND is localhost (Referer is ignored)
    - No Origin, Referer present AND is localhost
    - Non-POST methods (GET, HEAD, etc.)

  localhost = hostname in ("localhost", "127.0.0.1", "::1",
                           "0.0.0.0", "localhost.localdomain")

Threat model: The web UI is designed for loopback-only deployment.
If someone accidentally binds non-loopback, the CSRF check prevents
cross-origin POSTs from external sites. The "no Origin, no Referer"
rejection (case 3) means API-style tools (curl, etc.) must send
an Origin or Referer header.

NOTE: The earlier reflection (2026-06-12-mimo-v2.5-pro.md) stated
"POST requests with no Origin AND no Referer pass through" — this
described an earlier version. The current code rejects such requests.
"""

from __future__ import annotations

import sqlite3

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from gpo_lens.store import init_db
from gpo_lens.web.app import create_app
from gpo_lens.web.auth import Permission, Principal, get_principal


@pytest.fixture()
def csrf_db(tmp_path):
    """Create a temporary database for CSRF testing."""
    db = tmp_path / "csrf_test.db"
    conn = sqlite3.connect(str(db))
    init_db(conn)
    conn.close()
    return str(db)


@pytest.fixture()
def csrf_client(csrf_db: str):
    """TestClient with admin principal override and NO default headers.

    By default, TestClient sends no Origin or Referer, which lets
    each test control the exact headers sent.
    """
    admin = Principal(
        name="csrf-test-admin",
        role="admin",
        permissions=frozenset([Permission.VIEW, Permission.INGEST, Permission.NARRATE]),
    )
    app = create_app(csrf_db)
    app.dependency_overrides[get_principal] = lambda authorization=None: admin
    yield TestClient(app)
    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# 1. GET requests are not CSRF-checked
# ---------------------------------------------------------------------------


class TestCsrfGetRequests:
    """GET requests bypass CSRF checks entirely — they are safe (no side effects)."""

    def test_get_home_no_origin(self, csrf_client) -> None:
        resp = csrf_client.get("/")
        assert resp.status_code == 200

    def test_get_home_external_origin(self, csrf_client) -> None:
        """Even a suspicious external Origin doesn't block GETs."""
        resp = csrf_client.get("/", headers={"origin": "https://evil.com"})
        assert resp.status_code == 200

    def test_get_home_no_referer(self, csrf_client) -> None:
        resp = csrf_client.get("/")
        assert resp.status_code == 200

    def test_get_ask_page(self, csrf_client) -> None:
        resp = csrf_client.get("/ask")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# 2. POST with matching (localhost) Origin passes
# ---------------------------------------------------------------------------


class TestCsrfMatchingOrigin:
    """POST requests with a localhost Origin header are allowed."""

    @pytest.mark.parametrize("origin", [
        "http://localhost",
        "http://localhost:8000",
        "http://127.0.0.1",
        "http://127.0.0.1:8080",
        "http://[::1]",
        "http://[::1]:8000",
        "http://0.0.0.0",
        "http://localhost.localdomain",
    ])
    def test_post_with_localhost_origin_passes(self, csrf_client, origin: str) -> None:
        resp = csrf_client.post("/api/narrate", headers={"origin": origin})
        # Should NOT be 403 (CSRF blocked). The /api/narrate endpoint
        # returns 501 (not implemented), not 403.
        assert resp.status_code != 403

    def test_post_with_localhost_origin_ignores_evil_referer(self, csrf_client) -> None:
        """When Origin is localhost, Referer is not checked."""
        resp = csrf_client.post(
            "/api/narrate",
            headers={
                "origin": "http://localhost",
                "referer": "https://evil.com/attack",
            },
        )
        assert resp.status_code != 403


# ---------------------------------------------------------------------------
# 3. POST with mismatched (external) Origin is rejected
# ---------------------------------------------------------------------------


class TestCsrfMismatchedOrigin:
    """POST requests with a non-localhost Origin are blocked (403)."""

    @pytest.mark.parametrize("origin", [
        "https://evil.com",
        "http://evil.com",
        "https://attacker.example.com",
        "http://192.168.1.1",
        "http://10.0.0.1",
        "http://localhost.evil.com",  # hostname is NOT "localhost"
    ])
    def test_post_with_external_origin_rejected(self, csrf_client, origin: str) -> None:
        resp = csrf_client.post("/api/narrate", headers={"origin": origin})
        assert resp.status_code == 403
        assert "CSRF" in resp.json()["detail"]

    def test_spoofed_external_origin_to_localhost_server(self, csrf_client) -> None:
        """An attacker sends a cross-origin POST with their own Origin.

        This is the core CSRF attack: the attacker's site triggers a POST
        to the localhost-bound gpo-lens server. The browser sends the
        attacker's Origin, which is not localhost, so it's rejected.
        """
        resp = csrf_client.post(
            "/api/narrate",
            headers={
                "origin": "https://attacker.com",
                "referer": "https://attacker.com/evil-page",
            },
        )
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# 4. POST with matching (localhost) Referer and no Origin passes
# ---------------------------------------------------------------------------


class TestCsrfMatchingReferer:
    """When no Origin header is present, Referer is checked as fallback."""

    @pytest.mark.parametrize("referer", [
        "http://localhost:8000/ask",
        "http://localhost/ingest",
        "http://127.0.0.1:8000/ask",
        "http://[::1]:8000/ask",
        "http://0.0.0.0:8000/",
        "http://localhost.localdomain:8000/ask",
    ])
    def test_post_with_localhost_referer_no_origin_passes(
        self, csrf_client, referer: str
    ) -> None:
        resp = csrf_client.post("/api/narrate", headers={"referer": referer})
        assert resp.status_code != 403


# ---------------------------------------------------------------------------
# 5. POST with mismatched (external) Referer and no Origin is rejected
# ---------------------------------------------------------------------------


class TestCsrfMismatchedReferer:
    """When no Origin is present and Referer is non-localhost, blocked."""

    @pytest.mark.parametrize("referer", [
        "https://evil.com/page",
        "http://evil.com/attack",
        "https://attacker.example.com/csrf",
        "http://localhost.evil.com/page",  # hostname is NOT "localhost"
    ])
    def test_post_with_external_referer_no_origin_rejected(
        self, csrf_client, referer: str
    ) -> None:
        resp = csrf_client.post("/api/narrate", headers={"referer": referer})
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# 6. POST with neither Origin nor Referer is rejected
# ---------------------------------------------------------------------------


class TestCsrfNoOriginNoReferer:
    """POST requests with neither Origin nor Referer are rejected.

    Current behavior: 403 CSRF validation failed.

    Rationale: In normal browser usage, same-origin POSTs always send
    either Origin or Referer. Absence of both suggests a non-browser
    client or a stripped-header redirect — either way, rejecting is
    the safe default.

    Threat model note: For loopback-only deployment, this is acceptable
    because legitimate browser requests will always include one of these
    headers. API-style tools (curl, scripts) must add an Origin or
    Referer header explicitly.

    If a future use case requires headerless POSTs, consider adding
    a CSRF token mechanism instead of relaxing this check.
    """

    def test_post_with_no_origin_no_referer_returns_403(self, csrf_client) -> None:
        resp = csrf_client.post("/api/narrate")
        assert resp.status_code == 403

    def test_csrf_blocks_ingest_without_headers(self, csrf_client) -> None:
        resp = csrf_client.post("/ingest")
        assert resp.status_code == 403

    def test_csrf_blocks_ask_without_headers(self, csrf_client) -> None:
        resp = csrf_client.post("/ask", data={"question": "test"})
        assert resp.status_code == 403

    def test_csrf_blocks_baseline_without_headers(self, csrf_client) -> None:
        resp = csrf_client.post("/baseline")
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# 7. POST with spoofed external Origin to localhost-bound server is rejected
# ---------------------------------------------------------------------------


class TestCsrfSpoofedExternalOrigin:
    """Cross-origin POST from an attacker's site to the localhost server.

    This is the primary CSRF threat: the victim's browser sends a POST
    to gpo-lens (bound to localhost) from a malicious page. The browser
    automatically includes the attacker's Origin header, which the
    middleware correctly rejects.
    """

    def test_cross_origin_ingest_blocked(self, csrf_client) -> None:
        """Attacker tries to trigger a GPO ingest via CSRF."""
        resp = csrf_client.post(
            "/ingest",
            headers={"origin": "https://evil.com"},
        )
        assert resp.status_code == 403

    def test_cross_origin_ask_blocked(self, csrf_client) -> None:
        """Attacker tries to submit a question via CSRF."""
        resp = csrf_client.post(
            "/ask",
            headers={"origin": "https://evil.com"},
            data={"question": "exfiltrate data"},
        )
        assert resp.status_code == 403

    def test_cross_origin_baseline_blocked(self, csrf_client) -> None:
        """Attacker tries to upload a malicious baseline via CSRF."""
        resp = csrf_client.post(
            "/baseline",
            headers={"origin": "https://evil.com"},
        )
        assert resp.status_code == 403

    def test_cross_origin_narrate_blocked(self, csrf_client) -> None:
        resp = csrf_client.post(
            "/api/narrate",
            headers={"origin": "https://evil.com"},
        )
        assert resp.status_code == 403

    def test_form_submit_from_attacker_site_blocked(self, csrf_client) -> None:
        """Simulates a form submit from attacker's site.

        The browser sends Referer (not Origin in some older cases).
        """
        resp = csrf_client.post(
            "/api/narrate",
            headers={"referer": "https://evil.com/attack-form"},
        )
        assert resp.status_code == 403
