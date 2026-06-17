from __future__ import annotations

import argparse
import sqlite3
from dataclasses import dataclass

import pytest

pytest.importorskip("fastapi")

from fastapi import HTTPException
from fastapi.testclient import TestClient

from gpo_lens.model import Estate, Som
from gpo_lens.store import init_db, save_estate
from gpo_lens.web.app import create_app
from gpo_lens.web.auth import LOOPBACK_PRINCIPAL, Permission, get_principal

_FAKE_DOMAIN = "fakefixture.local"


@pytest.fixture
def forwarded_db(tmp_path):
    """Empty-but-initialized snapshot DB for web tests."""
    db = tmp_path / "forwarded.sqlite3"
    conn = sqlite3.connect(str(db))
    init_db(conn)
    estate = Estate(
        domain=_FAKE_DOMAIN,
        soms=[
            Som(
                path="dc=fakefixture,dc=local",
                name=_FAKE_DOMAIN,
                container_type="domain",
                inheritance_blocked=False,
            )
        ],
    )
    save_estate(conn, estate)
    conn.close()
    return str(db)


@pytest.fixture
def forwarded_client(forwarded_db, monkeypatch):
    """Authenticated TestClient against a real app instance."""
    monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "test-secret-token")
    app = create_app(forwarded_db)
    return TestClient(
        app,
        headers={
            "origin": "http://localhost",
            "Authorization": "Bearer test-secret-token",
        },
    )


@dataclass
class FakeClient:
    host: str | None


@dataclass
class FakeRequest:
    client: FakeClient
    headers: dict[str, str]

    def __init__(self, host: str | None, headers: dict[str, str] | None = None):
        self.client = FakeClient(host)
        self.headers = headers or {}


class TestForwardedProtoMiddleware:
    """A. The middleware upgrades the request scheme for valid forwarded-proto values."""

    @pytest.mark.parametrize(
        ("header", "expected_scheme"),
        [
            (None, "http"),
            ("http", "http"),
            ("https", "https"),
        ],
    )
    def test_scheme_upgraded(self, forwarded_client, header, expected_scheme):
        """Only valid http/https values change the scheme visible to templates."""
        headers = {"X-Forwarded-Proto": header} if header else {}
        resp = forwarded_client.get("/", headers=headers)
        assert resp.status_code == 200
        assert f'href="{expected_scheme}://testserver/' in resp.text

    def test_invalid_proto_is_ignored(self, forwarded_client):
        """B. Invalid values (junk, ftp) are rejected and the scheme stays http."""
        for bad in ("junk", "ftp"):
            resp = forwarded_client.get(
                "/", headers={"X-Forwarded-Proto": bad}
            )
            assert resp.status_code == 200
            assert 'href="http://testserver/' in resp.text


class TestForwardedProtoAuth:
    """C. X-Forwarded-Proto must never influence client identity or authorization."""

    def test_loopback_principal_ignores_header(self, monkeypatch):
        """Loopback clients get LOOPBACK_PRINCIPAL and the header cannot change it."""
        monkeypatch.delenv("GPO_LENS_AUTH_TOKEN", raising=False)

        req_without = FakeRequest("127.0.0.1")
        principal = get_principal(req_without)
        assert principal == LOOPBACK_PRINCIPAL
        assert principal.has(Permission.VIEW)
        assert principal.has(Permission.INGEST)
        assert principal.has(Permission.NARRATE)
        assert not principal.has(Permission.ADMIN)

        req_with = FakeRequest("127.0.0.1", headers={"x-forwarded-proto": "https"})
        assert get_principal(req_with) == LOOPBACK_PRINCIPAL

    def test_non_loopback_still_401_with_header(self, monkeypatch):
        """A forwarded-proto header cannot bypass the loopback gate."""
        monkeypatch.delenv("GPO_LENS_AUTH_TOKEN", raising=False)

        req_without = FakeRequest("192.168.1.5")
        with pytest.raises(HTTPException) as exc:
            get_principal(req_without)
        assert exc.value.status_code == 401

        req_with = FakeRequest("192.168.1.5", headers={"x-forwarded-proto": "https"})
        with pytest.raises(HTTPException) as exc:
            get_principal(req_with)
        assert exc.value.status_code == 401


class TestServeConfig:
    """D/E. Serve-time guarantees: proxy_headers disabled and bind guard active."""

    def test_cmd_serve_passes_proxy_headers_false(self, tmp_path, monkeypatch):
        """D. cmd_serve calls uvicorn.run with proxy_headers=False."""
        import uvicorn

        from gpo_lens.cli._serve import cmd_serve

        db = tmp_path / "serve.sqlite3"
        args = argparse.Namespace(
            db=str(db),
            host="127.0.0.1",
            port=8000,
            open=False,
            root_path="",
        )
        captured = {}

        def _fake_run(*a, **kwargs):
            captured["kwargs"] = kwargs

        monkeypatch.setattr(uvicorn, "run", _fake_run)
        ret = cmd_serve(args)
        assert ret == 0
        assert captured["kwargs"].get("proxy_headers") is False

    def test_non_loopback_without_token_refuses_to_start(
        self, tmp_path, monkeypatch, capsys
    ):
        """E. Binding to non-loopback without GPO_LENS_AUTH_TOKEN returns 1."""
        from gpo_lens.cli._serve import cmd_serve

        monkeypatch.delenv("GPO_LENS_AUTH_TOKEN", raising=False)
        db = tmp_path / "serve.sqlite3"
        args = argparse.Namespace(
            db=str(db),
            host="0.0.0.0",
            port=8000,
            open=False,
            root_path="",
        )
        ret = cmd_serve(args)
        stderr = capsys.readouterr().err
        assert ret == 1
        assert "non-loopback address requires an auth provider" in stderr.lower()
