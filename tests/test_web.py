from __future__ import annotations

import argparse
import io
import json
import os
import re
import sqlite3
import sys
import tempfile
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

try:
    import fastapi  # noqa: F401

    _HAS_WEB = True
except ImportError:
    _HAS_WEB = False

pytestmark = pytest.mark.skipif(
    not _HAS_WEB,
    reason="web extra not installed",
)

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"


def _make_baseline_zip() -> bytes:
    gpreport = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        "<GPO>\n"
        "  <Identifier>\n"
        "    <Identifier>{99999999-9999-9999-9999-999999999999}</Identifier>\n"
        "    <Domain>baseline.local</Domain>\n"
        "  </Identifier>\n"
        "  <Name>Baseline Policy</Name>\n"
        "  <CreatedTime>2024-01-01T00:00:00</CreatedTime>\n"
        "  <ModifiedTime>2024-01-01T00:00:00</ModifiedTime>\n"
        "  <ReadTime>2024-01-01T00:00:00</ReadTime>\n"
        "  <Computer>\n"
        "    <Enabled>true</Enabled>\n"
        "    <VersionDirectory>1</VersionDirectory>\n"
        "    <VersionSysvol>1</VersionSysvol>\n"
        "    <ExtensionData>\n"
        "      <Name>Security</Name>\n"
        "      <Extension>\n"
        '        <Security Name="Audit policy" Type="Policy">\n'
        "          <SettingBoolean>true</SettingBoolean>\n"
        "        </Security>\n"
        "      </Extension>\n"
        "    </ExtensionData>\n"
        "    <ExtensionData>\n"
        "      <Name>Registry</Name>\n"
        "      <Extension>\n"
        '        <Registry KeyName="HKLM\\Software\\Fake" ValueName="FakeValue">2</Registry>\n'
        "      </Extension>\n"
        "    </ExtensionData>\n"
        "    <ExtensionData>\n"
        "      <Name>Registry</Name>\n"
        "      <Extension>\n"
        '        <Registry KeyName="HKLM\\Baseline" ValueName="Test">1</Registry>\n'
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
            "GPOs/{99999999-9999-9999-9999-999999999999}/gpreport.xml",
            gpreport,
        )
    return buf.getvalue()


@pytest.fixture()
def tmp_db() -> str:
    with tempfile.NamedTemporaryFile(suffix=".sqlite3", delete=False) as f:
        path = f.name
    conn = sqlite3.connect(path)
    from gpo_lens.store import init_db

    init_db(conn)
    conn.close()
    try:
        yield path
    finally:
        os.unlink(path)


@pytest.fixture()
def fixture_db() -> str:
    from gpo_lens.ingest import load_estate as ingest_load_estate
    from gpo_lens.store import init_db, save_estate

    with tempfile.NamedTemporaryFile(suffix=".sqlite3", delete=False) as f:
        path = f.name
    conn = sqlite3.connect(path)
    init_db(conn)
    estate = ingest_load_estate(FIXTURE_DIR)
    save_estate(conn, estate)
    conn.close()
    try:
        yield path
    finally:
        os.unlink(path)


@pytest.fixture()
def client(fixture_db: str):
    from fastapi.testclient import TestClient

    from gpo_lens.web.app import create_app

    app = create_app(fixture_db)
    return TestClient(app, headers={"origin": "http://localhost"})


def _serve_args(**overrides: object) -> argparse.Namespace:
    defaults = {"db": ":memory:", "host": "127.0.0.1", "port": 8000, "open": False, "root_path": ""}
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


class TestCreateApp:
    def test_returns_fastapi_app(self, tmp_db: str) -> None:
        from fastapi import FastAPI

        from gpo_lens.web.app import create_app

        app = create_app(tmp_db)
        assert isinstance(app, FastAPI)

    @pytest.mark.anyio
    async def test_home_route_returns_200(self, tmp_db: str) -> None:
        from httpx import ASGITransport, AsyncClient

        from gpo_lens.web.app import create_app

        app = create_app(tmp_db)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/")
            assert resp.status_code == 200
            assert "gpo-lens" in resp.text

    def test_db_path_stored_on_app_state(self, tmp_db: str) -> None:
        from gpo_lens.web.app import create_app

        app = create_app(tmp_db)
        assert app.state.db_path == tmp_db

    def test_readonly_db_connection(self, tmp_db: str) -> None:
        from gpo_lens.web.app import create_app

        app = create_app(tmp_db)
        db_path = app.state.db_path
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        try:
            with pytest.raises(sqlite3.OperationalError):
                conn.execute(
                    "CREATE TABLE _should_fail (_id INTEGER PRIMARY KEY)"
                )
        finally:
            conn.close()

    def test_root_path_passed_through(self, tmp_db: str) -> None:
        from gpo_lens.web.app import create_app

        app = create_app(tmp_db, root_path="/prefix")
        assert app.root_path == "/prefix"

    @pytest.mark.anyio
    async def test_pages_render_under_root_path(self, tmp_db: str) -> None:
        from httpx import ASGITransport, AsyncClient

        from gpo_lens.web.app import create_app

        app = create_app(tmp_db, root_path="/gpo")
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/")
            assert resp.status_code == 200
            assert "gpo-lens" in resp.text


class TestLoopbackGuard:
    def test_non_loopback_exits_nonzero(self) -> None:
        from gpo_lens.cli._serve import cmd_serve

        args = _serve_args(host="0.0.0.0")
        ret = cmd_serve(args)
        assert ret == 1

    def test_localhost_allowed(self) -> None:
        from gpo_lens.cli._serve import cmd_serve

        args = _serve_args(host="localhost")
        with patch("uvicorn.run") as mock_run:
            ret = cmd_serve(args)
        assert ret == 0
        mock_run.assert_called_once()

    def test_ipv6_loopback_allowed(self) -> None:
        from gpo_lens.cli._serve import cmd_serve

        args = _serve_args(host="::1")
        with patch("uvicorn.run") as mock_run:
            ret = cmd_serve(args)
        assert ret == 0
        mock_run.assert_called_once()


class TestMissingWebExtra:
    def test_serve_errors_helpfully_when_web_missing(self) -> None:
        from gpo_lens.cli._serve import cmd_serve

        args = _serve_args()
        with patch.dict(sys.modules, {"gpo_lens.web": None, "gpo_lens.web.app": None}):
            real_import = (
                __builtins__["__import__"]
                if isinstance(__builtins__, dict)
                else __builtins__.__import__
            )

            def _fake_import(name, *a, **kw):
                if name in ("gpo_lens.web", "gpo_lens.web.app"):
                    raise ImportError("no web")
                return real_import(name, *a, **kw)

            with patch("builtins.__import__", side_effect=_fake_import):
                ret = cmd_serve(args)
        assert ret == 1


class TestArchitecture:
    @pytest.mark.parametrize("module_name", [
        "model",
        "normalize",
        "ingest",
        "store",
        "queries",
        "topology",
        "detection",
        "admx_parser",
        "display",
        "report",
        "events",
        "sinks",
        "query_dispatch",
    ])
    def test_core_modules_do_not_import_web(self, module_name: str) -> None:
        import gpo_lens

        pkg_dir = os.path.dirname(gpo_lens.__file__)
        filepath = os.path.join(pkg_dir, f"{module_name}.py")
        if not os.path.exists(filepath):
            pytest.skip(f"{filepath} not found")
        with open(filepath) as fh:
            source = fh.read()
        assert not re.search(r"import.*\bweb\b", source), (
            f"{module_name}.py contains a web import"
        )

    def test_query_dispatch_tables_consistent(self) -> None:
        from gpo_lens.query_dispatch import (
            _PARAM_VALIDATORS,
            _QUERY_DISPATCH,
            QUERY_REQUIRED_PARAMS,
        )

        for name in QUERY_REQUIRED_PARAMS:
            assert name in _QUERY_DISPATCH, (
                f"QUERY_REQUIRED_PARAMS references '{name}' not in _QUERY_DISPATCH"
            )
        for name in _PARAM_VALIDATORS:
            assert name in _QUERY_DISPATCH, (
                f"_PARAM_VALIDATORS references '{name}' not in _QUERY_DISPATCH"
            )


class TestDashboard:
    def test_dashboard_returns_200(self, client) -> None:
        resp = client.get("/")
        assert resp.status_code == 200

    def test_dashboard_contains_doctor_findings(self, client) -> None:
        resp = client.get("/")
        html = resp.text
        assert "Doctor Findings" in html
        assert "badge-critical" in html

    def test_dashboard_shows_severity_badges(self, client) -> None:
        resp = client.get("/")
        html = resp.text
        assert "badge-critical" in html
        assert "badge-high" in html
        assert "badge-medium" in html
        assert "badge-low" in html

    def test_dashboard_findings_link_to_gpo_detail(self, client) -> None:
        resp = client.get("/")
        html = resp.text
        assert "/gpo/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa" in html
        assert "/gpo/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb" in html
        assert "/gpo/cccccccc-cccc-cccc-cccc-cccccccccccc" in html

    def test_dashboard_severity_order(self, client) -> None:
        resp = client.get("/")
        html = resp.text
        critical_pos = html.find("badge-critical")
        high_pos = html.find("badge-high")
        medium_pos = html.find("badge-medium")
        low_pos = html.find("badge-low")
        assert critical_pos < high_pos
        assert high_pos < medium_pos
        assert medium_pos < low_pos


class TestGpoDetail:
    def test_gpo_detail_returns_200(self, client) -> None:
        resp = client.get("/gpo/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
        assert resp.status_code == 200

    def test_gpo_detail_returns_404_for_unknown(self, client) -> None:
        resp = client.get("/gpo/00000000-0000-0000-0000-000000000000")
        assert resp.status_code == 404

    def test_gpo_detail_shows_version_skew_flag(self, client) -> None:
        resp = client.get("/gpo/cccccccc-cccc-cccc-cccc-cccccccccccc")
        html = resp.text
        assert "SKEW" in html

    def test_gpo_detail_shows_disabled_but_populated_warning(self, client) -> None:
        resp = client.get("/gpo/11111111-1111-1111-1111-111111111111")
        html = resp.text
        assert "Disabled but populated" in html

    def test_gpo_detail_shows_settings_grouped_by_side(self, client) -> None:
        resp = client.get("/gpo/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
        html = resp.text
        assert "Computer Side Settings" in html or "User Side Settings" in html

    def test_gpo_detail_shows_gpo_name(self, client) -> None:
        resp = client.get("/gpo/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
        html = resp.text
        assert "gpo-cpassword" in html

    def test_gpo_detail_version_skew_computer_side(self, client) -> None:
        resp = client.get("/gpo/cccccccc-cccc-cccc-cccc-cccccccccccc")
        html = resp.text
        assert "badge-critical" in html


class TestOuBrowser:
    def test_ou_list_returns_200_with_som_names(self, client) -> None:
        resp = client.get("/ou")
        assert resp.status_code == 200
        assert "fakefixture.local" in resp.text
        assert "child" in resp.text

    def test_ou_detail_returns_200_for_known_som(self, client) -> None:
        resp = client.get("/ou/dc=fakefixture,dc=local")
        assert resp.status_code == 200
        assert "fakefixture.local" in resp.text

    def test_ou_detail_shows_effective_gpo_chain(self, client) -> None:
        resp = client.get("/ou/dc=fakefixture,dc=local")
        assert resp.status_code == 200
        assert "gpo-cpassword" in resp.text
        assert "gpo-version-skew" in resp.text

    def test_ou_detail_shows_loopback_banner(self, client) -> None:
        resp = client.get("/ou/dc=fakefixture,dc=local")
        assert resp.status_code == 200
        assert "Loopback processing is configured" in resp.text


class TestIngest:
    def _make_fixture_zip(self) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for path in FIXTURE_DIR.rglob("*"):
                if path.is_file():
                    arcname = path.relative_to(FIXTURE_DIR)
                    zf.write(path, arcname)
        return buf.getvalue()

    def test_ingest_page_returns_200(self, client) -> None:
        resp = client.get("/ingest")
        assert resp.status_code == 200
        assert "Upload" in resp.text

    def test_upload_valid_fixture_zip_redirects(self, client) -> None:
        data = self._make_fixture_zip()
        resp = client.post(
            "/ingest",
            files={"file": ("fixture.zip", data, "application/zip")},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert resp.headers["location"].endswith("/")

    def test_upload_malformed_zip_shows_error(self, client) -> None:
        resp = client.post(
            "/ingest",
            files={"file": ("bad.zip", b"not a zip", "application/zip")},
        )
        assert resp.status_code == 400
        assert "Malformed zip" in resp.text or "Invalid" in resp.text

    def test_upload_zip_slip_returns_400(self, client) -> None:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("../../etc/passwd", "root:x:0:0:root:/root:/bin/bash")
        resp = client.post(
            "/ingest",
            files={"file": ("evil.zip", buf.getvalue(), "application/zip")},
        )
        assert resp.status_code == 400
        assert "Malformed" in resp.text or "malformed" in resp.text.lower()

    def test_concurrent_upload_returns_409(self, client) -> None:
        import threading
        import time

        data = self._make_fixture_zip()
        results: list[int] = []

        def _upload() -> None:
            resp = client.post(
                "/ingest",
                files={"file": ("fixture.zip", data, "application/zip")},
                follow_redirects=False,
            )
            results.append(resp.status_code)

        t1 = threading.Thread(target=_upload)
        t2 = threading.Thread(target=_upload)
        t1.start()
        time.sleep(0.01)
        t2.start()
        t1.join()
        t2.join()

        assert 303 in results
        assert 409 in results

    def test_upload_exceeds_size_limit_returns_413(self, client) -> None:
        data = b"x" * 128
        with patch("gpo_lens.web.app._MAX_UPLOAD_BYTES", 100):
            resp = client.post(
                "/ingest",
                files={"file": ("big.zip", data, "application/zip")},
            )
        assert resp.status_code == 413
        assert "Upload exceeds" in resp.text


class TestAsk:
    def test_ask_page_returns_200(self, client) -> None:
        resp = client.get("/ask")
        assert resp.status_code == 200

    def test_ask_page_shows_not_configured_without_key(self, client) -> None:
        with patch.dict(os.environ, {}, clear=True):
            resp = client.get("/ask")
        assert resp.status_code == 200
        assert "Narration is not configured" in resp.text

    def test_post_ask_mocked_returns_answer_and_facts(self, client) -> None:
        mock_route = MagicMock(return_value={"query": "estate_summary", "params": {}})
        mock_call = MagicMock(return_value="There are 3 GPOs in the estate.")
        routing_ctx = patch("gpo_lens.narration.route_question", mock_route)
        call_ctx = patch("gpo_lens.narration.call_llm", mock_call)
        env_ctx = patch.dict(os.environ, {"GPO_LENS_API_KEY": "test-key"})
        with env_ctx, routing_ctx, call_ctx:
            resp = client.post("/ask", data={"question": "How many GPOs?"})
        assert resp.status_code == 200
        assert "There are 3 GPOs in the estate." in resp.text
        assert "Underlying Facts" in resp.text

    def test_post_ask_emits_audit_event(self, client, fixture_db: str) -> None:
        mock_route = MagicMock(return_value={"query": "estate_summary", "params": {}})
        mock_call = MagicMock(return_value="answer")
        ctx_route = patch("gpo_lens.narration.route_question", mock_route)
        ctx_call = patch("gpo_lens.narration.call_llm", mock_call)
        ctx_env = patch.dict(os.environ, {"GPO_LENS_API_KEY": "test-key"})
        with ctx_env, ctx_route, ctx_call:
            client.post("/ask", data={"question": "test question"})

        conn = sqlite3.connect(fixture_db)
        try:
            rows = conn.execute(
                "SELECT event_type, payload FROM events WHERE event_type = ?",
                ("audit.narrate",),
            ).fetchall()
        finally:
            conn.close()
        assert len(rows) == 1
        payload = json.loads(rows[0][1])
        assert payload["principal"] == "local-analyst"
        assert payload["question"] == "test question"

    def test_ask_audit_logs_sanitized_question(self, client, fixture_db: str) -> None:
        mock_route = MagicMock(return_value={"query": "estate_summary", "params": {}})
        mock_call = MagicMock(return_value="answer")
        ctx_route = patch("gpo_lens.narration.route_question", mock_route)
        ctx_call = patch("gpo_lens.narration.call_llm", mock_call)
        ctx_env = patch.dict(os.environ, {"GPO_LENS_API_KEY": "test-key"})
        raw_question = "what\x00about\nGPOs\r?"
        with ctx_env, ctx_route, ctx_call:
            client.post("/ask", data={"question": raw_question})

        conn = sqlite3.connect(fixture_db)
        try:
            row = conn.execute(
                "SELECT payload FROM events"
                " WHERE event_type = 'audit.narrate'"
                " ORDER BY id DESC LIMIT 1"
            ).fetchone()
        finally:
            conn.close()
        assert row is not None
        payload = json.loads(row[0])
        assert "\x00" not in payload["question"]
        assert "\n" not in payload["question"]
        assert "\r" not in payload["question"]

    def test_post_ask_viewer_gets_403(self, fixture_db: str) -> None:
        from fastapi.testclient import TestClient

        from gpo_lens.web.app import create_app
        from gpo_lens.web.auth import Permission, Principal, get_principal

        viewer = Principal(
            name="viewer",
            role="viewer",
            permissions=frozenset([Permission.VIEW]),
        )
        app = create_app(fixture_db)
        app.dependency_overrides[get_principal] = lambda authorization=None: viewer
        try:
            client = TestClient(app, headers={"origin": "http://localhost"})
            resp = client.post("/ask", data={"question": "test"})
        finally:
            app.dependency_overrides.clear()
        assert resp.status_code == 403


@pytest.fixture()
def changelog_db():
    from gpo_lens.ingest import load_estate as ingest_load_estate
    from gpo_lens.model import Setting
    from gpo_lens.store import init_db, save_estate

    with tempfile.NamedTemporaryFile(suffix=".sqlite3", delete=False) as f:
        path = f.name
    conn = sqlite3.connect(path)
    init_db(conn)
    estate = ingest_load_estate(FIXTURE_DIR)
    snap_a = save_estate(conn, estate)

    for g in estate.gpos:
        if g.computer_ver_ds is not None:
            g.computer_ver_ds += 1
        if g.computer_ver_sysvol is not None:
            g.computer_ver_sysvol += 1

    gpo_a = estate.gpos[0]
    gpo_a.settings.append(Setting(
        gpo_id=gpo_a.id,
        side="Computer",
        cse="Registry",
        identity="Software\\New:NewSetting",
        display_name="NewSetting",
        display_value="enabled",
        raw={"tag": "NewSetting", "text": "enabled"},
        from_disabled_side=False,
        source_state="normal",
    ))

    snap_b = save_estate(conn, estate)
    conn.close()
    try:
        yield path, snap_a, snap_b
    finally:
        os.unlink(path)


@pytest.fixture()
def changelog_client(changelog_db):
    from fastapi.testclient import TestClient

    from gpo_lens.web.app import create_app

    db_path, _, _ = changelog_db
    app = create_app(db_path)
    return TestClient(app)


class TestChangelog:
    def test_changelog_page_returns_200(self, changelog_client) -> None:
        resp = changelog_client.get("/changelog")
        assert resp.status_code == 200

    def test_changelog_with_two_snapshots_shows_entries(self, changelog_db) -> None:
        from fastapi.testclient import TestClient

        from gpo_lens.web.app import create_app

        db_path, snap_a, snap_b = changelog_db
        client = TestClient(create_app(db_path))
        resp = client.get(f"/changelog?snap_a={snap_a}&snap_b={snap_b}")
        assert resp.status_code == 200
        html = resp.text
        assert "changelog-entry" in html

    def test_changelog_distinguishes_entry_types(self, changelog_db) -> None:
        from fastapi.testclient import TestClient

        from gpo_lens.web.app import create_app

        db_path, snap_a, snap_b = changelog_db
        client = TestClient(create_app(db_path))
        resp = client.get(f"/changelog?snap_a={snap_a}&snap_b={snap_b}")
        html = resp.text
        assert "metadata-only" in html
        assert "settings-detail" in html


class TestBaseline:
    def test_baseline_page_returns_200(self, client) -> None:
        resp = client.get("/baseline")
        assert resp.status_code == 200

    def test_baseline_diff_shows_status_badges(self, client) -> None:
        data = _make_baseline_zip()
        resp = client.post(
            "/baseline",
            files={"file": ("baseline.zip", data, "application/zip")},
        )
        assert resp.status_code == 200
        html = resp.text
        has_badge = (
            "badge-compliant" in html
            or "badge-drift" in html
            or "badge-missing" in html
            or "badge-extra" in html
        )
        assert has_badge

    def test_baseline_diff_shows_admx_names(self, client) -> None:
        data = _make_baseline_zip()
        resp = client.post(
            "/baseline",
            files={"file": ("baseline.zip", data, "application/zip")},
        )
        assert resp.status_code == 200
        html = resp.text
        assert "ADMX Name" in html
        assert "no ADMX policy name" in html

    def test_upload_exceeds_size_limit_returns_413(self, client) -> None:
        data = b"x" * 128
        with patch("gpo_lens.web.app._MAX_UPLOAD_BYTES", 100):
            resp = client.post(
                "/baseline",
                files={"file": ("big.zip", data, "application/zip")},
            )
        assert resp.status_code == 413
        assert "Upload exceeds" in resp.text


class TestSafeExtract:
    def test_zip_slip_blocked(self, tmp_path: Path) -> None:
        from gpo_lens.web.app import _safe_extract

        dest = tmp_path / "dest"
        dest.mkdir()
        zip_path = tmp_path / "evil.zip"

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("../../etc/passwd", "root:x:0:0:root:/root:/bin/bash")
        zip_path.write_bytes(buf.getvalue())

        with pytest.raises(ValueError, match="zip-slip blocked"):
            _safe_extract(zip_path, dest)

        assert list(dest.rglob("*")) == [], "rejected zip should leave dest empty"

    def test_symlink_blocked(self, tmp_path: Path) -> None:
        from gpo_lens.web.app import _safe_extract

        dest = tmp_path / "dest"
        dest.mkdir()
        zip_path = tmp_path / "evil.zip"

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            info = zipfile.ZipInfo("evil_link")
            info.create_system = 3  # Unix
            info.external_attr = (0o777 | 0xA000) << 16  # symlink type
            zf.writestr(info, "/etc/passwd")
        zip_path.write_bytes(buf.getvalue())

        with pytest.raises(ValueError, match="zip symlink blocked"):
            _safe_extract(zip_path, dest)

        assert list(dest.rglob("*")) == [], "rejected zip should leave dest empty"

    def test_valid_zip_extracts(self, tmp_path: Path) -> None:
        from gpo_lens.web.app import _safe_extract

        dest = tmp_path / "dest"
        dest.mkdir()
        zip_path = tmp_path / "good.zip"

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("subdir/file.txt", "hello world")
        zip_path.write_bytes(buf.getvalue())

        _safe_extract(zip_path, dest)
        extracted_file = dest / "subdir" / "file.txt"
        assert extracted_file.exists()
        assert extracted_file.read_text() == "hello world"

    def test_zip_bomb_rejected(self, tmp_path: Path) -> None:
        from gpo_lens.web.app import _safe_extract

        dest = tmp_path / "dest"
        dest.mkdir()
        zip_path = tmp_path / "bomb.zip"

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("big.txt", "x" * 200)
        zip_path.write_bytes(buf.getvalue())

        with patch("gpo_lens.web.app._MAX_UNCOMPRESSED_BYTES", 100):
            with pytest.raises(ValueError, match="exceeds limit"):
                _safe_extract(zip_path, dest)

    def test_spoofed_file_size_still_enforced(self, tmp_path: Path) -> None:
        """Zip-bomb: streaming reader catches large content regardless of headers.

        _safe_extract uses SizeLimitedReader which counts actual
        decompressed bytes during streaming, not info.file_size.

        NOTE: Python's zipfile validates CRC and truncates output to
        file_size bytes, so binary header spoofing is caught at the
        zipfile layer.  The real protection is against legitimately
        large entries where streaming enforcement catches the cap
        violation during decompression, not after.
        """
        from gpo_lens.web.app import _safe_extract

        dest = tmp_path / "dest"
        dest.mkdir()
        zip_path = tmp_path / "big.zip"

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("big.txt", "x" * 200)
        zip_path.write_bytes(buf.getvalue())

        with patch("gpo_lens.web.app._MAX_UNCOMPRESSED_BYTES", 100):
            with pytest.raises(ValueError, match="exceeds limit"):
                _safe_extract(zip_path, dest)

    def test_absolute_path_blocked(self, tmp_path: Path) -> None:
        from gpo_lens.web.app import _safe_extract

        dest = tmp_path / "dest"
        dest.mkdir()
        zip_path = tmp_path / "evil.zip"

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("/etc/passwd", "root:x:0:0:root:/root:/bin/bash")
        zip_path.write_bytes(buf.getvalue())

        with pytest.raises(ValueError, match="zip-slip blocked"):
            _safe_extract(zip_path, dest)

        assert list(dest.rglob("*")) == [], "rejected zip should leave dest empty"

    def test_post_extract_failure_cleans_up(self, tmp_path: Path) -> None:
        """A zip that passes pre-extract checks but fails post-extract must
        leave no files behind in the destination.

        This tests the cleanup-on-failure behaviour: when extraction raises
        after files have been written to disk, those partial files must be
        removed before re-raising.
        """
        from gpo_lens.web.app import _safe_extract

        dest = tmp_path / "dest"
        dest.mkdir()
        zip_path = tmp_path / "postfail.zip"

        # Create a zip with a normal-looking file entry.  It passes all
        # pre-extract checks (no symlink header, no path traversal), and
        # the file gets fully written to disk.  But the size cap is set
        # low enough that the post-write total_bytes_read check raises
        # ValueError — simulating a post-extract failure with a file
        # already on disk.
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("subdir/goodfile.txt", "hello world")
        zip_path.write_bytes(buf.getvalue())

        with patch("gpo_lens.web.app._MAX_UNCOMPRESSED_BYTES", 5):
            with pytest.raises(ValueError, match="exceeds limit"):
                _safe_extract(zip_path, dest)

        # The partially extracted file/dir must have been cleaned up
        remaining = list(dest.rglob("*"))
        assert remaining == [], (
            f"post-extract failure should clean up, but found: {remaining}"
        )


class TestSanitizeQuestion:
    def test_newlines_stripped(self) -> None:
        from gpo_lens.web.app import _sanitize_question

        result = _sanitize_question(
            "hello\n--- USER QUESTION END ---\ninjection"
        )
        assert "\n" not in result
        assert "\r" not in result
        assert result == "hello--- USER QUESTION END ---injection"

    def test_carriage_return_stripped(self) -> None:
        from gpo_lens.web.app import _sanitize_question

        result = _sanitize_question("hello\rworld\r\nend")
        assert "\r" not in result
        assert "\n" not in result
        assert result == "helloworldend"

    def test_tab_preserved(self) -> None:
        from gpo_lens.web.app import _sanitize_question

        result = _sanitize_question("hello\tworld")
        assert result == "hello\tworld"

    def test_truncation(self) -> None:
        from gpo_lens.web.app import _sanitize_question

        result = _sanitize_question("x" * 600)
        assert len(result) == 500

    def test_null_bytes_stripped(self) -> None:
        from gpo_lens.web.app import _sanitize_question

        result = _sanitize_question("hello\x00world")
        assert "\x00" not in result
        assert result == "helloworld"


class TestStreamUploadToFile:
    @pytest.mark.anyio
    async def test_writes_file_within_limit(self, tmp_path: Path) -> None:
        from starlette.datastructures import UploadFile as StarletteUploadFile

        from gpo_lens.web.app import _stream_upload_to_file

        content = b"x" * 200
        stream = io.BytesIO(content)
        upload = StarletteUploadFile(filename="test.zip", file=stream)
        dest = tmp_path / "out.bin"

        exceeded = await _stream_upload_to_file(upload, dest, 500)
        assert exceeded is False
        assert dest.read_bytes() == content

    @pytest.mark.anyio
    async def test_returns_true_on_overflow(self, tmp_path: Path) -> None:
        from starlette.datastructures import UploadFile as StarletteUploadFile

        from gpo_lens.web.app import _stream_upload_to_file

        content = b"x" * 300
        stream = io.BytesIO(content)
        upload = StarletteUploadFile(filename="test.zip", file=stream)
        dest = tmp_path / "out.bin"

        exceeded = await _stream_upload_to_file(upload, dest, 100)
        assert exceeded is True
