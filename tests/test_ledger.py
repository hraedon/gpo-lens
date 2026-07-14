"""Tests for WI-1: normalized settings ledger."""

from __future__ import annotations

from pathlib import Path

import pytest

from gpo_lens.queries import LedgerRow, settings_ledger

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"


def _load_fixture_estate():
    from gpo_lens.ingest import load_estate

    return load_estate(FIXTURE_DIR)


class TestSettingsLedger:
    def test_ledger_returns_rows_for_gpo_with_settings(self) -> None:
        estate = _load_fixture_estate()
        gpo = estate.gpos[0]  # gpo-cpassword
        rows = settings_ledger(estate, gpo.id)
        assert len(rows) == len(gpo.settings)
        assert all(isinstance(r, LedgerRow) for r in rows)

    def test_ledger_empty_for_nonexistent_gpo(self) -> None:
        estate = _load_fixture_estate()
        rows = settings_ledger(estate, "nonexistent-id-1234")
        assert rows == []

    def test_ledger_empty_for_gpo_with_no_settings(self) -> None:
        estate = _load_fixture_estate()
        # gpo-ms16-072-vuln has 0 settings
        gpo = estate.gpo_by_id("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        assert gpo is not None
        rows = settings_ledger(estate, gpo.id)
        assert rows == []

    def test_ledger_uniform_rows_across_cses(self) -> None:
        """A GPO mixing AdminTemplates + Security shows all in uniform rows."""
        estate = _load_fixture_estate()
        # gpo-cpassword has Security CSE
        gpo = estate.gpos[0]
        rows = settings_ledger(estate, gpo.id)
        assert len(rows) >= 1
        # Every row has the same shape — all fields present
        for r in rows:
            assert r.gpo_id == gpo.id
            assert r.gpo_name == gpo.name
            assert r.side in ("Computer", "User")
            assert r.cse  # non-empty
            assert r.identity  # non-empty

    def test_ledger_registry_truth_extracted(self) -> None:
        """Registry CSE settings show key/value/type/data prominently."""
        estate = _load_fixture_estate()
        # gpo-version-skew has a Registry CSE setting
        gpo = estate.gpo_by_id("cccccccccccccccccccccccccccccccc")
        assert gpo is not None
        rows = settings_ledger(estate, gpo.id)
        assert len(rows) == 1
        row = rows[0]
        assert row.cse == "Registry"
        assert row.reg_key == "HKLM\\Software\\Fake"
        assert row.reg_value_name == "FakeValue"
        assert row.reg_data == "1"

    def test_ledger_no_admx_marked(self) -> None:
        """Rows with no ADMX mapping are first-class, not exiled."""
        estate = _load_fixture_estate()
        gpo = estate.gpo_by_id("cccccccccccccccccccccccccccccccc")
        assert gpo is not None
        rows = settings_ledger(estate, gpo.id, admx=None)
        assert rows[0].admx_name == ""

    def test_ledger_stable_identity_key(self) -> None:
        """Rows carry the same (cse, identity) key the merge model uses."""
        estate = _load_fixture_estate()
        gpo = estate.gpos[0]
        rows = settings_ledger(estate, gpo.id)
        for i, row in enumerate(rows):
            setting = gpo.settings[i]
            assert row.cse == setting.cse
            assert row.identity == setting.identity

    def test_ledger_from_disabled_side(self) -> None:
        """Disabled-side settings are marked."""
        estate = _load_fixture_estate()
        # gpo-version-skew has Computer side disabled
        gpo = estate.gpo_by_id("cccccccccccccccccccccccccccccccc")
        assert gpo is not None
        rows = settings_ledger(estate, gpo.id)
        assert rows[0].from_disabled_side is True

    def test_ledger_blocked_source_state(self) -> None:
        """Blocked extension settings are marked."""
        estate = _load_fixture_estate()
        # gpo-blocked-ext has source_state="blocked"
        gpo = estate.gpo_by_id("ffffffffffffffffffffffffffffffff")
        assert gpo is not None
        rows = settings_ledger(estate, gpo.id)
        assert len(rows) == 1
        assert rows[0].source_state == "blocked"

    def test_ledger_sorted_by_side_cse_identity(self) -> None:
        estate = _load_fixture_estate()
        for gpo in estate.gpos:
            rows = settings_ledger(estate, gpo.id)
            if len(rows) < 2:
                continue
            for i in range(len(rows) - 1):
                key_a = (rows[i].side, rows[i].cse, rows[i].identity.lower())
                key_b = (rows[i + 1].side, rows[i + 1].cse, rows[i + 1].identity.lower())
                assert key_a <= key_b, f"Not sorted: {key_a} > {key_b}"

    def test_ledger_admx_resolution(self, tmp_path: Path) -> None:
        """When ADMX resolver is provided, admx_name is populated."""
        estate = _load_fixture_estate()
        gpo = estate.gpo_by_id("cccccccccccccccccccccccccccccccc")
        assert gpo is not None

        from gpo_lens.admx_parser import AdmxPolicy, PolicyDefinitions

        fake_admx = PolicyDefinitions(
            policies=[
                AdmxPolicy(
                    name="FakeValue",
                    class_scope="Both",
                    key="HKLM\\Software\\Fake",
                    value_name="FakeValue",
                    display_name_ref="$(string.FakeValue)",
                    display_name="Prohibit Fake Value",
                    explain_text="Explains fake value",
                )
            ],
        )
        rows = settings_ledger(estate, gpo.id, admx=fake_admx)
        assert rows[0].admx_name == "Prohibit Fake Value"


class TestLedgerWeb:
    """Web integration tests for the ledger on the GPO detail page."""

    @pytest.fixture
    def client(self, monkeypatch, tmp_path):
        from fastapi.testclient import TestClient

        from gpo_lens.web.app import create_app

        # Per-test scratch DB: a shared file under tests/fixtures/ races
        # across xdist workers (transient -shm/-wal sidecars).
        db_path = str(tmp_path / "gpo-lens-test.sqlite3")
        import sqlite3

        from gpo_lens.store import init_db, save_estate

        estate = _load_fixture_estate()
        conn = sqlite3.connect(db_path)
        try:
            init_db(conn)
            from gpo_lens.store import save_estate

            save_estate(conn, estate)
        finally:
            conn.close()

        monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "test-secret-token")
        app = create_app(db_path)
        return TestClient(app)

    def test_gpo_detail_renders_ledger(self, client) -> None:
        resp = client.get(
            "/gpo/cccccccccccccccccccccccccccccccc",
            headers={"Authorization": "Bearer test-secret-token"},
        )
        assert resp.status_code == 200
        html = resp.text
        assert "Settings ledger" in html
        assert "gp-ledger" in html
        assert "data-ledger-filter" in html
        assert "ledger-filter.js" in html

    def test_gpo_detail_ledger_shows_registry_truth(self, client) -> None:
        resp = client.get(
            "/gpo/cccccccccccccccccccccccccccccccc",
            headers={"Authorization": "Bearer test-secret-token"},
        )
        assert resp.status_code == 200
        html = resp.text
        assert "HKLM" in html
        assert "FakeValue" in html

    def test_gpo_detail_ledger_no_admx_badge(self, client) -> None:
        resp = client.get(
            "/gpo/cccccccccccccccccccccccccccccccc",
            headers={"Authorization": "Bearer test-secret-token"},
        )
        assert resp.status_code == 200
        html = resp.text
        assert "no ADMX" in html

    def test_gpo_detail_ledger_works_without_js(self, client) -> None:
        """The ledger renders a full table without JS — filter is progressive."""
        resp = client.get(
            "/gpo/cccccccccccccccccccccccccccccccc",
            headers={"Authorization": "Bearer test-secret-token"},
        )
        assert resp.status_code == 200
        html = resp.text
        # The table rows are server-rendered
        assert "gp-ledger-row" in html
        # The filter input exists but the rows are visible by default
        assert 'type="search"' in html


class TestGpoDossier:
    """WI-2: GPO dossier page tests."""

    @pytest.fixture
    def client(self, monkeypatch, tmp_path):
        from fastapi.testclient import TestClient

        from gpo_lens.web.app import create_app

        # Per-test scratch DB: a shared file under tests/fixtures/ races
        # across xdist workers (transient -shm/-wal sidecars).
        db_path = str(tmp_path / "gpo-lens-test.sqlite3")
        import sqlite3

        from gpo_lens.store import init_db, save_estate

        estate = _load_fixture_estate()
        conn = sqlite3.connect(db_path)
        try:
            init_db(conn)
            save_estate(conn, estate)
        finally:
            conn.close()

        monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "test-secret-token")
        app = create_app(db_path)
        return TestClient(app)

    def test_verdict_strip_present(self, client) -> None:
        resp = client.get(
            "/gpo/cccccccccccccccccccccccccccccccc",
            headers={"Authorization": "Bearer test-secret-token"},
        )
        assert resp.status_code == 200
        html = resp.text
        assert "gp-verdict-strip" in html
        assert "Version skew" in html
        assert "Security filtered" in html
        assert "Owner" in html
        assert "Modified" in html

    def test_verdict_strip_shows_linked(self, client) -> None:
        resp = client.get(
            "/gpo/cccccccccccccccccccccccccccccccc",
            headers={"Authorization": "Bearer test-secret-token"},
        )
        assert resp.status_code == 200
        html = resp.text
        assert "Linked" in html

    def test_scope_and_control_panel(self, client) -> None:
        resp = client.get(
            "/gpo/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            headers={"Authorization": "Bearer test-secret-token"},
        )
        assert resp.status_code == 200
        html = resp.text
        assert "who receives this" in html.lower()
        assert "who can change this" in html.lower()

    def test_history_section(self, client) -> None:
        resp = client.get(
            "/gpo/cccccccccccccccccccccccccccccccc",
            headers={"Authorization": "Bearer test-secret-token"},
        )
        assert resp.status_code == 200
        html = resp.text
        assert "History" in html

    def test_compare_with_gpo(self, client) -> None:
        """GPO-vs-GPO diff shows setting differences."""
        # gpo-version-skew and gpo-conflict both have HKLM\Software\Fake:BadValue
        # gpo-conflict has value=HKLM\Software\Fake, gpo-version-skew has FakeValue=1
        resp = client.get(
            "/gpo/cccccccccccccccccccccccccccccccc?compare=dddddddddddddddddddddddddddddddd",
            headers={"Authorization": "Bearer test-secret-token"},
        )
        assert resp.status_code == 200
        html = resp.text
        assert "Compare with another GPO" in html
        assert "gp-verdict-strip" in html

    def test_compare_no_differences(self, client) -> None:
        """Comparing a GPO with itself shows no differences."""
        resp = client.get(
            "/gpo/cccccccccccccccccccccccccccccccc?compare=cccccccccccccccccccccccccccccccc",
            headers={"Authorization": "Bearer test-secret-token"},
        )
        assert resp.status_code == 200
        html = resp.text
        assert "No setting differences found" in html

    def test_existing_gpo_url_unchanged(self, client) -> None:
        """Existing /gpo/<id> URLs must continue to work."""
        resp = client.get(
            "/gpo/cccccccccccccccccccccccccccccccc",
            headers={"Authorization": "Bearer test-secret-token"},
        )
        assert resp.status_code == 200
