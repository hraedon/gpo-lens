"""Direct-call CLI tests for the golden-diff subcommand."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from gpo_lens.model import Estate, Gpo, Setting

GPO_A = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
GPO_B = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"


def _make_gpo(gpo_id: str, name: str, settings: list[Setting] | None = None) -> Gpo:
    return Gpo(
        id=gpo_id, name=name, domain="test.local",
        created=None, modified=None, read=None,
        computer_enabled=True, user_enabled=True,
        computer_ver_ds=None, computer_ver_sysvol=None,
        user_ver_ds=None, user_ver_sysvol=None,
        sddl=None, owner=None, filter_data_available=False,
        wmi_filter=None, sysvol_path=None,
        settings=settings or [],
    )


def _make_setting(
    gpo_id: str,
    side: str,
    identity: str,
    value: str,
    cse: str = "Registry",
    display_name: str = "",
) -> Setting:
    return Setting(
        gpo_id=gpo_id, side=side, cse=cse, identity=identity,
        display_name=display_name or identity,
        display_value=value,
        raw={},
        from_disabled_side=False,
        source_state="normal",
    )


def _make_live_db(tmp_path: Path) -> Path:
    from gpo_lens import store

    db = tmp_path / "live.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)

    settings_a = [
        _make_setting(GPO_A, "Computer", "HKLM\\Software\\Example\\Value1", "1"),
        _make_setting(GPO_A, "Computer", "HKLM\\Software\\Example\\Value2", "keep"),
        _make_setting(GPO_A, "Computer", "HKLM\\Software\\Example\\ValueAdded", "new"),
    ]
    settings_b = [
        _make_setting(GPO_B, "User", "HKCU\\Software\\Example\\Value3", "x"),
    ]
    gpos = [
        _make_gpo(GPO_A, "gpo-a", settings_a),
        _make_gpo(GPO_B, "gpo-b", settings_b),
    ]
    estate = Estate(domain="test.local", gpos=gpos)
    store.save_estate(conn, estate)
    conn.close()
    return db


def _make_golden_estate() -> Estate:
    settings_a = [
        _make_setting(GPO_A, "Computer", "HKLM\\Software\\Example\\Value1", "2"),
        _make_setting(GPO_A, "Computer", "HKLM\\Software\\Example\\Value2", "keep"),
        _make_setting(GPO_A, "Computer", "HKLM\\Software\\Example\\ValueRemoved", "old"),
    ]
    settings_b = [
        _make_setting(GPO_B, "User", "HKCU\\Software\\Example\\Value3", "x"),
    ]
    settings_c = [
        _make_setting(
            "cccccccc-cccc-cccc-cccc-cccccccccccc", "User",
            "HKCU\\Software\\Example\\Value", "v",
        ),
    ]
    gpos = [
        _make_gpo(GPO_A, "gpo-a", settings_a),
        _make_gpo(GPO_B, "gpo-b", settings_b),
        _make_gpo("cccccccc-cccc-cccc-cccc-cccccccccccc", "gpo-removed", settings_c),
    ]
    return Estate(domain="test.local", gpos=gpos)


@pytest.fixture
def live_db(tmp_path: Path) -> Path:
    return _make_live_db(tmp_path)


class TestGoldenDiffDirectCall:
    def test_text_output(self, live_db: Path, tmp_path: Path, monkeypatch, capsys) -> None:
        from gpo_lens.cli import _diff, main

        def _fake_load_estate(_src):
            return _make_golden_estate()

        monkeypatch.setattr(_diff.ingest, "load_estate", _fake_load_estate)

        golden_dir = tmp_path / "golden"
        ret = main(["--db", str(live_db), "golden-diff", str(golden_dir)])
        assert ret == 0
        captured = capsys.readouterr()
        assert "Golden-Backup Diff" in captured.out
        assert "GPOs matched: 2" in captured.out
        assert "Added: 1" in captured.out
        assert "Removed: 1" in captured.out
        assert "Settings — Compliant: 2" in captured.out
        assert "Changed: 1" in captured.out
        assert "Added: 1" in captured.out
        assert "Removed: 1" in captured.out
        assert "[GPO ADDED] gpo-added" not in captured.out
        assert "[CHANGED]" not in captured.out
        assert "HKLM\\Software\\Example\\Value1" in captured.out
        assert "HKLM\\Software\\Example\\ValueRemoved" in captured.out
        assert "HKLM\\Software\\Example\\ValueAdded" in captured.out

    def test_json_output(self, live_db: Path, tmp_path: Path, monkeypatch, capsys) -> None:
        from gpo_lens.cli import _diff, main

        def _fake_load_estate(_src):
            return _make_golden_estate()

        monkeypatch.setattr(_diff.ingest, "load_estate", _fake_load_estate)

        golden_dir = tmp_path / "golden"
        ret = main(["--json", "--db", str(live_db), "golden-diff", str(golden_dir)])
        assert ret == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["kind"] == "golden-diff"
        summary = data["data"]["summary"]
        assert summary["gpos_matched"] == 2
        assert summary["gpos_added"] == 0
        assert summary["gpos_removed"] == 1
        assert summary["settings_compliant"] == 2
        assert summary["settings_changed"] == 1
        assert summary["settings_added"] == 1
        assert summary["settings_removed"] == 1

        entries = data["data"]["entries"]
        statuses = {e["status"] for e in entries}
        assert statuses == {"compliant", "changed", "added", "removed", "gpo_removed"}

        changed = next(e for e in entries if e["status"] == "changed")
        assert changed["gpo_name"] == "gpo-a"
        assert changed["identity"] == "HKLM\\Software\\Example\\Value1"
        assert changed["golden_value"] == "2"
        assert changed["live_value"] == "1"

        removed = next(e for e in entries if e["status"] == "removed")
        assert removed["identity"] == "HKLM\\Software\\Example\\ValueRemoved"

        added = next(e for e in entries if e["status"] == "added")
        assert added["identity"] == "HKLM\\Software\\Example\\ValueAdded"

        gpo_removed = next(e for e in entries if e["status"] == "gpo_removed")
        assert gpo_removed["gpo_name"] == "gpo-removed"
