"""Direct-call CLI tests for diff/snapshot/changelog/baseline-diff subcommands.

Exercises cmd_diff, cmd_diff_settings, cmd_changelog, cmd_snapshots, and
cmd_baseline_diff via main() so coverage is measured. The underlying
snapshot_diff logic is covered by test_snapshot_diff; this file tests the
CLI argparse wiring and output rendering (text + JSON).
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

GPO_ALPHA = "11111111-1111-1111-1111-111111111111"
GPO_BETA = "22222222-2222-2222-2222-222222222222"
GPO_GAMMA = "33333333-3333-3333-3333-333333333333"
GPO_DELTA = "44444444-4444-4444-4444-444444444444"


def _make_gpo(
    gpo_id: str,
    name: str,
    *,
    computer_ver_ds=1,
    computer_ver_sysvol=1,
    user_ver_ds=1,
    user_ver_sysvol=1,
    computer_enabled=True,
    user_enabled=True,
    owner=None,
    wmi_filter=None,
    settings=None,
    delegation=None,
    links=None,
):
    from gpo_lens.model import Gpo

    return Gpo(
        id=gpo_id, name=name, domain="test.local",
        created=None, modified=None, read=None,
        computer_enabled=computer_enabled, user_enabled=user_enabled,
        computer_ver_ds=computer_ver_ds, computer_ver_sysvol=computer_ver_sysvol,
        user_ver_ds=user_ver_ds, user_ver_sysvol=user_ver_sysvol,
        sddl=None, owner=owner, filter_data_available=False,
        wmi_filter=wmi_filter, sysvol_path=None,
        settings=settings or [], delegation=delegation or [], links=links or [],
    )


def _setting(gpo_id, side, cse, identity, value):
    from gpo_lens.model import Setting

    return Setting(
        gpo_id=gpo_id, side=side, cse=cse, identity=identity,
        display_name=identity, display_value=value,
        raw={}, from_disabled_side=False,
    )


def _delegation(gpo_id, trustee, sid, permission, allowed=True):
    from gpo_lens.model import DelegationEntry

    return DelegationEntry(
        gpo_id=gpo_id, trustee=trustee, trustee_sid=sid,
        permission=permission, allowed=allowed,
    )


def _link(gpo_id, som_path, enabled=True, enforced=False):
    from gpo_lens.model import GpoLink

    return GpoLink(
        gpo_id=gpo_id, som_name="som", som_path=som_path,
        link_enabled=enabled, enforced=enforced,
    )


def _make_diff_db(tmp_path: Path):
    from gpo_lens import model, store

    db = tmp_path / "diff.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)

    estate_a = model.Estate(
        domain="test.local",
        gpos=[
            _make_gpo(
                GPO_ALPHA, "GPO Alpha",
                owner="Admin",
                settings=[_setting(GPO_ALPHA, "Computer", "Registry", "Alpha:Setting1", "old")],
                delegation=[_delegation(GPO_ALPHA, "Authenticated Users", "S-1-5-11", "Read")],
                links=[_link(GPO_ALPHA, "ou=a,dc=test,dc=local")],
            ),
            _make_gpo(
                GPO_BETA, "GPO Beta",
                settings=[_setting(GPO_BETA, "User", "Registry", "Beta:Setting2", "val2")],
            ),
            _make_gpo(
                GPO_DELTA, "GPO Delta",
                settings=[_setting(GPO_DELTA, "User", "Registry", "Delta:Setting4", "val4")],
            ),
        ],
    )
    sid_a = store.save_estate(conn, estate_a)

    estate_b = model.Estate(
        domain="test.local",
        gpos=[
            _make_gpo(
                GPO_ALPHA, "GPO Alpha Renamed",
                computer_ver_ds=2, computer_ver_sysvol=3,
                user_ver_ds=2, user_ver_sysvol=2,
                computer_enabled=False,
                owner="NewOwner",
                wmi_filter="MyFilter",
                settings=[_setting(GPO_ALPHA, "Computer", "Registry", "Alpha:Setting1", "new")],
                delegation=[_delegation(
                    GPO_ALPHA, "Authenticated Users", "S-1-5-11", "Apply Group Policy",
                )],
                links=[_link(GPO_ALPHA, "ou=b,dc=test,dc=local", enforced=True)],
            ),
            _make_gpo(
                GPO_BETA, "GPO Beta",
                computer_ver_ds=2, computer_ver_sysvol=2,
                settings=[_setting(GPO_BETA, "User", "Registry", "Beta:Setting2", "val2")],
            ),
            _make_gpo(
                GPO_GAMMA, "GPO Gamma",
                settings=[_setting(GPO_GAMMA, "Computer", "Registry", "Gamma:Setting3", "val3")],
            ),
        ],
    )
    sid_b = store.save_estate(conn, estate_b)
    conn.close()
    return db, sid_a, sid_b


def _make_identical_db(tmp_path: Path):
    from gpo_lens import model, store

    db = tmp_path / "identical.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)
    estate = model.Estate(
        domain="test.local",
        gpos=[
            _make_gpo(
                GPO_ALPHA, "GPO Alpha",
                settings=[_setting(GPO_ALPHA, "Computer", "Registry", "Alpha:Setting1", "val")],
            ),
        ],
    )
    sid_a = store.save_estate(conn, estate)
    sid_b = store.save_estate(conn, estate)
    conn.close()
    return db, sid_a, sid_b


def _make_bare_db(tmp_path: Path):
    from gpo_lens import model, store

    db = tmp_path / "bare.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)
    estate = model.Estate(
        domain="test.local",
        gpos=[
            _make_gpo(GPO_ALPHA, "GPO Alpha"),
        ],
    )
    store.save_estate(conn, estate)
    conn.close()
    return db


def _make_rich_db(tmp_path: Path):
    from gpo_lens import model, store

    db = tmp_path / "rich.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)
    estate = model.Estate(
        domain="test.local",
        gpos=[
            model.Gpo(
                id="aaa-bbb", name="GPO Alpha", domain="test.local",
                created=None, modified=None, read=None,
                computer_enabled=True, user_enabled=False,
                computer_ver_ds=1, computer_ver_sysvol=2,
                user_ver_ds=0, user_ver_sysvol=0,
                sddl=None, owner="BUILTIN\\Admins",
                filter_data_available=False,
                wmi_filter="MyFilter", sysvol_path=None,
                settings=[
                    model.Setting(
                        gpo_id="aaa-bbb", side="Computer", cse="Security",
                        identity="Account:LockoutBadCount",
                        display_name="LockoutBadCount", display_value="5",
                        raw={}, from_disabled_side=False,
                    ),
                    model.Setting(
                        gpo_id="aaa-bbb", side="Computer", cse="Registry",
                        identity=r"Software\MyApp:Setting1",
                        display_name=r"Software\MyApp", display_value="1",
                        raw={}, from_disabled_side=False,
                    ),
                ],
                delegation=[
                    model.DelegationEntry(
                        gpo_id="aaa-bbb", trustee="Authenticated Users",
                        trustee_sid="S-1-5-11", permission="Read", allowed=True,
                    ),
                ],
                links=[
                    model.GpoLink(
                        gpo_id="aaa-bbb",
                        som_name="Workstations",
                        som_path="ou=workstations,dc=test,dc=local",
                        link_enabled=True, enforced=False,
                    ),
                ],
            ),
            model.Gpo(
                id="ccc-ddd", name="GPO Beta", domain="test.local",
                created=None, modified=None, read=None,
                computer_enabled=False, user_enabled=True,
                computer_ver_ds=0, computer_ver_sysvol=0,
                user_ver_ds=0, user_ver_sysvol=0,
                sddl=None, owner=None,
                filter_data_available=False,
                wmi_filter=None, sysvol_path=None,
                settings=[
                    model.Setting(
                        gpo_id="ccc-ddd", side="User", cse="Registry",
                        identity="SomePolicy", display_name="SomePolicy",
                        display_value="Enabled", raw={},
                        from_disabled_side=False,
                    ),
                    model.Setting(
                        gpo_id="ccc-ddd", side="Computer", cse="Security",
                        identity="Account:LockoutBadCount",
                        display_name="LockoutBadCount", display_value="10",
                        raw={}, from_disabled_side=True,
                    ),
                ],
            ),
        ],
    )
    store.save_estate(conn, estate)
    conn.close()
    return db


def _write_baseline_dir(tmp_path: Path, xml: str) -> Path:
    baseline_dir = tmp_path / "baseline"
    baseline_dir.mkdir()
    (baseline_dir / "AllGPOs.xml").write_text(xml, encoding="utf-8")
    return baseline_dir


DRIFT_BASELINE_XML = (
    '<?xml version="1.0" encoding="utf-8"?>\n<AllGPOs>\n'
    "  <GPO>\n"
    "    <Identifier>\n"
    "      <Identifier>{00000000-0000-0000-0000-000000000000}</Identifier>\n"
    "      <Domain>baseline.local</Domain>\n"
    "    </Identifier>\n"
    "    <Name>baseline-gpo</Name>\n"
    "    <Computer>\n"
    "      <Enabled>true</Enabled>\n"
    "      <VersionDirectory>1</VersionDirectory>\n"
    "      <VersionSysvol>1</VersionSysvol>\n"
    "      <ExtensionData>\n"
    "        <Name>Security</Name>\n"
    "        <Extension>\n"
    '          <Security Name="LockoutBadCount" Type="Account">\n'
    "            <SettingNumber>99</SettingNumber>\n"
    "          </Security>\n"
    '          <Security Name="NonExistent" Type="Policy">\n'
    "            <SettingBoolean>true</SettingBoolean>\n"
    "          </Security>\n"
    "        </Extension>\n"
    "      </ExtensionData>\n"
    "    </Computer>\n"
    "    <User>\n"
    "      <Enabled>true</Enabled>\n"
    "      <VersionDirectory>1</VersionDirectory>\n"
    "      <VersionSysvol>1</VersionSysvol>\n"
    "    </User>\n"
    "  </GPO>\n"
    "</AllGPOs>\n"
)

EMPTY_BASELINE_XML = '<?xml version="1.0" encoding="utf-8"?>\n<GPOs/>\n'


@pytest.fixture
def diff_db(tmp_path: Path) -> Path:
    return _make_diff_db(tmp_path)


@pytest.fixture
def identical_db(tmp_path: Path) -> Path:
    return _make_identical_db(tmp_path)


@pytest.fixture
def bare_db(tmp_path: Path) -> Path:
    return _make_bare_db(tmp_path)


@pytest.fixture
def rich_db(tmp_path: Path) -> Path:
    return _make_rich_db(tmp_path)


class TestDiffDirect:
    def test_text_output_with_differences(self, diff_db, capsys) -> None:
        db, sid_a, sid_b = diff_db
        from gpo_lens.cli import main

        ret = main(["--db", str(db), "diff", str(sid_a), str(sid_b)])
        assert ret == 0
        captured = capsys.readouterr()
        assert "GPOs added:" in captured.out
        assert GPO_GAMMA in captured.out
        assert "GPOs removed:" in captured.out
        assert GPO_DELTA in captured.out
        assert "Settings changed:" in captured.out
        assert "Links changed:" in captured.out
        assert "Delegation changed:" in captured.out
        assert "Version skew changed:" in captured.out
        assert "Metadata:" in captured.out
        assert "WMI filter:" in captured.out
        assert "Enabled flip:" in captured.out

    def test_text_output_no_differences(self, identical_db, capsys) -> None:
        db, sid_a, sid_b = identical_db
        from gpo_lens.cli import main

        ret = main(["--db", str(db), "diff", str(sid_a), str(sid_b)])
        assert ret == 0
        captured = capsys.readouterr()
        assert "No differences found." in captured.out

    def test_json_output(self, diff_db, capsys) -> None:
        db, sid_a, sid_b = diff_db
        from gpo_lens.cli import main

        ret = main(["--json", "--db", str(db), "diff", str(sid_a), str(sid_b)])
        assert ret == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["kind"] == "diff"
        assert GPO_GAMMA in data["data"]["gpos_added"]
        assert GPO_DELTA in data["data"]["gpos_removed"]
        assert GPO_ALPHA in data["data"]["settings_changed"]
        assert GPO_ALPHA in data["data"]["links_changed"]
        assert GPO_ALPHA in data["data"]["delegation_changed"]
        assert GPO_ALPHA in data["data"]["version_skew_changed"]
        assert len(data["data"]["metadata_changes"]) > 0
        assert len(data["data"]["wmi_filter_changes"]) > 0
        assert len(data["data"]["enabled_flips"]) > 0

    def test_json_output_no_differences(self, identical_db, capsys) -> None:
        db, sid_a, sid_b = identical_db
        from gpo_lens.cli import main

        ret = main(["--json", "--db", str(db), "diff", str(sid_a), str(sid_b)])
        assert ret == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["data"]["gpos_added"] == []
        assert data["data"]["gpos_removed"] == []
        assert data["data"]["settings_changed"] == []


class TestDiffSettingsDirect:
    def test_text_output_with_changes(self, diff_db, capsys) -> None:
        db, sid_a, sid_b = diff_db
        from gpo_lens.cli import main

        ret = main(["--db", str(db), "diff-settings", str(sid_a), str(sid_b)])
        assert ret == 0
        captured = capsys.readouterr()
        assert "Alpha:Setting1" in captured.out
        assert "modified" in captured.out
        assert "Gamma:Setting3" in captured.out
        assert "added" in captured.out
        assert "Delta:Setting4" in captured.out
        assert "removed" in captured.out

    def test_text_output_no_changes(self, identical_db, capsys) -> None:
        db, sid_a, sid_b = identical_db
        from gpo_lens.cli import main

        ret = main(["--db", str(db), "diff-settings", str(sid_a), str(sid_b)])
        assert ret == 0
        captured = capsys.readouterr()
        assert "No setting differences found." in captured.out

    def test_json_output(self, diff_db, capsys) -> None:
        db, sid_a, sid_b = diff_db
        from gpo_lens.cli import main

        ret = main(["--json", "--db", str(db), "diff-settings", str(sid_a), str(sid_b)])
        assert ret == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["kind"] == "diff-settings"
        changes = data["data"]
        change_types = {c["change_type"] for c in changes}
        assert "added" in change_types
        assert "removed" in change_types
        assert "modified" in change_types

    def test_filter_gpo_id(self, diff_db, capsys) -> None:
        db, sid_a, sid_b = diff_db
        from gpo_lens.cli import main

        ret = main([
            "--db", str(db), "diff-settings", str(sid_a), str(sid_b),
            "--gpo-id", GPO_ALPHA,
        ])
        assert ret == 0
        captured = capsys.readouterr()
        assert "Alpha:Setting1" in captured.out
        assert "Gamma:Setting3" not in captured.out
        assert "Delta:Setting4" not in captured.out

    def test_filter_side(self, diff_db, capsys) -> None:
        db, sid_a, sid_b = diff_db
        from gpo_lens.cli import main

        ret = main([
            "--db", str(db), "diff-settings", str(sid_a), str(sid_b),
            "--side", "User",
        ])
        assert ret == 0
        captured = capsys.readouterr()
        assert "Delta:Setting4" in captured.out
        assert "Alpha:Setting1" not in captured.out

    def test_filter_cse(self, diff_db, capsys) -> None:
        db, sid_a, sid_b = diff_db
        from gpo_lens.cli import main

        ret = main([
            "--db", str(db), "diff-settings", str(sid_a), str(sid_b),
            "--cse", "Registry",
        ])
        assert ret == 0
        captured = capsys.readouterr()
        assert "Alpha:Setting1" in captured.out
        assert "Gamma:Setting3" in captured.out
        assert "Delta:Setting4" in captured.out

    def test_json_no_changes(self, identical_db, capsys) -> None:
        db, sid_a, sid_b = identical_db
        from gpo_lens.cli import main

        ret = main(["--json", "--db", str(db), "diff-settings", str(sid_a), str(sid_b)])
        assert ret == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["data"] == []


class TestChangelogDirect:
    def test_text_output_with_entries(self, diff_db, capsys) -> None:
        db, sid_a, sid_b = diff_db
        from gpo_lens.cli import main

        ret = main(["--db", str(db), "changelog", str(sid_a), str(sid_b)])
        assert ret == 0
        captured = capsys.readouterr()
        assert "[DETAIL]" in captured.out
        assert "[META]" in captured.out
        assert "GPO Alpha" in captured.out
        assert "settings_detail" not in captured.out
        assert "edited" in captured.out

    def test_text_output_no_entries(self, identical_db, capsys) -> None:
        db, sid_a, sid_b = identical_db
        from gpo_lens.cli import main

        ret = main(["--db", str(db), "changelog", str(sid_a), str(sid_b)])
        assert ret == 0
        captured = capsys.readouterr()
        assert "No changes found between snapshots." in captured.out

    def test_json_output(self, diff_db, capsys) -> None:
        db, sid_a, sid_b = diff_db
        from gpo_lens.cli import main

        ret = main(["--json", "--db", str(db), "changelog", str(sid_a), str(sid_b)])
        assert ret == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["kind"] == "changelog"
        entries = data["data"]
        assert len(entries) > 0
        kinds = {e["kind"] for e in entries}
        assert "settings_detail" in kinds
        assert "metadata_only" in kinds
        detail_entries = [e for e in entries if e["kind"] == "settings_detail"]
        assert any(e["setting_changes"] for e in detail_entries)

    def test_gpo_id_filter(self, diff_db, capsys) -> None:
        db, sid_a, sid_b = diff_db
        from gpo_lens.cli import main

        ret = main([
            "--db", str(db), "changelog", str(sid_a), str(sid_b),
            "--gpo-id", GPO_ALPHA,
        ])
        assert ret == 0
        captured = capsys.readouterr()
        assert "GPO Alpha" in captured.out
        assert "GPO Beta" not in captured.out

    def test_gpo_id_filter_no_matches(self, diff_db, capsys) -> None:
        db, sid_a, sid_b = diff_db
        from gpo_lens.cli import main

        ret = main([
            "--db", str(db), "changelog", str(sid_a), str(sid_b),
            "--gpo-id", GPO_DELTA,
        ])
        assert ret == 0
        captured = capsys.readouterr()
        assert "No changes found between snapshots." in captured.out

    def test_side_filter(self, diff_db, capsys) -> None:
        db, sid_a, sid_b = diff_db
        from gpo_lens.cli import main

        ret = main([
            "--db", str(db), "changelog", str(sid_a), str(sid_b),
            "--side", "Computer",
        ])
        assert ret == 0
        captured = capsys.readouterr()
        assert "GPO Alpha" in captured.out
        assert "GPO Beta" in captured.out

    def test_side_filter_user(self, diff_db, capsys) -> None:
        db, sid_a, sid_b = diff_db
        from gpo_lens.cli import main

        ret = main([
            "--db", str(db), "changelog", str(sid_a), str(sid_b),
            "--side", "User",
        ])
        assert ret == 0
        captured = capsys.readouterr()
        assert "GPO Alpha" in captured.out
        assert "GPO Beta" not in captured.out

    def test_json_no_entries(self, identical_db, capsys) -> None:
        db, sid_a, sid_b = identical_db
        from gpo_lens.cli import main

        ret = main(["--json", "--db", str(db), "changelog", str(sid_a), str(sid_b)])
        assert ret == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["data"] == []


class TestSnapshotsDirect:
    def test_text_output(self, diff_db, capsys) -> None:
        db, _, _ = diff_db
        from gpo_lens.cli import main

        ret = main(["--db", str(db), "snapshots"])
        assert ret == 0
        captured = capsys.readouterr()
        assert "id" in captured.out
        assert "domain" in captured.out
        assert "taken_at" in captured.out
        assert "test.local" in captured.out

    def test_json_output(self, diff_db, capsys) -> None:
        db, _, _ = diff_db
        from gpo_lens.cli import main

        ret = main(["--json", "--db", str(db), "snapshots"])
        assert ret == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["kind"] == "snapshots"
        assert len(data["data"]) >= 2
        for snap in data["data"]:
            assert "id" in snap
            assert "domain" in snap
            assert "taken_at" in snap


class TestBaselineDiffDirect:
    def test_text_output_with_drift_missing_extra(self, rich_db, tmp_path, capsys) -> None:
        baseline_dir = _write_baseline_dir(tmp_path, DRIFT_BASELINE_XML)
        from gpo_lens.cli import main

        ret = main(["--db", str(rich_db), "baseline-diff", str(baseline_dir)])
        assert ret == 0
        captured = capsys.readouterr()
        assert "Baseline Diff" in captured.out
        assert "DRIFT" in captured.out
        assert "MISSING" in captured.out
        assert "EXTRA" in captured.out
        assert "expected: 99" in captured.out
        assert "actual:" in captured.out

    def test_json_output(self, rich_db, tmp_path, capsys) -> None:
        baseline_dir = _write_baseline_dir(tmp_path, DRIFT_BASELINE_XML)
        from gpo_lens.cli import main

        ret = main(["--json", "--db", str(rich_db), "baseline-diff", str(baseline_dir)])
        assert ret == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["kind"] == "baseline-diff"
        results = data["data"]
        statuses = {r["status"] for r in results}
        assert "drift" in statuses
        assert "missing" in statuses
        assert "extra" in statuses

    def test_no_baseline_settings_to_compare(self, bare_db, tmp_path, capsys) -> None:
        baseline_dir = _write_baseline_dir(tmp_path, EMPTY_BASELINE_XML)
        from gpo_lens.cli import main

        ret = main(["--db", str(bare_db), "baseline-diff", str(baseline_dir)])
        assert ret == 0
        captured = capsys.readouterr()
        assert "No baseline settings to compare." in captured.out

    def test_admx_dir_warning(self, rich_db, tmp_path, capsys) -> None:
        baseline_dir = _write_baseline_dir(tmp_path, DRIFT_BASELINE_XML)
        from gpo_lens.cli import main

        ret = main([
            "--db", str(rich_db), "baseline-diff", str(baseline_dir),
            "--admx-dir", "/nonexistent",
        ])
        assert ret == 0
        captured = capsys.readouterr()
        assert "not found or not a directory" in captured.err

    def test_json_no_results(self, bare_db, tmp_path, capsys) -> None:
        baseline_dir = _write_baseline_dir(tmp_path, EMPTY_BASELINE_XML)
        from gpo_lens.cli import main

        ret = main(["--json", "--db", str(bare_db), "baseline-diff", str(baseline_dir)])
        assert ret == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["data"] == []

    def test_baseline_zip_path(self, rich_db, tmp_path, capsys) -> None:
        import zipfile

        zip_path = tmp_path / "baseline.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("GPOs/gpreport.xml", DRIFT_BASELINE_XML)
        from gpo_lens.cli import main

        ret = main(["--db", str(rich_db), "baseline-diff", str(zip_path)])
        assert ret == 0
        captured = capsys.readouterr()
        assert "Baseline Diff" in captured.out
        assert "DRIFT" in captured.out
