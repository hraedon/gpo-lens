"""Tests for loopback awareness in precedence_conflicts and settings_at_som.

Acceptance criterion: a fixture with a loopback-replace GPO shows the loopback
caveat banner in the CLI output.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from gpo_lens.model import Estate, Gpo, Setting, Som, SomLink

DOMAIN_SID = "S-1-5-21-100-200-300"
USER_SID = f"{DOMAIN_SID}-1001"
USER_SID_LOWER = USER_SID.lower()

GPO_LOOPBACK = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
GPO_NORMAL = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

SOM_DOMAIN = "DC=test,DC=local"
SOM_OU = "OU=Workstations,DC=test,DC=local"

_LOOPBACK_RAW = {
    "tag": "Policy",
    "children": [
        {"tag": "State", "text": "Enabled"},
        {"tag": "DropDownList", "children": [
            {"tag": "Value", "children": [
                {"tag": "Name", "text": "Replace"},
            ]},
        ]},
    ],
}


def _make_loopback_estate() -> Estate:
    gpo_lb = Gpo(
        id=GPO_LOOPBACK, name="Loopback-Policy", domain="test.local",
        created=None, modified=None, read=None,
        computer_enabled=True, user_enabled=True,
        computer_ver_ds=None, computer_ver_sysvol=None,
        user_ver_ds=None, user_ver_sysvol=None,
        sddl=None, owner=None, filter_data_available=False,
        wmi_filter=None, sysvol_path=None,
        settings=[
            Setting(
                gpo_id=GPO_LOOPBACK, side="Computer", cse="Registry",
                identity="Configure user group policy loopback processing mode",
                display_name="Loopback Processing Mode",
                display_value="Replace",
                raw=_LOOPBACK_RAW,
                from_disabled_side=False,
            ),
        ],
    )
    gpo_normal = Gpo(
        id=GPO_NORMAL, name="Normal-Policy", domain="test.local",
        created=None, modified=None, read=None,
        computer_enabled=True, user_enabled=True,
        computer_ver_ds=None, computer_ver_sysvol=None,
        user_ver_ds=None, user_ver_sysvol=None,
        sddl=None, owner=None, filter_data_available=False,
        wmi_filter=None, sysvol_path=None,
        settings=[
            Setting(
                gpo_id=GPO_NORMAL, side="User", cse="Registry",
                identity=r"HKCU\Software\Foo:Bar", display_name="Foo Bar",
                display_value="42", raw={}, from_disabled_side=False,
            ),
        ],
    )
    return Estate(
        domain="test.local",
        gpos=[gpo_lb, gpo_normal],
        soms=[
            Som(
                path=SOM_DOMAIN, name="test.local",
                container_type="domain", inheritance_blocked=False,
                links=[
                    SomLink(gpo_id=GPO_NORMAL, order=1, enabled=True,
                            enforced=False, target=SOM_DOMAIN),
                ],
            ),
            Som(
                path=SOM_OU, name="Workstations",
                container_type="ou", inheritance_blocked=False,
                links=[
                    SomLink(gpo_id=GPO_LOOPBACK, order=1, enabled=True,
                            enforced=False, target=SOM_OU),
                    SomLink(gpo_id=GPO_NORMAL, order=2, enabled=True,
                            enforced=False, target=SOM_OU),
                ],
            ),
        ],
        principals={
            USER_SID_LOWER: __import__("gpo_lens").model.ResolvedPrincipal(
                sid=USER_SID_LOWER, name="TEST\\user1", sam="user1",
                principal_type="User", domain="TEST", resolved=True,
            ),
        },
    )


@pytest.fixture
def loopback_db(tmp_path: Path) -> Path:
    from gpo_lens import store

    db = tmp_path / "loopback.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)
    store.save_estate(conn, _make_loopback_estate())
    conn.close()
    return db


class TestLoopbackAwarenessPrecedenceConflicts:
    def test_text_output_shows_loopback_caveat(self, loopback_db: Path, capsys) -> None:
        from gpo_lens.cli import main

        ret = main(["--db", str(loopback_db), "precedence-conflicts"])
        assert ret == 0
        captured = capsys.readouterr()
        assert "LOOPBACK CAVEAT" in captured.out
        assert "Loopback-Policy" in captured.out
        assert "loopback=replace" in captured.out.lower()

    def test_json_output_still_list(self, loopback_db: Path, capsys) -> None:
        import json

        from gpo_lens.cli import main

        ret = main(["--json", "--db", str(loopback_db), "precedence-conflicts"])
        assert ret == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["kind"] == "precedence-conflicts"
        assert isinstance(data["data"], list)


class TestLoopbackAwarenessSettingsAtSom:
    def test_settings_at_som_shows_loopback_caveat(self, loopback_db: Path, capsys) -> None:
        from gpo_lens.cli import main

        ret = main(["--db", str(loopback_db), "settings-at", SOM_OU])
        assert ret == 0
        captured = capsys.readouterr()
        assert "SCOPE CAVEATS" in captured.out
        assert "loopback=replace" in captured.out.lower()
