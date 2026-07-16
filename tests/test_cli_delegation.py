"""Direct-call CLI tests for the perms, delegation, and sddl subcommands.

Exercises cmd_perms, cmd_delegation, and cmd_sddl via main() directly so
coverage is measured. Uses capsys for output capture.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

DOMAIN_SID = "S-1-5-21-100-200-300"
HELPDESK_SID = f"{DOMAIN_SID}-5555"
HELPDESK_SID_LOWER = HELPDESK_SID.lower()
UNKNOWN_DENY_SID = "s-1-5-21-999-999-999-1234"
UNKNOWN_WRITER_SID = "s-1-5-21-999-888-777-6666"
ORPHANED_SID = "S-1-5-21-999-999-999-9999"

GPO_DENY = "11111111111111111111111111111111"
GPO_CLEAN = "cccccccccccccccccccccccccccccccc"

DENY_SDDL = (
    "O:BAG:BAD:(A;;GA;;;BA)(D;;GA;;;BA)"
    f"(D;CI;GR;;;{UNKNOWN_DENY_SID})S:(AU;SA;GA;;;BA)"
)
WRITER_SDDL = f"O:BAG:BAD:(A;;GA;;;{HELPDESK_SID})"
WRITER_SDDL_NO_OWNER = f"D:(A;;GA;;;{HELPDESK_SID})"
UNKNOWN_WRITER_SDDL = f"O:BAG:BAD:(A;;GA;;;{UNKNOWN_WRITER_SID})"


def _make_gpo(gpo_id: str, name: str, *, sddl: str | None = None, delegation=None):
    from gpo_lens.model import Gpo

    return Gpo(
        id=gpo_id, name=name, domain="test.local",
        created=None, modified=None, read=None,
        computer_enabled=True, user_enabled=True,
        computer_ver_ds=None, computer_ver_sysvol=None,
        user_ver_ds=None, user_ver_sysvol=None,
        sddl=sddl, owner=None, filter_data_available=False,
        wmi_filter=None, sysvol_path=None,
        delegation=delegation or [],
    )


def _make_deleg_db(tmp_path: Path) -> Path:
    from gpo_lens import store
    from gpo_lens.model import DelegationEntry, Estate, ResolvedPrincipal

    db = tmp_path / "deleg.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)

    principals = {
        HELPDESK_SID_LOWER: ResolvedPrincipal(
            sid=HELPDESK_SID_LOWER, name="TEST\\Helpdesk", sam="Helpdesk",
            principal_type="Group", domain="TEST", resolved=True,
        ),
    }

    deny_delegation = [
        DelegationEntry(
            gpo_id=GPO_DENY, trustee="Authenticated Users",
            trustee_sid="S-1-5-11", permission="Read", allowed=True,
        ),
        DelegationEntry(
            gpo_id=GPO_DENY, trustee="Helpdesk",
            trustee_sid=HELPDESK_SID, permission="Write", allowed=True,
        ),
        DelegationEntry(
            gpo_id=GPO_DENY, trustee="",
            trustee_sid=ORPHANED_SID, permission="Apply Group Policy",
            allowed=True,
        ),
    ]

    gpos = [_make_gpo(GPO_DENY, "gpo-deny", sddl=DENY_SDDL, delegation=deny_delegation)]
    for i in range(1, 6):
        gpos.append(_make_gpo(
            f"22222222222222222222{i:012x}", f"gpo-w{i}", sddl=WRITER_SDDL,
        ))
    gpos.append(_make_gpo(
        "22222222222222222222000000000006", "gpo-w6",
        sddl=WRITER_SDDL_NO_OWNER,
    ))
    for i in range(1, 6):
        gpos.append(_make_gpo(
            f"33333333333333333333{i:012x}", f"gpo-v{i}", sddl=UNKNOWN_WRITER_SDDL,
        ))

    estate = Estate(domain="test.local", gpos=gpos, principals=principals)
    store.save_estate(conn, estate)
    conn.close()
    return db


def _make_clean_db(tmp_path: Path) -> Path:
    from gpo_lens import store
    from gpo_lens.model import DelegationEntry, Estate, Gpo

    db = tmp_path / "clean.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)
    estate = Estate(
        domain="test.local",
        gpos=[
            Gpo(
                id=GPO_CLEAN, name="gpo-clean", domain="test.local",
                created=None, modified=None, read=None,
                computer_enabled=True, user_enabled=True,
                computer_ver_ds=None, computer_ver_sysvol=None,
                user_ver_ds=None, user_ver_sysvol=None,
                sddl=None, owner=None, filter_data_available=False,
                wmi_filter=None, sysvol_path=None,
                delegation=[
                    DelegationEntry(
                        gpo_id=GPO_CLEAN, trustee="Authenticated Users",
                        trustee_sid="S-1-5-11", permission="Read", allowed=True,
                    ),
                ],
            ),
        ],
    )
    store.save_estate(conn, estate)
    conn.close()
    return db


@pytest.fixture
def deleg_db(tmp_path: Path) -> Path:
    return _make_deleg_db(tmp_path)


@pytest.fixture
def clean_db(tmp_path: Path) -> Path:
    return _make_clean_db(tmp_path)


class TestPermsDirectCall:
    def test_text_with_issues(self, deleg_db: Path, capsys) -> None:
        from gpo_lens.cli import main

        ret = main(["--db", str(deleg_db), "perms"])
        assert ret == 0
        captured = capsys.readouterr()
        assert "MS16-072" in captured.out
        assert "No delegation entries" in captured.out
        assert "gpo-w1" in captured.out

    def test_json_with_issues(self, deleg_db: Path, capsys) -> None:
        from gpo_lens.cli import main

        ret = main(["--json", "--db", str(deleg_db), "perms"])
        assert ret == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["kind"] == "perms"
        assert isinstance(data["data"], list)
        assert len(data["data"]) > 0
        assert any("MS16-072" in e["issue"] for e in data["data"])

    def test_text_empty(self, clean_db: Path, capsys) -> None:
        from gpo_lens.cli import main

        ret = main(["--db", str(clean_db), "perms"])
        assert ret == 0
        captured = capsys.readouterr()
        assert "No results." in captured.out

    def test_json_empty(self, clean_db: Path, capsys) -> None:
        from gpo_lens.cli import main

        ret = main(["--json", "--db", str(clean_db), "perms"])
        assert ret == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["kind"] == "perms"
        assert data["data"] == []


class TestDelegationDirectCall:
    def test_text_with_findings(self, deleg_db: Path, capsys) -> None:
        from gpo_lens.cli import main

        ret = main(["--db", str(deleg_db), "delegation"])
        assert ret == 0
        captured = capsys.readouterr()
        assert "Delegation Deep-Dive" in captured.out
        assert "--- Deny ACEs ---" in captured.out
        assert "--- Excessive Write Access ---" in captured.out
        assert "--- Orphaned SIDs ---" in captured.out
        assert "--- Non-Default Editors with Write Rights ---" in captured.out
        assert "--- Privilege Rollup ---" in captured.out
        assert "No delegation issues found." not in captured.out

    def test_text_deny_aces_resolved_and_unresolved(self, deleg_db: Path, capsys) -> None:
        from gpo_lens.cli import main

        ret = main(["--db", str(deleg_db), "delegation"])
        assert ret == 0
        captured = capsys.readouterr()
        assert "BUILTIN\\Administrators s-1-5-32-544 (GA)" in captured.out
        assert f"{UNKNOWN_DENY_SID} (GR) [CI]" in captured.out

    def test_text_excessive_writers_more_and_no_more(self, deleg_db: Path, capsys) -> None:
        from gpo_lens.cli import main

        ret = main(["--db", str(deleg_db), "delegation"])
        assert ret == 0
        captured = capsys.readouterr()
        assert f"TEST\\Helpdesk {HELPDESK_SID_LOWER}: 6 GPOs (GA)" in captured.out
        assert "... and 1 more" in captured.out
        assert f"{UNKNOWN_WRITER_SID}: 5 GPOs (GA)" in captured.out

    def test_text_orphaned_and_broad_and_rollup(self, deleg_db: Path, capsys) -> None:
        from gpo_lens.cli import main

        ret = main(["--db", str(deleg_db), "delegation"])
        assert ret == 0
        captured = capsys.readouterr()
        assert f"gpo-deny: {ORPHANED_SID}" in captured.out
        assert "gpo-deny: Helpdesk (Write)" in captured.out
        assert "Helpdesk: gpo-deny" in captured.out

    def test_text_no_findings(self, clean_db: Path, capsys) -> None:
        from gpo_lens.cli import main

        ret = main(["--db", str(clean_db), "delegation"])
        assert ret == 0
        captured = capsys.readouterr()
        assert "No delegation issues found." in captured.out

    def test_json_with_findings(self, deleg_db: Path, capsys) -> None:
        from gpo_lens.cli import main

        ret = main(["--json", "--db", str(deleg_db), "delegation"])
        assert ret == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["kind"] == "delegation"
        d = data["data"]
        assert len(d["deny_aces"]) == 2
        assert len(d["excessive_writers"]) == 2
        assert len(d["orphaned_sids"]) == 1
        assert len(d["broad_writers"]) == 1
        assert "Helpdesk" in d["privilege_rollup"]
        ba_deny = next(x for x in d["deny_aces"] if x["trustee_sid"] == "s-1-5-32-544")
        assert ba_deny["resolved_name"] == "BUILTIN\\Administrators"
        assert ba_deny["rights"] == "GA"
        assert ba_deny["flags"] == ""
        unknown_deny = next(
            x for x in d["deny_aces"] if x["trustee_sid"] == UNKNOWN_DENY_SID
        )
        assert unknown_deny["resolved_name"] == UNKNOWN_DENY_SID
        assert unknown_deny["flags"] == "CI"
        helpdesk_writer = next(
            x for x in d["excessive_writers"] if x["gpo_count"] == 6
        )
        assert helpdesk_writer["resolved_name"] == "TEST\\Helpdesk"
        assert helpdesk_writer["trustee_sid"] == HELPDESK_SID_LOWER
        unknown_writer = next(
            x for x in d["excessive_writers"] if x["gpo_count"] == 5
        )
        assert unknown_writer["resolved_name"] == UNKNOWN_WRITER_SID
        assert unknown_writer["trustee_sid"] == UNKNOWN_WRITER_SID
        assert d["orphaned_sids"][0]["sid"] == ORPHANED_SID
        assert d["broad_writers"][0]["trustee"] == "Helpdesk"
        assert d["broad_writers"][0]["permission"] == "Write"
        assert d["privilege_rollup"]["Helpdesk"] == ["gpo-deny"]

    def test_json_no_findings(self, clean_db: Path, capsys) -> None:
        from gpo_lens.cli import main

        ret = main(["--json", "--db", str(clean_db), "delegation"])
        assert ret == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["kind"] == "delegation"
        d = data["data"]
        assert d["deny_aces"] == []
        assert d["excessive_writers"] == []
        assert d["orphaned_sids"] == []
        assert d["broad_writers"] == []
        assert d["privilege_rollup"] == {}


class TestSddlDirectCall:
    def test_text_with_sddl(self, deleg_db: Path, capsys) -> None:
        from gpo_lens.cli import main

        ret = main(["--db", str(deleg_db), "sddl"])
        assert ret == 0
        captured = capsys.readouterr()
        assert "gpo-deny" in captured.out
        assert "Owner: BA" in captured.out
        assert "Owner: N/A" in captured.out
        assert "DACL ALLOW: BA (GA)" in captured.out
        assert "DACL DENY: BA (GA)" in captured.out
        assert f"DACL DENY: {UNKNOWN_DENY_SID} (GR) [CI]" in captured.out
        assert "SACL AUDIT_SUCCESS: BA (GA) [SA]" in captured.out

    def test_json_with_sddl(self, deleg_db: Path, capsys) -> None:
        from gpo_lens.cli import main

        ret = main(["--json", "--db", str(deleg_db), "sddl"])
        assert ret == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["kind"] == "sddl"
        results = data["data"]
        assert len(results) > 0
        deny_entry = next(r for r in results if r["gpo_name"] == "gpo-deny")
        assert deny_entry["owner_sid"] == "BA"
        assert deny_entry["group_sid"] == "BA"
        assert len(deny_entry["dacl"]) == 3
        assert len(deny_entry["sacl"]) == 1
        sacl_ace = deny_entry["sacl"][0]
        assert sacl_ace["ace_type"] == "audit_success"
        assert sacl_ace["flags"] == "SA"
        assert sacl_ace["rights"] == "GA"
        assert sacl_ace["trustee_sid"] == "BA"
        no_owner_entry = next(r for r in results if r["owner_sid"] == "")
        assert no_owner_entry["gpo_name"] == "gpo-w6"
        assert no_owner_entry["group_sid"] == ""
        allow_ace = deny_entry["dacl"][0]
        assert allow_ace["ace_type"] == "allow"
        assert allow_ace["trustee_sid"] == "BA"

    def test_text_no_sddl(self, clean_db: Path, capsys) -> None:
        from gpo_lens.cli import main

        ret = main(["--db", str(clean_db), "sddl"])
        assert ret == 0
        captured = capsys.readouterr()
        assert "No GPOs with SDDL data found." in captured.out

    def test_json_no_sddl(self, clean_db: Path, capsys) -> None:
        from gpo_lens.cli import main

        ret = main(["--json", "--db", str(clean_db), "sddl"])
        assert ret == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["kind"] == "sddl"
        assert data["data"] == []
