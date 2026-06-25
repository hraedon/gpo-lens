"""Regression tests for the global ``--json`` flag shadowing bug (WI-065).

argparse subparsers with their own ``--json`` flag overwrote the value set by
the global ``--json`` flag, so ``gpo-lens --json danger`` produced non-JSON
output. These tests verify both flag positions produce identical JSON contracts.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from gpo_lens.cli import main
from gpo_lens.cli._helpers import JSON_CONTRACT_VERSION

FIXTURES = Path(__file__).resolve().parent / "fixtures"
ENVELOPE_KEYS = {"schema_version", "kind", "tool_version", "generated_at", "data"}


def _assert_envelope(env: dict, kind: str) -> None:
    assert set(env) == ENVELOPE_KEYS, f"unexpected envelope keys: {set(env)}"
    assert env["schema_version"] == JSON_CONTRACT_VERSION
    assert env["kind"] == kind


@pytest.fixture
def estate_db(tmp_path, capsys):
    """Populated estate DB with two snapshots for danger/trends tests."""
    db = tmp_path / "estate.db"
    assert main(["--db", str(db), "ingest", str(FIXTURES), "--diff-latest"]) == 0
    assert main(["--db", str(db), "ingest", str(FIXTURES), "--diff-latest"]) == 0
    capsys.readouterr()
    return db


@pytest.fixture
def principal_db(tmp_path):
    """Minimal DB with principal/group data for resultant tests."""
    from gpo_lens import store
    from gpo_lens.model import (
        DelegationEntry,
        Estate,
        Gpo,
        ResolvedPrincipal,
        Setting,
        Som,
        SomLink,
    )

    db = tmp_path / "principal.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)

    domain_sid = "s-1-5-21-1000000000-2000000000-3000000000"
    user_sid = f"{domain_sid}-1001"
    root_dn = "dc=test,dc=local"
    gpo_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"

    estate = Estate(
        domain="test.local",
        gpos=[Gpo(
            id=gpo_id, name="gpo-test", domain="test.local",
            created=None, modified=None, read=None,
            computer_enabled=True, user_enabled=True,
            computer_ver_ds=None, computer_ver_sysvol=None,
            user_ver_ds=None, user_ver_sysvol=None,
            sddl=None, owner=None, filter_data_available=False,
            wmi_filter=None, sysvol_path=None,
            settings=[Setting(
                gpo_id=gpo_id, side="User", cse="Registry",
                identity=r"HKCU\Software\A", display_name="A",
                display_value="1", raw={}, from_disabled_side=False,
            )],
            delegation=[DelegationEntry(
                gpo_id=gpo_id, trustee="Authenticated Users",
                trustee_sid="S-1-5-11", permission="Apply Group Policy",
                allowed=True,
            )],
        )],
        soms=[Som(
            path=root_dn, name="test", container_type="domain",
            inheritance_blocked=False,
            links=[SomLink(
                gpo_id=gpo_id, order=1, enabled=True, enforced=False,
                target=root_dn,
            )],
        )],
        principals={
            user_sid: ResolvedPrincipal(
                sid=user_sid, name="TEST\\jdoe", sam="jdoe",
                principal_type="User", domain="TEST", resolved=True,
            ),
        },
        group_members={},
    )
    store.save_estate(conn, estate)
    conn.close()
    return db


def _run_json(capsys, db, kind, *argv, json_first):
    if json_first:
        rc = main(["--json", "--db", str(db), kind, *argv])
    else:
        rc = main(["--db", str(db), kind, "--json", *argv])
    out = capsys.readouterr().out
    return rc, json.loads(out)


def _run_text(capsys, db, kind, *argv):
    rc = main(["--db", str(db), kind, *argv])
    return rc, capsys.readouterr().out


def test_danger_json_both_positions(estate_db, capsys):
    """danger: global ``--json`` before the subcommand is honored."""
    rc_a, env_a = _run_json(capsys, estate_db, "danger", json_first=True)
    rc_b, env_b = _run_json(capsys, estate_db, "danger", json_first=False)
    assert rc_a == rc_b == 0
    _assert_envelope(env_a, "danger")
    _assert_envelope(env_b, "danger")
    ids_a = {f["check_id"] for f in env_a["data"]}
    ids_b = {f["check_id"] for f in env_b["data"]}
    assert ids_a == ids_b

    rc, out = _run_text(capsys, estate_db, "danger")
    assert rc == 0
    assert not out.startswith("{")


def test_trends_json_both_positions(estate_db, capsys):
    """trends: global ``--json`` before the subcommand is honored."""
    rc_a, env_a = _run_json(capsys, estate_db, "trends", json_first=True)
    rc_b, env_b = _run_json(capsys, estate_db, "trends", json_first=False)
    assert rc_a == rc_b == 0
    _assert_envelope(env_a, "trends")
    _assert_envelope(env_b, "trends")
    assert len(env_a["data"]) == len(env_b["data"])
    if env_a["data"]:
        keys_a = set(env_a["data"][0])
        keys_b = set(env_b["data"][0])
        assert keys_a == keys_b
        ids_a = [p.get("snapshot_id") for p in env_a["data"]]
        ids_b = [p.get("snapshot_id") for p in env_b["data"]]
        assert ids_a == ids_b

    rc, out = _run_text(capsys, estate_db, "trends")
    assert rc == 0
    assert not out.startswith("{")


def test_resultant_json_both_positions(principal_db, capsys):
    """resultant: global ``--json`` before the subcommand is honored."""
    user_sid = "s-1-5-21-1000000000-2000000000-3000000000-1001"
    rc_a, env_a = _run_json(capsys, principal_db, "resultant", user_sid, json_first=True)
    rc_b, env_b = _run_json(capsys, principal_db, "resultant", user_sid, json_first=False)
    assert rc_a == rc_b == 0
    _assert_envelope(env_a, "resultant")
    _assert_envelope(env_b, "resultant")
    assert env_a["data"]["principal_sid"] == env_b["data"]["principal_sid"]
    assert env_a["data"]["settings"] == env_b["data"]["settings"]

    rc, out = _run_text(capsys, principal_db, "resultant", user_sid)
    assert rc == 0
    assert not out.startswith("{")


def test_ingest_json_both_positions(capsys, tmp_path):
    """ingest: global ``--json`` before the subcommand is honored."""
    db_a = tmp_path / "ingest_a.db"
    db_b = tmp_path / "ingest_b.db"

    rc_a = main(["--json", "--db", str(db_a), "ingest", str(FIXTURES)])
    out_a = capsys.readouterr().out
    rc_b = main(["--db", str(db_b), "ingest", str(FIXTURES), "--json"])
    out_b = capsys.readouterr().out

    assert rc_a == rc_b == 0
    env_a = json.loads(out_a)
    env_b = json.loads(out_b)
    _assert_envelope(env_a, "ingest")
    _assert_envelope(env_b, "ingest")
    assert env_a["data"]["domain"] == env_b["data"]["domain"]
    assert env_a["data"]["gpo_count"] == env_b["data"]["gpo_count"]
    assert env_a["data"]["som_count"] == env_b["data"]["som_count"]
    assert env_a["data"]["snapshot_id"] == env_b["data"]["snapshot_id"]

    db_text = tmp_path / "ingest_text.db"
    rc, out = _run_text(capsys, db_text, "ingest", str(FIXTURES))
    assert rc == 0
    assert not out.startswith("{")
