"""Frozen JSON output contract — the machine-readable seam complements consume.

These tests pin the versioned `--json` envelope and the per-command `data`
shapes that downstream tools (see /projects/maybe-projects/) build against.

A change here is a contract change, not an incidental test edit:
  * Adding a field to a `data` shape is additive — these tests assert a
    *subset* of required keys, so additive fields pass unchanged.
  * Removing/renaming a `data` field, or reshaping the envelope, is a BREAK —
    bump ``JSON_CONTRACT_VERSION`` and update docs/spec/json-contract.md and
    this test together.

The volatile envelope fields (``tool_version``, ``generated_at``) are
informational and deliberately not pinned to exact values.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from gpo_lens.cli import main
from gpo_lens.cli._helpers import JSON_CONTRACT_VERSION

FIXTURES = Path(__file__).parent / "fixtures"
ENVELOPE_KEYS = {"schema_version", "kind", "tool_version", "generated_at", "data"}


@pytest.fixture
def contract_db(tmp_path, capsys):
    """A populated estate DB with the events table exercised.

    Two ``--diff-latest`` ingests give a second snapshot so the append-only
    event log carries at least one record (an ``ingest.summary``).
    """
    db = tmp_path / "contract.db"
    assert main(["--db", str(db), "ingest", str(FIXTURES), "--diff-latest"]) == 0
    assert main(["--db", str(db), "ingest", str(FIXTURES), "--diff-latest"]) == 0
    capsys.readouterr()  # discard ingest chatter so tests see only their own output
    return db


def _run(capsys, db, *argv):
    rc = main(["--json", "--db", str(db), *argv])
    out = capsys.readouterr().out
    return rc, json.loads(out)


def _payload(capsys, db, kind, *argv):
    """Run a --json command, assert the envelope, return its ``data`` payload."""
    rc, env = _run(capsys, db, kind, *argv)
    assert rc == 0
    assert set(env) == ENVELOPE_KEYS, f"unexpected envelope keys: {set(env)}"
    assert env["schema_version"] == JSON_CONTRACT_VERSION
    assert env["kind"] == kind
    assert isinstance(env["tool_version"], str) and env["tool_version"]
    assert isinstance(env["generated_at"], str) and env["generated_at"]
    return env["data"]


def _assert_keys(obj: dict, required: set[str], where: str) -> None:
    missing = required - set(obj)
    assert not missing, f"{where}: missing contract fields {missing}"


# --- Envelope invariants ----------------------------------------------------

def test_every_consumed_command_emits_the_envelope(capsys, contract_db):
    """The six (+scope) commands complements consume all carry the envelope."""
    cases = [
        ("summary", ()),
        ("doctor", ()),
        ("settings-dump", ()),
        ("broken-refs", ()),
        ("events", ()),
        ("baseline-diff", (str(FIXTURES),)),
        ("scope", ("gpo-cpassword",)),
    ]
    for kind, args in cases:
        _payload(capsys, contract_db, kind, *args)


# --- Per-command data shapes ------------------------------------------------

def test_summary_shape(capsys, contract_db):
    data = _payload(capsys, contract_db, "summary")
    assert isinstance(data, dict)
    _assert_keys(
        data,
        {"domain", "gpo_count", "som_count", "wmi_filter_count", "broken_ref_count"},
        "summary",
    )


def test_doctor_shape(capsys, contract_db):
    data = _payload(capsys, contract_db, "doctor")
    assert isinstance(data, dict)
    assert isinstance(data["findings"], list) and data["findings"]
    _assert_keys(
        data["findings"][0],
        {"severity", "category", "gpo_id", "gpo_name", "summary"},
        "doctor.findings[]",
    )


def test_settings_dump_shape(capsys, contract_db):
    data = _payload(capsys, contract_db, "settings-dump")
    assert isinstance(data, list) and data
    _assert_keys(
        data[0],
        {
            "gpo_id", "gpo_name", "side", "cse", "identity",
            "display_name", "display_value", "from_disabled_side", "source_state",
        },
        "settings-dump[]",
    )


def test_broken_refs_shape(capsys, contract_db):
    data = _payload(capsys, contract_db, "broken-refs")
    assert isinstance(data, list) and data  # fixture has a broken UNC ref
    _assert_keys(
        data[0],
        {"gpo_id", "gpo_name", "ref_type", "ref_value", "detail"},
        "broken-refs[]",
    )


def test_baseline_diff_shape(capsys, contract_db):
    # Diff the estate against itself (the same fixture as baseline) -> rows.
    data = _payload(capsys, contract_db, "baseline-diff", str(FIXTURES))
    assert isinstance(data, list) and data
    _assert_keys(
        data[0],
        {
            "status", "side", "cse", "identity", "display_name",
            "expected_value", "actual_value", "gpo_id", "admx_name",
        },
        "baseline-diff[]",
    )


def test_events_shape(capsys, contract_db):
    data = _payload(capsys, contract_db, "events")
    assert isinstance(data, list) and data  # >=1 ingest.summary from --diff-latest
    _assert_keys(
        data[0],
        {"id", "timestamp", "event_type", "schema_version", "payload"},
        "events[]",
    )
    assert isinstance(data[0]["payload"], dict)


def test_scope_shape(capsys, contract_db):
    data = _payload(capsys, contract_db, "scope", "gpo-cpassword")
    assert isinstance(data, dict)
    _assert_keys(
        data,
        {
            "gpo_id", "gpo_name", "domain", "computer_enabled", "user_enabled",
            "links", "security_filtering", "wmi_filter", "loopback_mode", "caveats",
        },
        "scope",
    )
    _assert_keys(
        data["security_filtering"],
        {"is_filtered", "apply_trustees", "has_au_read", "has_dc_read"},
        "scope.security_filtering",
    )


# --- Contract guards (the gaps this freeze closed) --------------------------

def test_report_json_is_refused_not_silently_markdown(capsys, contract_db):
    """`report` is a human document; --json must error, not emit Markdown."""
    rc = main(["--json", "--db", str(contract_db), "report"])
    captured = capsys.readouterr()
    assert rc != 0
    assert captured.out == ""  # nothing parseable on stdout
    assert "summary --json" in captured.err  # points to the real machine command


def test_scope_not_found_errors_off_stdout(capsys, contract_db):
    """A not-found result is an error: nonzero exit, stderr, clean stdout."""
    rc = main(["--json", "--db", str(contract_db), "scope", "no-such-gpo"])
    captured = capsys.readouterr()
    assert rc != 0
    assert captured.out == ""
    assert "not found" in captured.err.lower()
