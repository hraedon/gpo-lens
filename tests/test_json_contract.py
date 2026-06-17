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
# Synthetic fixture domain root (matches tests/fixtures/build_fixture.py).
ROOT_DN = "dc=fakefixture,dc=local"
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
    """Every DB-driven --json command carries the versioned envelope.

    ``ingest`` (mutating; its own --json flag shadows the top-level one) and
    ``settings-diff`` (file-in, not DB-driven) are pinned in their own tests.
    """
    cases = [
        ("summary", ()),
        ("doctor", ()),
        ("settings-dump", ()),
        ("broken-refs", ()),
        ("events", ()),
        ("baseline-diff", (str(FIXTURES),)),
        ("scope", ("gpo-cpassword",)),
        ("sites", ()),
        ("gpp-tasks", ()),
        ("gpp-groups", ()),
        ("show", ("gpo-cpassword",)),
        ("unlinked", ()),
        ("empty", ()),
        ("disabled-populated", ()),
        ("blocked", ()),
        ("version-skew", ()),
        ("ms16-072", ()),
        ("cpassword", ()),
        ("conflicts", ()),
        ("who-sets", ("BadValue",)),
        ("search", ("gpo",)),
        ("perms", ()),
        ("delegation", ()),
        ("sddl", ()),
        ("snapshots", ()),
        ("diff", ("1", "2")),
        ("diff-settings", ("1", "2")),
        ("changelog", ("1", "2")),
        ("som", (ROOT_DN,)),
        ("settings-at", (ROOT_DN,)),
        ("som-conflicts", (ROOT_DN,)),
        ("dangling", ()),
        ("enforced", ()),
        ("loopback", ()),
        ("wmi", ()),
        ("wmi-filters", ()),
        ("topology-check", ()),
        ("admx-gaps", ()),
        ("precedence-conflicts", ()),
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


def test_sites_shape(capsys, contract_db):
    data = _payload(capsys, contract_db, "sites")
    assert isinstance(data, list) and data  # fixture has two sites
    _assert_keys(data[0], {"name", "dn", "links"}, "sites[]")
    linked = next((s for s in data if s["links"]), None)
    assert linked is not None, "expected a site with at least one link"
    _assert_keys(
        linked["links"][0],
        {"gpo_id", "gpo_name", "enabled", "enforced", "order"},
        "sites[].links[]",
    )


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


def test_gpp_tasks_shape(capsys, contract_db):
    data = _payload(capsys, contract_db, "gpp-tasks")
    assert isinstance(data, list) and data
    _assert_keys(
        data[0],
        {
            "gpo_id", "gpo_name", "side", "file", "kind", "name",
            "action", "command", "arguments", "run_as",
        },
        "gpp-tasks[]",
    )


def test_gpp_groups_shape(capsys, contract_db):
    data = _payload(capsys, contract_db, "gpp-groups")
    assert isinstance(data, list) and data
    _assert_keys(
        data[0],
        {
            "gpo_id", "gpo_name", "side", "file", "group_name",
            "group_sid", "members_added", "members_removed",
        },
        "gpp-groups[]",
    )
    assert isinstance(data[0]["members_added"], list)
    assert isinstance(data[0]["members_removed"], list)


def test_show_shape(capsys, contract_db):
    data = _payload(capsys, contract_db, "show", "gpo-cpassword")
    assert isinstance(data, dict)
    _assert_keys(
        data,
        {
            "id", "name", "domain", "description", "computer_enabled",
            "user_enabled", "links", "settings_count", "delegation_count",
        },
        "show",
    )


# --- Hygiene-list command shapes -------------------------------------------

def _assert_list_of(obj, required: set[str], where: str) -> None:
    assert isinstance(obj, list), f"{where}: expected list"
    if obj:
        first = obj[0]
        assert isinstance(first, dict), f"{where}: expected list of dicts"
        _assert_keys(first, required, where)


def test_unlinked_shape(capsys, contract_db):
    data = _payload(capsys, contract_db, "unlinked")
    _assert_list_of(data, {"id", "name"}, "unlinked[]")


def test_empty_shape(capsys, contract_db):
    data = _payload(capsys, contract_db, "empty")
    _assert_list_of(data, {"id", "name"}, "empty[]")


def test_disabled_populated_shape(capsys, contract_db):
    data = _payload(capsys, contract_db, "disabled-populated")
    _assert_list_of(data, {"id", "name", "side"}, "disabled-populated[]")


def test_blocked_shape(capsys, contract_db):
    data = _payload(capsys, contract_db, "blocked")
    _assert_list_of(data, {"id", "name", "side", "cse"}, "blocked[]")


def test_version_skew_shape(capsys, contract_db):
    data = _payload(capsys, contract_db, "version-skew")
    _assert_list_of(data, {"id", "name", "side"}, "version-skew[]")


def test_ms16_072_shape(capsys, contract_db):
    data = _payload(capsys, contract_db, "ms16-072")
    _assert_list_of(data, {"id", "name"}, "ms16-072[]")


def test_cpassword_shape(capsys, contract_db):
    data = _payload(capsys, contract_db, "cpassword")
    _assert_list_of(
        data,
        {"gpo_id", "gpo_name", "file", "tag", "cpassword"},
        "cpassword[]",
    )


def test_admx_gaps_shape(capsys, contract_db):
    data = _payload(capsys, contract_db, "admx-gaps")
    _assert_list_of(
        data,
        {"gpo_id", "gpo_name", "side", "identity", "key_path", "value_name"},
        "admx-gaps[]",
    )


def test_topology_check_shape(capsys, contract_db):
    data = _payload(capsys, contract_db, "topology-check")
    _assert_list_of(data, {"kind", "ou_dn", "detail"}, "topology-check[]")


# --- Topology command shapes ------------------------------------------------

def test_som_shape(capsys, contract_db):
    data = _payload(capsys, contract_db, "som", ROOT_DN)
    assert isinstance(data, list) and data
    _assert_keys(
        data[0],
        {"gpo_id", "gpo_name", "order", "enabled", "enforced", "target"},
        "som[]",
    )


def test_dangling_shape(capsys, contract_db):
    data = _payload(capsys, contract_db, "dangling")
    _assert_list_of(
        data, {"som_path", "som_name", "gpo_id", "order"}, "dangling[]",
    )


def test_enforced_shape(capsys, contract_db):
    data = _payload(capsys, contract_db, "enforced")
    _assert_list_of(
        data,
        {"som_path", "som_name", "gpo_id", "order", "target"},
        "enforced[]",
    )


def test_loopback_shape(capsys, contract_db):
    data = _payload(capsys, contract_db, "loopback")
    _assert_list_of(
        data,
        {"id", "name", "side", "cse", "identity", "display_value"},
        "loopback[]",
    )


def test_wmi_shape(capsys, contract_db):
    data = _payload(capsys, contract_db, "wmi")
    _assert_list_of(data, {"id", "name", "wmi_filter"}, "wmi[]")


def test_wmi_filters_shape(capsys, contract_db):
    data = _payload(capsys, contract_db, "wmi-filters")
    _assert_list_of(data, {"name", "query"}, "wmi-filters[]")


def test_settings_at_shape(capsys, contract_db):
    data = _payload(capsys, contract_db, "settings-at", ROOT_DN)
    assert isinstance(data, dict)
    _assert_keys(data, {"settings", "caveats"}, "settings-at")
    assert isinstance(data["settings"], list)
    assert isinstance(data["caveats"], list)
    if data["settings"]:
        _assert_keys(
            data["settings"][0],
            {
                "cse", "side", "identity", "display_name", "display_value",
                "winner_gpo_id", "winner_gpo_name", "overridden_by", "enforced",
            },
            "settings-at.settings[]",
        )


def test_som_conflicts_shape(capsys, contract_db):
    data = _payload(capsys, contract_db, "som-conflicts", ROOT_DN)
    _assert_list_of(
        data,
        {"som_path", "cse", "side", "identity", "display_name", "winner", "entries"},
        "som-conflicts[]",
    )


def test_precedence_conflicts_shape(capsys, contract_db):
    data = _payload(capsys, contract_db, "precedence-conflicts")
    assert isinstance(data, list)
    if data:
        _assert_keys(
            data[0],
            {"som_path", "som_name", "conflicts"},
            "precedence-conflicts[]",
        )
        conflicts = data[0].get("conflicts") or []
        if conflicts:
            _assert_keys(
                conflicts[0],
                {"cse", "side", "identity", "display_name", "winner", "entries"},
                "precedence-conflicts[].conflicts[]",
            )


# --- Settings-inspection command shapes ------------------------------------

def test_who_sets_shape(capsys, contract_db):
    data = _payload(capsys, contract_db, "who-sets", "BadValue")
    assert isinstance(data, list) and data
    _assert_keys(
        data[0],
        {"gpo_id", "gpo_name", "cse", "identity", "display_value"},
        "who-sets[]",
    )


def test_conflicts_shape(capsys, contract_db):
    data = _payload(capsys, contract_db, "conflicts")
    assert isinstance(data, list) and data
    _assert_keys(
        data[0],
        {"cse", "side", "identity", "display_name", "entries"},
        "conflicts[]",
    )
    assert isinstance(data[0]["entries"], list)
    if data[0]["entries"]:
        _assert_keys(
            data[0]["entries"][0],
            {"gpo_id", "display_value"},
            "conflicts[].entries[]",
        )


def test_search_shape(capsys, contract_db):
    data = _payload(capsys, contract_db, "search", "gpo")
    assert isinstance(data, list) and data
    _assert_keys(
        data[0], {"gpo_id", "field", "detail"}, "search[]",
    )


# --- Delegation / permissions shapes ---------------------------------------

def test_perms_shape(capsys, contract_db):
    data = _payload(capsys, contract_db, "perms")
    _assert_list_of(data, {"id", "name", "issue"}, "perms[]")


def test_delegation_shape(capsys, contract_db):
    data = _payload(capsys, contract_db, "delegation")
    assert isinstance(data, dict)
    _assert_keys(
        data,
        {
            "privilege_rollup", "orphaned_sids", "broad_writers",
            "deny_aces", "excessive_writers",
        },
        "delegation",
    )


def test_sddl_shape(capsys, contract_db):
    data = _payload(capsys, contract_db, "sddl")
    _assert_list_of(
        data,
        {"gpo_id", "gpo_name", "owner_sid", "group_sid", "dacl", "sacl"},
        "sddl[]",
    )


# --- Snapshot / diff command shapes ----------------------------------------

def test_snapshots_shape(capsys, contract_db):
    data = _payload(capsys, contract_db, "snapshots")
    assert isinstance(data, list) and data
    _assert_keys(data[0], {"id", "domain", "taken_at"}, "snapshots[]")


def test_diff_shape(capsys, contract_db):
    data = _payload(capsys, contract_db, "diff", "1", "2")
    assert isinstance(data, dict)
    _assert_keys(
        data,
        {
            "gpos_added", "gpos_removed", "settings_changed", "links_changed",
            "delegation_changed", "version_skew_changed", "metadata_changes",
            "wmi_filter_changes", "enabled_flips",
        },
        "diff",
    )


def test_diff_settings_shape(capsys, contract_db):
    data = _payload(capsys, contract_db, "diff-settings", "1", "2")
    _assert_list_of(
        data,
        {
            "gpo_id", "gpo_name", "side", "cse", "identity",
            "change_type", "old_value", "new_value",
        },
        "diff-settings[]",
    )


def test_changelog_shape(capsys, contract_db):
    data = _payload(capsys, contract_db, "changelog", "1", "2")
    assert isinstance(data, list)
    if data:
        _assert_keys(
            data[0],
            {
                "gpo_id", "gpo_name", "kind", "side", "summary",
                "version_change", "setting_changes",
            },
            "changelog[]",
        )


# --- Special-case commands (non-standard invocation) -----------------------

def test_ingest_shape(capsys, contract_db):
    """``ingest`` defines its own subparser ``--json`` that shadows the
    top-level flag, so the envelope only emits when ``--json`` follows the
    subcommand. It is also mutating, so it is pinned here, not in ``cases``.
    """
    rc = main(["--db", str(contract_db), "ingest", str(FIXTURES), "--json"])
    env = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert set(env) == ENVELOPE_KEYS
    assert env["schema_version"] == JSON_CONTRACT_VERSION
    assert env["kind"] == "ingest"
    data = env["data"]
    assert isinstance(data, dict)
    _assert_keys(
        data,
        {"domain", "gpo_count", "som_count", "snapshot_id"},
        "ingest",
    )


def test_settings_diff_shape(capsys, contract_db, tmp_path):
    """``settings-diff`` reads two settings-dump JSON exports (files), so it
    cannot ride the shared DB-driven ``cases`` loop. Diff a dump against
    itself -> no changes, but the envelope and the ``{skipped, changes}``
    shape are pinned.
    """
    dump = _payload(capsys, contract_db, "settings-dump")
    fa = tmp_path / "a.json"
    fb = tmp_path / "b.json"
    fa.write_text(json.dumps(dump))
    fb.write_text(json.dumps(dump))
    data = _payload(capsys, contract_db, "settings-diff", str(fa), str(fb))
    assert isinstance(data, dict)
    _assert_keys(data, {"skipped", "changes"}, "settings-diff")
    assert isinstance(data["changes"], list)


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
