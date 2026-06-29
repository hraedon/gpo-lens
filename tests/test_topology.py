"""Tests for topology.gate_summaries — per-candidate gate attribution (Plan 019 Phase A).

Runs against the synthetic fixture estate (no samples/ required). The fixture
exercises every gate kind: a security-filtered GPO, a valid + a broken WMI ref,
loopback merge/replace/unknown, a disabled computer/user side, and an ILT GPO.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from gpo_lens.ingest import load_estate
from gpo_lens.topology import effective_scope, gate_summaries

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"
ROOT_DN = "dc=fakefixture,dc=local"

GPO_IDS = {
    "cpassword": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "version_skew": "cccccccccccccccccccccccccccccccc",
    "loopback": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
    "loopback_merge": "33333333333333333333333333333333",
    "loopback_unknown": "44444444444444444444444444444444",
    "user_disabled": "11111111111111111111111111111111",
    "security_filtered": "55555555555555555555555555555555",
    "wmi_broken_ref": "66666666666666666666666666666666",
    "gpp_ilt": "77777777777777777777777777777777",
    "stale": "88888888888888888888888888888888",
}


@pytest.fixture(scope="session")
def fixture_estate():
    return load_estate(FIXTURE_DIR)


def _by_id(pairs):
    return {eg.gpo_id: (eg, gs) for eg, gs in pairs}


# AC-1: security-filtered GPO shows its explicit Apply-Group-Policy trustees

def test_gate_summaries_security_filtered(fixture_estate):
    pairs = gate_summaries(fixture_estate, ROOT_DN)
    eg, gs = _by_id(pairs)[GPO_IDS["security_filtered"]]
    assert gs.is_security_filtered is True
    assert gs.apply_trustees == ("Helpdesk Operators",)
    assert eg.gpo_name == "gpo-security-filtered"


# AC-2: WMI-gated GPO shows the filter name; a broken ref is marked broken

def test_gate_summaries_wmi_filter_valid(fixture_estate):
    pairs = gate_summaries(fixture_estate, ROOT_DN)
    gs = _by_id(pairs)[GPO_IDS["loopback"]][1]
    assert gs.wmi_filter_name == "Fake WMI Filter"
    assert gs.wmi_filter_broken is False


def test_gate_summaries_wmi_filter_broken(fixture_estate):
    pairs = gate_summaries(fixture_estate, ROOT_DN)
    gs = _by_id(pairs)[GPO_IDS["wmi_broken_ref"]][1]
    assert gs.wmi_filter_name == "Nonexistent WMI Filter"
    assert gs.wmi_filter_broken is True


# AC-3: loopback GPO shows its mode (WI-028 resolved → merge/replace/unknown)

def test_gate_summaries_loopback_mode(fixture_estate):
    pairs = gate_summaries(fixture_estate, ROOT_DN)
    by_id = _by_id(pairs)
    assert by_id[GPO_IDS["loopback"]][1].loopback_mode == "replace"
    assert by_id[GPO_IDS["loopback_merge"]][1].loopback_mode == "merge"
    assert by_id[GPO_IDS["loopback_unknown"]][1].loopback_mode == "unknown"
    # A non-loopback GPO has no loopback mode.
    assert by_id[GPO_IDS["cpassword"]][1].loopback_mode is None


# AC-4: a GPO with a disabled side shows that on its row

def test_gate_summaries_side_disabled(fixture_estate):
    pairs = gate_summaries(fixture_estate, ROOT_DN)
    by_id = _by_id(pairs)
    assert by_id[GPO_IDS["version_skew"]][1].side_disabled == "computer"
    assert by_id[GPO_IDS["user_disabled"]][1].side_disabled == "user"
    assert by_id[GPO_IDS["cpassword"]][1].side_disabled is None


def test_gate_summaries_ilt(fixture_estate):
    pairs = gate_summaries(fixture_estate, ROOT_DN)
    by_id = _by_id(pairs)
    assert by_id[GPO_IDS["gpp_ilt"]][1].has_ilt is True
    assert by_id[GPO_IDS["cpassword"]][1].has_ilt is False


def test_gate_summaries_link_enabled_reflects_chain_row(fixture_estate):
    pairs = gate_summaries(fixture_estate, ROOT_DN)
    # Every link in the fixture's root chain is enabled.
    for eg, gs in pairs:
        assert gs.link_enabled is eg.enabled
    assert all(gs.link_enabled for _, gs in pairs)


# AC-5: a GPO with no gates renders cleanly as unconditional-in-scope

def test_gate_summaries_no_gates_clean(fixture_estate):
    pairs = gate_summaries(fixture_estate, ROOT_DN)
    gs = _by_id(pairs)[GPO_IDS["cpassword"]][1]
    assert gs.is_security_filtered is False
    assert gs.apply_trustees == ()
    assert gs.wmi_filter_name is None
    assert gs.wmi_filter_broken is False
    assert gs.loopback_mode is None
    assert gs.has_ilt is False
    assert gs.side_disabled is None


def test_gate_summaries_empty_for_missing_som(fixture_estate):
    assert gate_summaries(fixture_estate, "dc=does,dc=not,dc=exist") == []


def test_gate_summaries_chain_order_matches_som_effective_gpos(fixture_estate):
    from gpo_lens.topology import som_effective_gpos

    pairs = gate_summaries(fixture_estate, ROOT_DN)
    plain = som_effective_gpos(fixture_estate, ROOT_DN)
    assert [eg for eg, _ in pairs] == plain


# Anti-drift (critical): gate_summaries agrees with effective_scope's components
# for the same GPO. The two surfaces describe the same facts in two places —
# this test keeps them from diverging (WI-029 lesson).

@pytest.mark.parametrize("gpo_key", [
    "security_filtered",
    "loopback",
    "wmi_broken_ref",
    "version_skew",
    "gpp_ilt",
    "cpassword",
    "loopback_merge",
    "loopback_unknown",
])
def test_gate_summaries_match_effective_scope(fixture_estate, gpo_key):
    gpo_id = GPO_IDS[gpo_key]
    pairs = gate_summaries(fixture_estate, ROOT_DN)
    gs = _by_id(pairs)[gpo_id][1]
    scope = effective_scope(fixture_estate, gpo_id)
    assert scope is not None

    assert gs.is_security_filtered == scope.security_filtering.is_filtered
    assert gs.apply_trustees == tuple(scope.security_filtering.apply_trustees)
    assert gs.wmi_filter_name == (
        scope.wmi_filter.name if scope.wmi_filter else None
    )
    assert gs.wmi_filter_broken == (
        scope.wmi_filter.is_broken if scope.wmi_filter else False
    )
    assert gs.loopback_mode == scope.loopback_mode
    assert gs.has_ilt == any(
        "item-level targeting" in c.lower() for c in scope.caveats
    )
    if not scope.computer_enabled and not scope.user_enabled:
        assert gs.side_disabled == "both"
    elif not scope.computer_enabled:
        assert gs.side_disabled == "computer"
    elif not scope.user_enabled:
        assert gs.side_disabled == "user"
    else:
        assert gs.side_disabled is None
