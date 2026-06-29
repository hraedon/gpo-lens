"""Tests for topology.gate_summaries — per-candidate gate attribution (Plan 019 Phase A).

Runs against the synthetic fixture estate (no samples/ required). The fixture
exercises every gate kind: a security-filtered GPO, a valid + a broken WMI ref,
loopback merge/replace/unknown, a disabled computer/user side, and an ILT GPO.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

import pytest

from gpo_lens.ingest import load_estate
from gpo_lens.model import Estate, Gpo, Setting, Som, SomLink
from gpo_lens.topology import (
    _enabled_chain_signature,
    effective_scope,
    gate_summaries,
    precedence_conflict_rollup,
    precedence_conflicts,
)

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


# ---------------------------------------------------------------------------
# WI-081 — precedence_conflict_rollup signature-dedup optimization
# ---------------------------------------------------------------------------

def _conflicting_gpo(gpo_id: str, value: str) -> Gpo:
    return Gpo(
        id=gpo_id, name=f"gpo-{gpo_id[:4]}", domain="test.local",
        created=None, modified=None, read=None,
        computer_enabled=True, user_enabled=True,
        computer_ver_ds=None, computer_ver_sysvol=None,
        user_ver_ds=None, user_ver_sysvol=None,
        sddl=None, owner=None, filter_data_available=False,
        wmi_filter=None, sysvol_path=None,
        settings=[
            Setting(
                gpo_id=gpo_id, side="User", cse="Registry",
                identity=r"HKCU\Software\Test", display_name="Test",
                display_value=value, raw={}, from_disabled_side=False,
            ),
        ],
        delegation=[],
    )


def _shared_chain_estate(n_ous: int) -> Estate:
    """``n_ous`` OUs that all link the same two conflicting GPOs in the same
    order — every OU resolves to the identical conflict."""
    g1 = "11111111-1111-1111-1111-111111111111"
    g2 = "22222222-2222-2222-2222-222222222222"
    gpos = [_conflicting_gpo(g1, "A"), _conflicting_gpo(g2, "B")]
    soms = []
    for i in range(n_ous):
        dn = f"ou=unit{i},dc=test,dc=local"
        soms.append(Som(
            path=dn, name=f"unit{i}", container_type="ou",
            inheritance_blocked=False,
            links=[
                SomLink(gpo_id=g1, order=1, enabled=True, enforced=False, target=dn),
                SomLink(gpo_id=g2, order=2, enabled=True, enforced=False, target=dn),
            ],
        ))
    return Estate(domain="test.local", gpos=gpos, soms=soms, principals={})


def _naive_rollup(estate):
    """Reference: the pre-WI-081 per-SOM rollup, as comparable tuples."""
    groups = defaultdict(list)
    meta = {}
    for som, scs in precedence_conflicts(estate):
        for sc in scs:
            key = (sc.cse, sc.side, sc.identity, sc.winner, tuple(sc.entries))
            groups[key].append(som.path)
            meta[key] = sc
    return sorted(
        (k[0], k[1], k[2], k[3], k[4], tuple(sorted(v)))
        for k, v in groups.items()
    )


def _opt_rollup(estate):
    return sorted(
        (r.cse, r.side, r.identity, r.winner, tuple(r.entries), tuple(sorted(r.scopes)))
        for r in precedence_conflict_rollup(estate)
    )


def test_rollup_collapses_shared_chain_to_one_row():
    estate = _shared_chain_estate(50)
    rows = precedence_conflict_rollup(estate)
    assert len(rows) == 1
    # one root cause, blast radius = all 50 OUs
    assert len(rows[0].scopes) == 50
    assert rows[0].identity == r"HKCU\Software\Test"


def test_rollup_matches_naive_per_som_walk():
    estate = _shared_chain_estate(30)
    assert _opt_rollup(estate) == _naive_rollup(estate)


def test_chain_signature_is_order_independent():
    g1 = "11111111-1111-1111-1111-111111111111"
    g2 = "22222222-2222-2222-2222-222222222222"
    a = Som(path="ou=a,dc=t", name="a", container_type="ou", inheritance_blocked=False,
            links=[SomLink(gpo_id=g1, order=1, enabled=True, enforced=False, target="a"),
                   SomLink(gpo_id=g2, order=2, enabled=True, enforced=False, target="a")])
    b = Som(path="ou=b,dc=t", name="b", container_type="ou", inheritance_blocked=False,
            links=[SomLink(gpo_id=g2, order=2, enabled=True, enforced=False, target="b"),
                   SomLink(gpo_id=g1, order=1, enabled=True, enforced=False, target="b")])
    assert _enabled_chain_signature(a) == _enabled_chain_signature(b)


def test_chain_signature_excludes_disabled_links():
    g1 = "11111111-1111-1111-1111-111111111111"
    g2 = "22222222-2222-2222-2222-222222222222"
    s = Som(path="ou=a,dc=t", name="a", container_type="ou", inheritance_blocked=False,
            links=[SomLink(gpo_id=g1, order=1, enabled=True, enforced=False, target="a"),
                   SomLink(gpo_id=g2, order=2, enabled=False, enforced=False, target="a")])
    assert _enabled_chain_signature(s) == ((g1, 1, False),)
