"""Tests for topology.gate_summaries — per-candidate gate attribution (Plan 019 Phase A).

Runs against the synthetic fixture estate (no samples/ required). The fixture
exercises every gate kind: a security-filtered GPO, a valid + a broken WMI ref,
loopback merge/replace/unknown, a disabled computer/user side, and an ILT GPO.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

import pytest
from _helpers import _make_gpo

from gpo_lens.ingest import load_estate
from gpo_lens.model import DelegationEntry, Estate, Gpo, GpoLink, Setting, Som, SomLink
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
    return _make_gpo(
        id=gpo_id, name=f"gpo-{gpo_id[:4]}",
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
    g1 = "11111111111111111111111111111111"
    g2 = "22222222222222222222222222222222"
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
    g1 = "11111111111111111111111111111111"
    g2 = "22222222222222222222222222222222"
    a = Som(path="ou=a,dc=t", name="a", container_type="ou", inheritance_blocked=False,
            links=[SomLink(gpo_id=g1, order=1, enabled=True, enforced=False, target="a"),
                   SomLink(gpo_id=g2, order=2, enabled=True, enforced=False, target="a")])
    b = Som(path="ou=b,dc=t", name="b", container_type="ou", inheritance_blocked=False,
            links=[SomLink(gpo_id=g2, order=2, enabled=True, enforced=False, target="b"),
                   SomLink(gpo_id=g1, order=1, enabled=True, enforced=False, target="b")])
    assert _enabled_chain_signature(a) == _enabled_chain_signature(b)


def test_chain_signature_excludes_disabled_links():
    g1 = "11111111111111111111111111111111"
    g2 = "22222222222222222222222222222222"
    s = Som(path="ou=a,dc=t", name="a", container_type="ou", inheritance_blocked=False,
            links=[SomLink(gpo_id=g1, order=1, enabled=True, enforced=False, target="a"),
                   SomLink(gpo_id=g2, order=2, enabled=False, enforced=False, target="a")])
    assert _enabled_chain_signature(s) == ((g1, 1, False),)


# ---------------------------------------------------------------------------
# _split_dn — DN splitting with backslash escaping
# ---------------------------------------------------------------------------


class TestSplitDn:
    def test_simple_dn(self):
        from gpo_lens.topology import _split_dn

        parts = _split_dn("CN=user,OU=Users,DC=test,DC=local")
        assert parts == ["CN=user", "OU=Users", "DC=test", "DC=local"]

    def test_escaped_comma(self):
        from gpo_lens.topology import _split_dn

        parts = _split_dn(r"CN=Last\,First,OU=Users,DC=test")
        assert parts == [r"CN=Last\,First", "OU=Users", "DC=test"]

    def test_double_backslash_before_comma(self):
        from gpo_lens.topology import _split_dn

        parts = _split_dn(r"CN=Name\\,OU=Users,DC=test")
        assert parts == [r"CN=Name\\", "OU=Users", "DC=test"]

    def test_single_component(self):
        from gpo_lens.topology import _split_dn

        parts = _split_dn("DC=test")
        assert parts == ["DC=test"]

    def test_empty_string(self):
        from gpo_lens.topology import _split_dn

        parts = _split_dn("")
        assert parts == [""]


# ---------------------------------------------------------------------------
# _find_parent_som — walk up DN to find closest non-site SOM
# ---------------------------------------------------------------------------


class TestFindParentSom:
    def test_finds_direct_parent(self):
        from gpo_lens.topology import _find_parent_som

        root = Som(path="dc=test,dc=local", name="test", container_type="domain",
                   inheritance_blocked=False, links=[])
        estate = Estate(domain="test.local", soms=[root])
        result = _find_parent_som(estate, "ou=users,dc=test,dc=local")
        assert result is not None
        assert result.path == "dc=test,dc=local"

    def test_finds_grandparent(self):
        from gpo_lens.topology import _find_parent_som

        root = Som(path="dc=test,dc=local", name="test", container_type="domain",
                   inheritance_blocked=False, links=[])
        estate = Estate(domain="test.local", soms=[root])
        result = _find_parent_som(estate, "ou=sub,ou=users,dc=test,dc=local")
        assert result is not None
        assert result.path == "dc=test,dc=local"

    def test_skips_site_soms(self):
        from gpo_lens.topology import _find_parent_som

        site = Som(path="cn=default-first-site-name,cn=sites,cn=configuration,dc=test,dc=local",
                   name="Default-First-Site-Name", container_type="site",
                   inheritance_blocked=False, links=[])
        root = Som(path="dc=test,dc=local", name="test", container_type="domain",
                   inheritance_blocked=False, links=[])
        estate = Estate(domain="test.local", soms=[site, root])
        result = _find_parent_som(estate, "ou=users,dc=test,dc=local")
        assert result is not None
        assert result.path == "dc=test,dc=local"

    def test_returns_none_when_no_parent(self):
        from gpo_lens.topology import _find_parent_som

        estate = Estate(domain="test.local", soms=[])
        result = _find_parent_som(estate, "ou=users,dc=test,dc=local")
        assert result is None

    def test_returns_none_for_empty_dn(self):
        from gpo_lens.topology import _find_parent_som

        estate = Estate(domain="test.local", soms=[])
        result = _find_parent_som(estate, "")
        assert result is None


# ---------------------------------------------------------------------------
# som_effective_gpos — resolved GPO chain at a SOM
# ---------------------------------------------------------------------------


class TestSomEffectiveGpos:
    def test_returns_chain_for_exact_som(self):
        from gpo_lens.topology import som_effective_gpos

        gpo_id = "11111111111111111111111111111111"
        som = Som(path="dc=test,dc=local", name="test", container_type="domain",
                  inheritance_blocked=False,
                  links=[SomLink(gpo_id=gpo_id, order=1, enabled=True,
                                 enforced=False, target="dc=test,dc=local")])
        gpo = _make_gpo(id=gpo_id, name="Test GPO")
        estate = Estate(domain="test.local", gpos=[gpo], soms=[som])
        chain = som_effective_gpos(estate, "dc=test,dc=local")
        assert len(chain) == 1
        assert chain[0].gpo_id == gpo_id
        assert chain[0].gpo_name == "Test GPO"

    def test_falls_back_to_parent_som(self):
        from gpo_lens.topology import som_effective_gpos

        gpo_id = "11111111111111111111111111111111"
        root = Som(path="dc=test,dc=local", name="test", container_type="domain",
                   inheritance_blocked=False,
                   links=[SomLink(gpo_id=gpo_id, order=1, enabled=True,
                                  enforced=False, target="dc=test,dc=local")])
        gpo = _make_gpo(id=gpo_id, name="Test GPO")
        estate = Estate(domain="test.local", gpos=[gpo], soms=[root])
        chain = som_effective_gpos(estate, "ou=missing,dc=test,dc=local")
        assert len(chain) == 1
        assert chain[0].gpo_id == gpo_id

    def test_returns_empty_for_unknown_path(self):
        from gpo_lens.topology import som_effective_gpos

        estate = Estate(domain="test.local")
        chain = som_effective_gpos(estate, "dc=nowhere,dc=local")
        assert chain == []

    def test_unknown_gpo_name_shows_placeholder(self):
        from gpo_lens.topology import som_effective_gpos

        gpo_id = "11111111111111111111111111111111"
        som = Som(path="dc=test,dc=local", name="test", container_type="domain",
                  inheritance_blocked=False,
                  links=[SomLink(gpo_id=gpo_id, order=1, enabled=True,
                                 enforced=False, target="dc=test,dc=local")])
        estate = Estate(domain="test.local", soms=[som])
        chain = som_effective_gpos(estate, "dc=test,dc=local")
        assert chain[0].gpo_name == "<unknown>"


# ---------------------------------------------------------------------------
# loopback_gpos / _extract_loopback_mode / loopback_awareness
# ---------------------------------------------------------------------------


class TestLoopbackDetection:
    def test_loopback_gpos_finds_security_cse(self):
        from gpo_lens.topology import loopback_gpos

        gpo = _make_gpo(id="11111111111111111111111111111111", name="LB",
                        settings=[Setting(
                            gpo_id="11111111111111111111111111111111",
                            side="Computer", cse="Security",
                            identity="Configure user group policy loopback processing mode",
                            display_name="Loopback", display_value="Replace",
                            raw={}, from_disabled_side=False,
                        )])
        estate = Estate(domain="test.local", gpos=[gpo])
        hits = loopback_gpos(estate)
        assert len(hits) == 1

    def test_loopback_gpos_returns_empty_when_none(self):
        from gpo_lens.topology import loopback_gpos

        gpo = _make_gpo(id="11111111111111111111111111111111", name="NoLB",
                        settings=[Setting(
                            gpo_id="11111111111111111111111111111111",
                            side="Computer", cse="Registry",
                            identity="HKLM\\Software\\X", display_name="X",
                            display_value="1", raw={}, from_disabled_side=False,
                        )])
        estate = Estate(domain="test.local", gpos=[gpo])
        hits = loopback_gpos(estate)
        assert hits == []

    def test_extract_loopback_mode_replace(self):
        from gpo_lens.topology import _extract_loopback_mode

        s = Setting(gpo_id="x", side="Computer", cse="Security",
                    identity="Configure user group policy loopback processing mode",
                    display_name="Loopback", display_value="Replace",
                    raw={}, from_disabled_side=False)
        assert _extract_loopback_mode(s) == "replace"

    def test_extract_loopback_mode_merge(self):
        from gpo_lens.topology import _extract_loopback_mode

        s = Setting(gpo_id="x", side="Computer", cse="Security",
                    identity="Configure user group policy loopback processing mode",
                    display_name="Loopback", display_value="Merge",
                    raw={}, from_disabled_side=False)
        assert _extract_loopback_mode(s) == "merge"

    def test_extract_loopback_mode_not_configured(self):
        from gpo_lens.topology import _extract_loopback_mode

        s = Setting(gpo_id="x", side="Computer", cse="Security",
                    identity="Configure user group policy loopback processing mode",
                    display_name="Loopback", display_value="Not Configured",
                    raw={}, from_disabled_side=False)
        assert _extract_loopback_mode(s) is None

    def test_extract_loopback_mode_disabled(self):
        from gpo_lens.topology import _extract_loopback_mode

        s = Setting(gpo_id="x", side="Computer", cse="Security",
                    identity="Configure user group policy loopback processing mode",
                    display_name="Loopback", display_value="Disabled",
                    raw={}, from_disabled_side=False)
        assert _extract_loopback_mode(s) is None

    def test_extract_loopback_mode_unknown(self):
        from gpo_lens.topology import _extract_loopback_mode

        s = Setting(gpo_id="x", side="Computer", cse="Security",
                    identity="Configure user group policy loopback processing mode",
                    display_name="Loopback", display_value="SomeWeirdValue",
                    raw={}, from_disabled_side=False)
        assert _extract_loopback_mode(s) == "unknown"

    def test_extract_loopback_mode_from_security_cse_raw(self):
        from gpo_lens.topology import _extract_loopback_mode

        s = Setting(gpo_id="x", side="Computer", cse="Security",
                    identity="Configure user group policy loopback processing mode",
                    display_name="Loopback", display_value="",
                    raw={"children": [
                        {"tag": "SettingString", "text": "Replace"},
                    ]}, from_disabled_side=False)
        assert _extract_loopback_mode(s) == "replace"

    def test_extract_loopback_mode_from_security_cse_raw_numeric(self):
        from gpo_lens.topology import _extract_loopback_mode

        s = Setting(gpo_id="x", side="Computer", cse="Security",
                    identity="Configure user group policy loopback processing mode",
                    display_name="Loopback", display_value="",
                    raw={"children": [
                        {"tag": "SettingNumber", "text": "2"},
                    ]}, from_disabled_side=False)
        assert _extract_loopback_mode(s) == "merge"

    def test_extract_loopback_mode_from_dropdownlist(self):
        from gpo_lens.topology import _extract_loopback_mode

        s = Setting(gpo_id="x", side="Computer", cse="Registry",
                    identity="Configure user group policy loopback processing mode",
                    display_name="Loopback", display_value="",
                    raw={"children": [
                        {"tag": "DropDownList", "children": [
                            {"tag": "Value", "children": [
                                {"tag": "Name", "text": "Replace"},
                            ]},
                        ]},
                    ]}, from_disabled_side=False)
        assert _extract_loopback_mode(s) == "replace"

    def test_extract_loopback_mode_state_disabled(self):
        from gpo_lens.topology import _extract_loopback_mode

        s = Setting(gpo_id="x", side="Computer", cse="Registry",
                    identity="Configure user group policy loopback processing mode",
                    display_name="Loopback", display_value="",
                    raw={"children": [
                        {"tag": "State", "text": "Disabled"},
                    ]}, from_disabled_side=False)
        assert _extract_loopback_mode(s) is None

    def test_loopback_awareness_mixed_mode(self):
        from gpo_lens.topology import loopback_awareness

        gpo = _make_gpo(
            id="11111111111111111111111111111111", name="LB",
            settings=[
                Setting(gpo_id="11111111111111111111111111111111",
                        side="Computer", cse="Security",
                        identity="Configure user group policy loopback processing mode",
                        display_name="LB1", display_value="Replace",
                        raw={}, from_disabled_side=False),
                Setting(gpo_id="11111111111111111111111111111111",
                        side="Computer", cse="Security",
                        identity="Configure group policy loopback processing mode",
                        display_name="LB2", display_value="Merge",
                        raw={}, from_disabled_side=False),
            ])
        estate = Estate(domain="test.local", gpos=[gpo])
        result = loopback_awareness(estate)
        assert result["11111111111111111111111111111111"] == "mixed"

    def test_loopback_awareness_excludes_disabled(self):
        from gpo_lens.topology import loopback_awareness

        gpo = _make_gpo(id="11111111111111111111111111111111", name="LB",
                        settings=[Setting(
                            gpo_id="11111111111111111111111111111111",
                            side="Computer", cse="Security",
                            identity="Configure user group policy loopback processing mode",
                            display_name="Loopback", display_value="Not Configured",
                            raw={}, from_disabled_side=False,
                        )])
        estate = Estate(domain="test.local", gpos=[gpo])
        result = loopback_awareness(estate)
        assert "11111111111111111111111111111111" not in result


# ---------------------------------------------------------------------------
# wmi_filtered_gpos
# ---------------------------------------------------------------------------


class TestWmiFilteredGpos:
    def test_returns_gpos_with_wmi_filter(self):
        from gpo_lens.topology import wmi_filtered_gpos

        gpo = _make_gpo(id="11111111111111111111111111111111", name="WMI GPO",
                        wmi_filter="SomeFilter")
        estate = Estate(domain="test.local", gpos=[gpo])
        result = wmi_filtered_gpos(estate)
        assert len(result) == 1
        assert result[0].wmi_filter == "SomeFilter"

    def test_excludes_gpos_without_wmi_filter(self):
        from gpo_lens.topology import wmi_filtered_gpos

        gpo = _make_gpo(id="11111111111111111111111111111111", name="No WMI")
        estate = Estate(domain="test.local", gpos=[gpo])
        result = wmi_filtered_gpos(estate)
        assert result == []


# ---------------------------------------------------------------------------
# som_conflicts / precedence_conflicts
# ---------------------------------------------------------------------------


class TestSomConflicts:
    def test_detects_conflict_between_two_gpos(self):
        from gpo_lens.topology import som_conflicts

        g1 = _make_gpo(id="11111111111111111111111111111111", name="GPO-A",
                       settings=[Setting(gpo_id="11111111111111111111111111111111",
                                         side="User", cse="Registry",
                                         identity="HKLM\\X", display_name="X",
                                         display_value="A", raw={},
                                         from_disabled_side=False)])
        g2 = _make_gpo(id="22222222222222222222222222222222", name="GPO-B",
                       settings=[Setting(gpo_id="22222222222222222222222222222222",
                                         side="User", cse="Registry",
                                         identity="HKLM\\X", display_name="X",
                                         display_value="B", raw={},
                                         from_disabled_side=False)])
        som = Som(path="dc=test,dc=local", name="test", container_type="domain",
                  inheritance_blocked=False,
                  links=[SomLink(gpo_id="11111111111111111111111111111111",
                                 order=1, enabled=True, enforced=False,
                                 target="dc=test,dc=local"),
                         SomLink(gpo_id="22222222222222222222222222222222",
                                 order=2, enabled=True, enforced=False,
                                 target="dc=test,dc=local")])
        estate = Estate(domain="test.local", gpos=[g1, g2], soms=[som])
        conflicts = som_conflicts(estate, "dc=test,dc=local")
        assert len(conflicts) == 1
        assert conflicts[0].identity == "HKLM\\X"
        assert conflicts[0].winner == "GPO-B"

    def test_no_conflict_when_values_agree(self):
        from gpo_lens.topology import som_conflicts

        g1 = _make_gpo(id="11111111111111111111111111111111", name="GPO-A",
                       settings=[Setting(gpo_id="11111111111111111111111111111111",
                                         side="User", cse="Registry",
                                         identity="HKLM\\X", display_name="X",
                                         display_value="Same", raw={},
                                         from_disabled_side=False)])
        g2 = _make_gpo(id="22222222222222222222222222222222", name="GPO-B",
                       settings=[Setting(gpo_id="22222222222222222222222222222222",
                                         side="User", cse="Registry",
                                         identity="HKLM\\X", display_name="X",
                                         display_value="Same", raw={},
                                         from_disabled_side=False)])
        som = Som(path="dc=test,dc=local", name="test", container_type="domain",
                  inheritance_blocked=False,
                  links=[SomLink(gpo_id="11111111111111111111111111111111",
                                 order=1, enabled=True, enforced=False,
                                 target="dc=test,dc=local"),
                         SomLink(gpo_id="22222222222222222222222222222222",
                                 order=2, enabled=True, enforced=False,
                                 target="dc=test,dc=local")])
        estate = Estate(domain="test.local", gpos=[g1, g2], soms=[som])
        conflicts = som_conflicts(estate, "dc=test,dc=local")
        assert conflicts == []

    def test_returns_empty_for_missing_som(self):
        from gpo_lens.topology import som_conflicts

        estate = Estate(domain="test.local")
        conflicts = som_conflicts(estate, "dc=nowhere,dc=local")
        assert conflicts == []

    def test_skips_disabled_side_settings(self):
        from gpo_lens.topology import som_conflicts

        g1 = _make_gpo(id="11111111111111111111111111111111", name="GPO-A",
                       settings=[Setting(gpo_id="11111111111111111111111111111111",
                                         side="User", cse="Registry",
                                         identity="HKLM\\X", display_name="X",
                                         display_value="A", raw={},
                                         from_disabled_side=True)])
        g2 = _make_gpo(id="22222222222222222222222222222222", name="GPO-B",
                       settings=[Setting(gpo_id="22222222222222222222222222222222",
                                         side="User", cse="Registry",
                                         identity="HKLM\\X", display_name="X",
                                         display_value="B", raw={},
                                         from_disabled_side=False)])
        som = Som(path="dc=test,dc=local", name="test", container_type="domain",
                  inheritance_blocked=False,
                  links=[SomLink(gpo_id="11111111111111111111111111111111",
                                 order=1, enabled=True, enforced=False,
                                 target="dc=test,dc=local"),
                         SomLink(gpo_id="22222222222222222222222222222222",
                                 order=2, enabled=True, enforced=False,
                                 target="dc=test,dc=local")])
        estate = Estate(domain="test.local", gpos=[g1, g2], soms=[som])
        conflicts = som_conflicts(estate, "dc=test,dc=local")
        assert conflicts == []


class TestPrecedenceConflicts:
    def test_estate_wide_conflicts(self):
        from gpo_lens.topology import precedence_conflicts

        g1 = _make_gpo(id="11111111111111111111111111111111", name="GPO-A",
                       settings=[Setting(gpo_id="11111111111111111111111111111111",
                                         side="User", cse="Registry",
                                         identity="HKLM\\X", display_name="X",
                                         display_value="A", raw={},
                                         from_disabled_side=False)])
        g2 = _make_gpo(id="22222222222222222222222222222222", name="GPO-B",
                       settings=[Setting(gpo_id="22222222222222222222222222222222",
                                         side="User", cse="Registry",
                                         identity="HKLM\\X", display_name="X",
                                         display_value="B", raw={},
                                         from_disabled_side=False)])
        som = Som(path="dc=test,dc=local", name="test", container_type="domain",
                  inheritance_blocked=False,
                  links=[SomLink(gpo_id="11111111111111111111111111111111",
                                 order=1, enabled=True, enforced=False,
                                 target="dc=test,dc=local"),
                         SomLink(gpo_id="22222222222222222222222222222222",
                                 order=2, enabled=True, enforced=False,
                                 target="dc=test,dc=local")])
        estate = Estate(domain="test.local", gpos=[g1, g2], soms=[som])
        results = precedence_conflicts(estate)
        assert len(results) == 1
        assert results[0][0].path == "dc=test,dc=local"
        assert len(results[0][1]) == 1

    def test_excludes_site_soms(self):
        from gpo_lens.topology import precedence_conflicts

        g1 = _make_gpo(id="11111111111111111111111111111111", name="GPO-A",
                       settings=[Setting(gpo_id="11111111111111111111111111111111",
                                         side="User", cse="Registry",
                                         identity="HKLM\\X", display_name="X",
                                         display_value="A", raw={},
                                         from_disabled_side=False)])
        g2 = _make_gpo(id="22222222222222222222222222222222", name="GPO-B",
                       settings=[Setting(gpo_id="22222222222222222222222222222222",
                                         side="User", cse="Registry",
                                         identity="HKLM\\X", display_name="X",
                                         display_value="B", raw={},
                                         from_disabled_side=False)])
        site = Som(path="cn=site,cn=sites,cn=configuration,dc=test,dc=local",
                   name="Site", container_type="site",
                   inheritance_blocked=False,
                   links=[SomLink(gpo_id="11111111111111111111111111111111",
                                  order=1, enabled=True, enforced=False,
                                  target="cn=site"),
                          SomLink(gpo_id="22222222222222222222222222222222",
                                  order=2, enabled=True, enforced=False,
                                  target="cn=site")])
        estate = Estate(domain="test.local", gpos=[g1, g2], soms=[site])
        results = precedence_conflicts(estate)
        assert results == []


# ---------------------------------------------------------------------------
# settings_at_som
# ---------------------------------------------------------------------------


class TestSettingsAtSom:
    def test_returns_effective_settings(self):
        from gpo_lens.topology import settings_at_som

        g1 = _make_gpo(id="11111111111111111111111111111111", name="GPO-A",
                       settings=[Setting(gpo_id="11111111111111111111111111111111",
                                         side="User", cse="Registry",
                                         identity="HKLM\\X", display_name="X",
                                         display_value="A", raw={},
                                         from_disabled_side=False)])
        g2 = _make_gpo(id="22222222222222222222222222222222", name="GPO-B",
                       settings=[Setting(gpo_id="22222222222222222222222222222222",
                                         side="User", cse="Registry",
                                         identity="HKLM\\X", display_name="X",
                                         display_value="B", raw={},
                                         from_disabled_side=False)])
        som = Som(path="dc=test,dc=local", name="test", container_type="domain",
                  inheritance_blocked=False,
                  links=[SomLink(gpo_id="11111111111111111111111111111111",
                                 order=1, enabled=True, enforced=False,
                                 target="dc=test,dc=local"),
                         SomLink(gpo_id="22222222222222222222222222222222",
                                 order=2, enabled=True, enforced=False,
                                 target="dc=test,dc=local")])
        estate = Estate(domain="test.local", gpos=[g1, g2], soms=[som])
        settings = settings_at_som(estate, "dc=test,dc=local")
        assert len(settings) == 1
        assert settings[0].display_value == "B"
        assert settings[0].winner_gpo_name == "GPO-B"
        assert len(settings[0].overridden_by) == 1
        assert settings[0].overridden_by[0][0] == "GPO-A"

    def test_returns_empty_for_missing_som(self):
        from gpo_lens.topology import settings_at_som

        estate = Estate(domain="test.local")
        settings = settings_at_som(estate, "dc=nowhere,dc=local")
        assert settings == []


# ---------------------------------------------------------------------------
# is_security_filtered
# ---------------------------------------------------------------------------


class TestIsSecurityFiltered:
    def test_not_filtered_when_au_has_apply(self):
        from gpo_lens.topology import is_security_filtered

        gpo = _make_gpo(id="11111111111111111111111111111111", name="GPO",
                        delegation=[DelegationEntry(
                            gpo_id="", trustee="Authenticated Users",
                            trustee_sid="S-1-5-11",
                            permission="Apply Group Policy", allowed=True,
                        )])
        assert is_security_filtered(gpo) is False

    def test_filtered_when_only_specific_group_has_apply(self):
        from gpo_lens.topology import is_security_filtered

        gpo = _make_gpo(id="11111111111111111111111111111111", name="GPO",
                        delegation=[DelegationEntry(
                            gpo_id="", trustee="Helpdesk Operators",
                            trustee_sid="S-1-5-21-1-2-3-1000",
                            permission="Apply Group Policy", allowed=True,
                        )])
        assert is_security_filtered(gpo) is True

    def test_not_filtered_when_no_delegation_data(self):
        from gpo_lens.topology import is_security_filtered

        gpo = _make_gpo(id="11111111111111111111111111111111", name="GPO",
                        delegation=[])
        assert is_security_filtered(gpo) is False

    def test_sddl_fallback_not_filtered_with_au_allow(self):
        from gpo_lens.topology import is_security_filtered

        gpo = _make_gpo(id="11111111111111111111111111111111", name="GPO",
                        sddl="D:(A;;GA;;;S-1-5-11)", delegation=[])
        assert is_security_filtered(gpo) is False

    def test_sddl_fallback_filtered_without_broad_allow(self):
        from gpo_lens.topology import is_security_filtered

        gpo = _make_gpo(id="11111111111111111111111111111111", name="GPO",
                        sddl="D:(A;;GA;;;S-1-5-21-1-2-3-1000)", delegation=[])
        assert is_security_filtered(gpo) is True

    def test_sddl_fallback_empty_dacl_not_filtered(self):
        from gpo_lens.topology import is_security_filtered

        gpo = _make_gpo(id="11111111111111111111111111111111", name="GPO",
                        sddl="D:", delegation=[])
        assert is_security_filtered(gpo) is False


# ---------------------------------------------------------------------------
# security_filtering_detail
# ---------------------------------------------------------------------------


class TestSecurityFilteringDetail:
    def test_au_read_and_apply_tracked(self):
        from gpo_lens.topology import security_filtering_detail

        gpo = _make_gpo(id="11111111111111111111111111111111", name="GPO",
                        delegation=[DelegationEntry(
                            gpo_id="", trustee="Authenticated Users",
                            trustee_sid="S-1-5-11",
                            permission="Apply Group Policy", allowed=True,
                        )])
        detail = security_filtering_detail(gpo)
        assert detail.has_au_read is True
        assert "Authenticated Users" in detail.apply_trustees

    def test_sddl_fallback_tracks_au_read(self):
        from gpo_lens.topology import security_filtering_detail

        gpo = _make_gpo(id="11111111111111111111111111111111", name="GPO",
                        sddl="D:(A;;GA;;;S-1-5-11)", delegation=[])
        detail = security_filtering_detail(gpo)
        assert detail.has_au_read is True

    def test_deny_does_not_count_as_apply_trustee(self):
        from gpo_lens.topology import security_filtering_detail

        gpo = _make_gpo(id="11111111111111111111111111111111", name="GPO",
                        delegation=[DelegationEntry(
                            gpo_id="", trustee="Authenticated Users",
                            trustee_sid="S-1-5-11",
                            permission="Apply Group Policy", allowed=False,
                        )])
        detail = security_filtering_detail(gpo)
        assert "Authenticated Users" not in detail.apply_trustees


# ---------------------------------------------------------------------------
# scope_caveats
# ---------------------------------------------------------------------------


class TestScopeCaveats:
    def test_all_links_disabled_caveat(self):
        from gpo_lens.topology import scope_caveats

        som = Som(path="dc=test,dc=local", name="test", container_type="domain",
                  inheritance_blocked=False,
                  links=[SomLink(gpo_id="11111111111111111111111111111111",
                                 order=1, enabled=False, enforced=False,
                                 target="dc=test,dc=local")])
        estate = Estate(domain="test.local", soms=[som])
        caveats = scope_caveats(estate, "dc=test,dc=local")
        assert any("all" in c and "disabled" in c for c in caveats)

    def test_missing_som_returns_empty(self):
        from gpo_lens.topology import scope_caveats

        estate = Estate(domain="test.local")
        caveats = scope_caveats(estate, "dc=nowhere,dc=local")
        assert caveats == []

    def test_security_filtered_gpo_caveat(self):
        from gpo_lens.topology import scope_caveats

        gpo = _make_gpo(id="11111111111111111111111111111111", name="FilteredGPO",
                        delegation=[DelegationEntry(
                            gpo_id="", trustee="Helpdesk Operators",
                            trustee_sid="S-1-5-21-1-2-3-1000",
                            permission="Apply Group Policy", allowed=True,
                        )])
        som = Som(path="dc=test,dc=local", name="test", container_type="domain",
                  inheritance_blocked=False,
                  links=[SomLink(gpo_id="11111111111111111111111111111111",
                                 order=1, enabled=True, enforced=False,
                                 target="dc=test,dc=local")])
        estate = Estate(domain="test.local", gpos=[gpo], soms=[som])
        caveats = scope_caveats(estate, "dc=test,dc=local")
        assert any("security-filtered" in c for c in caveats)

    def test_wmi_filter_caveat(self):
        from gpo_lens.topology import scope_caveats

        gpo = _make_gpo(id="11111111111111111111111111111111", name="WmiGPO",
                        wmi_filter="SomeFilter",
                        delegation=[DelegationEntry(
                            gpo_id="", trustee="Authenticated Users",
                            trustee_sid="S-1-5-11",
                            permission="Apply Group Policy", allowed=True,
                        )])
        som = Som(path="dc=test,dc=local", name="test", container_type="domain",
                  inheritance_blocked=False,
                  links=[SomLink(gpo_id="11111111111111111111111111111111",
                                 order=1, enabled=True, enforced=False,
                                 target="dc=test,dc=local")])
        estate = Estate(domain="test.local", gpos=[gpo], soms=[som])
        caveats = scope_caveats(estate, "dc=test,dc=local")
        assert any("WMI filter" in c for c in caveats)


# ---------------------------------------------------------------------------
# effective_scope
# ---------------------------------------------------------------------------


class TestEffectiveScope:
    def test_returns_scope_for_gpo_by_id(self):
        from gpo_lens.topology import effective_scope

        gpo = _make_gpo(id="11111111111111111111111111111111", name="TestGPO",
                        delegation=[DelegationEntry(
                            gpo_id="", trustee="Authenticated Users",
                            trustee_sid="S-1-5-11",
                            permission="Apply Group Policy", allowed=True,
                        )],
                        links=[GpoLink(gpo_id="11111111111111111111111111111111",
                                       som_name="test", som_path="dc=test,dc=local",
                                       link_enabled=True, enforced=False)])
        estate = Estate(domain="test.local", gpos=[gpo])
        scope = effective_scope(estate, "11111111111111111111111111111111")
        assert scope is not None
        assert scope.gpo_name == "TestGPO"
        assert scope.security_filtering.is_filtered is False

    def test_returns_scope_for_gpo_by_name(self):
        from gpo_lens.topology import effective_scope

        gpo = _make_gpo(id="11111111111111111111111111111111", name="TestGPO",
                        delegation=[DelegationEntry(
                            gpo_id="", trustee="Authenticated Users",
                            trustee_sid="S-1-5-11",
                            permission="Apply Group Policy", allowed=True,
                        )])
        estate = Estate(domain="test.local", gpos=[gpo])
        scope = effective_scope(estate, "TestGPO")
        assert scope is not None
        assert scope.gpo_name == "TestGPO"

    def test_returns_none_for_unknown_gpo(self):
        from gpo_lens.topology import effective_scope

        estate = Estate(domain="test.local")
        scope = effective_scope(estate, "nonexistent")
        assert scope is None

    def test_no_links_caveat(self):
        from gpo_lens.topology import effective_scope

        gpo = _make_gpo(id="11111111111111111111111111111111", name="UnlinkedGPO",
                        delegation=[DelegationEntry(
                            gpo_id="", trustee="Authenticated Users",
                            trustee_sid="S-1-5-11",
                            permission="Apply Group Policy", allowed=True,
                        )])
        estate = Estate(domain="test.local", gpos=[gpo])
        scope = effective_scope(estate, "11111111111111111111111111111111")
        assert scope is not None
        assert any("no links" in c.lower() for c in scope.caveats)

    def test_no_delegation_caveat(self):
        from gpo_lens.topology import effective_scope

        gpo = _make_gpo(id="11111111111111111111111111111111", name="NoDelegGPO",
                        delegation=[])
        estate = Estate(domain="test.local", gpos=[gpo])
        scope = effective_scope(estate, "11111111111111111111111111111111")
        assert scope is not None
        assert any("No delegation entries" in c for c in scope.caveats)

    def test_broken_wmi_filter_caveat(self):
        from gpo_lens.topology import effective_scope

        gpo = _make_gpo(id="11111111111111111111111111111111", name="BrokenWmiGPO",
                        wmi_filter="NonexistentFilter",
                        delegation=[DelegationEntry(
                            gpo_id="", trustee="Authenticated Users",
                            trustee_sid="S-1-5-11",
                            permission="Apply Group Policy", allowed=True,
                        )])
        estate = Estate(domain="test.local", gpos=[gpo])
        scope = effective_scope(estate, "11111111111111111111111111111111")
        assert scope is not None
        assert scope.wmi_filter is not None
        assert scope.wmi_filter.is_broken is True

    def test_ms16_072_caveat(self):
        from gpo_lens.topology import effective_scope

        gpo = _make_gpo(id="11111111111111111111111111111111", name="MS16GPO",
                        delegation=[DelegationEntry(
                            gpo_id="", trustee="Everyone",
                            trustee_sid="S-1-1-0",
                            permission="Read", allowed=True,
                        )])
        estate = Estate(domain="test.local", gpos=[gpo])
        scope = effective_scope(estate, "11111111111111111111111111111111")
        assert scope is not None
        assert any("MS16-072" in c for c in scope.caveats)


# ---------------------------------------------------------------------------
# site_scopes / has_site_links
# ---------------------------------------------------------------------------


class TestSiteScopes:
    def test_site_scopes_returns_site_links(self):
        from gpo_lens.topology import site_scopes

        gpo = _make_gpo(id="11111111111111111111111111111111", name="SiteGPO")
        site = Som(path="cn=site,cn=sites,cn=configuration,dc=test,dc=local",
                   name="Default-First-Site-Name", container_type="site",
                   inheritance_blocked=False,
                   links=[SomLink(gpo_id="11111111111111111111111111111111",
                                  order=1, enabled=True, enforced=False,
                                  target="cn=site")])
        estate = Estate(domain="test.local", gpos=[gpo], soms=[site])
        scopes = site_scopes(estate)
        assert len(scopes) == 1
        assert scopes[0].name == "Default-First-Site-Name"
        assert len(scopes[0].links) == 1
        assert scopes[0].links[0].gpo_name == "SiteGPO"

    def test_site_scopes_returns_empty_when_no_sites(self):
        from gpo_lens.topology import site_scopes

        estate = Estate(domain="test.local")
        scopes = site_scopes(estate)
        assert scopes == []

    def test_has_site_links_true(self):
        from gpo_lens.topology import has_site_links

        site = Som(path="cn=site,cn=sites,cn=configuration,dc=test,dc=local",
                   name="Site", container_type="site",
                   inheritance_blocked=False,
                   links=[SomLink(gpo_id="11111111111111111111111111111111",
                                  order=1, enabled=True, enforced=False,
                                  target="cn=site")])
        estate = Estate(domain="test.local", soms=[site])
        assert has_site_links(estate) is True

    def test_has_site_links_false_when_disabled(self):
        from gpo_lens.topology import has_site_links

        site = Som(path="cn=site,cn=sites,cn=configuration,dc=test,dc=local",
                   name="Site", container_type="site",
                   inheritance_blocked=False,
                   links=[SomLink(gpo_id="11111111111111111111111111111111",
                                  order=1, enabled=False, enforced=False,
                                  target="cn=site")])
        estate = Estate(domain="test.local", soms=[site])
        assert has_site_links(estate) is False

    def test_has_site_links_false_when_no_sites(self):
        from gpo_lens.topology import has_site_links

        estate = Estate(domain="test.local")
        assert has_site_links(estate) is False
