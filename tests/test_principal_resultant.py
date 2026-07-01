"""Tests for the principal resultant (Plan 021 Phase A).

Covers token building (A.1), security-filter gate evaluation (A.3), WMI/ILT
exclusion (decision 2), the "resultant given collected inputs" label
(decision 4), and that a GPO the token CAN Apply contributes (AC-2).
No samples required — all fixtures are synthetic.
"""

from __future__ import annotations

import pytest

from gpo_lens.danger import DangerFinding
from gpo_lens.merge import (
    ConditionalDanger,
    ExcludedGpo,
    ExcludedSetting,
    build_token,
    principal_resultant,
)
from gpo_lens.model import (
    DelegationEntry,
    Estate,
    Gpo,
    GroupMembership,
    ResolvedPrincipal,
    Setting,
    Som,
    SomLink,
    WmiFilter,
)

DOMAIN_SID = "s-1-5-21-1000000000-2000000000-3000000000"
USER_SID = f"{DOMAIN_SID}-1001"
GROUP_SID = f"{DOMAIN_SID}-2001"
OTHER_GROUP_SID = f"{DOMAIN_SID}-2002"
ROOT_DN = "dc=test,dc=local"

GPO_BROAD = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
GPO_GROUP_APPLY = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
GPO_OTHER_GROUP = "cccccccc-cccc-cccc-cccc-cccccccccccc"
GPO_WMI = "dddddddd-dddd-dddd-dddd-dddddddddddd"
GPO_NO_DELEGATION = "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"


def _gpo(
    gpo_id: str,
    name: str,
    *,
    settings: list[Setting] | None = None,
    delegation: list[DelegationEntry] | None = None,
    sddl: str | None = None,
    wmi_filter: str | None = None,
    sysvol_path: str | None = None,
    user_enabled: bool = True,
    computer_enabled: bool = True,
) -> Gpo:
    return Gpo(
        id=gpo_id,
        name=name,
        domain="test.local",
        created=None,
        modified=None,
        read=None,
        computer_enabled=computer_enabled,
        user_enabled=user_enabled,
        computer_ver_ds=None,
        computer_ver_sysvol=None,
        user_ver_ds=None,
        user_ver_sysvol=None,
        sddl=sddl,
        owner=None,
        filter_data_available=False,
        wmi_filter=wmi_filter,
        sysvol_path=sysvol_path,
        settings=settings or [],
        delegation=delegation or [],
    )


def _user_setting(gpo_id: str, identity: str, value: str) -> Setting:
    return Setting(
        gpo_id=gpo_id, side="User", cse="Registry",
        identity=identity, display_name=identity,
        display_value=value, raw={}, from_disabled_side=False,
    )


def _computer_setting(gpo_id: str, identity: str, value: str) -> Setting:
    return Setting(
        gpo_id=gpo_id, side="Computer", cse="Registry",
        identity=identity, display_name=identity,
        display_value=value, raw={}, from_disabled_side=False,
    )


def _au_apply() -> list[DelegationEntry]:
    return [
        DelegationEntry(
            gpo_id="", trustee="Authenticated Users", trustee_sid="S-1-5-11",
            permission="Apply Group Policy", allowed=True,
        ),
    ]


def _group_apply(group_name: str, group_sid: str) -> list[DelegationEntry]:
    return [
        DelegationEntry(
            gpo_id="", trustee=group_name, trustee_sid=group_sid,
            permission="Apply Group Policy", allowed=True,
        ),
    ]


_DOMAIN_GROUP_SID = "S-1-5-21-1000000000-2000000000-3000000000-2001"
_OTHER_GROUP_SID_FULL = "S-1-5-21-1000000000-2000000000-3000000000-2002"


def _principal_estate() -> Estate:
    principals = {
        USER_SID: ResolvedPrincipal(
            sid=USER_SID, name="TEST\\jdoe", sam="jdoe",
            principal_type="User", domain="TEST", resolved=True,
        ),
        GROUP_SID: ResolvedPrincipal(
            sid=GROUP_SID, name="TEST\\Helpdesk Operators", sam="Helpdesk Operators",
            principal_type="Group", domain="TEST", resolved=True,
        ),
        OTHER_GROUP_SID: ResolvedPrincipal(
            sid=OTHER_GROUP_SID, name="TEST\\Server Admins", sam="Server Admins",
            principal_type="Group", domain="TEST", resolved=True,
        ),
    }
    group_members = {
        GROUP_SID: GroupMembership(
            sid=GROUP_SID, name="TEST\\Helpdesk Operators",
            members=(USER_SID,), member_count=1,
        ),
        OTHER_GROUP_SID: GroupMembership(
            sid=OTHER_GROUP_SID, name="TEST\\Server Admins",
            members=(), member_count=0,
        ),
    }
    gpos = [
        _gpo(GPO_BROAD, "gpo-broad",
             settings=[_user_setting(GPO_BROAD, r"HKCU\Software\A", "1")],
             delegation=_au_apply()),
        _gpo(GPO_GROUP_APPLY, "gpo-group-apply",
             settings=[_user_setting(GPO_GROUP_APPLY, r"HKCU\Software\B", "2")],
             delegation=_group_apply("Helpdesk Operators", _DOMAIN_GROUP_SID)),
        _gpo(GPO_OTHER_GROUP, "gpo-other-group",
             settings=[_user_setting(GPO_OTHER_GROUP, r"HKCU\Software\C", "3")],
             delegation=_group_apply("Server Admins", _OTHER_GROUP_SID_FULL)),
        _gpo(GPO_WMI, "gpo-wmi",
             settings=[_user_setting(GPO_WMI, r"HKCU\Software\D", "4")],
             delegation=_au_apply(),
             wmi_filter="Some WMI Filter"),
        _gpo(GPO_NO_DELEGATION, "gpo-no-delegation",
             settings=[_user_setting(GPO_NO_DELEGATION, r"HKCU\Software\E", "5")]),
    ]
    som = Som(
        path=ROOT_DN, name="test", container_type="domain",
        inheritance_blocked=False,
        links=[
            SomLink(gpo_id=GPO_BROAD, order=1, enabled=True,
                    enforced=False, target=ROOT_DN),
            SomLink(gpo_id=GPO_GROUP_APPLY, order=2, enabled=True,
                    enforced=False, target=ROOT_DN),
            SomLink(gpo_id=GPO_OTHER_GROUP, order=3, enabled=True,
                    enforced=False, target=ROOT_DN),
            SomLink(gpo_id=GPO_WMI, order=4, enabled=True,
                    enforced=False, target=ROOT_DN),
            SomLink(gpo_id=GPO_NO_DELEGATION, order=5, enabled=True,
                    enforced=False, target=ROOT_DN),
        ],
    )
    wmi_filters = [WmiFilter(name="Some WMI Filter", query="SELECT * FROM Win32_OperatingSystem")]
    return Estate(
        domain="test.local", gpos=gpos, soms=[som],
        wmi_filters=wmi_filters, principals=principals,
        group_members=group_members,
    )


@pytest.fixture()
def estate():
    return _principal_estate()


# ---------------------------------------------------------------------------
# A.1 — build_token
# ---------------------------------------------------------------------------

class TestBuildToken:
    def test_includes_principal_sid(self, estate):
        token = build_token(estate, USER_SID)
        assert USER_SID in token.token_sids

    def test_includes_well_known_groups(self, estate):
        token = build_token(estate, USER_SID)
        assert "s-1-5-11" in token.token_sids  # Authenticated Users
        assert "s-1-1-0" in token.token_sids    # Everyone

    def test_includes_domain_users_for_user(self, estate):
        token = build_token(estate, USER_SID)
        assert f"{DOMAIN_SID}-513" in token.token_sids  # Domain Users

    def test_expands_transitive_group_membership(self, estate):
        token = build_token(estate, USER_SID)
        assert GROUP_SID in token.token_sids

    def test_computer_principal_gets_domain_computers(self, estate):
        comp_sid = f"{DOMAIN_SID}-5001"
        estate.principals[comp_sid] = ResolvedPrincipal(
            sid=comp_sid, name="TEST\\WKS$", sam="WKS$",
            principal_type="Computer", domain="TEST", resolved=True,
        )
        token = build_token(estate, comp_sid)
        assert f"{DOMAIN_SID}-515" in token.token_sids  # Domain Computers

    def test_records_caveat_for_unresolved_foreign_sid(self, estate):
        estate.group_members[GROUP_SID] = GroupMembership(
            sid=GROUP_SID, name="TEST\\Helpdesk Operators",
            members=(USER_SID, "s-1-5-21-9999999999-9999999999-9999999999-1234"),
            member_count=2,
        )
        token = build_token(estate, USER_SID)
        assert GROUP_SID in token.token_sids
        assert "s-1-5-21-9999999999-9999999999-9999999999-1234" not in token.token_sids


# ---------------------------------------------------------------------------
# A.3 — Security-filter gate evaluation
# ---------------------------------------------------------------------------

class TestSecurityFilterGate:
    def test_broad_gpo_contributes_to_resultant(self, estate):
        result = principal_resultant(estate, USER_SID)
        idents = {m.identity for m in result.settings}
        assert r"HKCU\Software\A" in idents

    def test_gpo_filtered_out_when_token_does_not_match(self, estate):
        result = principal_resultant(estate, USER_SID)
        idents = {m.identity for m in result.settings}
        assert r"HKCU\Software\C" not in idents
        excluded_kinds = {e.kind for e in result.excluded}
        assert "security_filter" in excluded_kinds
        assert any(e.gpo_id == GPO_OTHER_GROUP for e in result.excluded)

    def test_gpo_matching_group_membership_contributes(self, estate):
        result = principal_resultant(estate, USER_SID)
        idents = {m.identity for m in result.settings}
        assert r"HKCU\Software\B" in idents

    def test_excluded_gpo_records_reason(self, estate):
        result = principal_resultant(estate, USER_SID)
        exc = next(e for e in result.excluded if e.gpo_id == GPO_OTHER_GROUP)
        assert "security filter" in exc.reason.lower()
        assert exc.kind == "security_filter"

    def test_no_delegation_gpo_included_with_caveat(self, estate):
        result = principal_resultant(estate, USER_SID)
        idents = {m.identity for m in result.settings}
        assert r"HKCU\Software\E" in idents


# ---------------------------------------------------------------------------
# A.3 — WMI filter exclusion (decision 2: flag, don't simulate)
# ---------------------------------------------------------------------------

class TestWmiExclusion:
    def test_wmi_gated_gpo_excluded_and_listed(self, estate):
        result = principal_resultant(estate, USER_SID)
        idents = {m.identity for m in result.settings}
        assert r"HKCU\Software\D" not in idents
        wmi_excluded = [e for e in result.excluded if e.kind == "wmi_filter"]
        assert len(wmi_excluded) == 1
        assert wmi_excluded[0].gpo_id == GPO_WMI
        assert "WMI" in wmi_excluded[0].reason

    def test_wmi_excluded_never_silently_dropped(self, estate):
        result = principal_resultant(estate, USER_SID)
        excluded_ids = {e.gpo_id for e in result.excluded}
        assert GPO_WMI in excluded_ids


# ---------------------------------------------------------------------------
# A.5 — Output labeling (decision 4: "resultant given collected inputs")
# ---------------------------------------------------------------------------

class TestResultantLabeling:
    def test_caveat_summary_says_resultant_given_collected_inputs(self, estate):
        result = principal_resultant(estate, USER_SID)
        assert "resultant given collected inputs" in result.caveat_summary.lower()

    def test_caveat_summary_does_not_say_effective_unqualified(self, estate):
        result = principal_resultant(estate, USER_SID)
        assert "effective" not in result.caveat_summary.lower()

    def test_user_no_computer_labeled(self, estate):
        result = principal_resultant(estate, USER_SID)
        assert "no loopback" in result.caveat_summary.lower()
        assert "no computer" in result.caveat_summary.lower()

    def test_user_with_computer_labeled(self, estate):
        comp_sid = f"{DOMAIN_SID}-5001"
        estate.principals[comp_sid] = ResolvedPrincipal(
            sid=comp_sid, name="TEST\\WKS$", sam="WKS$",
            principal_type="Computer", domain="TEST", resolved=True,
        )
        result = principal_resultant(estate, USER_SID, computer_sid=comp_sid)
        assert "computer pair" in result.caveat_summary.lower()

    def test_computer_resultant_labeled(self, estate):
        comp_sid = f"{DOMAIN_SID}-5001"
        estate.principals[comp_sid] = ResolvedPrincipal(
            sid=comp_sid, name="TEST\\WKS$", sam="WKS$",
            principal_type="Computer", domain="TEST", resolved=True,
        )
        result = principal_resultant(estate, comp_sid)
        assert "computer resultant" in result.caveat_summary.lower()


# ---------------------------------------------------------------------------
# A.5 — Provenance + structure
# ---------------------------------------------------------------------------

class TestResultantStructure:
    def test_every_setting_traceable_to_winning_gpo(self, estate):
        result = principal_resultant(estate, USER_SID)
        for s in result.settings:
            assert s.winning_gpo_id
            assert s.winning_gpo_name
            assert s.merge_mode

    def test_principal_name_resolved(self, estate):
        result = principal_resultant(estate, USER_SID)
        assert result.principal_name == "TEST\\jdoe"
        assert result.principal_sid == USER_SID

    def test_computer_sid_none_by_default(self, estate):
        result = principal_resultant(estate, USER_SID)
        assert result.computer_sid is None

    def test_excluded_list_is_list_of_excluded_gpo(self, estate):
        result = principal_resultant(estate, USER_SID)
        assert isinstance(result.excluded, list)
        for e in result.excluded:
            assert isinstance(e, ExcludedGpo)
            assert e.reason
            assert e.kind

    def test_deterministic_settings_excluded_are_separate(self, estate):
        result = principal_resultant(estate, USER_SID)
        excluded_ids = {e.gpo_id for e in result.excluded}
        setting_gpo_ids = {s.winning_gpo_id for s in result.settings}
        assert excluded_ids.isdisjoint(setting_gpo_ids)


# ---------------------------------------------------------------------------
# DN → SOM resolution
# ---------------------------------------------------------------------------

class TestSomResolution:
    def test_dn_walk_finds_most_specific_som(self, estate):
        child_dn = f"ou=workstations,{ROOT_DN}"
        child_som = Som(
            path=child_dn, name="workstations", container_type="ou",
            inheritance_blocked=False,
            links=[
                SomLink(gpo_id=GPO_BROAD, order=1, enabled=True,
                        enforced=False, target=child_dn),
            ],
        )
        estate.soms.append(child_som)
        result = principal_resultant(estate, USER_SID, dn=child_dn)
        assert any(m.winning_gpo_id == GPO_BROAD for m in result.settings)

    def test_missing_dn_defaults_to_domain_root(self, estate):
        result = principal_resultant(estate, USER_SID, dn=None)
        assert result.settings

    def test_empty_estate_returns_empty_resultant(self):
        estate = Estate()
        result = principal_resultant(estate, "s-1-5-21-1-2-3-1000")
        assert result.settings == []
        assert result.excluded == []
        assert "resultant given collected inputs" in result.caveat_summary.lower()


# ---------------------------------------------------------------------------
# Bug 1 — Domain Users/Domain Computers RID-suffix resolution
# ---------------------------------------------------------------------------

class TestDomainUsersRidResolution:
    def test_gpo_delegated_to_domain_users_by_name_applies_to_user(self, estate):
        """A GPO whose delegation names 'Domain Users' (no SID) must match the
        user's token. The well-known name resolves to a RID suffix (-513),
        which is expanded with the estate's domain SID before intersecting
        the token's full Domain Users SID.
        """
        gpo_id = "11111111-1111-1111-1111-111111111111"
        estate.gpos.append(_gpo(
            gpo_id, "gpo-domain-users",
            settings=[_user_setting(gpo_id, r"HKCU\Software\DU", "1")],
            delegation=[DelegationEntry(
                gpo_id="", trustee="Domain Users", trustee_sid=None,
                permission="Apply Group Policy", allowed=True,
            )],
        ))
        estate.soms[0].links.append(SomLink(
            gpo_id=gpo_id, order=10, enabled=True, enforced=False, target=ROOT_DN,
        ))
        result = principal_resultant(estate, USER_SID, dn=ROOT_DN)
        idents = {m.identity for m in result.settings}
        assert r"HKCU\Software\DU" in idents

    def test_gpo_delegated_to_domain_computers_excludes_user(self, estate):
        """A GPO delegated to 'Domain Computers' (by name) must NOT apply to a
        user principal — the user token carries Domain Users (-513), not
        Domain Computers (-515).
        """
        gpo_id = "12121212-1212-1212-1212-121212121212"
        estate.gpos.append(_gpo(
            gpo_id, "gpo-domain-computers",
            settings=[_user_setting(gpo_id, r"HKCU\Software\DC", "1")],
            delegation=[DelegationEntry(
                gpo_id="", trustee="Domain Computers", trustee_sid=None,
                permission="Apply Group Policy", allowed=True,
            )],
        ))
        estate.soms[0].links.append(SomLink(
            gpo_id=gpo_id, order=10, enabled=True, enforced=False, target=ROOT_DN,
        ))
        result = principal_resultant(estate, USER_SID, dn=ROOT_DN)
        idents = {m.identity for m in result.settings}
        assert r"HKCU\Software\DC" not in idents
        assert any(e.gpo_id == gpo_id for e in result.excluded)


# ---------------------------------------------------------------------------
# Bug 2 — Token carries Domain Users XOR Domain Computers
# ---------------------------------------------------------------------------

class TestTokenDomainGroupExclusivity:
    def test_user_token_has_domain_users_not_domain_computers(self, estate):
        token = build_token(estate, USER_SID)
        assert f"{DOMAIN_SID}-513" in token.token_sids   # Domain Users
        assert f"{DOMAIN_SID}-515" not in token.token_sids  # NOT Domain Computers

    def test_computer_token_has_domain_computers_not_domain_users(self, estate):
        comp_sid = f"{DOMAIN_SID}-5001"
        estate.principals[comp_sid] = ResolvedPrincipal(
            sid=comp_sid, name="TEST\\WKS$", sam="WKS$",
            principal_type="Computer", domain="TEST", resolved=True,
        )
        token = build_token(estate, comp_sid)
        assert f"{DOMAIN_SID}-515" in token.token_sids   # Domain Computers
        assert f"{DOMAIN_SID}-513" not in token.token_sids  # NOT Domain Users


# ---------------------------------------------------------------------------
# Bug 3 — User+computer chain mode: separate DNs, both sides
# ---------------------------------------------------------------------------

class TestUserComputerPairChains:
    def _setup_pair_estate(self, estate):
        """User OU (User-side GPO) + Computer OU (Computer-side GPO)."""
        comp_sid = f"{DOMAIN_SID}-5001"
        estate.principals[comp_sid] = ResolvedPrincipal(
            sid=comp_sid, name="TEST\\WKS$", sam="WKS$",
            principal_type="Computer", domain="TEST", resolved=True,
        )
        user_dn = f"ou=users,{ROOT_DN}"
        comp_dn = f"ou=computers,{ROOT_DN}"
        user_gpo = "21111111-2111-2111-2111-211111111111"
        comp_gpo = "32222222-3222-3222-3222-322222222222"
        estate.gpos.append(_gpo(
            user_gpo, "gpo-user-side",
            settings=[_user_setting(user_gpo, r"HKCU\Software\UserOnly", "u")],
            delegation=_au_apply(),
        ))
        estate.gpos.append(_gpo(
            comp_gpo, "gpo-computer-side",
            settings=[_computer_setting(comp_gpo, r"HKLM\Software\CompOnly", "c")],
            delegation=_au_apply(),
        ))
        estate.soms.append(Som(
            path=user_dn, name="users", container_type="ou",
            inheritance_blocked=False,
            links=[SomLink(gpo_id=user_gpo, order=1, enabled=True,
                           enforced=False, target=user_dn)],
        ))
        estate.soms.append(Som(
            path=comp_dn, name="computers", container_type="ou",
            inheritance_blocked=False,
            links=[SomLink(gpo_id=comp_gpo, order=1, enabled=True,
                           enforced=False, target=comp_dn)],
        ))
        return comp_sid, user_dn, comp_dn, user_gpo, comp_gpo

    def test_both_user_and_computer_side_settings_present(self, estate):
        comp_sid, user_dn, comp_dn, _, _ = self._setup_pair_estate(estate)
        result = principal_resultant(
            estate, USER_SID, computer_sid=comp_sid,
            dn=user_dn, computer_dn=comp_dn,
        )
        idents = {m.identity for m in result.settings}
        # User-side from the user's chain (user's OU), computer-side from the
        # computer's chain (computer's OU) — both must appear.
        assert r"HKCU\Software\UserOnly" in idents
        assert r"HKLM\Software\CompOnly" in idents
        assert "computer pair" in result.caveat_summary.lower()

    def test_computer_dn_used_not_user_dn(self, estate):
        """The computer chain must resolve from computer_dn, not the user's dn.
        The computer's OU holds the only Computer-side GPO; if the user's dn
        were (incorrectly) used for the computer, no Computer-side setting
        would appear.
        """
        comp_sid, user_dn, comp_dn, _, _ = self._setup_pair_estate(estate)
        result = principal_resultant(
            estate, USER_SID, computer_sid=comp_sid,
            dn=user_dn, computer_dn=comp_dn,
        )
        comp_settings = [m for m in result.settings if m.side == "Computer"]
        assert any(m.identity == r"HKLM\Software\CompOnly" for m in comp_settings)

    def test_shared_ancestor_gated_gpo_listed_once(self, estate):
        """A GPO present in BOTH the user and computer chains (here both resolve
        to the domain-root SOM when dn/computer_dn are None) must be listed
        once in ``excluded``, not duplicated per chain.
        """
        comp_sid = f"{DOMAIN_SID}-5001"
        estate.principals[comp_sid] = ResolvedPrincipal(
            sid=comp_sid, name="TEST\\WKS$", sam="WKS$",
            principal_type="Computer", domain="TEST", resolved=True,
        )
        # GPO_OTHER_GROUP is security-filtered for the user; it sits on the
        # domain-root SOM that both chains resolve to.
        result = principal_resultant(estate, USER_SID, computer_sid=comp_sid)
        other = [e for e in result.excluded if e.gpo_id == GPO_OTHER_GROUP]
        assert len(other) == 1


# ---------------------------------------------------------------------------
# Bug 6 — Computer-chain security/WMI failures are recorded as excluded
# ---------------------------------------------------------------------------

class TestComputerChainExclusions:
    def test_computer_chain_wmi_gated_gpo_recorded_as_excluded(self, estate):
        comp_sid = f"{DOMAIN_SID}-5001"
        estate.principals[comp_sid] = ResolvedPrincipal(
            sid=comp_sid, name="TEST\\WKS$", sam="WKS$",
            principal_type="Computer", domain="TEST", resolved=True,
        )
        comp_dn = f"ou=computers,{ROOT_DN}"
        wmi_gpo = "43333333-4333-4333-4333-433333333333"
        estate.gpos.append(_gpo(
            wmi_gpo, "gpo-comp-wmi",
            settings=[_computer_setting(wmi_gpo, r"HKLM\Software\Wmi", "w")],
            delegation=_au_apply(),
            wmi_filter="Comp WMI Filter",
        ))
        estate.soms.append(Som(
            path=comp_dn, name="computers", container_type="ou",
            inheritance_blocked=False,
            links=[SomLink(gpo_id=wmi_gpo, order=1, enabled=True,
                           enforced=False, target=comp_dn)],
        ))
        result = principal_resultant(
            estate, USER_SID, computer_sid=comp_sid,
            dn=ROOT_DN, computer_dn=comp_dn,
        )
        # The WMI-gated computer-chain GPO must be listed, not silently dropped.
        wmi_excluded = [e for e in result.excluded if e.gpo_id == wmi_gpo]
        assert len(wmi_excluded) == 1
        assert wmi_excluded[0].kind == "wmi_filter"

    def test_computer_chain_security_filtered_gpo_recorded(self, estate):
        comp_sid = f"{DOMAIN_SID}-5001"
        estate.principals[comp_sid] = ResolvedPrincipal(
            sid=comp_sid, name="TEST\\WKS$", sam="WKS$",
            principal_type="Computer", domain="TEST", resolved=True,
        )
        comp_dn = f"ou=computers,{ROOT_DN}"
        # Delegated to a group the computer is NOT a member of.
        sec_gpo = "44444444-4444-4444-4444-444444444444"
        estate.gpos.append(_gpo(
            sec_gpo, "gpo-comp-secfiltered",
            settings=[_computer_setting(sec_gpo, r"HKLM\Software\Sec", "s")],
            delegation=_group_apply("Server Admins", _OTHER_GROUP_SID_FULL),
        ))
        estate.soms.append(Som(
            path=comp_dn, name="computers", container_type="ou",
            inheritance_blocked=False,
            links=[SomLink(gpo_id=sec_gpo, order=1, enabled=True,
                           enforced=False, target=comp_dn)],
        ))
        result = principal_resultant(
            estate, USER_SID, computer_sid=comp_sid,
            dn=ROOT_DN, computer_dn=comp_dn,
        )
        sec_excluded = [e for e in result.excluded if e.gpo_id == sec_gpo]
        assert len(sec_excluded) == 1
        assert sec_excluded[0].kind == "security_filter"


# ---------------------------------------------------------------------------
# Issue 7 — Deny-ACE precedence in the security gate
# ---------------------------------------------------------------------------

class TestDenyAcePrecedence:
    def test_sddl_deny_cancels_allow_on_same_trustee(self, estate):
        """An SDDL that both allows and denies Apply to Authenticated Users
        must exclude the GPO (deny precedence), not apply it.
        """
        gpo_id = "55555555-5555-5555-5555-555555555555"
        # DACL: allow GA to S-1-5-11, then deny GA to S-1-5-11.
        sddl = "D:(A;;GA;;;S-1-5-11)(D;;GA;;;S-1-5-11)"
        estate.gpos.append(_gpo(
            gpo_id, "gpo-sddl-deny",
            settings=[_user_setting(gpo_id, r"HKCU\Software\Deny", "1")],
            delegation=[],
            sddl=sddl,
        ))
        estate.soms[0].links.append(SomLink(
            gpo_id=gpo_id, order=10, enabled=True, enforced=False, target=ROOT_DN,
        ))
        result = principal_resultant(estate, USER_SID, dn=ROOT_DN)
        idents = {m.identity for m in result.settings}
        assert r"HKCU\Software\Deny" not in idents
        assert any(e.gpo_id == gpo_id and e.kind == "security_filter"
                   for e in result.excluded)

    def test_sddl_allow_only_still_applies(self, estate):
        """Same SDDL without the deny ACE must apply (regression guard)."""
        gpo_id = "56565656-5656-5656-5656-565656565656"
        sddl = "D:(A;;GA;;;S-1-5-11)"
        estate.gpos.append(_gpo(
            gpo_id, "gpo-sddl-allow",
            settings=[_user_setting(gpo_id, r"HKCU\Software\Allow", "1")],
            delegation=[],
            sddl=sddl,
        ))
        estate.soms[0].links.append(SomLink(
            gpo_id=gpo_id, order=10, enabled=True, enforced=False, target=ROOT_DN,
        ))
        result = principal_resultant(estate, USER_SID, dn=ROOT_DN)
        idents = {m.identity for m in result.settings}
        assert r"HKCU\Software\Allow" in idents

    def test_delegation_deny_cancels_allow_on_same_trustee(self, estate):
        """Delegation entries: an allow + deny for Authenticated Users cancel."""
        gpo_id = "57575757-5757-5757-5757-575757575757"
        estate.gpos.append(_gpo(
            gpo_id, "gpo-delegation-deny",
            settings=[_user_setting(gpo_id, r"HKCU\Software\DelDeny", "1")],
            delegation=[
                DelegationEntry(
                    gpo_id="", trustee="Authenticated Users", trustee_sid="S-1-5-11",
                    permission="Apply Group Policy", allowed=True,
                ),
                DelegationEntry(
                    gpo_id="", trustee="Authenticated Users", trustee_sid="S-1-5-11",
                    permission="Apply Group Policy", allowed=False,
                ),
            ],
        ))
        estate.soms[0].links.append(SomLink(
            gpo_id=gpo_id, order=10, enabled=True, enforced=False, target=ROOT_DN,
        ))
        result = principal_resultant(estate, USER_SID, dn=ROOT_DN)
        idents = {m.identity for m in result.settings}
        assert r"HKCU\Software\DelDeny" not in idents
        assert any(e.gpo_id == gpo_id and e.kind == "security_filter"
                   for e in result.excluded)


# ---------------------------------------------------------------------------
# Issue 9 / Issue 12 / Bug 5 — conditional_dangers + danger param
# ---------------------------------------------------------------------------

class TestConditionalDangers:
    def test_wmi_gated_gpo_with_danger_appears_in_conditional_dangers(self, estate):
        """Issue 12: a GPO with both a WMI filter AND a danger must surface in
        conditional_dangers (decision 3: never hide a danger).
        """
        danger = [DangerFinding(
            check_id="TEST-001", severity="high", title="Test danger",
            gpo_id=GPO_WMI, gpo_name="gpo-wmi",
            detail="a test danger in a WMI-gated GPO", reference="test",
        )]
        result = principal_resultant(estate, USER_SID, danger=danger)
        cd = [c for c in result.conditional_dangers if c.gpo_id == GPO_WMI]
        assert len(cd) == 1
        assert cd[0].finding_count == 1
        assert isinstance(cd[0], ConditionalDanger)

    def test_danger_param_is_used_not_recomputed(self, estate):
        """Issue 9: passing ``danger`` avoids recomputation. A synthetic danger
        for GPO_WMI (which ``danger_findings`` would not produce for this
        synthetic estate) appears only because the param is honored.
        """
        danger = [DangerFinding(
            check_id="SYNTHETIC", severity="medium", title="synthetic",
            gpo_id=GPO_WMI, gpo_name="gpo-wmi",
            detail="synthetic danger", reference="test",
        )]
        result_with = principal_resultant(estate, USER_SID, danger=danger)
        assert any(c.gpo_id == GPO_WMI for c in result_with.conditional_dangers)
        # Passing an empty list must yield zero conditional dangers (param used,
        # not recomputed against the estate).
        result_empty = principal_resultant(estate, USER_SID, danger=[])
        assert result_empty.conditional_dangers == []

    def test_ilt_gated_gpo_with_danger_appears_in_conditional_dangers(
        self, estate, tmp_path,
    ):
        """Bug 5: an ILT-excluded GPP GPO with a danger must surface in
        conditional_dangers. Its GPP setting is excluded (excluded_settings)
        but the danger is not silently dropped.
        """
        ilt_gpo_id = "68888888-6888-6888-6888-688888888888"
        # SYSVOL GPP XML carrying <Filters> → scan_ilt flags the GPO as ILT.
        base = tmp_path / ilt_gpo_id
        sched = base / "User" / "Preferences" / "ScheduledTasks"
        sched.mkdir(parents=True)
        (sched / "ScheduledTasks.xml").write_text(
            '<?xml version="1.0" encoding="utf-8"?>'
            '<ScheduledTasks><Task name="t">'
            '<Filters><Filter1/></Filters>'
            '</Task></ScheduledTasks>',
            encoding="utf-8",
        )
        estate.gpos.append(_gpo(
            ilt_gpo_id, "gpo-ilt",
            settings=[Setting(
                gpo_id=ilt_gpo_id, side="User", cse="ScheduledTasks",
                identity="Task:t", display_name="Task t",
                display_value="t", raw={"@attr": {"action": "C"}},
                from_disabled_side=False,
            )],
            delegation=_au_apply(),
            sysvol_path=str(base),
        ))
        estate.soms[0].links.append(SomLink(
            gpo_id=ilt_gpo_id, order=10, enabled=True, enforced=False,
            target=ROOT_DN,
        ))
        danger = [DangerFinding(
            check_id="ILT-DANGER", severity="high", title="ilt danger",
            gpo_id=ilt_gpo_id, gpo_name="gpo-ilt",
            detail="danger in an ILT-gated GPP GPO", reference="test",
        )]
        result = principal_resultant(estate, USER_SID, dn=ROOT_DN, danger=danger)
        # The GPP setting is excluded from the deterministic resultant...
        assert all(m.identity != "Task:t" for m in result.settings)
        ilt_excluded = [e for e in result.excluded_settings if e.gpo_id == ilt_gpo_id]
        assert len(ilt_excluded) == 1
        assert ilt_excluded[0].kind == "ilt"
        assert isinstance(ilt_excluded[0], ExcludedSetting)
        # ...but its danger surfaces in conditional_dangers (Bug 5).
        cd = [c for c in result.conditional_dangers if c.gpo_id == ilt_gpo_id]
        assert len(cd) == 1
        assert cd[0].finding_count == 1
        assert "ILT" in cd[0].reason


# ---------------------------------------------------------------------------
# Cross-trustee deny-ACE (token intersects deny set independently of allow)
# ---------------------------------------------------------------------------

class TestCrossTrusteeDeny:
    """The deny set must be checked against the token independently of the
    allow set. A GPO that allows Authenticated Users but denies a group the
    principal is a member of must be blocked — the current intersection-only
    logic (allow_sids - deny_sids) silently ignores cross-trustee deny.
    """

    def test_delegation_cross_trustee_deny_blocks_gpo(self, estate):
        """GPO allows AU, denies a group the user is in → GPO excluded."""
        gpo_id = "71111111-7111-7111-7111-711111111111"
        estate.gpos.append(_gpo(
            gpo_id, "gpo-cross-deny",
            settings=[_user_setting(gpo_id, r"HKCU\Software\XDeny", "1")],
            delegation=[
                DelegationEntry(
                    gpo_id="", trustee="Authenticated Users",
                    trustee_sid="S-1-5-11",
                    permission="Apply Group Policy", allowed=True,
                ),
                DelegationEntry(
                    gpo_id="", trustee="Helpdesk Operators",
                    trustee_sid=_DOMAIN_GROUP_SID,
                    permission="Apply Group Policy", allowed=False,
                ),
            ],
        ))
        estate.soms[0].links.append(SomLink(
            gpo_id=gpo_id, order=10, enabled=True, enforced=False, target=ROOT_DN,
        ))
        result = principal_resultant(estate, USER_SID, dn=ROOT_DN)
        idents = {m.identity for m in result.settings}
        assert r"HKCU\Software\XDeny" not in idents
        exc = [e for e in result.excluded if e.gpo_id == gpo_id]
        assert len(exc) == 1
        assert "deny ACE" in exc[0].reason

    def test_delegation_cross_trustee_deny_unrelated_group_passes(self, estate):
        """GPO allows AU, denies a group the user is NOT in → GPO applies."""
        gpo_id = "72222222-7222-7222-7222-722222222222"
        estate.gpos.append(_gpo(
            gpo_id, "gpo-cross-deny-unrelated",
            settings=[_user_setting(gpo_id, r"HKCU\Software\XOK", "1")],
            delegation=[
                DelegationEntry(
                    gpo_id="", trustee="Authenticated Users",
                    trustee_sid="S-1-5-11",
                    permission="Apply Group Policy", allowed=True,
                ),
                DelegationEntry(
                    gpo_id="", trustee="Server Admins",
                    trustee_sid=_OTHER_GROUP_SID_FULL,
                    permission="Apply Group Policy", allowed=False,
                ),
            ],
        ))
        estate.soms[0].links.append(SomLink(
            gpo_id=gpo_id, order=10, enabled=True, enforced=False, target=ROOT_DN,
        ))
        result = principal_resultant(estate, USER_SID, dn=ROOT_DN)
        idents = {m.identity for m in result.settings}
        assert r"HKCU\Software\XOK" in idents

    def test_sddl_cross_trustee_deny_blocks_gpo(self, estate):
        """SDDL: allow AU, deny a group the user is in → GPO excluded."""
        gpo_id = "73333333-7333-7333-7333-733333333333"
        sddl = (
            "D:(A;;GA;;;S-1-5-11)"
            f"(D;;GA;;;{_DOMAIN_GROUP_SID})"
        )
        estate.gpos.append(_gpo(
            gpo_id, "gpo-sddl-cross-deny",
            settings=[_user_setting(gpo_id, r"HKCU\Software\SDdlDeny", "1")],
            delegation=[],
            sddl=sddl,
        ))
        estate.soms[0].links.append(SomLink(
            gpo_id=gpo_id, order=10, enabled=True, enforced=False, target=ROOT_DN,
        ))
        result = principal_resultant(estate, USER_SID, dn=ROOT_DN)
        idents = {m.identity for m in result.settings}
        assert r"HKCU\Software\SDdlDeny" not in idents
        exc = [e for e in result.excluded if e.gpo_id == gpo_id]
        assert len(exc) == 1
        assert "deny ACE" in exc[0].reason

    def test_sddl_deny_only_ace_blocks_gpo(self, estate):
        """SDDL: allow AU, deny-only ACE for a group the user is in (no
        corresponding allow for that group) → GPO excluded.

        This is the gap in the old SDDL path: deny-only trustees were never
        tracked, so a cross-trustee deny with no matching allow was silently
        ignored.
        """
        gpo_id = "74444444-7444-7444-7444-744444444444"
        sddl = (
            "D:(A;;GA;;;S-1-5-11)"
            f"(D;;GR;;;{_DOMAIN_GROUP_SID})"
        )
        estate.gpos.append(_gpo(
            gpo_id, "gpo-sddl-deny-only",
            settings=[_user_setting(gpo_id, r"HKCU\Software\DenyOnly", "1")],
            delegation=[],
            sddl=sddl,
        ))
        estate.soms[0].links.append(SomLink(
            gpo_id=gpo_id, order=10, enabled=True, enforced=False, target=ROOT_DN,
        ))
        result = principal_resultant(estate, USER_SID, dn=ROOT_DN)
        idents = {m.identity for m in result.settings}
        assert r"HKCU\Software\DenyOnly" not in idents
        assert any(e.gpo_id == gpo_id and "deny ACE" in e.reason
                   for e in result.excluded)

    def test_sddl_deny_only_non_apply_right_does_not_block(self, estate):
        """SDDL: deny with a non-read/apply right (e.g. WD = write deny)
        should NOT block the GPO — only deny ACEs with read/apply rights
        are tracked.
        """
        gpo_id = "75555555-7555-7555-7555-755555555555"
        sddl = (
            "D:(A;;GA;;;S-1-5-11)"
            f"(D;;WD;;;{_DOMAIN_GROUP_SID})"
        )
        estate.gpos.append(_gpo(
            gpo_id, "gpo-sddl-wd-deny",
            settings=[_user_setting(gpo_id, r"HKCU\Software\WdDenyOK", "1")],
            delegation=[],
            sddl=sddl,
        ))
        estate.soms[0].links.append(SomLink(
            gpo_id=gpo_id, order=10, enabled=True, enforced=False, target=ROOT_DN,
        ))
        result = principal_resultant(estate, USER_SID, dn=ROOT_DN)
        idents = {m.identity for m in result.settings}
        assert r"HKCU\Software\WdDenyOK" in idents


# ---------------------------------------------------------------------------
# Best-effort loopback (WI-028)
# ---------------------------------------------------------------------------

_LOOPBACK_IDENT = "Configure user group policy loopback processing mode"


def _loopback_setting(gpo_id: str, mode: str) -> Setting:
    return Setting(
        gpo_id=gpo_id, side="Computer", cse="Security",
        identity=_LOOPBACK_IDENT, display_name="Loopback",
        display_value=mode, raw={}, from_disabled_side=False,
    )


class TestLoopbackReplace:
    """In replace mode, user-side settings come ONLY from the computer's chain."""

    def _setup_replace_estate(self, estate):
        comp_sid = f"{DOMAIN_SID}-5001"
        estate.principals[comp_sid] = ResolvedPrincipal(
            sid=comp_sid, name="TEST\\WKS$", sam="WKS$",
            principal_type="Computer", domain="TEST", resolved=True,
        )
        user_dn = f"ou=users,{ROOT_DN}"
        comp_dn = f"ou=computers,{ROOT_DN}"

        user_gpo = "81111111-8111-8111-8111-811111111111"
        comp_gpo = "82222222-8222-8222-8222-822222222222"

        estate.gpos.append(_gpo(
            user_gpo, "gpo-user-chain",
            settings=[_user_setting(user_gpo, r"HKCU\Software\UserChain", "u")],
            delegation=_au_apply(),
        ))
        estate.gpos.append(_gpo(
            comp_gpo, "gpo-comp-loopback-replace",
            settings=[
                _loopback_setting(comp_gpo, "Replace"),
                _user_setting(comp_gpo, r"HKCU\Software\CompChain", "c"),
            ],
            delegation=_au_apply(),
        ))
        estate.soms.append(Som(
            path=user_dn, name="users", container_type="ou",
            inheritance_blocked=False,
            links=[SomLink(gpo_id=user_gpo, order=1, enabled=True,
                           enforced=False, target=user_dn)],
        ))
        estate.soms.append(Som(
            path=comp_dn, name="computers", container_type="ou",
            inheritance_blocked=False,
            links=[SomLink(gpo_id=comp_gpo, order=1, enabled=True,
                           enforced=False, target=comp_dn)],
        ))
        return comp_sid, user_dn, comp_dn

    def test_replace_user_chain_setting_not_present(self, estate):
        comp_sid, user_dn, comp_dn = self._setup_replace_estate(estate)
        result = principal_resultant(
            estate, USER_SID, computer_sid=comp_sid,
            dn=user_dn, computer_dn=comp_dn,
        )
        idents = {m.identity for m in result.settings}
        assert r"HKCU\Software\UserChain" not in idents
        assert r"HKCU\Software\CompChain" in idents

    def test_replace_label_says_loopback_replace(self, estate):
        comp_sid, user_dn, comp_dn = self._setup_replace_estate(estate)
        result = principal_resultant(
            estate, USER_SID, computer_sid=comp_sid,
            dn=user_dn, computer_dn=comp_dn,
        )
        assert "loopback=replace" in result.caveat_summary.lower()

    def test_replace_computer_side_still_present(self, estate):
        """Computer-side settings from the computer chain are unaffected."""
        comp_sid, user_dn, comp_dn = self._setup_replace_estate(estate)
        result = principal_resultant(
            estate, USER_SID, computer_sid=comp_sid,
            dn=user_dn, computer_dn=comp_dn,
        )
        comp_settings = {m.identity for m in result.settings if m.side == "Computer"}
        assert _LOOPBACK_IDENT in comp_settings

    def test_replace_security_filter_uses_computer_token(self, estate):
        """In replace mode, loopback user-side GPOs are evaluated against
        the computer's token only. A GPO filtered to a user group should
        NOT apply via loopback.
        """
        comp_sid = f"{DOMAIN_SID}-5001"
        estate.principals[comp_sid] = ResolvedPrincipal(
            sid=comp_sid, name="TEST\\WKS$", sam="WKS$",
            principal_type="Computer", domain="TEST", resolved=True,
        )
        comp_dn = f"ou=computers,{ROOT_DN}"
        user_dn = f"ou=users,{ROOT_DN}"

        loopback_gpo = "83333333-8333-8333-8333-833333333333"
        estate.gpos.append(_gpo(
            loopback_gpo, "gpo-loopback-replace-filtered",
            settings=[
                _loopback_setting(loopback_gpo, "Replace"),
                _user_setting(loopback_gpo, r"HKCU\Software\LoopFiltered", "1"),
            ],
            delegation=_group_apply("Helpdesk Operators", _DOMAIN_GROUP_SID),
        ))
        estate.soms.append(Som(
            path=user_dn, name="users", container_type="ou",
            inheritance_blocked=False, links=[],
        ))
        estate.soms.append(Som(
            path=comp_dn, name="computers", container_type="ou",
            inheritance_blocked=False,
            links=[SomLink(gpo_id=loopback_gpo, order=1, enabled=True,
                           enforced=False, target=comp_dn)],
        ))
        result = principal_resultant(
            estate, USER_SID, computer_sid=comp_sid,
            dn=user_dn, computer_dn=comp_dn,
        )
        idents = {m.identity for m in result.settings}
        # The user is in Helpdesk Operators, but the computer is NOT.
        # In replace mode, the computer token is used → GPO excluded.
        assert r"HKCU\Software\LoopFiltered" not in idents
        assert any(e.gpo_id == loopback_gpo and e.kind == "security_filter"
                   for e in result.excluded)


class TestLoopbackMerge:
    """In merge mode, both user and computer chain contribute user-side
    settings, with the computer chain winning conflicts."""

    def _setup_merge_estate(self, estate):
        comp_sid = f"{DOMAIN_SID}-5001"
        estate.principals[comp_sid] = ResolvedPrincipal(
            sid=comp_sid, name="TEST\\WKS$", sam="WKS$",
            principal_type="Computer", domain="TEST", resolved=True,
        )
        user_dn = f"ou=users,{ROOT_DN}"
        comp_dn = f"ou=computers,{ROOT_DN}"

        user_gpo = "84444444-8444-8444-8444-844444444444"
        comp_gpo = "85555555-8555-8555-8555-855555555555"

        estate.gpos.append(_gpo(
            user_gpo, "gpo-user-chain-merge",
            settings=[_user_setting(user_gpo, r"HKCU\Software\Shared", "from_user")],
            delegation=_au_apply(),
        ))
        estate.gpos.append(_gpo(
            comp_gpo, "gpo-comp-loopback-merge",
            settings=[
                _loopback_setting(comp_gpo, "Merge"),
                _user_setting(comp_gpo, r"HKCU\Software\Shared", "from_comp"),
                _user_setting(comp_gpo, r"HKCU\Software\CompOnly", "c"),
            ],
            delegation=_au_apply(),
        ))
        estate.soms.append(Som(
            path=user_dn, name="users", container_type="ou",
            inheritance_blocked=False,
            links=[SomLink(gpo_id=user_gpo, order=1, enabled=True,
                           enforced=False, target=user_dn)],
        ))
        estate.soms.append(Som(
            path=comp_dn, name="computers", container_type="ou",
            inheritance_blocked=False,
            links=[SomLink(gpo_id=comp_gpo, order=1, enabled=True,
                           enforced=False, target=comp_dn)],
        ))
        return comp_sid, user_dn, comp_dn

    def test_merge_both_chains_contribute_user_side(self, estate):
        comp_sid, user_dn, comp_dn = self._setup_merge_estate(estate)
        result = principal_resultant(
            estate, USER_SID, computer_sid=comp_sid,
            dn=user_dn, computer_dn=comp_dn,
        )
        idents = {m.identity for m in result.settings if m.side == "User"}
        assert r"HKCU\Software\Shared" in idents
        assert r"HKCU\Software\CompOnly" in idents

    def test_merge_computer_chain_wins_conflict(self, estate):
        """When both chains define the same setting, the computer chain wins
        (its entries are offset to higher order).
        """
        comp_sid, user_dn, comp_dn = self._setup_merge_estate(estate)
        result = principal_resultant(
            estate, USER_SID, computer_sid=comp_sid,
            dn=user_dn, computer_dn=comp_dn,
        )
        shared = [m for m in result.settings if m.identity == r"HKCU\Software\Shared"]
        assert len(shared) == 1
        assert shared[0].winning_value == "from_comp"
        assert shared[0].winning_gpo_name == "gpo-comp-loopback-merge"

    def test_merge_label_says_loopback_merge(self, estate):
        comp_sid, user_dn, comp_dn = self._setup_merge_estate(estate)
        result = principal_resultant(
            estate, USER_SID, computer_sid=comp_sid,
            dn=user_dn, computer_dn=comp_dn,
        )
        assert "loopback=merge" in result.caveat_summary.lower()

    def test_merge_security_filter_uses_computer_token(self, estate):
        """In merge mode, loopback user-side GPOs from the computer chain
        are evaluated against the computer's token. A GPO filtered to a
        user group should NOT contribute user-side settings via loopback.
        """
        comp_sid = f"{DOMAIN_SID}-5001"
        estate.principals[comp_sid] = ResolvedPrincipal(
            sid=comp_sid, name="TEST\\WKS$", sam="WKS$",
            principal_type="Computer", domain="TEST", resolved=True,
        )
        comp_dn = f"ou=computers,{ROOT_DN}"
        user_dn = f"ou=users,{ROOT_DN}"

        comp_gpo = "86666666-8666-8666-8666-866666666666"
        estate.gpos.append(_gpo(
            comp_gpo, "gpo-merge-filtered",
            settings=[
                _loopback_setting(comp_gpo, "Merge"),
                _user_setting(comp_gpo, r"HKCU\Software\MergeFiltered", "1"),
            ],
            delegation=_group_apply("Helpdesk Operators", _DOMAIN_GROUP_SID),
        ))
        estate.soms.append(Som(
            path=user_dn, name="users", container_type="ou",
            inheritance_blocked=False, links=[],
        ))
        estate.soms.append(Som(
            path=comp_dn, name="computers", container_type="ou",
            inheritance_blocked=False,
            links=[SomLink(gpo_id=comp_gpo, order=1, enabled=True,
                           enforced=False, target=comp_dn)],
        ))
        result = principal_resultant(
            estate, USER_SID, computer_sid=comp_sid,
            dn=user_dn, computer_dn=comp_dn,
        )
        idents = {m.identity for m in result.settings}
        assert r"HKCU\Software\MergeFiltered" not in idents
        assert any(e.gpo_id == comp_gpo and e.kind == "security_filter"
                   for e in result.excluded)


class TestLoopbackNoLoopback:
    """Without loopback, the existing user+computer pair behavior is unchanged."""

    def test_no_loopback_label_unaffected(self, estate):
        comp_sid = f"{DOMAIN_SID}-5001"
        estate.principals[comp_sid] = ResolvedPrincipal(
            sid=comp_sid, name="TEST\\WKS$", sam="WKS$",
            principal_type="Computer", domain="TEST", resolved=True,
        )
        result = principal_resultant(estate, USER_SID, computer_sid=comp_sid)
        assert "no loopback" in result.caveat_summary.lower()


class TestLoopbackEdgeCases:
    """Regression tests for edge cases identified by adversarial review."""

    def test_disabled_loopback_link_does_not_activate_loopback(self, estate):
        """A loopback GPO whose link is disabled must NOT trigger replace/merge.
        The user chain's settings must survive.
        """
        comp_sid = f"{DOMAIN_SID}-5001"
        estate.principals[comp_sid] = ResolvedPrincipal(
            sid=comp_sid, name="TEST\\WKS$", sam="WKS$",
            principal_type="Computer", domain="TEST", resolved=True,
        )
        user_dn = f"ou=users,{ROOT_DN}"
        comp_dn = f"ou=computers,{ROOT_DN}"
        user_gpo = "87111111-8711-8711-8711-871111111111"
        comp_gpo = "87222222-8722-8722-8722-872222222222"

        estate.gpos.append(_gpo(
            user_gpo, "gpo-user-only",
            settings=[_user_setting(user_gpo, r"HKCU\Software\Survives", "1")],
            delegation=_au_apply(),
        ))
        estate.gpos.append(_gpo(
            comp_gpo, "gpo-loopback-disabled-link",
            settings=[
                _loopback_setting(comp_gpo, "Replace"),
                _user_setting(comp_gpo, r"HKCU\Software\DisabledLink", "x"),
            ],
            delegation=_au_apply(),
        ))
        estate.soms.append(Som(
            path=user_dn, name="users", container_type="ou",
            inheritance_blocked=False,
            links=[SomLink(gpo_id=user_gpo, order=1, enabled=True,
                           enforced=False, target=user_dn)],
        ))
        estate.soms.append(Som(
            path=comp_dn, name="computers", container_type="ou",
            inheritance_blocked=False,
            links=[SomLink(gpo_id=comp_gpo, order=1, enabled=False,
                           enforced=False, target=comp_dn)],
        ))
        result = principal_resultant(
            estate, USER_SID, computer_sid=comp_sid,
            dn=user_dn, computer_dn=comp_dn,
        )
        idents = {m.identity for m in result.settings}
        assert r"HKCU\Software\Survives" in idents
        assert r"HKCU\Software\DisabledLink" not in idents
        assert "no loopback" in result.caveat_summary.lower()

    def test_mixed_loopback_falls_back_with_caveat(self, estate):
        """Two loopback GPOs with conflicting modes (replace + merge) →
        active_loopback='mixed' → falls back to non-loopback behavior.
        """
        comp_sid = f"{DOMAIN_SID}-5001"
        estate.principals[comp_sid] = ResolvedPrincipal(
            sid=comp_sid, name="TEST\\WKS$", sam="WKS$",
            principal_type="Computer", domain="TEST", resolved=True,
        )
        user_dn = f"ou=users,{ROOT_DN}"
        comp_dn = f"ou=computers,{ROOT_DN}"
        user_gpo = "88111111-8811-8811-8811-881111111111"
        comp_replace = "88222222-8822-8822-8822-882222222222"
        comp_merge = "88333333-8833-8833-8833-883333333333"

        estate.gpos.append(_gpo(
            user_gpo, "gpo-user-side",
            settings=[_user_setting(user_gpo, r"HKCU\Software\UserSide", "u")],
            delegation=_au_apply(),
        ))
        estate.gpos.append(_gpo(
            comp_replace, "gpo-comp-replace",
            settings=[
                _loopback_setting(comp_replace, "Replace"),
                _user_setting(comp_replace, r"HKCU\Software\CompReplace", "r"),
            ],
            delegation=_au_apply(),
        ))
        estate.gpos.append(_gpo(
            comp_merge, "gpo-comp-merge",
            settings=[
                _loopback_setting(comp_merge, "Merge"),
                _user_setting(comp_merge, r"HKCU\Software\CompMerge", "m"),
            ],
            delegation=_au_apply(),
        ))
        estate.soms.append(Som(
            path=user_dn, name="users", container_type="ou",
            inheritance_blocked=False,
            links=[SomLink(gpo_id=user_gpo, order=1, enabled=True,
                           enforced=False, target=user_dn)],
        ))
        estate.soms.append(Som(
            path=comp_dn, name="computers", container_type="ou",
            inheritance_blocked=False,
            links=[
                SomLink(gpo_id=comp_replace, order=1, enabled=True,
                        enforced=False, target=comp_dn),
                SomLink(gpo_id=comp_merge, order=2, enabled=True,
                        enforced=False, target=comp_dn),
            ],
        ))
        result = principal_resultant(
            estate, USER_SID, computer_sid=comp_sid,
            dn=user_dn, computer_dn=comp_dn,
        )
        assert "loopback=mixed" in result.caveat_summary.lower()
        assert "best-effort" in result.caveat_summary.lower()
        idents = {m.identity for m in result.settings if m.side == "User"}
        assert r"HKCU\Software\UserSide" in idents

    def test_merge_offset_strictly_greater(self, estate):
        """Even when user_entries is empty, comp-chain entries must not
        collide with order 0 user entries. The offset must be > 0.
        """
        comp_sid = f"{DOMAIN_SID}-5001"
        estate.principals[comp_sid] = ResolvedPrincipal(
            sid=comp_sid, name="TEST\\WKS$", sam="WKS$",
            principal_type="Computer", domain="TEST", resolved=True,
        )
        user_dn = f"ou=users,{ROOT_DN}"
        comp_dn = f"ou=computers,{ROOT_DN}"
        user_gpo = "89111111-8911-8911-8911-891111111111"
        comp_gpo = "89222222-8922-8922-8922-892222222222"

        estate.gpos.append(_gpo(
            user_gpo, "gpo-user-shared",
            settings=[_user_setting(user_gpo, r"HKCU\Software\Conflict", "user_val")],
            delegation=_au_apply(),
        ))
        estate.gpos.append(_gpo(
            comp_gpo, "gpo-comp-shared",
            settings=[
                _loopback_setting(comp_gpo, "Merge"),
                _user_setting(comp_gpo, r"HKCU\Software\Conflict", "comp_val"),
            ],
            delegation=_au_apply(),
        ))
        estate.soms.append(Som(
            path=user_dn, name="users", container_type="ou",
            inheritance_blocked=False,
            links=[SomLink(gpo_id=user_gpo, order=1, enabled=True,
                           enforced=False, target=user_dn)],
        ))
        estate.soms.append(Som(
            path=comp_dn, name="computers", container_type="ou",
            inheritance_blocked=False,
            links=[SomLink(gpo_id=comp_gpo, order=1, enabled=True,
                           enforced=False, target=comp_dn)],
        ))
        result = principal_resultant(
            estate, USER_SID, computer_sid=comp_sid,
            dn=user_dn, computer_dn=comp_dn,
        )
        shared = [m for m in result.settings if m.identity == r"HKCU\Software\Conflict"]
        assert len(shared) == 1
        assert shared[0].winning_value == "comp_val"
