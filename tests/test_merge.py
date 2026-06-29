"""Tests for the per-CSE merge-resolution model (Plan 021 Phase B).

Covers the CSE→mode mapping, the merge-resolution function for each mode, the
GPP action state machine, APPROXIMATE flagging, and ILT conditional flagging.
No samples required — all fixtures are synthetic.
"""

from __future__ import annotations

from gpo_lens.merge import (
    ANONYMOUS_SID,
    AU_SID,
    EVERYONE_SID,
    ChainEntry,
    CseMergeMode,
    ExcludedGpo,
    _gpo_apply_trustee_sids,
    _resolve_som_path_for_principal,
    build_token,
    cse_merge_mode,
    merge_settings,
    merge_settings_with_exclusions,
    principal_resultant,
)
from gpo_lens.model import (
    DelegationEntry,
    Estate,
    Gpo,
    ResolvedPrincipal,
    Setting,
    Som,
    SomLink,
)


def _setting(
    gpo_id: str,
    cse: str,
    identity: str,
    value: str,
    *,
    side: str = "Computer",
    display_name: str = "",
    raw: dict | None = None,
) -> Setting:
    return Setting(
        gpo_id=gpo_id,
        side=side,
        cse=cse,
        identity=identity,
        display_name=display_name or identity,
        display_value=value,
        raw=raw or {},
        from_disabled_side=False,
    )


def _entry(
    gpo_id: str,
    gpo_name: str,
    order: int,
    settings: list[Setting],
    *,
    enforced: bool = False,
) -> ChainEntry:
    return ChainEntry(
        gpo_id=gpo_id,
        gpo_name=gpo_name,
        order=order,
        enforced=enforced,
        settings=settings,
    )


# ---------------------------------------------------------------------------
# B.1 — cse_merge_mode mapping
# ---------------------------------------------------------------------------

class TestCseMergeMode:
    def test_registry_is_last_writer_wins(self) -> None:
        assert cse_merge_mode("Registry") is CseMergeMode.LAST_WRITER_WINS
        assert cse_merge_mode("Windows Registry") is CseMergeMode.LAST_WRITER_WINS

    def test_scripts_is_union(self) -> None:
        assert cse_merge_mode("Scripts") is CseMergeMode.UNION
        assert cse_merge_mode("Group Policy Scripts") is CseMergeMode.UNION

    def test_security_restricted_groups_members_is_authoritative_replace(self) -> None:
        s = _setting("g1", "Security", "RestrictedGroups:Administrators", "",
                     raw={"children": [{"tag": "Members", "children": []}]})
        assert cse_merge_mode("Security", s) is CseMergeMode.AUTHORITATIVE_REPLACE

    def test_security_restricted_groups_member_of_is_additive(self) -> None:
        s = _setting("g1", "Security", "RestrictedGroups:GroupName", "",
                     raw={"children": [{"tag": "MemberOf", "children": []}]})
        assert cse_merge_mode("Security", s) is CseMergeMode.ADDITIVE

    def test_security_non_restricted_is_last_writer_wins(self) -> None:
        s = _setting("g1", "Security", "Account:LockoutBadCount", "5")
        assert cse_merge_mode("Security", s) is CseMergeMode.LAST_WRITER_WINS

    def test_software_installation_is_accumulate(self) -> None:
        assert cse_merge_mode("Software Installation") is CseMergeMode.ACCUMULATE

    def test_gpp_cses_are_accumulate(self) -> None:
        for cse in ("Group Policy Preferences", "GPP",
                    "GPP Drive Maps", "GPP Registry", "GPP Files",
                    "GPP Local Users and Groups", "GPP Scheduled Tasks"):
            assert cse_merge_mode(cse) is CseMergeMode.ACCUMULATE, cse

    def test_ipsec_wireless_wired_are_single_winner(self) -> None:
        for cse in ("IPsec", "Wireless", "Wired"):
            assert cse_merge_mode(cse) is CseMergeMode.SINGLE_WINNER, cse

    def test_folder_redirection_replace_is_authoritative_replace(self) -> None:
        s = _setting("g1", "Folder Redirection", "Documents", "Replace")
        assert cse_merge_mode("Folder Redirection", s) is CseMergeMode.AUTHORITATIVE_REPLACE

    def test_folder_redirection_merge_is_accumulate(self) -> None:
        s = _setting("g1", "Folder Redirection", "Documents", "Merge")
        assert cse_merge_mode("Folder Redirection", s) is CseMergeMode.ACCUMULATE

    def test_unknown_cse_is_approximate(self) -> None:
        assert cse_merge_mode("Some Unknown CSE") is CseMergeMode.APPROXIMATE
        assert cse_merge_mode("") is CseMergeMode.APPROXIMATE

    def test_case_insensitive(self) -> None:
        assert cse_merge_mode("registry") is CseMergeMode.LAST_WRITER_WINS
        assert cse_merge_mode("SCRIPTS") is CseMergeMode.UNION


# ---------------------------------------------------------------------------
# merge_settings — per-mode resolution
# ---------------------------------------------------------------------------

class TestMergeSettingsLastWriterWins:
    def test_highest_order_wins(self) -> None:
        entries = [
            _entry("g1", "GPO A", 1, [
                _setting("g1", "Registry", r"HKLM\Software\Foo:Bar", "5"),
            ]),
            _entry("g2", "GPO B", 2, [
                _setting("g2", "Registry", r"HKLM\Software\Foo:Bar", "10"),
            ]),
        ]
        result = merge_settings(entries)
        assert len(result) == 1
        m = result[0]
        assert m.merge_mode is CseMergeMode.LAST_WRITER_WINS
        assert m.winning_value == "10"
        assert m.winning_gpo_name == "GPO B"
        assert m.overridden_by == [("GPO A", "5")]
        assert m.approximate is False
        assert m.conditional is False

    def test_single_entry_no_overrides(self) -> None:
        entries = [
            _entry("g1", "GPO A", 1, [
                _setting("g1", "Registry", r"HKLM\Software\Foo:Bar", "5"),
            ]),
        ]
        result = merge_settings(entries)
        assert len(result) == 1
        assert result[0].overridden_by == []

    def test_excludes_disabled_side_settings(self) -> None:
        entries = [
            _entry("g1", "GPO A", 1, [
                Setting(
                    gpo_id="g1", side="Computer", cse="Registry",
                    identity="HKLM\\Software\\Foo:Bar", display_name="Bar",
                    display_value="5", raw={}, from_disabled_side=True,
                ),
            ]),
        ]
        assert merge_settings(entries) == []


class TestMergeSettingsUnion:
    def test_union_keeps_all_entries_in_overridden_by(self) -> None:
        entries = [
            _entry("g1", "GPO A", 1, [
                _setting("g1", "Scripts", "Startup:logon.cmd", "logon.cmd",
                         display_name="Startup script"),
            ]),
            _entry("g2", "GPO B", 2, [
                _setting("g2", "Scripts", "Startup:logon.cmd", "startup.cmd",
                         display_name="Startup script"),
            ]),
        ]
        result = merge_settings(entries)
        assert len(result) == 1
        m = result[0]
        assert m.merge_mode is CseMergeMode.UNION
        assert m.winning_value == "startup.cmd"
        assert m.winning_gpo_name == "GPO B"
        assert ("GPO A", "logon.cmd") in m.overridden_by


class TestMergeSettingsAuthoritativeReplace:
    def test_restricted_groups_members_replace(self) -> None:
        raw_members = {"children": [{"tag": "Members", "children": []}]}
        entries = [
            _entry("g1", "GPO A", 1, [
                _setting("g1", "Security", "RestrictedGroups:Administrators",
                         "GroupA", raw=raw_members),
            ]),
            _entry("g2", "GPO B", 2, [
                _setting("g2", "Security", "RestrictedGroups:Administrators",
                         "GroupB", raw=raw_members),
            ]),
        ]
        result = merge_settings(entries)
        assert len(result) == 1
        m = result[0]
        assert m.merge_mode is CseMergeMode.AUTHORITATIVE_REPLACE
        assert m.winning_value == "GroupB"
        assert m.winning_gpo_name == "GPO B"
        assert m.overridden_by == [("GPO A", "GroupA")]


class TestMergeSettingsAdditive:
    def test_restricted_groups_member_of_additive(self) -> None:
        raw_memberof = {"children": [{"tag": "MemberOf", "children": []}]}
        entries = [
            _entry("g1", "GPO A", 1, [
                _setting("g1", "Security", "RestrictedGroups:GroupX",
                         "MemberOfA", raw=raw_memberof),
            ]),
            _entry("g2", "GPO B", 2, [
                _setting("g2", "Security", "RestrictedGroups:GroupX",
                         "MemberOfB", raw=raw_memberof),
            ]),
        ]
        result = merge_settings(entries)
        assert len(result) == 1
        m = result[0]
        assert m.merge_mode is CseMergeMode.ADDITIVE
        assert m.winning_value == "MemberOfB"
        assert ("GPO A", "MemberOfA") in m.overridden_by
        assert ("GPO B", "MemberOfB") not in m.overridden_by


class TestMergeSettingsAccumulate:
    def test_accumulate_create_then_replace_supersedes(self) -> None:
        raw_create = {"@attr": {"action": "C"}}
        raw_replace = {"@attr": {"action": "R"}}
        entries = [
            _entry("g1", "GPO A", 1, [
                _setting("g1", "GPP Drive Maps", "Drive:H:", "H:\\share1",
                         raw=raw_create),
            ]),
            _entry("g2", "GPO B", 2, [
                _setting("g2", "GPP Drive Maps", "Drive:H:", "H:\\share2",
                         raw=raw_replace),
            ]),
        ]
        result = merge_settings(entries)
        assert len(result) == 1
        m = result[0]
        assert m.merge_mode is CseMergeMode.ACCUMULATE
        assert m.winning_value == "H:\\share2"
        assert m.winning_gpo_name == "GPO B"

    def test_accumulate_create_then_update_merges(self) -> None:
        raw_create = {"@attr": {"action": "C"}}
        raw_update = {"@attr": {"action": "U"}}
        entries = [
            _entry("g1", "GPO A", 1, [
                _setting("g1", "GPP Drive Maps", "Drive:H:", "H:\\share1",
                         raw=raw_create),
            ]),
            _entry("g2", "GPO B", 2, [
                _setting("g2", "GPP Drive Maps", "Drive:H:", "H:\\share1-updated",
                         raw=raw_update),
            ]),
        ]
        result = merge_settings(entries)
        assert len(result) == 1
        m = result[0]
        assert m.winning_gpo_name == "GPO B"
        assert m.winning_value == "H:\\share1-updated"

    def test_accumulate_create_then_delete_removes(self) -> None:
        raw_create = {"@attr": {"action": "C"}}
        raw_delete = {"@attr": {"action": "D"}}
        entries = [
            _entry("g1", "GPO A", 1, [
                _setting("g1", "GPP Drive Maps", "Drive:H:", "H:\\share1",
                         raw=raw_create),
            ]),
            _entry("g2", "GPO B", 2, [
                _setting("g2", "GPP Drive Maps", "Drive:H:", "",
                         raw=raw_delete),
            ]),
        ]
        result = merge_settings(entries)
        assert result == [], "a later Delete must remove the item from the resultant"

    def test_accumulate_action_in_properties_child(self) -> None:
        raw_with_props = {
            "children": [
                {"tag": "Properties", "@attr": {"action": "C"}},
            ],
        }
        entries = [
            _entry("g1", "GPO A", 1, [
                _setting("g1", "GPP Registry", "Registry:HKEY_LOCAL_USER:Setting", "1",
                         raw=raw_with_props),
            ]),
        ]
        result = merge_settings(entries)
        assert len(result) == 1
        assert result[0].merge_mode is CseMergeMode.ACCUMULATE

    def test_accumulate_long_action_names(self) -> None:
        raw_create = {"@attr": {"action": "CREATE"}}
        raw_delete = {"@attr": {"action": "DELETE"}}
        entries = [
            _entry("g1", "GPO A", 1, [
                _setting("g1", "GPP Files", "Files:\\\\srv\\share", "src1",
                         raw=raw_create),
            ]),
            _entry("g2", "GPO B", 2, [
                _setting("g2", "GPP Files", "Files:\\\\srv\\share", "",
                         raw=raw_delete),
            ]),
        ]
        assert merge_settings(entries) == []


class TestMergeSettingsApproximate:
    def test_unknown_cse_flagged_approximate(self) -> None:
        entries = [
            _entry("g1", "GPO A", 1, [
                _setting("g1", "SomeUnknownCSE", "Foo:Bar", "5"),
            ]),
        ]
        result = merge_settings(entries)
        assert len(result) == 1
        m = result[0]
        assert m.merge_mode is CseMergeMode.APPROXIMATE
        assert m.approximate is True
        assert m.conditional is False

    def test_unknown_cse_two_entries_last_wins_but_flagged(self) -> None:
        entries = [
            _entry("g1", "GPO A", 1, [
                _setting("g1", "SomeUnknownCSE", "Foo:Bar", "5"),
            ]),
            _entry("g2", "GPO B", 2, [
                _setting("g2", "SomeUnknownCSE", "Foo:Bar", "10"),
            ]),
        ]
        result = merge_settings(entries)
        assert len(result) == 1
        m = result[0]
        assert m.winning_value == "10"
        assert m.approximate is True


class TestMergeSettingsIlt:
    def test_ilt_gated_gpp_setting_is_excluded(self) -> None:
        """Per Plan 021 decision 2 / B.3, an ILT-gated GPP item is excluded
        from the deterministic resultant and listed — not carried as a
        conditional survivor (that would be an over-claim).
        """
        raw_create = {"@attr": {"action": "C"}}
        entries = [
            _entry("g1", "GPO A", 1, [
                _setting("g1", "GPP Drive Maps", "Drive:H:", "H:\\share",
                         raw=raw_create),
            ]),
        ]
        result = merge_settings_with_exclusions(
            entries, ilt_gpo_ids=frozenset({"g1"}),
        )
        # The setting is EXCLUDED from the deterministic resultant.
        assert result.settings == []
        # ...and listed for visibility, never silently dropped.
        assert len(result.excluded_settings) == 1
        exc = result.excluded_settings[0]
        assert exc.kind == "ilt"
        assert exc.gpo_id == "g1"
        assert exc.gpo_name == "GPO A"
        assert exc.cse == "GPP Drive Maps"
        assert exc.identity == "Drive:H:"
        assert exc.value == "H:\\share"

    def test_ilt_gated_gpp_setting_excluded_from_merge_settings(self) -> None:
        """The backward-compatible ``merge_settings`` wrapper also excludes."""
        raw_create = {"@attr": {"action": "C"}}
        entries = [
            _entry("g1", "GPO A", 1, [
                _setting("g1", "GPP Drive Maps", "Drive:H:", "H:\\share",
                         raw=raw_create),
            ]),
        ]
        assert merge_settings(entries, ilt_gpo_ids=frozenset({"g1"})) == []

    def test_ilt_on_non_gpp_cse_not_conditional(self) -> None:
        entries = [
            _entry("g1", "GPO A", 1, [
                _setting("g1", "Registry", r"HKLM\Software\Foo:Bar", "5"),
            ]),
        ]
        result = merge_settings_with_exclusions(
            entries, ilt_gpo_ids=frozenset({"g1"}),
        )
        # Registry is not a GPP CSE, so ILT does not exclude it.
        assert len(result.settings) == 1
        assert result.excluded_settings == []
        m = result.settings[0]
        assert m.conditional is False
        assert m.approximate is False

    def test_no_ilt_gpo_ids_no_conditional(self) -> None:
        raw_create = {"@attr": {"action": "C"}}
        entries = [
            _entry("g1", "GPO A", 1, [
                _setting("g1", "GPP Drive Maps", "Drive:H:", "H:\\share",
                         raw=raw_create),
            ]),
        ]
        result = merge_settings_with_exclusions(entries)
        assert len(result.settings) == 1
        assert result.excluded_settings == []
        assert result.settings[0].conditional is False


# ---------------------------------------------------------------------------
# Merge — multiple identities / sorting
# ---------------------------------------------------------------------------

class TestMergeSettingsMultipleIdentities:
    def test_separate_identities_produce_separate_settings(self) -> None:
        entries = [
            _entry("g1", "GPO A", 1, [
                _setting("g1", "Registry", r"HKLM\Software\Foo:Bar", "1"),
                _setting("g1", "Registry", r"HKLM\Software\Foo:Baz", "2"),
            ]),
        ]
        result = merge_settings(entries)
        assert len(result) == 2
        idents = {m.identity for m in result}
        assert r"HKLM\Software\Foo:Bar" in idents
        assert r"HKLM\Software\Foo:Baz" in idents

    def test_results_sorted_by_cse_side_identity(self) -> None:
        entries = [
            _entry("g1", "GPO A", 1, [
                _setting("g1", "Registry", "zeta", "1"),
                _setting("g1", "Registry", "alpha", "2", side="User"),
                _setting("g1", "Registry", "alpha", "3", side="Computer"),
            ]),
        ]
        result = merge_settings(entries)
        keys = [(m.cse, m.side, m.identity) for m in result]
        assert keys == sorted(keys)

    def test_empty_chain_returns_empty(self) -> None:
        assert merge_settings([]) == []


class TestCreateAfterDelete:
    def test_create_after_delete_recreates_item(self) -> None:
        raw_create = {"@attr": {"action": "C"}}
        raw_delete = {"@attr": {"action": "D"}}
        raw_recreate = {"@attr": {"action": "C"}}
        entries = [
            _entry("g1", "GPO A", 1, [
                _setting("g1", "GPP Drive Maps", "Drive:H:", "H:\\share1",
                         raw=raw_create),
            ]),
            _entry("g2", "GPO B", 2, [
                _setting("g2", "GPP Drive Maps", "Drive:H:", "",
                         raw=raw_delete),
            ]),
            _entry("g3", "GPO C", 3, [
                _setting("g3", "GPP Drive Maps", "Drive:H:", "H:\\share2",
                         raw=raw_recreate),
            ]),
        ]
        result = merge_settings(entries)
        assert len(result) == 1
        m = result[0]
        assert m.winning_value == "H:\\share2"
        assert m.winning_gpo_name == "GPO C"


class TestAnonymousTokenExclusion:
    def test_anonymous_not_in_authenticated_users(self) -> None:
        estate = Estate()
        token = build_token(estate, ANONYMOUS_SID)
        assert AU_SID not in token.token_sids
        assert EVERYONE_SID in token.token_sids
        assert ANONYMOUS_SID in token.token_sids

    def test_normal_principal_has_au_sid(self) -> None:
        estate = Estate()
        token = build_token(estate, "s-1-5-21-1-2-3-1000")
        assert AU_SID in token.token_sids
        assert EVERYONE_SID in token.token_sids


# ---------------------------------------------------------------------------
# H-5 — Escaped comma in DN (split must respect backslash-escaping)
# ---------------------------------------------------------------------------

class TestEscapedCommaDn:
    def test_dn_with_escaped_comma_resolves_exact_som(self) -> None:
        """A SOM whose path contains an escaped comma must match the
        principal's DN when the CN component has an escaped comma.
        """
        dn = r"CN=Last\,First,OU=Users,DC=test"
        estate = Estate(soms=[Som(
            path=dn, name="user", container_type="ou",
            inheritance_blocked=False, links=[],
        )])
        result = _resolve_som_path_for_principal(estate, dn)
        assert result.lower() == dn.lower()

    def test_dn_with_escaped_comma_resolves_parent_ou(self) -> None:
        """The parent OU must be found even when the CN has an escaped comma.

        With the old ``dn.split(",")`` the candidate walk produced a spurious
        ``First,OU=Users,DC=test`` intermediate; the fix (``re.split`` with
        negative lookbehind) produces correct candidates.
        """
        dn = r"CN=Last\,First,OU=Users,DC=test"
        ou_path = "ou=users,dc=test"
        estate = Estate(soms=[Som(
            path=ou_path, name="users", container_type="ou",
            inheritance_blocked=False, links=[],
        )])
        result = _resolve_som_path_for_principal(estate, dn)
        assert result.lower() == ou_path


# ---------------------------------------------------------------------------
# M-9 / WI-079 — security gate: Read does not imply Apply
# ---------------------------------------------------------------------------

_DOM_SID = "s-1-5-21-1000000000-2000000000-3000000000"
_USER_SID = f"{_DOM_SID}-1001"
_ROOT_DN = "dc=test,dc=local"


def _sec_estate(
    permission: str,
    *,
    gpo_id: str = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
) -> Estate:
    """Minimal estate: one user principal + one GPO delegated to AU."""
    principals = {
        _USER_SID: ResolvedPrincipal(
            sid=_USER_SID, name="TEST\\user", sam="user",
            principal_type="User", domain="TEST", resolved=True,
        ),
    }
    gpos = [
        Gpo(
            id=gpo_id, name="gpo-test", domain="test.local",
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
                    display_value="1", raw={}, from_disabled_side=False,
                ),
            ],
            delegation=[
                DelegationEntry(
                    gpo_id="", trustee="Authenticated Users",
                    trustee_sid="S-1-5-11",
                    permission=permission, allowed=True,
                ),
            ],
        ),
    ]
    som = Som(
        path=_ROOT_DN, name="test", container_type="domain",
        inheritance_blocked=False,
        links=[SomLink(gpo_id=gpo_id, order=1, enabled=True,
                       enforced=False, target=_ROOT_DN)],
    )
    return Estate(
        domain="test.local", gpos=gpos, soms=[som],
        principals=principals,
    )


class TestSecurityGateReadVsApply:
    def test_read_only_permission_excludes_gpo(self) -> None:
        """A GPO whose delegation grants only 'Read' (not Apply) must NOT
        pass the security gate — the principal cannot Apply the GPO.
        """
        estate = _sec_estate("Read")
        result = principal_resultant(estate, _USER_SID, dn=_ROOT_DN)
        idents = {m.identity for m in result.settings}
        assert r"HKCU\Software\Test" not in idents
        assert any(e.kind == "security_filter" for e in result.excluded)

    def test_apply_group_policy_includes_gpo(self) -> None:
        """A GPO whose delegation grants 'Apply Group Policy' must pass the
        security gate and contribute settings to the resultant.
        """
        estate = _sec_estate("Apply Group Policy")
        result = principal_resultant(estate, _USER_SID, dn=_ROOT_DN)
        idents = {m.identity for m in result.settings}
        assert r"HKCU\Software\Test" in idents

    def test_read_only_not_in_allow_sids(self) -> None:
        """Unit-level: _gpo_apply_trustee_sids must not put a Read-only
        trustee into allow_sids.
        """
        estate = _sec_estate("Read")
        gpo = estate.gpos[0]
        allow, _deny = _gpo_apply_trustee_sids(gpo, {})
        assert "s-1-5-11" not in allow

    def test_apply_in_allow_sids(self) -> None:
        """Unit-level: _gpo_apply_trustee_sids must put an Apply trustee
        into allow_sids.
        """
        estate = _sec_estate("Apply Group Policy")
        gpo = estate.gpos[0]
        allow, _deny = _gpo_apply_trustee_sids(gpo, {})
        assert "s-1-5-11" in allow


# ---------------------------------------------------------------------------
# L-13 / WI-078 — ExcludedGpo.side populated in loopback mode
# ---------------------------------------------------------------------------

_LOOPBACK_IDENT = "Configure user group policy loopback processing mode"


def _loopback_setting(gpo_id: str, mode: str) -> Setting:
    return Setting(
        gpo_id=gpo_id, side="Computer", cse="Security",
        identity=_LOOPBACK_IDENT, display_name="Loopback",
        display_value=mode, raw={}, from_disabled_side=False,
    )


class TestExcludedGpoSide:
    def _setup_loopback_estate(self):
        comp_sid = f"{_DOM_SID}-5001"
        principals = {
            _USER_SID: ResolvedPrincipal(
                sid=_USER_SID, name="TEST\\user", sam="user",
                principal_type="User", domain="TEST", resolved=True,
            ),
            comp_sid: ResolvedPrincipal(
                sid=comp_sid, name="TEST\\WKS$", sam="WKS$",
                principal_type="Computer", domain="TEST", resolved=True,
            ),
        }
        user_dn = f"ou=users,{_ROOT_DN}"
        comp_dn = f"ou=computers,{_ROOT_DN}"

        loopback_gpo = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
        # GPO with loopback=Replace + a user-side setting, but delegated
        # to a group the computer is NOT in → security-filtered.
        filtered_gpo = "cccccccc-cccc-cccc-cccc-cccccccccccc"
        gpos = [
            Gpo(
                id=loopback_gpo, name="gpo-loopback", domain="test.local",
                created=None, modified=None, read=None,
                computer_enabled=True, user_enabled=True,
                computer_ver_ds=None, computer_ver_sysvol=None,
                user_ver_ds=None, user_ver_sysvol=None,
                sddl=None, owner=None, filter_data_available=False,
                wmi_filter=None, sysvol_path=None,
                settings=[
                    _loopback_setting(loopback_gpo, "Replace"),
                    Setting(
                        gpo_id=loopback_gpo, side="User", cse="Registry",
                        identity=r"HKCU\Software\Loopback", display_name="LB",
                        display_value="1", raw={}, from_disabled_side=False,
                    ),
                ],
                delegation=[
                    DelegationEntry(
                        gpo_id="", trustee="Authenticated Users",
                        trustee_sid="S-1-5-11",
                        permission="Apply Group Policy", allowed=True,
                    ),
                ],
            ),
            Gpo(
                id=filtered_gpo, name="gpo-filtered", domain="test.local",
                created=None, modified=None, read=None,
                computer_enabled=True, user_enabled=True,
                computer_ver_ds=None, computer_ver_sysvol=None,
                user_ver_ds=None, user_ver_sysvol=None,
                sddl=None, owner=None, filter_data_available=False,
                wmi_filter=None, sysvol_path=None,
                settings=[
                    Setting(
                        gpo_id=filtered_gpo, side="User", cse="Registry",
                        identity=r"HKCU\Software\Filtered", display_name="F",
                        display_value="1", raw={}, from_disabled_side=False,
                    ),
                ],
                # Delegated to a SID the computer token does NOT carry.
                delegation=[
                    DelegationEntry(
                        gpo_id="", trustee="Helpdesk Operators",
                        trustee_sid=f"{_DOM_SID}-2001",
                        permission="Apply Group Policy", allowed=True,
                    ),
                ],
            ),
        ]
        soms = [
            Som(
                path=_ROOT_DN, name="test", container_type="domain",
                inheritance_blocked=False, links=[],
            ),
            Som(
                path=user_dn, name="users", container_type="ou",
                inheritance_blocked=False, links=[],
            ),
            Som(
                path=comp_dn, name="computers", container_type="ou",
                inheritance_blocked=False,
                links=[
                    SomLink(gpo_id=loopback_gpo, order=1, enabled=True,
                            enforced=False, target=comp_dn),
                    SomLink(gpo_id=filtered_gpo, order=2, enabled=True,
                            enforced=False, target=comp_dn),
                ],
            ),
        ]
        estate = Estate(
            domain="test.local", gpos=gpos, soms=soms,
            principals=principals,
        )
        return estate, comp_sid, user_dn, comp_dn, filtered_gpo

    def test_excluded_gpo_has_side_field(self) -> None:
        """ExcludedGpo must carry a ``side`` attribute."""
        exc = ExcludedGpo(
            gpo_id="x", gpo_name="x", reason="test", kind="security_filter",
            side="User",
        )
        assert exc.side == "User"

    def test_excluded_gpo_side_default_empty(self) -> None:
        """ExcludedGpo.side defaults to '' for backward compatibility."""
        exc = ExcludedGpo(
            gpo_id="x", gpo_name="x", reason="test", kind="security_filter",
        )
        assert exc.side == ""

    def test_loopback_excluded_gpo_side_populated(self) -> None:
        """In loopback replace mode, a GPO excluded during the user-side
        evaluation of the computer chain must have side='User'.
        """
        estate, comp_sid, user_dn, comp_dn, filtered_gpo = (
            self._setup_loopback_estate()
        )
        result = principal_resultant(
            estate, _USER_SID, computer_sid=comp_sid,
            dn=user_dn, computer_dn=comp_dn,
        )
        exc = [e for e in result.excluded if e.gpo_id == filtered_gpo]
        assert len(exc) == 1
        assert exc[0].side == "User"
        assert exc[0].kind == "security_filter"

    def test_non_loopback_excluded_gpo_side_populated(self) -> None:
        """Outside loopback, an excluded GPO must carry the principal's side.
        """
        estate = _sec_estate("Read")
        result = principal_resultant(estate, _USER_SID, dn=_ROOT_DN)
        exc = [e for e in result.excluded if e.kind == "security_filter"]
        assert len(exc) == 1
        assert exc[0].side == "User"
