"""Tests for the per-CSE merge-resolution model (Plan 021 Phase B).

Covers the CSE→mode mapping, the merge-resolution function for each mode, the
GPP action state machine, APPROXIMATE flagging, and ILT conditional flagging.
No samples required — all fixtures are synthetic.
"""

from __future__ import annotations

from gpo_lens.merge import (
    ChainEntry,
    CseMergeMode,
    cse_merge_mode,
    merge_settings,
    merge_settings_with_exclusions,
)
from gpo_lens.model import Setting


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
