"""Tests for v0.8.0 features: golden-backup diff, ADMX coverage, delegation rollup, ADMX auto-detection."""  # noqa: E501

from __future__ import annotations

from gpo_lens import queries
from gpo_lens.admx_parser import AdmxPolicy, PolicyDefinitions, find_admx_dir
from gpo_lens.model import DelegationEntry, Estate, Gpo, ResolvedPrincipal, Setting


def _make_gpo(**kwargs) -> Gpo:
    defaults = {
        "id": "11111111111111111111111111111111",
        "name": "Test GPO",
        "domain": "test.local",
        "created": None,
        "modified": None,
        "read": None,
        "computer_enabled": True,
        "user_enabled": True,
        "computer_ver_ds": None,
        "computer_ver_sysvol": None,
        "user_ver_ds": None,
        "user_ver_sysvol": None,
        "sddl": None,
        "owner": None,
        "filter_data_available": False,
        "wmi_filter": None,
        "sysvol_path": None,
    }
    defaults.update(kwargs)
    return Gpo(**defaults)


def _make_setting(gpo_id: str, side: str, cse: str, identity: str,
                  display_name: str = "", display_value: str = "") -> Setting:
    return Setting(
        gpo_id=gpo_id, side=side, cse=cse, identity=identity,
        display_name=display_name, display_value=display_value,
        raw={}, from_disabled_side=False,
    )


# ===========================================================================
# Golden-backup comparison (WI-061)
# ====================================================================================

class TestGoldenDiff:
    def test_identical_estates_are_all_compliant(self):
        gpo = _make_gpo(id="aaa", name="Policy A")
        gpo.settings = [
            _make_setting("aaa", "Computer", "Security", "Lockout:Threshold",
                          "Lockout Threshold", "5"),
            _make_setting("aaa", "User", "Registry", r"Software\Foo:Bar",
                          "Foo Bar", "1"),
        ]
        live = Estate(gpos=[gpo])
        golden = Estate(gpos=[_make_gpo(id="bbb", name="Policy A")])
        golden.gpos[0].settings = [
            _make_setting("bbb", "Computer", "Security", "Lockout:Threshold",
                          "Lockout Threshold", "5"),
            _make_setting("bbb", "User", "Registry", r"Software\Foo:Bar",
                          "Foo Bar", "1"),
        ]
        results = queries.golden_diff(live, golden)
        assert all(r.status == "compliant" for r in results)
        assert len(results) == 2

    def test_changed_setting_detected(self):
        gpo = _make_gpo(id="aaa", name="Policy A")
        gpo.settings = [
            _make_setting("aaa", "Computer", "Security", "Lockout:Threshold",
                          "Lockout Threshold", "10"),
        ]
        live = Estate(gpos=[gpo])
        golden_gpo = _make_gpo(id="bbb", name="Policy A")
        golden_gpo.settings = [
            _make_setting("bbb", "Computer", "Security", "Lockout:Threshold",
                          "Lockout Threshold", "5"),
        ]
        golden = Estate(gpos=[golden_gpo])
        results = queries.golden_diff(live, golden)
        changed = [r for r in results if r.status == "changed"]
        assert len(changed) == 1
        assert changed[0].golden_value == "5"
        assert changed[0].live_value == "10"

    def test_added_setting_detected(self):
        gpo = _make_gpo(id="aaa", name="Policy A")
        gpo.settings = [
            _make_setting("aaa", "Computer", "Security", "Lockout:Threshold",
                          "Lockout Threshold", "5"),
            _make_setting("aaa", "Computer", "Registry", r"Software\New:Setting",
                          "New Setting", "1"),
        ]
        live = Estate(gpos=[gpo])
        golden_gpo = _make_gpo(id="bbb", name="Policy A")
        golden_gpo.settings = [
            _make_setting("bbb", "Computer", "Security", "Lockout:Threshold",
                          "Lockout Threshold", "5"),
        ]
        golden = Estate(gpos=[golden_gpo])
        results = queries.golden_diff(live, golden)
        added = [r for r in results if r.status == "added"]
        assert len(added) == 1
        assert added[0].live_value == "1"
        assert added[0].golden_value == ""

    def test_removed_setting_detected(self):
        gpo = _make_gpo(id="aaa", name="Policy A")
        gpo.settings = [
            _make_setting("aaa", "Computer", "Security", "Lockout:Threshold",
                          "Lockout Threshold", "5"),
        ]
        live = Estate(gpos=[gpo])
        golden_gpo = _make_gpo(id="bbb", name="Policy A")
        golden_gpo.settings = [
            _make_setting("bbb", "Computer", "Security", "Lockout:Threshold",
                          "Lockout Threshold", "5"),
            _make_setting("bbb", "Computer", "Registry", r"Software\Old:Setting",
                          "Old Setting", "0"),
        ]
        golden = Estate(gpos=[golden_gpo])
        results = queries.golden_diff(live, golden)
        removed = [r for r in results if r.status == "removed"]
        assert len(removed) == 1
        assert removed[0].golden_value == "0"
        assert removed[0].live_value == ""

    def test_gpo_added_and_removed(self):
        live = Estate(gpos=[
            _make_gpo(id="aaa", name="Policy A"),
            _make_gpo(id="ccc", name="Policy C"),
        ])
        golden = Estate(gpos=[
            _make_gpo(id="bbb", name="Policy A"),
            _make_gpo(id="ddd", name="Policy B"),
        ])
        results = queries.golden_diff(live, golden)
        added = [r for r in results if r.status == "gpo_added"]
        removed = [r for r in results if r.status == "gpo_removed"]
        assert {r.gpo_name for r in added} == {"Policy C"}
        assert {r.gpo_name for r in removed} == {"Policy B"}

    def test_blocked_extensions_skipped(self):
        gpo = _make_gpo(id="aaa", name="Policy A")
        gpo.settings = [
            Setting(
                gpo_id="aaa", side="Computer", cse="Registry",
                identity=r"Software\Foo:Bar", display_name="Foo Bar",
                display_value="1", raw={}, from_disabled_side=False,
                source_state="blocked",
            ),
        ]
        live = Estate(gpos=[gpo])
        golden = Estate(gpos=[_make_gpo(id="bbb", name="Policy A")])
        results = queries.golden_diff(live, golden)
        assert all(r.status != "added" for r in results)

    def test_summary_counts(self):
        live = Estate(gpos=[
            _make_gpo(id="aaa", name="Policy A"),
            _make_gpo(id="ccc", name="Policy C"),
        ])
        live.gpos[0].settings = [
            _make_setting("aaa", "Computer", "Security", "Lockout:Threshold",
                          "Lockout Threshold", "10"),
        ]
        golden = Estate(gpos=[
            _make_gpo(id="bbb", name="Policy A"),
        ])
        golden.gpos[0].settings = [
            _make_setting("bbb", "Computer", "Security", "Lockout:Threshold",
                          "Lockout Threshold", "5"),
        ]
        results = queries.golden_diff(live, golden)
        summary = queries.golden_diff_summary(results)
        assert summary.gpos_matched == 1
        assert summary.gpos_added == 1
        assert summary.gpos_removed == 0
        assert summary.settings_changed == 1

    def test_admx_name_resolved(self):
        admx = PolicyDefinitions(policies=[
            AdmxPolicy(
                name="LockoutPolicy", class_scope="Machine",
                key=r"Software\Lockout", value_name="Threshold",
                display_name_ref="", display_name="Account Lockout Threshold",
                explain_text="",
            ),
        ])
        gpo = _make_gpo(id="aaa", name="Policy A")
        gpo.settings = [
            _make_setting("aaa", "Computer", "Registry",
                          r"Software\Lockout:Threshold", "Threshold", "5"),
        ]
        live = Estate(gpos=[gpo])
        golden_gpo = _make_gpo(id="bbb", name="Policy A")
        golden_gpo.settings = [
            _make_setting("bbb", "Computer", "Registry",
                          r"Software\Lockout:Threshold", "Threshold", "5"),
        ]
        golden = Estate(gpos=[golden_gpo])
        results = queries.golden_diff(live, golden, admx)
        compliant = [r for r in results if r.status == "compliant"]
        assert len(compliant) == 1
        assert compliant[0].admx_name == "Account Lockout Threshold"

    def test_original_casing_preserved(self):
        gpo = _make_gpo(id="aaa", name="Policy A")
        gpo.settings = [
            _make_setting("aaa", "Computer", "Security", "Lockout:Threshold",
                          "Lockout Threshold", "5"),
        ]
        live = Estate(gpos=[gpo])
        golden_gpo = _make_gpo(id="bbb", name="Policy A")
        golden_gpo.settings = [
            _make_setting("bbb", "Computer", "Security", "Lockout:Threshold",
                          "Lockout Threshold", "5"),
        ]
        golden = Estate(gpos=[golden_gpo])
        results = queries.golden_diff(live, golden)
        compliant = [r for r in results if r.status == "compliant"]
        assert compliant[0].cse == "Security"
        assert compliant[0].identity == "Lockout:Threshold"

    def test_matched_gpo_with_zero_settings(self):
        live = Estate(gpos=[_make_gpo(id="aaa", name="Empty Policy")])
        golden = Estate(gpos=[_make_gpo(id="bbb", name="Empty Policy")])
        results = queries.golden_diff(live, golden)
        assert results == []
        live_names = {g.name.lower() for g in live.gpos}
        golden_names = {g.name.lower() for g in golden.gpos}
        summary = queries.golden_diff_summary(
            results, matched_gpo_count=len(live_names & golden_names),
        )
        assert summary.gpos_matched == 1

    def test_case_insensitive_gpo_name_matching(self):
        gpo = _make_gpo(id="aaa", name="Policy A")
        gpo.settings = [
            _make_setting("aaa", "Computer", "Security", "Lockout:Threshold",
                          "Lockout Threshold", "5"),
        ]
        live = Estate(gpos=[gpo])
        golden_gpo = _make_gpo(id="bbb", name="policy a")
        golden_gpo.settings = [
            _make_setting("bbb", "Computer", "Security", "Lockout:Threshold",
                          "Lockout Threshold", "5"),
        ]
        golden = Estate(gpos=[golden_gpo])
        results = queries.golden_diff(live, golden)
        assert all(r.status == "compliant" for r in results)

    def test_added_setting_display_name_from_live(self):
        gpo = _make_gpo(id="aaa", name="Policy A")
        gpo.settings = [
            _make_setting("aaa", "Computer", "Registry", r"Software\New:Setting",
                          "New Setting Name", "1"),
        ]
        live = Estate(gpos=[gpo])
        golden = Estate(gpos=[_make_gpo(id="bbb", name="Policy A")])
        results = queries.golden_diff(live, golden)
        added = [r for r in results if r.status == "added"]
        assert len(added) == 1
        assert added[0].display_name == "New Setting Name"


# ===========================================================================
# ADMX coverage view (WI-062)
# ====================================================================================

class TestAdmxCoverage:
    def test_empty_admx_returns_empty_report(self):
        estate = Estate(gpos=[_make_gpo()])
        report = queries.admx_coverage(estate, None)
        assert report.summary.total_policies == 0
        assert report.summary.referenced_policies == 0

    def test_referenced_policy_detected(self):
        admx = PolicyDefinitions(policies=[
            AdmxPolicy(
                name="NoControlPanel", class_scope="User",
                key=r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
                value_name="NoControlPanel",
                display_name_ref="", display_name="Prohibit access to Control Panel",
                explain_text="",
            ),
        ])
        gpo = _make_gpo(id="aaa", name="Lockdown")
        gpo.settings = [
            _make_setting("aaa", "User", "Registry",
                          r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer:NoControlPanel",
                          "NoControlPanel", "1"),
        ]
        estate = Estate(gpos=[gpo])
        report = queries.admx_coverage(estate, admx)
        assert report.summary.referenced_policies == 1
        assert report.summary.unreferenced_policies == 0
        assert len(report.referenced) == 1
        assert report.referenced[0].policy_name == "NoControlPanel"
        assert "Lockdown" in report.referenced[0].referenced_gpos

    def test_unreferenced_policy_detected(self):
        admx = PolicyDefinitions(policies=[
            AdmxPolicy(
                name="UnusedPolicy", class_scope="Machine",
                key=r"Software\Unused", value_name="Setting",
                display_name_ref="", display_name="Unused Setting",
                explain_text="",
            ),
        ])
        estate = Estate(gpos=[_make_gpo()])
        report = queries.admx_coverage(estate, admx)
        assert report.summary.unreferenced_policies == 1
        assert len(report.unreferenced) == 1

    def test_gap_settings_detected(self):
        admx = PolicyDefinitions(policies=[])
        gpo = _make_gpo(id="aaa", name="Policy A")
        gpo.settings = [
            _make_setting("aaa", "Computer", "Registry",
                          r"Software\Unknown\Path:Value", "Unknown Value", "1"),
        ]
        estate = Estate(gpos=[gpo])
        report = queries.admx_coverage(estate, admx)
        assert report.summary.gap_count == 1
        assert len(report.gaps) == 1
        assert "Policy A" in report.gaps[0].referenced_gpos

    def test_blocked_extensions_skipped_in_gaps(self):
        admx = PolicyDefinitions(policies=[])
        gpo = _make_gpo(id="aaa", name="Policy A")
        gpo.settings = [
            Setting(
                gpo_id="aaa", side="Computer", cse="Registry",
                identity=r"Software\Blocked:Path", display_name="Blocked",
                display_value="1", raw={}, from_disabled_side=False,
                source_state="blocked",
            ),
        ]
        estate = Estate(gpos=[gpo])
        report = queries.admx_coverage(estate, admx)
        assert report.summary.gap_count == 0


# ===========================================================================
# Delegation rollup (breadcrumb: estate-wide-delegation-view)
# ====================================================================================

class TestDelegationRollup:
    def test_empty_estate(self):
        estate = Estate()
        assert queries.delegation_rollup(estate) == []

    def test_read_only_excluded(self):
        gpo = _make_gpo(id="aaa", name="Policy A")
        gpo.delegation = [
            DelegationEntry(gpo_id="aaa", trustee="Domain Admins",
                           trustee_sid="S-1-5-21-1-512", permission="Read",
                           allowed=True),
        ]
        estate = Estate(gpos=[gpo])
        assert queries.delegation_rollup(estate) == []

    def test_edit_permission_included(self):
        gpo = _make_gpo(id="aaa", name="Policy A")
        gpo.delegation = [
            DelegationEntry(gpo_id="aaa", trustee="Domain Admins",
                           trustee_sid="S-1-5-21-1-512", permission="Edit settings",
                           allowed=True),
        ]
        estate = Estate(gpos=[gpo])
        rollup = queries.delegation_rollup(estate)
        assert len(rollup) == 1
        assert rollup[0].gpo_count == 1
        assert "Policy A" in rollup[0].gpo_names
        assert "Edit settings" in rollup[0].permissions
        assert rollup[0].is_default_writer

    def test_unknown_sid_flagged(self):
        gpo = _make_gpo(id="aaa", name="Policy A")
        gpo.delegation = [
            DelegationEntry(gpo_id="aaa", trustee="",
                           trustee_sid="S-1-5-21-99-12345", permission="Edit settings",
                           allowed=True),
        ]
        estate = Estate(gpos=[gpo])
        rollup = queries.delegation_rollup(estate)
        assert len(rollup) == 1
        assert rollup[0].is_unknown_sid
        assert not rollup[0].is_default_writer

    def test_non_default_writer_flagged(self):
        gpo = _make_gpo(id="aaa", name="Policy A")
        gpo.delegation = [
            DelegationEntry(gpo_id="aaa", trustee="Helpdesk Team",
                           trustee_sid="S-1-5-21-1-1001", permission="Edit settings",
                           allowed=True),
        ]
        estate = Estate(
            gpos=[gpo],
            principals={
                "s-1-5-21-1-1001": ResolvedPrincipal(
                    sid="s-1-5-21-1-1001", name="Helpdesk Team", sam="Helpdesk",
                    principal_type="Group", domain="TEST", resolved=True,
                ),
            },
        )
        rollup = queries.delegation_rollup(estate)
        assert len(rollup) == 1
        assert not rollup[0].is_default_writer
        assert not rollup[0].is_unknown_sid
        assert rollup[0].resolved_name == "Helpdesk Team"

    def test_sorted_by_breadth(self):
        gpo_a = _make_gpo(id="aaa", name="Policy A")
        gpo_a.delegation = [
            DelegationEntry(gpo_id="aaa", trustee="Trustee X",
                           trustee_sid="", permission="Edit settings",
                           allowed=True),
        ]
        gpo_b = _make_gpo(id="bbb", name="Policy B")
        gpo_b.delegation = [
            DelegationEntry(gpo_id="bbb", trustee="Trustee X",
                           trustee_sid="", permission="Edit settings",
                           allowed=True),
        ]
        gpo_c = _make_gpo(id="ccc", name="Policy C")
        gpo_c.delegation = [
            DelegationEntry(gpo_id="ccc", trustee="Trustee Y",
                           trustee_sid="", permission="Edit settings",
                           allowed=True),
        ]
        estate = Estate(gpos=[gpo_a, gpo_b, gpo_c])
        rollup = queries.delegation_rollup(estate)
        assert rollup[0].gpo_count == 2
        assert rollup[0].trustee == "Trustee X"
        assert rollup[1].gpo_count == 1
        assert rollup[1].trustee == "Trustee Y"

    def test_deny_entries_excluded(self):
        gpo = _make_gpo(id="aaa", name="Policy A")
        gpo.delegation = [
            DelegationEntry(gpo_id="aaa", trustee="Denied Trustee",
                           trustee_sid="", permission="Edit settings",
                           allowed=False),
        ]
        estate = Estate(gpos=[gpo])
        assert queries.delegation_rollup(estate) == []

    def test_apply_group_policy_excluded(self):
        gpo = _make_gpo(id="aaa", name="Policy A")
        gpo.delegation = [
            DelegationEntry(gpo_id="aaa", trustee="Authenticated Users",
                           trustee_sid="S-1-5-11", permission="Apply Group Policy",
                           allowed=True),
        ]
        estate = Estate(gpos=[gpo])
        assert queries.delegation_rollup(estate) == []


# ===========================================================================
# ADMX auto-detection (Plan 010 WI-B.2)
# ====================================================================================

class TestFindAdmxDir:
    def test_returns_none_for_nonexistent(self, tmp_path):
        result = find_admx_dir(tmp_path)
        assert result is None

    def test_finds_sysvol_policies_path(self, tmp_path):
        pd_dir = tmp_path / "SYSVOL-Policies" / "PolicyDefinitions"
        pd_dir.mkdir(parents=True)
        result = find_admx_dir(tmp_path)
        assert result == pd_dir

    def test_finds_direct_policy_definitions(self, tmp_path):
        pd_dir = tmp_path / "PolicyDefinitions"
        pd_dir.mkdir()
        result = find_admx_dir(tmp_path)
        assert result == pd_dir

    def test_sysvol_policies_takes_priority(self, tmp_path):
        (tmp_path / "PolicyDefinitions").mkdir()
        pd_dir = tmp_path / "SYSVOL-Policies" / "PolicyDefinitions"
        pd_dir.mkdir(parents=True)
        result = find_admx_dir(tmp_path)
        assert result == pd_dir
