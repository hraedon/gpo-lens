"""Tests for the dangerous-configuration detectors (Plan 018 Phase B)."""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
from pathlib import Path

import pytest

from gpo_lens.danger import (
    DangerRule,
    danger_findings,
    evaluate_danger_rules,
    gpo_writable_by_nonadmin,
    load_danger_rules,
    local_admin_push,
    overbroad_apply_group_policy,
)
from gpo_lens.model import DelegationEntry, Estate, Gpo, Setting

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"
DEFAULT_GID = "11111111-2222-3333-4444-555555555555"
_WDIGEST_ID = r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa:UseLogonCredential"
_LMCOMP_ID = r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa:LmCompatibilityLevel"


def _make_gpo(**kwargs) -> Gpo:
    defaults = {
        "id": DEFAULT_GID,
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


def _reg_setting(
    gpo_id: str,
    identity: str,
    value: str,
    side: str = "Computer",
) -> Setting:
    return Setting(
        gpo_id=gpo_id,
        side=side,
        cse="Registry",
        identity=identity,
        display_name=identity.split(":")[-1] if ":" in identity else identity,
        display_value=value,
        raw={},
        from_disabled_side=False,
    )


# ---------------------------------------------------------------------------
# Bucket 2 — structural / attack-path
# ---------------------------------------------------------------------------

class TestGpoWritableByNonadmin:
    def test_detects_writable_gpo(self) -> None:
        # GA (Generic All) includes write rights; S-1-5-21-...-1000 is a
        # non-default-writer trustee (not Domain Admins/System/Administrators).
        sddl = "D:(A;;GA;;;S-1-5-21-1-2-3-1000)"
        gpo = _make_gpo(sddl=sddl, name="writable-gpo")
        estate = Estate(gpos=[gpo])
        findings = gpo_writable_by_nonadmin(estate)
        assert len(findings) == 1
        f = findings[0]
        assert f.check_id == "gpo_writable_nonadmin"
        assert f.severity == "high"
        assert f.gpo_id == gpo.id
        assert "S-1-5-21-1-2-3-1000" in f.detail
        assert f.reference

    def test_ignores_domain_admins(self) -> None:
        sddl = "D:(A;;GA;;;S-1-5-21-1234567890-1234567890-1234567890-512)"
        gpo = _make_gpo(sddl=sddl)
        estate = Estate(gpos=[gpo])
        assert gpo_writable_by_nonadmin(estate) == []

    def test_ignores_system(self) -> None:
        sddl = "D:(A;;GA;;;S-1-5-18)"
        gpo = _make_gpo(sddl=sddl)
        estate = Estate(gpos=[gpo])
        assert gpo_writable_by_nonadmin(estate) == []

    def test_ignores_read_only_ace(self) -> None:
        # GR (Generic Read) is not a write right.
        sddl = "D:(A;;GR;;;S-1-5-21-1-2-3-1000)"
        gpo = _make_gpo(sddl=sddl)
        estate = Estate(gpos=[gpo])
        assert gpo_writable_by_nonadmin(estate) == []

    def test_no_sddl_no_finding(self) -> None:
        gpo = _make_gpo(sddl=None)
        estate = Estate(gpos=[gpo])
        assert gpo_writable_by_nonadmin(estate) == []

    def test_detects_nonadmin_owner(self) -> None:
        sddl = "O:S-1-5-21-1-2-3-1000D:(A;;GA;;;BA)"
        gpo = _make_gpo(sddl=sddl, name="owned-gpo")
        estate = Estate(gpos=[gpo])
        findings = gpo_writable_by_nonadmin(estate)
        owner_findings = [f for f in findings if f.check_id == "gpo_owner_nonadmin"]
        assert len(owner_findings) == 1
        assert "S-1-5-21-1-2-3-1000" in owner_findings[0].detail

    def test_ignores_admin_owner(self) -> None:
        sddl = "O:S-1-5-21-1234567890-1234567890-1234567890-512D:(A;;GA;;;BA)"
        gpo = _make_gpo(sddl=sddl)
        estate = Estate(gpos=[gpo])
        findings = gpo_writable_by_nonadmin(estate)
        owner_findings = [f for f in findings if f.check_id == "gpo_owner_nonadmin"]
        assert owner_findings == []

    def test_detects_object_allow_ace(self) -> None:
        sddl = "D:(OA;;GA;;;S-1-5-21-1-2-3-1000)"
        gpo = _make_gpo(sddl=sddl)
        estate = Estate(gpos=[gpo])
        findings = gpo_writable_by_nonadmin(estate)
        writable = [f for f in findings if f.check_id == "gpo_writable_nonadmin"]
        assert len(writable) == 1

    def test_ignores_real_default_gpo_dacl(self) -> None:
        """Regression: real GPO SDDL uses the ``O:DA`` alias and a Creator Owner
        (CO) full-control ACE. Neither is a hijack primitive — flagging them
        produced a finding on *every* GPO and buried the real signal."""
        sddl = (
            "O:DAG:DAD:PAI"
            "(A;CI;CCDCLCSWRPWPDTLOSDRCWDWO;;;DA)"   # Domain Admins full control
            "(A;CI;CCDCLCSWRPWPDTLOSDRCWDWO;;;EA)"   # Enterprise Admins full control
            "(A;CI;CCDCLCSWRPWPDTLOSDRCWDWO;;;CO)"   # Creator Owner full control
            "(A;CI;CCDCLCSWRPWPDTLOSDRCWDWO;;;SY)"   # SYSTEM full control
            "(A;CI;RPLCRC;;;AU)"                     # Authenticated Users read+apply
        )
        gpo = _make_gpo(sddl=sddl)
        findings = gpo_writable_by_nonadmin(Estate(gpos=[gpo]))
        assert findings == []

    def test_detail_shows_resolved_name_with_sid(self) -> None:
        """AC-1/AC-4: detail shows 'name (sid)' when principals.json is present."""
        from gpo_lens.model import ResolvedPrincipal

        sid = "S-1-5-21-1-2-3-1000"
        sddl = f"D:(A;;GA;;;{sid})"
        gpo = _make_gpo(sddl=sddl, name="writable-gpo")
        estate = Estate(gpos=[gpo], principals={
            sid.lower(): ResolvedPrincipal(
                sid=sid.lower(), name="TEST\\GPO-Admins", sam="GPO-Admins",
                principal_type="Group", domain="TEST", resolved=True,
            ),
        })
        findings = gpo_writable_by_nonadmin(estate)
        assert len(findings) == 1
        assert "TEST\\GPO-Admins" in findings[0].detail
        # AC-4: SID always present alongside the resolved name
        assert sid in findings[0].detail

    def test_detail_unresolved_shows_sid_only(self) -> None:
        """AC-3: unresolved SID → detail shows the raw SID, no blank."""
        sid = "S-1-5-21-1-2-3-1000"
        sddl = f"D:(A;;GA;;;{sid})"
        gpo = _make_gpo(sddl=sddl)
        estate = Estate(gpos=[gpo])
        findings = gpo_writable_by_nonadmin(estate)
        assert len(findings) == 1
        assert sid in findings[0].detail

    def test_owner_detail_shows_resolved_name(self) -> None:
        from gpo_lens.model import ResolvedPrincipal

        sid = "S-1-5-21-1-2-3-1000"
        sddl = f"O:{sid}D:(A;;GA;;;BA)"
        gpo = _make_gpo(sddl=sddl, name="owned-gpo")
        estate = Estate(gpos=[gpo], principals={
            sid.lower(): ResolvedPrincipal(
                sid=sid.lower(), name="TEST\\Owner", sam="Owner",
                principal_type="User", domain="TEST", resolved=True,
            ),
        })
        findings = gpo_writable_by_nonadmin(estate)
        owner = [f for f in findings if f.check_id == "gpo_owner_nonadmin"]
        assert len(owner) == 1
        assert "TEST\\Owner" in owner[0].detail
        assert sid in owner[0].detail


class TestLocalAdminPush:
    @staticmethod
    def _make_sysvol(tmp_path: Path) -> str:
        sysvol = tmp_path / "Sysvol"
        prefs = sysvol / "Machine" / "Preferences"
        prefs.mkdir(parents=True)
        (prefs / "LocalUsersAndGroups.xml").write_text(
            '<?xml version="1.0" encoding="utf-8"?>\n'
            '<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D66F83}">\n'
            '  <Group name="Administrators (local)" changed="2025-06-01">\n'
            '    <Properties action="UPDATE" groupName="Administrators"\n'
            '      groupSid="S-1-5-32-544" removePolicy="0">\n'
            '      <Members>\n'
            '        <Member name="HELPDESK\\Tier1Admins" action="ADD"\n'
            '          sid="S-1-5-21-1-2-3-1101"/>\n'
            '      </Members>\n'
            '    </Properties>\n'
            '  </Group>\n'
            '</Groups>\n',
            encoding="utf-8",
        )
        return str(sysvol)

    def test_detects_admin_group_mod(self, tmp_path: Path) -> None:
        gpo = _make_gpo(
            id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            name="admin-push-gpo",
            sysvol_path=self._make_sysvol(tmp_path),
        )
        estate = Estate(gpos=[gpo])
        findings = local_admin_push(estate)
        assert len(findings) == 1
        f = findings[0]
        assert f.check_id == "local_admin_push"
        assert f.severity == "high"
        assert f.gpo_id == gpo.id
        assert "Tier1Admins" in f.detail
        assert f.reference

    def test_ignores_non_admin_group(self, tmp_path: Path) -> None:
        sysvol = tmp_path / "Sysvol"
        prefs = sysvol / "Machine" / "Preferences"
        prefs.mkdir(parents=True)
        (prefs / "LocalUsersAndGroups.xml").write_text(
            '<?xml version="1.0" encoding="utf-8"?>\n'
            '<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D66F83}">\n'
            '  <Group name="Remote Desktop Users" changed="2025-06-01">\n'
            '    <Properties action="UPDATE" groupName="Remote Desktop Users"\n'
            '      groupSid="S-1-5-32-555" removePolicy="0">\n'
            '      <Members>\n'
            '        <Member name="HELPDESK\\Users" action="ADD" sid="S-1-5-21-1-2-3-9"/>\n'
            '      </Members>\n'
            '    </Properties>\n'
            '  </Group>\n'
            '</Groups>\n',
            encoding="utf-8",
        )
        gpo = _make_gpo(sysvol_path=str(sysvol))
        estate = Estate(gpos=[gpo])
        assert local_admin_push(estate) == []

    def test_ignores_admin_group_with_no_adds(self, tmp_path: Path) -> None:
        sysvol = tmp_path / "Sysvol"
        prefs = sysvol / "Machine" / "Preferences"
        prefs.mkdir(parents=True)
        (prefs / "LocalUsersAndGroups.xml").write_text(
            '<?xml version="1.0" encoding="utf-8"?>\n'
            '<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D66F83}">\n'
            '  <Group name="Administrators (local)" changed="2025-06-01">\n'
            '    <Properties action="UPDATE" groupName="Administrators"\n'
            '      groupSid="S-1-5-32-544" removePolicy="0">\n'
            '      <Members>\n'
            '        <Member name="HELPDESK\\OldAdmin" action="REMOVE"\n'
            '         sid="S-1-5-21-1-2-3-1102"/>\n'
            '      </Members>\n'
            '    </Properties>\n'
            '  </Group>\n'
            '</Groups>\n',
            encoding="utf-8",
        )
        gpo = _make_gpo(sysvol_path=str(sysvol))
        estate = Estate(gpos=[gpo])
        assert local_admin_push(estate) == []


class TestOverbroadApplyGroupPolicy:
    def test_detects_everyone(self) -> None:
        gpo = _make_gpo(
            delegation=[
                DelegationEntry(
                    gpo_id="g1", trustee="Everyone", trustee_sid="S-1-1-0",
                    permission="Apply Group Policy", allowed=True,
                ),
            ],
        )
        estate = Estate(gpos=[gpo])
        findings = overbroad_apply_group_policy(estate)
        assert len(findings) == 1
        f = findings[0]
        assert f.check_id == "overbroad_apply_gp"
        assert f.severity == "medium"
        assert "s-1-1-0" in f.detail.lower()
        assert f.reference

    def test_detects_anonymous(self) -> None:
        gpo = _make_gpo(
            delegation=[
                DelegationEntry(
                    gpo_id="g1", trustee="Anonymous", trustee_sid="S-1-5-7",
                    permission="Apply Group Policy", allowed=True,
                ),
            ],
        )
        estate = Estate(gpos=[gpo])
        assert len(overbroad_apply_group_policy(estate)) == 1

    def test_ignores_helpdesk_apply(self) -> None:
        gpo = _make_gpo(
            delegation=[
                DelegationEntry(
                    gpo_id="g1", trustee="Helpdesk", trustee_sid="S-1-5-21-1-2-3-1000",
                    permission="Apply Group Policy", allowed=True,
                ),
            ],
        )
        estate = Estate(gpos=[gpo])
        assert overbroad_apply_group_policy(estate) == []

    def test_ignores_denied(self) -> None:
        gpo = _make_gpo(
            delegation=[
                DelegationEntry(
                    gpo_id="g1", trustee="Everyone", trustee_sid="S-1-1-0",
                    permission="Apply Group Policy", allowed=False,
                ),
            ],
        )
        estate = Estate(gpos=[gpo])
        assert overbroad_apply_group_policy(estate) == []

    def test_sddl_fallback_when_delegation_empty(self) -> None:
        gpo = _make_gpo(
            sddl="D:(A;;GA;;;WD)",
            delegation=[],
        )
        estate = Estate(gpos=[gpo])
        findings = overbroad_apply_group_policy(estate)
        assert len(findings) == 1
        assert findings[0].check_id == "overbroad_apply_gp"

    def test_no_sddl_fallback_when_delegation_populated(self) -> None:
        gpo = _make_gpo(
            sddl="D:(A;;GA;;;WD)",
            delegation=[
                DelegationEntry(
                    gpo_id="g1", trustee="Helpdesk",
                    trustee_sid="S-1-5-21-1-2-3-1000",
                    permission="Apply Group Policy", allowed=True,
                ),
            ],
        )
        estate = Estate(gpos=[gpo])
        assert overbroad_apply_group_policy(estate) == []

    def test_overbroad_detail_shows_resolved_name(self) -> None:
        """AC-1: delegation path already carries the trustee name + SID."""
        gpo = _make_gpo(
            delegation=[
                DelegationEntry(
                    gpo_id="g1", trustee="Everyone", trustee_sid="S-1-1-0",
                    permission="Apply Group Policy", allowed=True,
                ),
            ],
        )
        estate = Estate(gpos=[gpo])
        findings = overbroad_apply_group_policy(estate)
        assert len(findings) == 1
        assert "Everyone" in findings[0].detail
        assert "s-1-1-0" in findings[0].detail.lower()

    def test_overbroad_sddl_fallback_detail_shows_resolved_name(self) -> None:
        """SDDL fallback path resolves the bare SID to a name via resolve_principal."""
        gpo = _make_gpo(
            sddl="D:(A;;GA;;;S-1-1-0)",
            delegation=[],
        )
        estate = Estate(gpos=[gpo])
        findings = overbroad_apply_group_policy(estate)
        assert len(findings) == 1
        assert "Everyone" in findings[0].detail
        assert "S-1-1-0" in findings[0].detail

    def test_overbroad_verdict_invariant_with_principals(self) -> None:
        """AC-5: the set of findings is unchanged by principal resolution."""
        from gpo_lens.model import ResolvedPrincipal

        sid = "S-1-1-0"
        gpo = _make_gpo(
            delegation=[
                DelegationEntry(
                    gpo_id="g1", trustee="Everyone", trustee_sid=sid,
                    permission="Apply Group Policy", allowed=True,
                ),
            ],
        )
        estate_bare = Estate(gpos=[gpo])
        estate_resolved = Estate(gpos=[gpo], principals={
            sid.lower(): ResolvedPrincipal(
                sid=sid.lower(), name="Everyone", sam="Everyone",
                principal_type="WellKnown", domain="", resolved=True,
            ),
        })
        bare = overbroad_apply_group_policy(estate_bare)
        resolved = overbroad_apply_group_policy(estate_resolved)
        assert len(bare) == len(resolved) == 1
        assert bare[0].check_id == resolved[0].check_id
        assert bare[0].gpo_id == resolved[0].gpo_id


# ---------------------------------------------------------------------------
# Bucket 1 — setting-value dangers
# ---------------------------------------------------------------------------

class TestDangerRules:
    def test_load_danger_rules_ships_cited_set(self) -> None:
        rules = load_danger_rules()
        ids = {r.id for r in rules}
        assert {"wdigest_creds", "smb_signing_disabled", "lm_hash_enabled",
                "autoadmin_logon", "ntlmv1_allowed"} <= ids
        for r in rules:
            assert r.reference, f"rule {r.id} has no citation"
            assert r.severity in ("critical", "high", "medium", "low")

    def test_wdigest_creds(self) -> None:
        rule = DangerRule(
            id="wdigest_creds", title="WDigest", severity="critical",
            applies="Machine",
            identity=r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa:UseLogonCredential",
            predicate="equals", value="1",
            reference="https://attack.mitre.org/techniques/T1003/001/",
        )
        gpo = _make_gpo(settings=[
            _reg_setting(DEFAULT_GID, _WDIGEST_ID, "1"),
        ])
        findings = evaluate_danger_rules(Estate(gpos=[gpo]), [rule])
        assert len(findings) == 1
        assert findings[0].severity == "critical"
        assert findings[0].reference == rule.reference

    def test_smb_signing_disabled(self) -> None:
        rule = DangerRule(
            id="smb_signing_disabled", title="SMB signing", severity="high",
            applies="Machine",
            identity=r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters:RequireSecuritySignature",
            predicate="equals", value="0",
            reference="https://attack.mitre.org/techniques/T1557/001/",
        )
        gpo = _make_gpo(settings=[
            _reg_setting(
                DEFAULT_GID,
                r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters:RequireSecuritySignature",
                "0",
            ),
        ])
        findings = evaluate_danger_rules(Estate(gpos=[gpo]), [rule])
        assert len(findings) == 1
        assert findings[0].severity == "high"

    def test_no_match_when_value_safe(self) -> None:
        rule = DangerRule(
            id="wdigest_creds", title="WDigest", severity="critical",
            applies="Machine",
            identity=r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa:UseLogonCredential",
            predicate="equals", value="1",
            reference="ref",
        )
        gpo = _make_gpo(settings=[
            _reg_setting(DEFAULT_GID, _WDIGEST_ID, "0"),
        ])
        assert evaluate_danger_rules(Estate(gpos=[gpo]), [rule]) == []

    def test_case_insensitive_identity(self) -> None:
        rule = DangerRule(
            id="x", title="x", severity="high", applies="Machine",
            identity=r"hklm\system\currentcontrolset\control\lsa:uselogoncredential",
            predicate="equals", value="1", reference="ref",
        )
        gpo = _make_gpo(settings=[
            _reg_setting(DEFAULT_GID, _WDIGEST_ID, "1"),
        ])
        assert len(evaluate_danger_rules(Estate(gpos=[gpo]), [rule])) == 1

    def test_side_filter_machine_excludes_user(self) -> None:
        rule = DangerRule(
            id="x", title="x", severity="high", applies="Machine",
            identity=r"HKLM\Key:Val", predicate="equals", value="1", reference="ref",
        )
        gpo = _make_gpo(settings=[
            _reg_setting(DEFAULT_GID, r"HKLM\Key:Val", "1", side="User"),
        ])
        assert evaluate_danger_rules(Estate(gpos=[gpo]), [rule]) == []

    def test_in_predicate(self) -> None:
        rule = DangerRule(
            id="ntlmv1", title="NTLMv1", severity="high", applies="Machine",
            identity=r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa:LmCompatibilityLevel",
            predicate="in", value="0,1", reference="ref",
        )
        for bad in ("0", "1"):
            gpo = _make_gpo(settings=[
                _reg_setting(DEFAULT_GID, _LMCOMP_ID, bad),
            ])
            assert len(evaluate_danger_rules(Estate(gpos=[gpo]), [rule])) == 1, bad
        gpo_safe = _make_gpo(settings=[
            _reg_setting(DEFAULT_GID, _LMCOMP_ID, "3"),
        ])
        assert evaluate_danger_rules(Estate(gpos=[gpo_safe]), [rule]) == []

    def test_admx_name_keyed_resolves(self) -> None:
        from gpo_lens.admx_parser import AdmxPolicy, PolicyDefinitions

        admx = PolicyDefinitions(policies=[
            AdmxPolicy(
                name="WDigestCreds", class_scope="Machine",
                key=r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
                value_name="UseLogonCredential",
                display_name_ref="$(string.WDigestCreds)",
                display_name="WDigest plaintext credential caching",
                explain_text="",
            )
        ])
        rule = DangerRule(
            id="wdigest", title="WDigest", severity="critical", applies="Machine",
            identity="WDigest plaintext credential caching",
            predicate="equals", value="1",
            reference="https://attack.mitre.org/techniques/T1003/001/",
        )
        gpo = _make_gpo(settings=[
            _reg_setting(DEFAULT_GID, _WDIGEST_ID, "1"),
        ])
        findings = evaluate_danger_rules(Estate(gpos=[gpo]), [rule], admx=admx)
        assert len(findings) == 1
        assert findings[0].check_id == "wdigest"

    def test_admx_none_degrades_gracefully(self) -> None:
        name_keyed = DangerRule(
            id="name_keyed", title="x", severity="high", applies="Machine",
            identity="Some Policy Display Name",
            predicate="equals", value="1", reference="ref",
        )
        identity_keyed = DangerRule(
            id="identity_keyed", title="y", severity="high", applies="Machine",
            identity=r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa:UseLogonCredential",
            predicate="equals", value="1", reference="ref2",
        )
        gpo = _make_gpo(settings=[
            _reg_setting(DEFAULT_GID, _WDIGEST_ID, "1"),
        ])
        estate = Estate(gpos=[gpo])
        # No crash; name-keyed produces nothing, identity-keyed still fires.
        findings = evaluate_danger_rules(estate, [name_keyed, identity_keyed], admx=None)
        ids = {f.check_id for f in findings}
        assert ids == {"identity_keyed"}

    def test_blocked_settings_skipped(self) -> None:
        rule = DangerRule(
            id="x", title="x", severity="critical", applies="Machine",
            identity=r"HKLM\Key:Val", predicate="equals", value="1", reference="ref",
        )
        gpo = _make_gpo(settings=[
            Setting(
                gpo_id=DEFAULT_GID, side="Computer", cse="Registry",
                identity=r"HKLM\Key:Val", display_name="Val", display_value="1",
                raw={}, from_disabled_side=False, source_state="blocked",
            ),
        ])
        estate = Estate(gpos=[gpo])
        assert evaluate_danger_rules(estate, [rule]) == []

    def test_malformed_toml_returns_empty(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.toml"
        bad.write_text("not valid toml {{{{", encoding="utf-8")
        from gpo_lens.danger import _load_rules_file
        assert _load_rules_file(bad) == []

    def test_invalid_predicate_skipped_at_load(self, tmp_path: Path) -> None:
        toml_file = tmp_path / "rules.toml"
        toml_file.write_text(
            '[[rules]]\n'
            'id = "bad"\n'
            'title = "Bad"\n'
            'severity = "high"\n'
            'applies = "Machine"\n'
            'identity = "HKLM\\\\Key:Val"\n'
            'predicate = "exquls"\n'
            'value = "1"\n'
            'reference = "ref"\n',
            encoding="utf-8",
        )
        from gpo_lens.danger import _load_rules_file
        rules = _load_rules_file(toml_file)
        assert rules == []


# ---------------------------------------------------------------------------
# Aggregate
# ---------------------------------------------------------------------------

class TestDangerFindings:
    def test_aggregate_sorted_by_severity(self) -> None:
        critical_rule = DangerRule(
            id="wdigest_creds", title="WDigest", severity="critical", applies="Machine",
            identity=r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa:UseLogonCredential",
            predicate="equals", value="1", reference="ref",
        )
        writable_gpo = _make_gpo(
            id="11111111-1111-1111-1111-111111111111",
            name="writable",
            sddl="D:(A;;GA;;;S-1-5-21-1-2-3-1000)",
        )
        dangerous_gpo = _make_gpo(
            id="22222222-2222-2222-2222-222222222222",
            name="wdigest-gpo",
            settings=[
                _reg_setting(
                    "22222222-2222-2222-2222-222222222222",
                    r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa:UseLogonCredential", "1",
                ),
            ],
        )
        estate = Estate(gpos=[writable_gpo, dangerous_gpo])
        findings = danger_findings(estate, rules=[critical_rule])
        severities = [f.severity for f in findings]
        rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        assert severities == sorted(severities, key=lambda s: rank.get(s, 99))
        assert len(findings) == 2


# ---------------------------------------------------------------------------
# Integration: estate_doctor + estate_summary
# ---------------------------------------------------------------------------

class TestIntegration:
    def test_danger_findings_in_estate_doctor(self) -> None:
        from gpo_lens.queries import estate_doctor

        gpo = _make_gpo(
            sddl="D:(A;;GA;;;S-1-5-21-1-2-3-1000)",
            name="writable-gpo",
        )
        estate = Estate(gpos=[gpo])
        findings = estate_doctor(estate)
        danger_cats = {f.category for f in findings if f.category.startswith("danger:")}
        assert "danger:gpo_writable_nonadmin" in danger_cats
        assert all("[ref:" in f.detail for f in findings if f.category.startswith("danger:"))

    def test_danger_findings_in_estate_summary(self) -> None:
        from gpo_lens.queries import estate_summary

        gpo = _make_gpo(
            sddl="D:(A;;GA;;;S-1-5-21-1-2-3-1000)",
            name="writable-gpo",
        )
        estate = Estate(gpos=[gpo])
        summary = estate_summary(estate)
        assert summary.danger_finding_count == 1

        clean = Estate(gpos=[_make_gpo()])
        assert estate_summary(clean).danger_finding_count == 0


# ---------------------------------------------------------------------------
# Web route
# ---------------------------------------------------------------------------

try:
    import fastapi  # noqa: F401

    _HAS_WEB = True
except ImportError:
    _HAS_WEB = False

pytestmark_web = pytest.mark.skipif(not _HAS_WEB, reason="web extra not installed")


@pytest.fixture()
def _fixture_db():
    from gpo_lens.ingest import load_estate as ingest_load_estate
    from gpo_lens.store import init_db, save_estate

    with tempfile.NamedTemporaryFile(suffix=".sqlite3", delete=False) as f:
        path = f.name
    conn = sqlite3.connect(path)
    init_db(conn)
    estate = ingest_load_estate(FIXTURE_DIR)
    save_estate(conn, estate)
    conn.close()
    try:
        yield path
    finally:
        os.unlink(path)


@pytest.fixture()
def _client(_fixture_db, monkeypatch):
    from fastapi.testclient import TestClient

    from gpo_lens.web.app import create_app

    monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "test-secret-token")
    app = create_app(_fixture_db)
    return TestClient(
        app,
        headers={
            "origin": "http://localhost",
            "Authorization": "Bearer test-secret-token",
        },
    )


@pytest.mark.skipif(not _HAS_WEB, reason="web extra not installed")
class TestDangerWebRoute:
    def test_danger_route_returns_200(self, _client) -> None:
        resp = _client.get("/danger")
        assert resp.status_code == 200
        assert "Dangerous configurations" in resp.text

    def test_danger_route_shows_finding(self, _client) -> None:
        resp = _client.get("/danger")
        assert resp.status_code == 200
        # The fixture GPO AAAAAAAA pushes local Administrators membership.
        assert "local_admin_push" in resp.text
        assert "citation" in resp.text

    def test_danger_route_severity_filter(self, _client) -> None:
        resp = _client.get("/danger", params={"severity": "high"})
        assert resp.status_code == 200
        assert "gp-pill high" in resp.text


# ---------------------------------------------------------------------------
# CLI parity
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not _HAS_WEB, reason="needs fixture estate + web stack")
class TestDangerCli:
    def test_danger_cli_json(self, _fixture_db, capsys) -> None:
        from gpo_lens.cli import main

        rc = main(["--db", _fixture_db, "danger", "--json"])
        out = capsys.readouterr().out
        assert rc == 0
        env = json.loads(out)
        assert env["schema_version"] == 1
        assert env["kind"] == "danger"
        data = env["data"]
        assert isinstance(data, list)
        assert len(data) >= 1
        expected = {
            "check_id", "severity", "title", "gpo_id",
            "gpo_name", "detail", "reference",
        }
        assert expected <= set(data[0])
