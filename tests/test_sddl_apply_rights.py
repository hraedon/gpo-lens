"""Tests for the SDDL Read-vs-Apply rights separation.

``READ_OR_APPLY_RIGHTS`` includes GR/RP (read-only rights) and is correct for
deny checks and the MS16-072 check. ``APPLY_RIGHTS`` contains only GA and CR —
the rights that actually confer Apply Group Policy. These tests verify that
apply-only code paths (``iter_sddl_apply_aces``, the merge security-gate allow
check, and the danger overbroad-apply check) use ``APPLY_RIGHTS``, while the
deny check in merge.py still uses ``READ_OR_APPLY_RIGHTS``.

All fixtures are synthetic — no real domain names or GUIDs.
"""

from __future__ import annotations

from gpo_lens.authz import iter_sddl_apply_aces
from gpo_lens.danger import danger_findings
from gpo_lens.merge import _gpo_apply_trustee_sids
from gpo_lens.model import Estate, Gpo

_GPO_ID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
_EVERYONE_SID = "s-1-1-0"
_AU_SID = "s-1-5-11"


def _make_gpo(sddl: str) -> Gpo:
    return Gpo(
        id=_GPO_ID,
        name="Test GPO",
        domain="test.local",
        created=None,
        modified=None,
        read=None,
        computer_enabled=True,
        user_enabled=True,
        computer_ver_ds=None,
        computer_ver_sysvol=None,
        user_ver_ds=None,
        user_ver_sysvol=None,
        sddl=sddl,
        owner=None,
        filter_data_available=False,
        wmi_filter=None,
        sysvol_path=None,
        delegation=[],
        settings=[],
    )


# ---------------------------------------------------------------------------
# 1. iter_sddl_apply_aces (authz.py)
# ---------------------------------------------------------------------------

class TestIterSddlApplyAces:
    def test_gr_not_returned(self) -> None:
        aces = iter_sddl_apply_aces("D:(A;;GR;;;WD)")
        assert aces == []

    def test_rp_not_returned(self) -> None:
        aces = iter_sddl_apply_aces("D:(A;;RP;;;WD)")
        assert aces == []

    def test_cr_returned(self) -> None:
        aces = iter_sddl_apply_aces("D:(A;;CR;;;WD)")
        assert len(aces) == 1
        assert "CR" in aces[0].rights

    def test_ga_returned(self) -> None:
        aces = iter_sddl_apply_aces("D:(A;;GA;;;WD)")
        assert len(aces) == 1
        assert "GA" in aces[0].rights

    def test_deny_not_returned(self) -> None:
        aces = iter_sddl_apply_aces("D:(D;;CR;;;WD)")
        assert aces == []


# ---------------------------------------------------------------------------
# 2. Security gate (merge.py _gpo_apply_trustee_sids)
# ---------------------------------------------------------------------------

class TestSecurityGateApplyRights:
    def test_gr_not_in_allow_sids(self) -> None:
        gpo = _make_gpo("D:(A;;GR;;;S-1-5-11)")
        allow, _deny = _gpo_apply_trustee_sids(gpo, {})
        assert _AU_SID not in allow

    def test_cr_in_allow_sids(self) -> None:
        gpo = _make_gpo("D:(A;;CR;;;S-1-5-11)")
        allow, _deny = _gpo_apply_trustee_sids(gpo, {})
        assert _AU_SID in allow

    def test_ga_in_allow_sids(self) -> None:
        gpo = _make_gpo("D:(A;;GA;;;S-1-5-11)")
        allow, _deny = _gpo_apply_trustee_sids(gpo, {})
        assert _AU_SID in allow

    def test_rp_not_in_allow_sids(self) -> None:
        gpo = _make_gpo("D:(A;;RP;;;S-1-5-11)")
        allow, _deny = _gpo_apply_trustee_sids(gpo, {})
        assert _AU_SID not in allow


# ---------------------------------------------------------------------------
# 3. Danger overbroad-apply (danger.py danger_findings)
# ---------------------------------------------------------------------------

class TestDangerOverbroadApply:
    def test_gr_to_everyone_no_finding(self) -> None:
        gpo = _make_gpo("D:(A;;GR;;;WD)")
        estate = Estate(gpos=[gpo])
        findings = [
            f for f in danger_findings(estate) if f.check_id == "overbroad_apply_gp"
        ]
        assert findings == []

    def test_cr_to_everyone_produces_finding(self) -> None:
        gpo = _make_gpo("D:(A;;CR;;;WD)")
        estate = Estate(gpos=[gpo])
        findings = [
            f for f in danger_findings(estate) if f.check_id == "overbroad_apply_gp"
        ]
        assert len(findings) == 1
        assert findings[0].gpo_id == _GPO_ID

    def test_ga_to_everyone_produces_finding(self) -> None:
        gpo = _make_gpo("D:(A;;GA;;;WD)")
        estate = Estate(gpos=[gpo])
        findings = [
            f for f in danger_findings(estate) if f.check_id == "overbroad_apply_gp"
        ]
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# 4. Deny check still uses READ_OR_APPLY_RIGHTS (merge.py:653)
# ---------------------------------------------------------------------------

class TestDenyCheckReadOrApply:
    def test_deny_gr_blocks(self) -> None:
        gpo = _make_gpo("D:(D;;GR;;;S-1-5-11)")
        _allow, deny = _gpo_apply_trustee_sids(gpo, {})
        assert _AU_SID in deny

    def test_deny_gw_does_not_block(self) -> None:
        gpo = _make_gpo("D:(D;;GW;;;S-1-5-11)")
        _allow, deny = _gpo_apply_trustee_sids(gpo, {})
        assert _AU_SID not in deny

    def test_deny_gr_blocks_read_while_allow_cr_grants_apply(self) -> None:
        gpo = _make_gpo("D:(A;;CR;;;S-1-5-11)(D;;GR;;;S-1-5-11)")
        allow, deny = _gpo_apply_trustee_sids(gpo, {})
        assert _AU_SID in allow
        assert _AU_SID in deny
