"""Boundary tests for PrincipalResultant — per docs/design/per-user-rsop.md ACs.

Each test class maps to one acceptance criterion. All fixtures are synthetic
(no real domain identifiers).
"""
from __future__ import annotations

from gpo_lens.merge import principal_resultant
from gpo_lens.model import (
    DelegationEntry,
    Estate,
    Gpo,
    GroupMembership,
    ResolvedPrincipal,
    Setting,
    Som,
    SomLink,
)

DOMAIN_SID = "S-1-5-21-100-200-300"
USER_SID = f"{DOMAIN_SID}-1001"
USER_SID_LOWER = USER_SID.lower()
COMPUTER_SID = f"{DOMAIN_SID}-2001"
COMPUTER_SID_LOWER = COMPUTER_SID.lower()
GROUP_A_SID = f"{DOMAIN_SID}-5001"
GROUP_A_SID_LOWER = GROUP_A_SID.lower()
GROUP_B_SID = f"{DOMAIN_SID}-5002"
GROUP_B_SID_LOWER = GROUP_B_SID.lower()
FOREIGN_SID = "s-1-5-21-999-888-777-6666"

GPO_A = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
GPO_B = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
GPO_WMI = "cccccccc-cccc-cccc-cccc-cccccccccccc"
GPO_ILT = "dddddddd-dddd-dddd-dddd-dddddddddddd"
GPO_DANGER = "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"

SOM_DOMAIN = "DC=test,DC=local"
SOM_OU = "OU=Workstations,DC=test,DC=local"
SOM_SITE = "CN=Default-First-Site,CN=Sites,CN=Configuration,DC=test,DC=local"


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
        side=side,  # type: ignore[arg-type]
        cse=cse,
        identity=identity,
        display_name=display_name or identity,
        display_value=value,
        raw=raw or {},
        from_disabled_side=False,
    )


def _gpo(
    gpo_id: str,
    name: str,
    *,
    settings: list[Setting] | None = None,
    delegation: list[DelegationEntry] | None = None,
    wmi_filter: str | None = None,
    sddl: str | None = None,
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
        sysvol_path=None,
        delegation=delegation or [],
        settings=settings or [],
    )


def _som(
    path: str,
    name: str,
    *,
    links: list[SomLink] | None = None,
    container_type: str = "domain",
    inheritance_blocked: bool = False,
) -> Som:
    return Som(
        path=path,
        name=name,
        container_type=container_type,
        inheritance_blocked=inheritance_blocked,
        links=links or [],
    )


def _apply_delegation(gpo_id: str, sid: str) -> list[DelegationEntry]:
    return [
        DelegationEntry(
            gpo_id=gpo_id,
            trustee="Group A",
            trustee_sid=sid,
            permission="Apply Group Policy",
            allowed=True,
        ),
    ]


def _user_estate(
    *,
    gpos: list[Gpo],
    som_path: str = SOM_DOMAIN,
    soms: list[Som] | None = None,
    group_members: dict[str, GroupMembership] | None = None,
    principals: dict[str, ResolvedPrincipal] | None = None,
) -> Estate:
    if soms is None:
        soms = [_som(SOM_DOMAIN, "test.local")]
        soms[0].links = [
            SomLink(
                gpo_id=g.id, order=i + 1, enabled=True, enforced=False,
                target=SOM_DOMAIN,
            )
            for i, g in enumerate(gpos)
        ]

    if principals is None:
        principals = {
            USER_SID_LOWER: ResolvedPrincipal(
                sid=USER_SID_LOWER, name="TEST\\user1", sam="user1",
                principal_type="User", domain="TEST", resolved=True,
            ),
        }

    if group_members is None:
        group_members = {}

    return Estate(
        domain="test.local",
        gpos=gpos,
        soms=soms,
        principals=principals,
        group_members=group_members,
    )


# ---------------------------------------------------------------------------
# AC-1: Security-filtered GPO appears in settings when token matches
# ---------------------------------------------------------------------------

class TestAC1SecurityFilteredGpoInResultant:
    def test_user_in_group_gets_gpo_settings(self) -> None:
        gpos = [
            _gpo(
                GPO_A, "Policy-A",
                settings=[_setting(GPO_A, "Registry", r"HKCU\Software\Foo:Bar", "1", side="User")],
                delegation=_apply_delegation(GPO_A, GROUP_A_SID),
            ),
        ]
        estate = _user_estate(
            gpos=gpos,
            group_members={
                GROUP_A_SID_LOWER: GroupMembership(
                    sid=GROUP_A_SID_LOWER, name="Group A",
                    members=(USER_SID_LOWER,), member_count=1,
                ),
            },
        )
        result = principal_resultant(estate, USER_SID, dn=SOM_DOMAIN)
        assert any(s.winning_gpo_id == GPO_A for s in result.settings)
        assert any(s.identity == r"HKCU\Software\Foo:Bar" for s in result.settings)


# ---------------------------------------------------------------------------
# AC-2: Token does not intersect Apply trustees → GPO excluded
# ---------------------------------------------------------------------------

class TestAC2SecurityFilterExclusion:
    def test_user_not_in_group_excludes_gpo(self) -> None:
        gpos = [
            _gpo(
                GPO_A, "Policy-A",
                settings=[_setting(GPO_A, "Registry", r"HKLM\Software\Foo:Bar", "1")],
                delegation=_apply_delegation(GPO_A, GROUP_A_SID),
            ),
        ]
        estate = _user_estate(gpos=gpos)
        result = principal_resultant(estate, USER_SID, dn=SOM_DOMAIN)
        assert not any(s.winning_gpo_id == GPO_A for s in result.settings)
        assert any(
            e.gpo_id == GPO_A and e.kind == "security_filter"
            for e in result.excluded
        )
        assert any("security filter" in e.reason.lower() for e in result.excluded)


# ---------------------------------------------------------------------------
# AC-3: WMI-filtered GPO excluded with kind="wmi_filter"
# ---------------------------------------------------------------------------

class TestAC3WmiFilterExclusion:
    def test_wmi_filtered_gpo_excluded(self) -> None:
        gpos = [
            _gpo(
                GPO_WMI, "Policy-WMI",
                settings=[_setting(GPO_WMI, "Registry", r"HKLM\Software\Wmi:Test", "1")],
                wmi_filter="{guid-filter}",
            ),
        ]
        estate = _user_estate(gpos=gpos)
        result = principal_resultant(estate, USER_SID, dn=SOM_DOMAIN)
        assert not any(s.winning_gpo_id == GPO_WMI for s in result.settings)
        assert any(
            e.gpo_id == GPO_WMI and e.kind == "wmi_filter"
            for e in result.excluded
        )


# ---------------------------------------------------------------------------
# AC-4: ILT-gated GPP item excluded from settings, appears in excluded_settings
# ---------------------------------------------------------------------------

class TestAC4IltExclusion:
    def test_ilt_gated_gpp_excluded(self, monkeypatch) -> None:
        from gpo_lens.detection import IltHit

        raw_create = {"@attr": {"action": "C"}}
        gpos = [
            _gpo(
                GPO_ILT, "Policy-ILT",
                settings=[
                    _setting(
                        GPO_ILT, "GPP Drive Maps", "Drive:H:", r"H:\share",
                        side="User", raw=raw_create,
                    ),
                ],
            ),
        ]
        estate = _user_estate(gpos=gpos)
        monkeypatch.setattr(
            "gpo_lens.merge.scan_ilt",
            lambda e: [IltHit(
                gpo_id=GPO_ILT, gpo_name="Policy-ILT",
                files=("DriveMaps.xml",), filter_types=("Group",),
            )],
        )
        result = principal_resultant(estate, USER_SID, dn=SOM_DOMAIN)
        assert not any(s.winning_gpo_id == GPO_ILT for s in result.settings)
        assert any(
            es.gpo_id == GPO_ILT and es.kind == "ilt"
            for es in result.excluded_settings
        )


# ---------------------------------------------------------------------------
# AC-5: caveat_summary is non-empty and contains "given collected inputs"
# ---------------------------------------------------------------------------

class TestAC5CaveatSummary:
    def test_caveat_summary_non_empty_with_qualifier(self) -> None:
        gpos = [
            _gpo(GPO_A, "Policy-A", settings=[
                _setting(GPO_A, "Registry", r"HKLM\Software\Foo:Bar", "1"),
            ]),
        ]
        estate = _user_estate(gpos=gpos)
        result = principal_resultant(estate, USER_SID, dn=SOM_DOMAIN)
        assert result.caveat_summary
        assert "given collected inputs" in result.caveat_summary


# ---------------------------------------------------------------------------
# AC-6: Computer SID supplied → computer side merged, loopback in caveats
# ---------------------------------------------------------------------------

class TestAC6UserComputerPair:
    def test_computer_pair_surfaces_loopback(self) -> None:
        user_gpos = [
            _gpo(
                GPO_A, "User-Policy",
                settings=[_setting(GPO_A, "Registry", r"HKCU\Software\Foo:Bar", "1", side="User")],
            ),
        ]
        comp_gpos = [
            _gpo(
                GPO_B, "Computer-Policy",
                settings=[_setting(
                    GPO_B, "Registry", r"HKLM\Software\Comp:Set", "1",
                    side="Computer",
                )],
            ),
        ]
        all_gpos = user_gpos + comp_gpos
        soms = [
            _som(SOM_DOMAIN, "test.local", links=[
                SomLink(gpo_id=GPO_A, order=1, enabled=True, enforced=False, target=SOM_DOMAIN),
            ]),
            _som(SOM_OU, "Workstations", links=[
                SomLink(gpo_id=GPO_B, order=1, enabled=True, enforced=False, target=SOM_OU),
            ]),
        ]
        estate = Estate(
            domain="test.local",
            gpos=all_gpos,
            soms=soms,
            principals={
                USER_SID_LOWER: ResolvedPrincipal(
                    sid=USER_SID_LOWER, name="TEST\\user1", sam="user1",
                    principal_type="User", domain="TEST", resolved=True,
                ),
                COMPUTER_SID_LOWER: ResolvedPrincipal(
                    sid=COMPUTER_SID_LOWER, name="TEST\\comp1$", sam="comp1$",
                    principal_type="Computer", domain="TEST", resolved=True,
                ),
            },
        )
        result = principal_resultant(
            estate, USER_SID,
            computer_sid=COMPUTER_SID,
            dn=SOM_DOMAIN,
            computer_dn=SOM_OU,
        )
        assert any(s.side == "User" for s in result.settings)
        assert any(s.side == "Computer" for s in result.settings)
        assert "computer pair" in result.caveat_summary.lower()
        assert "Loopback processing" in result.caveat_mechanisms


# ---------------------------------------------------------------------------
# AC-7: Dangerous config in gated GPO → conditional_dangers, not settings
# ---------------------------------------------------------------------------

class TestAC7DangerInGatedGpo:
    def test_danger_in_security_filtered_gpo_surfaces(self) -> None:
        from gpo_lens.danger import DangerFinding

        gpos = [
            _gpo(
                GPO_DANGER, "Danger-Policy",
                settings=[_setting(GPO_DANGER, "Registry", r"HKLM\Software\Danger:Key", "evil")],
                delegation=_apply_delegation(GPO_DANGER, GROUP_A_SID),
            ),
        ]
        estate = _user_estate(gpos=gpos)
        danger = [
            DangerFinding(
                check_id="test_danger",
                severity="high",
                title="Dangerous setting",
                gpo_id=GPO_DANGER,
                gpo_name="Danger-Policy",
                detail="evil value",
                reference="test-ref",
            ),
        ]
        result = principal_resultant(estate, USER_SID, dn=SOM_DOMAIN, danger=danger)
        assert not any(s.winning_gpo_id == GPO_DANGER for s in result.settings)
        assert any(
            cd.gpo_id == GPO_DANGER for cd in result.conditional_dangers
        )


# ---------------------------------------------------------------------------
# AC-8: CLI never renders "effective" without "given collected inputs"
# ---------------------------------------------------------------------------

class TestAC8CliEffectiveLabel:
    def test_cli_text_contains_given_collected_inputs(
        self, tmp_path, capsys,
    ) -> None:
        import sqlite3

        from gpo_lens import store
        from gpo_lens.cli import main

        db_path = str(tmp_path / "test_rsop_ac8.db")
        conn = sqlite3.connect(db_path)
        store.init_db(conn)
        gpos = [
            _gpo(GPO_A, "Policy-A", settings=[
                _setting(GPO_A, "Registry", r"HKLM\Software\Foo:Bar", "1"),
            ]),
        ]
        estate = Estate(
            domain="test.local",
            gpos=gpos,
            soms=[_som(SOM_DOMAIN, "test.local", links=[
                SomLink(gpo_id=GPO_A, order=1, enabled=True, enforced=False, target=SOM_DOMAIN),
            ])],
            principals={
                USER_SID_LOWER: ResolvedPrincipal(
                    sid=USER_SID_LOWER, name="TEST\\user1", sam="user1",
                    principal_type="User", domain="TEST", resolved=True,
                ),
            },
        )
        store.save_estate(conn, estate)
        conn.close()

        ret = main([
            "--db", db_path, "resultant", USER_SID, "--dn", SOM_DOMAIN,
        ])
        assert ret == 0
        captured = capsys.readouterr()
        assert "given collected inputs" in captured.out

    def test_cli_json_includes_caveat_mechanisms(
        self, tmp_path, capsys,
    ) -> None:
        import json
        import sqlite3

        from gpo_lens import store
        from gpo_lens.cli import main

        db_path = str(tmp_path / "test_rsop_ac8_json.db")
        conn = sqlite3.connect(db_path)
        store.init_db(conn)
        gpos = [
            _gpo(GPO_A, "Policy-A", settings=[
                _setting(GPO_A, "Registry", r"HKLM\Software\Foo:Bar", "1"),
            ]),
        ]
        estate = Estate(
            domain="test.local",
            gpos=gpos,
            soms=[_som(SOM_DOMAIN, "test.local", links=[
                SomLink(gpo_id=GPO_A, order=1, enabled=True, enforced=False, target=SOM_DOMAIN),
            ])],
            principals={
                USER_SID_LOWER: ResolvedPrincipal(
                    sid=USER_SID_LOWER, name="TEST\\user1", sam="user1",
                    principal_type="User", domain="TEST", resolved=True,
                ),
            },
        )
        store.save_estate(conn, estate)
        conn.close()

        ret = main([
            "--json", "--db", db_path, "resultant", USER_SID, "--dn", SOM_DOMAIN,
        ])
        assert ret == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "caveat_mechanisms" in data["data"]
        assert isinstance(data["data"]["caveat_mechanisms"], list)


# ---------------------------------------------------------------------------
# AC-9: Unresolved foreign SIDs in token_caveats
# ---------------------------------------------------------------------------

class TestAC9TokenCaveats:
    def test_foreign_sid_in_token_caveats(self) -> None:
        gpos = [
            _gpo(GPO_A, "Policy-A", settings=[
                _setting(GPO_A, "Registry", r"HKCU\Software\Foo:Bar", "1", side="User"),
            ]),
        ]
        estate = _user_estate(
            gpos=gpos,
            group_members={
                GROUP_A_SID_LOWER: GroupMembership(
                    sid=GROUP_A_SID_LOWER, name="Group A",
                    members=(USER_SID_LOWER, FOREIGN_SID), member_count=2,
                ),
            },
        )
        result = principal_resultant(estate, USER_SID, dn=SOM_DOMAIN)
        assert result.token_caveats
        assert any(FOREIGN_SID in c for c in result.token_caveats)


# ---------------------------------------------------------------------------
# Caveat mechanisms list
# ---------------------------------------------------------------------------

class TestCaveatMechanisms:
    def test_user_resultant_includes_loopback(self) -> None:
        gpos = [
            _gpo(GPO_A, "Policy-A", settings=[
                _setting(GPO_A, "Registry", r"HKLM\Software\Foo:Bar", "1"),
            ]),
        ]
        estate = _user_estate(gpos=gpos)
        result = principal_resultant(estate, USER_SID, dn=SOM_DOMAIN)
        assert "Loopback processing" in result.caveat_mechanisms
        assert "Deny-ACE interaction" in result.caveat_mechanisms

    def test_wmi_exclusion_adds_wmi_mechanism(self) -> None:
        gpos = [
            _gpo(
                GPO_WMI, "Policy-WMI",
                settings=[_setting(GPO_WMI, "Registry", r"HKLM\Software\Wmi:Test", "1")],
                wmi_filter="{guid}",
            ),
        ]
        estate = _user_estate(gpos=gpos)
        result = principal_resultant(estate, USER_SID, dn=SOM_DOMAIN)
        assert "WMI filter evaluation" in result.caveat_mechanisms

    def test_site_soms_add_site_mechanism(self) -> None:
        gpos = [
            _gpo(GPO_A, "Policy-A", settings=[
                _setting(GPO_A, "Registry", r"HKLM\Software\Foo:Bar", "1"),
            ]),
        ]
        estate = _user_estate(gpos=gpos)
        estate.soms.append(
            _som(SOM_SITE, "Default-First-Site", container_type="site", links=[
                SomLink(gpo_id=GPO_A, order=1, enabled=True, enforced=False, target=SOM_SITE),
            ]),
        )
        result = principal_resultant(estate, USER_SID, dn=SOM_DOMAIN)
        assert "AD-site membership" in result.caveat_mechanisms

    def test_no_wmi_no_wmi_mechanism(self) -> None:
        gpos = [
            _gpo(GPO_A, "Policy-A", settings=[
                _setting(GPO_A, "Registry", r"HKLM\Software\Foo:Bar", "1"),
            ]),
        ]
        estate = _user_estate(gpos=gpos)
        result = principal_resultant(estate, USER_SID, dn=SOM_DOMAIN)
        assert "WMI filter evaluation" not in result.caveat_mechanisms
