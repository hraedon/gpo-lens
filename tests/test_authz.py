"""Pure unit tests for authorization/SIDL primitives."""

from __future__ import annotations

import pytest

from gpo_lens.authz import resolve_principal, resolve_well_known
from gpo_lens.detection import _is_default_writer_sid
from gpo_lens.model import Estate, ResolvedPrincipal


@pytest.mark.parametrize(
    "sid, name",
    [
        ("S-1-1-0", "Everyone"),
        ("S-1-5-7", "Anonymous"),
        ("S-1-5-9", "Enterprise Domain Controllers"),
        ("S-1-5-10", "Self"),
        ("S-1-5-11", "Authenticated Users"),
        ("S-1-5-12", "Restricted Code"),
        ("S-1-5-13", "Terminal Server Users"),
        ("S-1-5-14", "Remote Interactive Logon"),
        ("S-1-5-15", "This Organization"),
        ("S-1-5-17", "IUSR"),
        ("S-1-5-18", "SYSTEM"),
        ("S-1-5-19", "Local Service"),
        ("S-1-5-20", "Network Service"),
        ("S-1-5-33", "Write Restricted"),
        ("S-1-5-1000", "Other Organization"),
    ],
)
def test_resolve_absolute_well_known_sids(sid: str, name: str):
    assert resolve_well_known(sid) == name


@pytest.mark.parametrize(
    "rid, name",
    [
        ("544", "BUILTIN\\Administrators"),
        ("545", "BUILTIN\\Users"),
        ("546", "BUILTIN\\Guests"),
        ("547", "BUILTIN\\Power Users"),
        ("548", "BUILTIN\\Account Operators"),
        ("549", "BUILTIN\\Server Operators"),
        ("550", "BUILTIN\\Print Operators"),
        ("551", "BUILTIN\\Backup Operators"),
        ("552", "BUILTIN\\Replicator"),
        ("553", "BUILTIN\\All Users"),
        ("554", "BUILTIN\\Pre-Windows 2000 Compatible Access"),
        ("555", "BUILTIN\\Remote Desktop Users"),
        ("556", "BUILTIN\\Remote Management Users"),
        ("557", "BUILTIN\\Network Configuration Operators"),
        ("558", "BUILTIN\\Incoming Forest Trust Builders"),
        ("559", "BUILTIN\\Performance Monitor Users"),
        ("560", "BUILTIN\\Performance Log Users"),
        ("561", "BUILTIN\\Windows Authorization Access Group"),
        ("562", "BUILTIN\\Terminal Server License Servers"),
        ("568", "BUILTIN\\IIS_IUSRS"),
        ("569", "BUILTIN\\Cryptographic Operators"),
        ("573", "BUILTIN\\Event Log Readers"),
        ("574", "BUILTIN\\Certificate Service DCOM Access"),
        ("575", "BUILTIN\\RDS Remote Access Servers"),
        ("576", "BUILTIN\\RDS Endpoint Servers"),
        ("577", "BUILTIN\\RDS Management Servers"),
        ("578", "BUILTIN\\Hyper-V Administrators"),
        ("579", "BUILTIN\\Access Control Assistance Operators"),
        ("580", "BUILTIN\\Remote Management Users"),
        ("582", "BUILTIN\\Storage Replica Administrators"),
    ],
)
def test_resolve_builtin_well_known_sids(rid: str, name: str):
    assert resolve_well_known(f"S-1-5-32-{rid}") == name


@pytest.mark.parametrize(
    "rid, name",
    [
        ("512", "Domain Admins"),
        ("513", "Domain Users"),
        ("514", "Domain Guests"),
        ("515", "Domain Computers"),
        ("516", "Domain Controllers"),
        ("517", "Cert Publishers"),
        ("518", "Schema Admins"),
        ("519", "Enterprise Admins"),
        ("520", "Group Policy Creator Owners"),
        ("521", "Read-only Domain Controllers"),
        ("522", "Cloneable Domain Controllers"),
        ("525", "Protected Users"),
        ("526", "Key Admins"),
        ("527", "Enterprise Key Admins"),
    ],
)
def test_resolve_domain_relative_well_known_rids(rid: str, name: str):
    sid = f"S-1-5-21-123-456-789-{rid}"
    assert resolve_well_known(sid) == name


@pytest.mark.parametrize(
    "sid, name",
    [
        ("S-1-16-0", "Untrusted Mandatory Level"),
        ("S-1-16-4096", "Low Mandatory Level"),
        ("S-1-16-8192", "Medium Mandatory Level"),
        ("S-1-16-8448", "Medium Plus Mandatory Level"),
        ("S-1-16-12288", "High Mandatory Level"),
        ("S-1-16-16384", "System Mandatory Level"),
        ("S-1-16-20480", "Protected Process Mandatory Level"),
        ("S-1-16-28672", "Secure Process Mandatory Level"),
    ],
)
def test_resolve_mandatory_label_sids(sid: str, name: str):
    assert resolve_well_known(sid) == name


def test_resolve_well_known_is_case_insensitive():
    assert resolve_well_known("s-1-5-32-544") == "BUILTIN\\Administrators"
    assert resolve_well_known("S-1-5-32-544") == "BUILTIN\\Administrators"
    assert resolve_well_known("S-1-5-11") == "Authenticated Users"
    assert resolve_well_known("s-1-5-11") == "Authenticated Users"


def test_resolve_well_known_returns_none_for_unknown_sids():
    assert resolve_well_known("S-1-5-21-123-456-789-99999") is None
    assert resolve_well_known("S-1-5-32-999") is None
    assert resolve_well_known("not-a-sid") is None
    assert resolve_well_known("S-1-2-3-4") is None


def test_resolve_well_known_strips_whitespace():
    assert resolve_well_known("  S-1-5-11  ") == "Authenticated Users"


@pytest.mark.parametrize(
    "sid, expected",
    [
        ("S-1-5-18", True),
        ("S-1-5-32-544", True),
        ("S-1-5-21-123-456-789-512", True),
        ("S-1-5-21-123-456-789-519", True),
        ("S-1-5-21-123-456-789-515", False),
        ("S-1-1-0", False),
        ("S-1-5-11", False),
        ("S-1-5-32-545", False),
        ("S-1-5-21-123-456-789-99999", False),
    ],
)
def test_is_default_writer_sid_verdicts_unchanged(sid: str, expected: bool):
    assert _is_default_writer_sid(sid) is expected


@pytest.mark.parametrize(
    "alias, name",
    [
        ("DA", "Domain Admins"),
        ("da", "Domain Admins"),
        ("EA", "Enterprise Admins"),
        ("CO", "Creator Owner"),
        ("CG", "Creator Group"),
        ("DC", "Domain Computers"),
        ("DU", "Domain Users"),
    ],
)
def test_resolve_well_known_domain_relative_sddl_aliases(alias: str, name: str):
    # Real SDDL emits domain-relative aliases (O:DA, not a raw -512 SID). These
    # must resolve, or every Domain-Admins-owned GPO is mis-flagged as
    # non-admin-owned. Regression for the danger.py owner false positive.
    assert resolve_well_known(alias) == name


@pytest.mark.parametrize("sid", ["DA", "da", "EA", "CO", "S-1-3-0", "s-1-3-1"])
def test_is_default_writer_recognizes_sddl_aliases(sid: str):
    # DA/EA are the common GPO owner/writer; Creator Owner (CO / S-1-3-0) is a
    # non-actionable placeholder in the default DACL. None is a hijack trustee.
    assert _is_default_writer_sid(sid) is True


# ---- resolve_principal (Plan 020 A.3) -------------------------------------


def test_resolve_principal_well_known_no_principals_map():
    """AC-2: well-known SIDs resolve with no principals.json."""
    estate = Estate()
    rp = resolve_principal(estate, "S-1-5-11")
    assert rp.resolved is True
    assert rp.name == "Authenticated Users"
    assert rp.principal_type == "WellKnown"
    assert rp.sid == "s-1-5-11"


def test_resolve_principal_builtin_well_known():
    estate = Estate()
    rp = resolve_principal(estate, "S-1-5-32-544")
    assert rp.resolved is True
    assert rp.name == "BUILTIN\\Administrators"
    assert rp.principal_type == "WellKnown"


def test_resolve_principal_domain_rid_well_known():
    estate = Estate()
    rp = resolve_principal(estate, "S-1-5-21-100-200-300-512")
    assert rp.resolved is True
    assert rp.name == "Domain Admins"
    assert rp.principal_type == "WellKnown"


def test_resolve_principal_collected_sid():
    """AC-1: a collected SID resolves from estate.principals."""
    sid = "s-1-5-21-100-200-300-1131"
    estate = Estate(principals={
        sid: ResolvedPrincipal(
            sid=sid,
            name="HRAENET\\GPO-Admins",
            sam="GPO-Admins",
            principal_type="Group",
            domain="HRAENET",
            resolved=True,
        ),
    })
    rp = resolve_principal(estate, "S-1-5-21-100-200-300-1131")
    assert rp.resolved is True
    assert rp.name == "HRAENET\\GPO-Admins"
    assert rp.sam == "GPO-Admins"
    assert rp.principal_type == "Group"
    assert rp.domain == "HRAENET"
    assert rp.sid == sid


def test_resolve_principal_unknown_sid_unresolved():
    """AC-3: unknown SID returns resolved=False with the raw SID as name."""
    estate = Estate()
    rp = resolve_principal(estate, "S-1-5-21-999-999-999-99999")
    assert rp.resolved is False
    assert rp.name == "s-1-5-21-999-999-999-99999"
    assert rp.principal_type == "Unresolved"
    assert rp.sid == "s-1-5-21-999-999-999-99999"


def test_resolve_principal_well_known_takes_precedence_over_collected():
    """The static table is tried first (tier 1) per Plan 020 A.3."""
    sid = "s-1-5-11"
    estate = Estate(principals={
        sid: ResolvedPrincipal(
            sid=sid, name="Custom Name", sam="x",
            principal_type="Group", domain="X", resolved=True,
        ),
    })
    rp = resolve_principal(estate, "S-1-5-11")
    assert rp.name == "Authenticated Users"
    assert rp.principal_type == "WellKnown"


def test_resolve_principal_case_insensitive_sid_lookup():
    sid = "s-1-5-21-100-200-300-1131"
    estate = Estate(principals={
        sid: ResolvedPrincipal(
            sid=sid, name="GPO-Admins", sam="GPO-Admins",
            principal_type="Group", domain="X", resolved=True,
        ),
    })
    rp = resolve_principal(estate, "S-1-5-21-100-200-300-1131")
    assert rp.resolved is True
    assert rp.name == "GPO-Admins"


def test_resolve_principal_strips_whitespace():
    estate = Estate()
    rp = resolve_principal(estate, "  S-1-5-11  ")
    assert rp.resolved is True
    assert rp.name == "Authenticated Users"
    assert rp.sid == "s-1-5-11"


def test_extract_aces_unbalanced_paren_does_not_drop_aces():
    from gpo_lens.authz import _extract_aces

    sddl = "(A;;GA;;;S-1-5-11))(D;;GR;;;S-1-1-0)"
    aces = _extract_aces(sddl)
    trustee_sids = {ace.trustee_sid for ace in aces}
    assert "S-1-5-11" in trustee_sids
    assert "S-1-1-0" in trustee_sids


def test_extract_aces_normal_balanced():
    from gpo_lens.authz import _extract_aces

    sddl = "(A;;GA;;;S-1-5-11)(D;;GR;;;S-1-1-0)"
    aces = _extract_aces(sddl)
    assert len(aces) == 2
    assert aces[0].trustee_sid == "S-1-5-11"
    assert aces[1].trustee_sid == "S-1-1-0"


# ---- SDDL conditional ACE parsing (H-3) -----------------------------------


def test_parse_ace_string_conditional_ace_returns_ace():
    """Conditional ACEs (7+ fields) must not be silently dropped."""
    from gpo_lens.authz import _parse_ace_string

    # XA = callback allow with a conditional expression in the 7th field.
    ace = _parse_ace_string("XA;;GW;;;S-1-5-11;(WIN://OAFD)")
    assert ace is not None
    assert ace.trustee_sid == "S-1-5-11"
    assert ace.rights == "GW"
    assert ace.ace_type == "allow"


def test_parse_ace_string_six_fields_still_works():
    """Standard 6-field ACEs are still parsed correctly."""
    from gpo_lens.authz import _parse_ace_string

    ace = _parse_ace_string("A;;GA;;;S-1-5-11")
    assert ace is not None
    assert ace.trustee_sid == "S-1-5-11"
    assert ace.rights == "GA"


def test_parse_ace_string_too_few_fields_returns_none():
    """ACEs with fewer than 6 fields are still rejected."""
    from gpo_lens.authz import _parse_ace_string

    assert _parse_ace_string("A;;GA;;") is None   # 5 fields
    assert _parse_ace_string("A;;GA") is None      # 3 fields


def test_parse_sddl_with_conditional_ace():
    """parse_sddl correctly extracts conditional ACEs from a full SDDL string."""
    from gpo_lens.authz import parse_sddl

    sddl = "O:SYG:SYD:(A;;GA;;;S-1-5-11)(XA;;GW;;;S-1-1-0;(WIN://OAFD))"
    acl = parse_sddl(sddl)
    assert len(acl.dacl) == 2
    assert acl.dacl[0].trustee_sid == "S-1-5-11"
    assert acl.dacl[1].trustee_sid == "S-1-1-0"
    assert acl.dacl[1].ace_type == "allow"


# ---- SW (DS_SELF) letter-form rights parsing ------------------------------


def test_parse_sddl_rights_sw_in_full_ad_rights_string():
    """The canonical AD full-rights string must parse losslessly.

    GPMC emits ``CCDCLCSWRPWPDTLOCRSDRCWDWO`` on essentially every GPO DACL.
    Before SW joined the valid set, the tokenizer dropped it (386 of 767 ACEs
    in the real-estate corpus contained SW).
    """
    from gpo_lens.authz import parse_sddl_rights

    codes = parse_sddl_rights("CCDCLCSWRPWPDTLOCRSDRCWDWO")
    assert codes == [
        "CC", "DC", "LC", "SW", "RP", "WP", "DT", "LO", "CR", "SD",
        "RC", "WD", "WO",
    ]


def test_parse_sddl_rights_sw_dt_does_not_fabricate_wd():
    """``SWDT`` must parse as [SW, DT], never a phantom WD.

    With SW unknown, the 1-char resync re-tokenized ``SWDT`` at offset 1 and
    produced ``WD`` (Write DAC) — a fabricated write right that would flip
    excessive-writer / danger verdicts for a trustee holding only
    self-write + delete-tree.
    """
    from gpo_lens.authz import parse_sddl_rights

    codes = parse_sddl_rights("SWDT")
    assert codes == ["SW", "DT"]
    assert "WD" not in codes


# ---- ACL control flags (D:PAI / S:AI) --------------------------------------


def test_parse_sddl_captures_dacl_and_sacl_flags():
    """Control flags before the ACE list are preserved, not discarded.

    ``P`` (protected) means inheritance is blocked — posture-relevant.
    GPMC emits ``D:PAI(...)`` / ``S:AI(...)`` on nearly every GPO.
    """
    from gpo_lens.authz import parse_sddl

    acl = parse_sddl("O:DAG:DAD:PAI(A;;GR;;;WD)S:AI(AU;SA;GA;;;WD)")
    assert acl.dacl_flags == "PAI"
    assert acl.sacl_flags == "AI"
    assert len(acl.dacl) == 1
    assert len(acl.sacl) == 1


def test_parse_sddl_flagless_acl_has_empty_flags():
    from gpo_lens.authz import parse_sddl

    acl = parse_sddl("O:SYG:SYD:(A;;GA;;;S-1-5-11)")
    assert acl.dacl_flags == ""
    assert acl.sacl_flags == ""


# ---- Hex rights mask parsing (H-4) ----------------------------------------


def test_parse_sddl_rights_hex_mask_generic_read():
    """0x80000000 = GENERIC_READ → ["GR"]."""
    from gpo_lens.authz import parse_sddl_rights

    assert parse_sddl_rights("0x80000000") == ["GR"]


def test_parse_sddl_rights_hex_mask_0x1200a9():
    """0x1200a9 is a common GPO read mask — must decode to known codes.

    0x1200a9 = SYNCHRONIZE(0x100000) | READ_CONTROL(0x20000) |
               DS_LIST_OBJECT(0x80) | DS_WRITE_PROP(0x20) |
               DS_SELF(0x08) | DS_CREATE_CHILD(0x01)
    SYNCHRONIZE has no SDDL 2-letter code and is skipped.
    """
    from gpo_lens.authz import parse_sddl_rights

    codes = parse_sddl_rights("0x1200a9")
    assert "RC" in codes   # READ_CONTROL (0x00020000)
    assert "LO" in codes   # DS_LIST_OBJECT (0x00000080)
    assert "WP" in codes   # DS_WRITE_PROP (0x00000020)
    assert "SW" in codes   # DS_SELF (0x00000008)
    assert "CC" in codes   # DS_CREATE_CHILD (0x00000001)
    # DS_SELF must NOT decode to CR: CR is ADS_RIGHT_DS_CONTROL_ACCESS
    # (0x100). Mapping 0x8 → CR made a self-write mask count as an apply
    # right (READ_OR_APPLY_RIGHTS includes CR) — a false "applies".
    assert "CR" not in codes


def test_parse_sddl_rights_hex_mask_control_access():
    """0x100 = ADS_RIGHT_DS_CONTROL_ACCESS → ["CR"].

    This is the bit Apply Group Policy actually uses. Before the fix it was
    absent from the map entirely, so a hex mask granting apply decoded to
    nothing — a missed apply right.
    """
    from gpo_lens.authz import parse_sddl_rights

    assert parse_sddl_rights("0x100") == ["CR"]


def test_parse_sddl_rights_hex_mask_uppercase():
    """Hex masks should be case-insensitive."""
    from gpo_lens.authz import parse_sddl_rights

    assert parse_sddl_rights("0X80000000") == ["GR"]


def test_parse_sddl_rights_hex_mask_with_pipe():
    """Hex masks can be pipe-separated with 2-letter codes."""
    from gpo_lens.authz import parse_sddl_rights

    codes = parse_sddl_rights("0x80000000|GW")
    assert "GR" in codes
    assert "GW" in codes


def test_parse_sddl_rights_hex_mask_generic_all():
    """0x10000000 = GENERIC_ALL → ["GA"]."""
    from gpo_lens.authz import parse_sddl_rights

    assert parse_sddl_rights("0x10000000") == ["GA"]


def test_parse_sddl_rights_hex_mask_zero():
    """0x0 produces an empty list (no rights)."""
    from gpo_lens.authz import parse_sddl_rights

    assert parse_sddl_rights("0x0") == []


def test_parse_sddl_rights_invalid_hex_ignored():
    """Invalid hex values are silently skipped, not crashed on."""
    from gpo_lens.authz import parse_sddl_rights

    assert parse_sddl_rights("0xZZZZ") == []


# ---- READ_OR_APPLY_RIGHTS excludes CC (M-1) -------------------------------


def test_read_or_apply_rights_excludes_cc():
    """CC (Create Child) is a write right, not read/apply — must be excluded."""
    from gpo_lens.authz import READ_OR_APPLY_RIGHTS

    assert "CC" not in READ_OR_APPLY_RIGHTS
    assert "GA" in READ_OR_APPLY_RIGHTS
    assert "GR" in READ_OR_APPLY_RIGHTS
    assert "CR" in READ_OR_APPLY_RIGHTS
    assert "RP" in READ_OR_APPLY_RIGHTS


# ---------------------------------------------------------------------------
# WI-084: SDDL alias vs canonical SID must compare equal
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "alias,raw,key",
    [
        ("au", "s-1-5-11", "authenticated_users"),
        ("wd", "s-1-1-0", "everyone"),
    ],
)
def test_broad_trustee_key_alias_matches_raw_sid(alias, raw, key):
    """An SDDL alias and its raw SID resolve to the same broad-trustee key."""
    from gpo_lens.authz import broad_trustee_key

    assert broad_trustee_key("", alias) == key
    assert broad_trustee_key("", raw) == key


def test_broad_trustee_key_domain_computers_alias_and_suffix():
    """Domain Computers via the ``DC`` alias and the -515 SID suffix agree."""
    from gpo_lens.authz import broad_trustee_key

    assert broad_trustee_key("", "dc") == "domain_computers"
    assert broad_trustee_key("", "s-1-5-21-1-2-3-515") == "domain_computers"


def test_applies_broadly_alias_deny_cancels_raw_allow():
    """A deny in alias form cancels an allow in raw-SID form (WI-084).

    Before the fix the two trustee forms produced different keys, so the deny
    never canceled the allow and a broad-apply finding fired falsely.
    """
    from gpo_lens.authz import applies_broadly, broad_trustee_key

    allow = broad_trustee_key("", "s-1-5-11")  # raw SID
    deny = broad_trustee_key("", "au")         # alias
    assert allow == deny  # same key is the whole point
    assert applies_broadly([(allow, True), (deny, False)]) is False


@pytest.mark.parametrize(
    "token,domain_sid,expected",
    [
        ("AU", None, "s-1-5-11"),
        ("WD", None, "s-1-1-0"),
        ("BA", None, "s-1-5-32-544"),
        ("DA", "s-1-5-21-1-2-3", "s-1-5-21-1-2-3-512"),
        ("DC", "s-1-5-21-1-2-3", "s-1-5-21-1-2-3-515"),
        ("da", None, "da"),                     # domain-relative, no domain SID
        ("s-1-5-11", None, "s-1-5-11"),          # raw SID passes through
        ("S-1-5-11", None, "s-1-5-11"),          # lowercased
    ],
)
def test_canonical_sddl_sid(token, domain_sid, expected):
    from gpo_lens.authz import canonical_sddl_sid

    assert canonical_sddl_sid(token, domain_sid) == expected
