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
        ("555", "BUILTIN\\Pre-Windows 2000 Compatible Access"),
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
