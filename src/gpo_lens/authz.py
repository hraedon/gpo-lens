"""Shared authorization primitives for SDDL parsing and broad-trustee recognition.

This module is the shared substrate for ``detection`` (MS16-072) and
``topology`` (security-filtering / scope honesty). It intentionally does not
model Windows ACL evaluation; it only centralizes the duplicated SDDL parser
and trustee/rights normalization so the two predicates stop drifting.
"""

from __future__ import annotations

import warnings
from collections.abc import Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from gpo_lens.model import ResolvedPrincipal, SddlAce, SddlAcl

if TYPE_CHECKING:
    from gpo_lens.model import Estate

__all__ = [
    "ACE_TYPE_MAP",
    "APPLY_RIGHTS",
    "READ_OR_APPLY_RIGHTS",
    "AU_SID",
    "DEFAULT_WRITER_NAMES",
    "DEFAULT_WRITER_SID_SUFFIXES",
    "DOMAIN_COMPUTERS_RID_SUFFIX",
    "DOMAIN_SID_PREFIX",
    "EVERYONE_SID",
    "MS16_072_TRUSTEES",
    "READ_IMPLYING_PERMISSIONS",
    "SCOPE_BROAD_TRUSTEES",
    "SddlApplyAce",
    "applies_broadly",
    "broad_trustee_key",
    "canonical_sddl_sid",
    "is_allow_ace_type",
    "is_default_writer",
    "is_default_writer_sid",
    "is_deny_ace_type",
    "iter_sddl_apply_aces",
    "parse_sddl",
    "parse_sddl_rights",
    "permission_implies_apply",
    "permission_implies_read",
    "resolve_principal",
    "resolve_well_known",
]

AU_SID = "s-1-5-11"
EVERYONE_SID = "s-1-1-0"
DOMAIN_SID_PREFIX = "s-1-5-21-"

# SDDL right codes that convey Read or Apply Group Policy access.
# Used by danger, merge, and topology to test whether an ACE grants
# read/apply rights — previously duplicated as _APPLY_RIGHTS (danger,
# merge) and _SDDL_READ_OR_APPLY_RIGHTS (topology).
# The name READ_OR_APPLY_RIGHTS (not APPLY_RIGHTS) reflects that the set
# includes GR (Generic Read) and RP (Read Property), which are read-only
# rights, not "apply" rights. GA (Generic All) also includes write.
# CC (Create Child / ADS_RIGHT_DS_CREATE_CHILD) is excluded because it is
# a write right, not a read/apply right — including it caused false MS16-072
# compliance and missed security-filtering findings.
READ_OR_APPLY_RIGHTS = frozenset({"GA", "GR", "CR", "RP"})

# SDDL right codes that convey Apply Group Policy access (not just read).
# GA (Generic All) includes everything — read, write, apply, delete.
# CR (Control Access / ADS_RIGHT_DS_CONTROL_ACCESS) is the extended right
# that "Apply Group Policy" uses; in real GPMC SDDL the Apply Group Policy
# ACE is an Object ACE with CR rights and the extended-right GUID
# edacfd8f-ffb3-11d1-b41d-00a0c968f939.
# GR (Generic Read) and RP (Read Property) are deliberately excluded — they
# are read-only rights and do NOT confer Apply Group Policy. Using
# READ_OR_APPLY_RIGHTS in apply-only checks caused false positives in
# danger detection (overbroad_apply_gp) and over-granted the security
# gate in merge.py.
APPLY_RIGHTS = frozenset({"GA", "CR"})
DOMAIN_COMPUTERS_RID_SUFFIX = "-515"
_BUILTIN_PREFIX = "s-1-5-32-"
_MANDATORY_PREFIX = "s-1-16-"

_ABSOLUTE_WELL_KNOWN: dict[str, str] = {
    "s-1-3-0": "Creator Owner",
    "s-1-3-1": "Creator Group",
    "s-1-3-4": "Owner Rights",
    "s-1-1-0": "Everyone",
    "s-1-5-7": "Anonymous",
    "s-1-5-9": "Enterprise Domain Controllers",
    "s-1-5-10": "Self",
    "s-1-5-11": "Authenticated Users",
    "s-1-5-12": "Restricted Code",
    "s-1-5-13": "Terminal Server Users",
    "s-1-5-14": "Remote Interactive Logon",
    "s-1-5-15": "This Organization",
    "s-1-5-17": "IUSR",
    "s-1-5-18": "SYSTEM",
    "s-1-5-19": "Local Service",
    "s-1-5-20": "Network Service",
    "s-1-5-33": "Write Restricted",
    "s-1-5-1000": "Other Organization",
}

_BUILTIN_WELL_KNOWN: dict[str, str] = {
    "544": "BUILTIN\\Administrators",
    "545": "BUILTIN\\Users",
    "546": "BUILTIN\\Guests",
    "547": "BUILTIN\\Power Users",
    "548": "BUILTIN\\Account Operators",
    "549": "BUILTIN\\Server Operators",
    "550": "BUILTIN\\Print Operators",
    "551": "BUILTIN\\Backup Operators",
    "552": "BUILTIN\\Replicator",
    "553": "BUILTIN\\All Users",
    "554": "BUILTIN\\Pre-Windows 2000 Compatible Access",
    "555": "BUILTIN\\Remote Desktop Users",
    "556": "BUILTIN\\Remote Management Users",
    "557": "BUILTIN\\Network Configuration Operators",
    "558": "BUILTIN\\Incoming Forest Trust Builders",
    "559": "BUILTIN\\Performance Monitor Users",
    "560": "BUILTIN\\Performance Log Users",
    "561": "BUILTIN\\Windows Authorization Access Group",
    "562": "BUILTIN\\Terminal Server License Servers",
    "568": "BUILTIN\\IIS_IUSRS",
    "569": "BUILTIN\\Cryptographic Operators",
    "573": "BUILTIN\\Event Log Readers",
    "574": "BUILTIN\\Certificate Service DCOM Access",
    "575": "BUILTIN\\RDS Remote Access Servers",
    "576": "BUILTIN\\RDS Endpoint Servers",
    "577": "BUILTIN\\RDS Management Servers",
    "578": "BUILTIN\\Hyper-V Administrators",
    "579": "BUILTIN\\Access Control Assistance Operators",
    "580": "BUILTIN\\Remote Management Users",
    "582": "BUILTIN\\Storage Replica Administrators",
}

_DOMAIN_RID_WELL_KNOWN: dict[str, str] = {
    "512": "Domain Admins",
    "513": "Domain Users",
    "514": "Domain Guests",
    "515": "Domain Computers",
    "516": "Domain Controllers",
    "517": "Cert Publishers",
    "518": "Schema Admins",
    "519": "Enterprise Admins",
    "520": "Group Policy Creator Owners",
    "521": "Read-only Domain Controllers",
    "522": "Cloneable Domain Controllers",
    "525": "Protected Users",
    "526": "Key Admins",
    "527": "Enterprise Key Admins",
}

_MANDATORY_LABEL_WELL_KNOWN: dict[str, str] = {
    "s-1-16-0": "Untrusted Mandatory Level",
    "s-1-16-4096": "Low Mandatory Level",
    "s-1-16-8192": "Medium Mandatory Level",
    "s-1-16-8448": "Medium Plus Mandatory Level",
    "s-1-16-12288": "High Mandatory Level",
    "s-1-16-16384": "System Mandatory Level",
    "s-1-16-20480": "Protected Process Mandatory Level",
    "s-1-16-28672": "Secure Process Mandatory Level",
}

MS16_072_TRUSTEES = frozenset({"authenticated users", "domain computers"})
SCOPE_BROAD_TRUSTEES = frozenset({"authenticated users", "domain computers", "everyone"})

_NAME_TO_KEY = {
    "authenticated users": "authenticated_users",
    "domain computers": "domain_computers",
    "everyone": "everyone",
}

ACE_TYPE_MAP = {
    "A": "allow",
    "D": "deny",
    "OA": "object_allow",
    "OD": "object_deny",
    # Callback ACE types (Windows 8+) — used for conditional ACEs where the
    # 7th+ field is a conditional expression. Treated as allow/deny for
    # permission evaluation.
    "XA": "allow",
    "XD": "deny",
    "AU": "audit_success",
    "OU": "audit_object",
    "AL": "alarm",
}

_VALID_SDDL_RIGHTS = {
    "GA", "GR", "GW", "GX", "RC", "SD", "WD", "WO", "RP", "WP",
    "CC", "DC", "LC", "LO", "DT", "CR", "SW", "FA", "FR", "FW", "FX",
    "KA", "KR", "KW", "KX",
}

# Mapping of ADS_RIGHTS_ENUM bit values to SDDL 2-letter right codes.
# Used to decode hex rights masks (e.g. 0x1200a9) that some tools emit
# instead of the mnemonic 2-letter codes. Values from Microsoft's
# iads.h ADS_RIGHTS_ENUM documentation.
_HEX_RIGHTS_MAP: tuple[tuple[int, str], ...] = (
    (0x80000000, "GR"),   # ADS_RIGHT_GENERIC_READ
    (0x40000000, "GW"),   # ADS_RIGHT_GENERIC_WRITE
    (0x20000000, "GX"),   # ADS_RIGHT_GENERIC_EXECUTE
    (0x10000000, "GA"),   # ADS_RIGHT_GENERIC_ALL
    (0x00080000, "WO"),   # ADS_RIGHT_WRITE_OWNER
    (0x00040000, "WD"),   # ADS_RIGHT_WRITE_DAC
    (0x00020000, "RC"),   # ADS_RIGHT_READ_CONTROL
    (0x00010000, "SD"),   # ADS_RIGHT_DELETE
    (0x00000100, "CR"),   # ADS_RIGHT_DS_CONTROL_ACCESS (extended rights,
                          # e.g. Apply Group Policy)
    (0x00000080, "LO"),   # ADS_RIGHT_DS_LIST_OBJECT
    (0x00000040, "DT"),   # ADS_RIGHT_DS_DELETE_TREE
    (0x00000020, "WP"),   # ADS_RIGHT_DS_WRITE_PROP
    (0x00000010, "RP"),   # ADS_RIGHT_DS_READ_PROP
    (0x00000008, "SW"),   # ADS_RIGHT_DS_SELF (validated write)
    (0x00000004, "LC"),   # ADS_RIGHT_ACTRL_DS_LIST
    (0x00000002, "DC"),   # ADS_RIGHT_DS_DELETE_CHILD
    (0x00000001, "CC"),   # ADS_RIGHT_DS_CREATE_CHILD
)

_SDDL_SID_ALIASES: dict[str, str] = {
    "wd": "Everyone",
    "an": "Anonymous",
    "au": "Authenticated Users",
    "sy": "SYSTEM",
    "ba": "BUILTIN\\Administrators",
    "bu": "BUILTIN\\Users",
    "bg": "BUILTIN\\Guests",
    "bo": "BUILTIN\\Backup Operators",
    "bf": "BUILTIN\\Server Operators",
    "br": "BUILTIN\\Account Operators",
    "bp": "BUILTIN\\Print Operators",
    # Per sddl.h, PS is SDDL_PERSONAL_SELF (S-1-5-10), not Pre-Windows 2000
    # Compatible Access (that is RU) — confirmed against RawSecurityDescriptor
    # in the reference corpus (tests/fixtures/sddl/).
    "ps": "Self",
    "ru": "BUILTIN\\Pre-Windows 2000 Compatible Access",
    "ao": "BUILTIN\\Account Operators",
    "so": "BUILTIN\\Server Operators",
    "po": "BUILTIN\\Print Operators",
    # Domain-relative aliases. SDDL emits these for the domain the object
    # lives in (e.g. a GPO owner is almost always ``O:DA`` = Domain Admins,
    # not a raw S-1-5-21-...-512 SID). They resolve to the same friendly
    # names as the corresponding domain RIDs above, which is what
    # ``is_default_writer_sid`` matches on by name.
    "da": "Domain Admins",
    "dg": "Domain Guests",
    "du": "Domain Users",
    "dd": "Domain Controllers",
    "dc": "Domain Computers",
    "ea": "Enterprise Admins",
    "sa": "Schema Admins",
    "ca": "Cert Publishers",
    "pa": "Group Policy Creator Owners",
    "cg": "Creator Group",
    "co": "Creator Owner",
    "ow": "Owner Rights",
    "ed": "Enterprise Domain Controllers",
    "ro": "Enterprise Read-only Domain Controllers",
    "la": "Administrator",
    "lg": "Guest",
    "ns": "Network Service",
    "ls": "Local Service",
    "iu": "Interactive",
    "nu": "Network",
    "su": "Service",
    "wr": "Write Restricted",
    "rc": "Restricted Code",
    "rd": "BUILTIN\\Remote Desktop Users",
}


def resolve_well_known(sid: str) -> str | None:
    s = sid.strip().lower()
    if s in _SDDL_SID_ALIASES:
        return _SDDL_SID_ALIASES[s]
    if s in _ABSOLUTE_WELL_KNOWN:
        return _ABSOLUTE_WELL_KNOWN[s]
    if s.startswith(_MANDATORY_PREFIX):
        return _MANDATORY_LABEL_WELL_KNOWN.get(s)
    if s.startswith(_BUILTIN_PREFIX):
        return _BUILTIN_WELL_KNOWN.get(s[len(_BUILTIN_PREFIX):])
    if s.startswith(DOMAIN_SID_PREFIX):
        parts = s.split("-")
        if len(parts) >= 7:
            return _DOMAIN_RID_WELL_KNOWN.get(parts[-1])
    return None


# SDDL 2-letter aliases → canonical SID. ``_ABS`` aliases resolve to a fixed
# well-known SID; ``_DOMREL`` aliases are domain-relative and resolve to
# ``{domain_sid}-{rid}`` when the domain SID is known. Used by
# :func:`canonical_sddl_sid` so alias and raw-SID forms of the same trustee
# compare equal in the security gate (WI-084).
_SDDL_ALIAS_ABS_SID: dict[str, str] = {
    "wd": EVERYONE_SID,        # Everyone               S-1-1-0
    "an": "s-1-5-7",           # Anonymous
    "au": AU_SID,              # Authenticated Users    S-1-5-11
    "sy": "s-1-5-18",          # SYSTEM
    "ns": "s-1-5-20",          # Network Service
    "ls": "s-1-5-19",          # Local Service
    "iu": "s-1-5-4",           # Interactive
    "nu": "s-1-5-2",           # Network
    "su": "s-1-5-6",           # Service
    "wr": "s-1-5-33",          # Write Restricted
    "rc": "s-1-5-12",          # Restricted Code
    "ed": "s-1-5-9",           # Enterprise Domain Controllers
    "co": "s-1-3-0",           # Creator Owner
    "cg": "s-1-3-1",           # Creator Group
    "ow": "s-1-3-4",           # Owner Rights
    "ba": "s-1-5-32-544",      # BUILTIN\\Administrators
    "bu": "s-1-5-32-545",      # BUILTIN\\Users
    "bg": "s-1-5-32-546",      # BUILTIN\\Guests
    "bo": "s-1-5-32-551",      # Backup Operators
    "bf": "s-1-5-32-549",      # Server Operators
    "br": "s-1-5-32-548",      # Account Operators
    "bp": "s-1-5-32-550",      # Print Operators
    "ps": "s-1-5-10",          # Principal Self (sddl.h SDDL_PERSONAL_SELF)
    "ru": "s-1-5-32-554",      # Pre-Windows 2000 Compatible Access
    "rd": "s-1-5-32-555",      # Remote Desktop Users
}

_SDDL_ALIAS_DOMREL_RID: dict[str, str] = {
    "da": "512",  # Domain Admins
    "dg": "514",  # Domain Guests
    "du": "513",  # Domain Users
    "dd": "516",  # Domain Controllers
    "dc": "515",  # Domain Computers
    "ea": "519",  # Enterprise Admins
    "sa": "518",  # Schema Admins
    "ca": "517",  # Cert Publishers
    "pa": "520",  # Group Policy Creator Owners
    "la": "500",  # Administrator (RID)
    "lg": "501",  # Guest (RID)
    "ro": "498",  # Enterprise Read-only Domain Controllers
}


def canonical_sddl_sid(token: str, domain_sid: str | None = None) -> str:
    """Canonicalize an SDDL trustee token (alias or SID) to a comparable SID.

    SDDL emits 2-letter aliases (``AU``, ``WD``, ``DA``) interchangeably with
    raw SIDs. Without canonicalization an allow against ``S-1-5-11`` and a deny
    against ``AU`` are different keys, so the deny never cancels the allow and a
    principal can be wrongly granted a security-filtered GPO (WI-084).

    Absolute aliases resolve to a fixed SID. Domain-relative aliases resolve to
    ``{domain_sid}-{rid}`` when *domain_sid* is known (matching the full SIDs in
    a principal's token); without it they are returned unchanged. Non-alias
    input (raw SIDs, names) is lowercased and returned as-is.
    """
    s = token.strip().lower()
    if s in _SDDL_ALIAS_ABS_SID:
        return _SDDL_ALIAS_ABS_SID[s]
    if s in _SDDL_ALIAS_DOMREL_RID and domain_sid:
        return f"{domain_sid}-{_SDDL_ALIAS_DOMREL_RID[s]}"
    return s


def resolve_principal(estate: Estate, sid: str) -> ResolvedPrincipal:
    """Resolve a SID to a :class:`ResolvedPrincipal`.

    Tries (1) the static well-known SID/RID table, then (2) the collected
    ``estate.principals`` map, then (3) falls back to the raw SID with
    ``resolved=False`` and ``principal_type="Unresolved"``. The SID is always
    preserved on the returned object (Plan 020, decision 2). Pure — no side
    effects, no model calls.
    """
    canonical = sid.strip().lower()
    wk = resolve_well_known(canonical)
    if wk is not None:
        return ResolvedPrincipal(
            sid=canonical,
            name=wk,
            sam=wk,
            principal_type="WellKnown",
            domain="",
            resolved=True,
        )
    stored = estate.principals.get(canonical)
    if stored is not None:
        return stored
    return ResolvedPrincipal(
        sid=canonical,
        name=canonical,
        sam="",
        principal_type="Unresolved",
        domain="",
        resolved=False,
    )


def broad_trustee_key(
    trustee: str,
    sid: str | None,
    broad_names: Iterable[str] = SCOPE_BROAD_TRUSTEES,
) -> str | None:
    """Canonical key for a broad-application trustee, or None.

    Collapses name, SDDL-alias, and raw-SID forms of Authenticated Users,
    Domain Computers, and (optionally) Everyone to a single key. Domain
    Computers is recognized by SID when it matches ``S-1-5-21-...-515``.

    The SID is resolved through :func:`resolve_well_known` so an SDDL alias
    (``AU``/``WD``) and the corresponding raw SID (``S-1-5-11``/``S-1-1-0``)
    yield the *same* key — without this, a deny written against one form does
    not cancel an allow written against the other in ``applies_broadly``
    (WI-084).
    """
    names = set(broad_names)
    t = trustee.strip().lower()
    s = (sid or "").strip().lower()
    # Unify the trustee-name argument with the name the SID resolves to, so
    # alias and raw-SID forms collapse to one key.
    candidate_names = {t}
    resolved = resolve_well_known(s) if s else None
    if resolved is not None:
        candidate_names.add(resolved.lower())
    for name in candidate_names:
        name_key = _NAME_TO_KEY.get(name)
        if name_key is not None and name in names:
            return name_key
    # Raw canonical-SID fast paths (resolve_well_known also covers these, but
    # keep them explicit for the absolute well-knowns and the -515 suffix).
    if s == AU_SID and "authenticated users" in names:
        return "authenticated_users"
    if s == EVERYONE_SID and "everyone" in names:
        return "everyone"
    if (
        s.startswith(DOMAIN_SID_PREFIX)
        and s.endswith(DOMAIN_COMPUTERS_RID_SUFFIX)
        and "domain computers" in names
    ):
        return "domain_computers"
    return None


def applies_broadly(
    grants: Iterable[tuple[str | None, bool]],
) -> bool:
    """True if any broad trustee has an allow grant not canceled by a deny.

    Each grant is ``(canonical_key, allowed)`` where ``allowed=True`` is an
    allow and ``allowed=False`` is a deny. Deny ACEs override allows on the
    *same* trustee; grants for different trustees are independent.
    """
    allowed: set[str] = set()
    denied: set[str] = set()
    for key, is_allowed in grants:
        if key is None:
            continue
        if is_allowed:
            allowed.add(key)
        else:
            denied.add(key)
    return any(key not in denied for key in allowed)


def is_allow_ace_type(ace_type: str) -> bool:
    return ace_type in ("allow", "object_allow")


def is_deny_ace_type(ace_type: str) -> bool:
    return ace_type in ("deny", "object_deny")


# ---------------------------------------------------------------------------
# Authorization predicates (WI-047: consolidated from detection.py and
# queries/_delegation.py where they were duplicated 2-3x each).
# ---------------------------------------------------------------------------

# Names that are considered "default writers" — trustees whose write access
# to a GPO is expected and not a security concern.  The lowercase subset is
# used by the name-based predicate; the full set is used by the SID-based
# predicate via resolve_well_known.
DEFAULT_WRITER_NAMES = frozenset({
    "BUILTIN\\Administrators",
    "Domain Admins",
    "Enterprise Admins",
    "SYSTEM",
    # Non-actionable placeholder identities present in the default GPO DACL.
    # No security principal ever authenticates as Creator Owner / Creator
    # Group / Owner Rights, so a write ACE for them is not a hijack primitive
    # — flagging them buries the real findings under per-GPO noise.
    "Creator Owner",
    "Creator Group",
    "Owner Rights",
})

DEFAULT_WRITER_SID_SUFFIXES = frozenset({"-512", "-519"})

# Lowercase subset for the name-based check (queries/_delegation.py formerly
# used only {"domain admins", "enterprise admins", "system"} — missing
# "administrators" and the placeholder identities).
_DEFAULT_WRITER_NAMES_LOWER = frozenset(
    n.lower() for n in DEFAULT_WRITER_NAMES
)


def is_default_writer(trustee: str) -> bool:
    """True if *trustee* (by display name) is a default GPO writer."""
    return trustee.strip().lower() in _DEFAULT_WRITER_NAMES_LOWER


def is_default_writer_sid(sid: str) -> bool:
    """True if *sid* belongs to a default GPO writer.

    Checks the well-known-SID table and domain RID suffixes (-512, -519).
    """
    s = sid.strip().lower()
    if resolve_well_known(s) in DEFAULT_WRITER_NAMES:
        return True
    return (
        s.startswith(DOMAIN_SID_PREFIX)
        and any(s.endswith(suffix) for suffix in DEFAULT_WRITER_SID_SUFFIXES)
    )


# GPMC's grouped-permission labels (GPOGroupedAccessEnum / GPPermissionType).
# Per Microsoft, every standard grouping except "Custom"/"None" includes the
# READ access right:
#   GpoRead                     -> "Read"
#   GpoApply                    -> "Apply Group Policy"  (Read AND Apply)
#   GpoEdit                     -> "Edit settings"
#   GpoEditDeleteModifySecurity -> "Edit, delete, modify security"
# "Apply Group Policy" in particular IS Read+Apply — GPMC's Delegation tab
# shows it as "Read (from Security Filtering)".  Treating it as non-Read
# produced MS16-072 false positives on every GPO with default Authenticated
# Users filtering.  (ref: gpmgmt.h GPMPermissionType, KB MS16-072.)
#
# GPMC display strings for the Edit* family vary across versions and locales
# ("Edit settings" / "Edit Settings" / "Edit, delete, modify security" /
# "Edit settings, delete, modify security"), so we match that family by prefix
# rather than enumerating every spelling.
READ_IMPLYING_PERMISSIONS = frozenset({
    "read",
    "apply group policy",
    "full control",
})


def permission_implies_read(permission: str) -> bool:
    """True if a GPMC grouped-permission label confers the READ access right."""
    p = permission.strip().lower()
    return (
        p in READ_IMPLYING_PERMISSIONS
        or p.startswith("edit ")
        or p.startswith("edit,")
    )


def permission_implies_apply(permission: str) -> bool:
    """True if a GPMC grouped-permission label confers the APPLY access right.

    Only ``Apply Group Policy`` and ``Full control`` explicitly grant Apply.
    The ``Edit*`` family grants Read+Write but **not** Apply.
    """
    return permission.strip().lower() in ("apply group policy", "full control")


# ---------------------------------------------------------------------------
# SDDL fallback (WI-046: consolidated from topology.py, danger.py, merge.py).
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SddlApplyAce:
    """An allow ACE in the SDDL DACL that grants apply rights."""

    ace: SddlAce
    rights: frozenset[str]
    broad_key: str | None


def iter_sddl_apply_aces(
    sddl: str,
    broad_names: Iterable[str] = SCOPE_BROAD_TRUSTEES,
    *,
    rights_filter: frozenset[str] = APPLY_RIGHTS,
) -> list[SddlApplyAce]:
    """Extract allow ACEs whose rights intersect *rights_filter* from an SDDL string.

    Used as the SDDL fallback when a GPO has no ``delegation`` entries (common
    when the collector only captured the raw SDDL string).  Returns one
    ``SddlApplyAce`` per allow ACE whose rights intersect *rights_filter*
    (default: ``APPLY_RIGHTS`` — only GA/CR, the rights that confer Apply Group
    Policy).  Callers that need read-or-apply detection (e.g. MS16-072's
    Authenticated-Users-Read check) pass ``rights_filter=READ_OR_APPLY_RIGHTS``.
    ``broad_key`` is set when the trustee is a recognized broad-application
    trustee (Authenticated Users, Domain Computers, Everyone).
    """
    acl = parse_sddl(sddl)
    result: list[SddlApplyAce] = []
    for ace in acl.dacl:
        if not is_allow_ace_type(ace.ace_type):
            continue
        rights = frozenset(parse_sddl_rights(ace.rights))
        if not (rights & rights_filter):
            continue
        key = broad_trustee_key("", ace.trustee_sid, broad_names)
        result.append(SddlApplyAce(ace=ace, rights=rights, broad_key=key))
    return result


def parse_sddl_rights(rights: str) -> list[str]:
    """Extract individual 2-letter SDDL right codes from a rights string.

    SDDL rights may be pipe-separated (``GR|GW``) or concatenated
    (``RPWP``) or both. We split on ``|`` first, then walk each part
    extracting consecutive 2-letter codes from the known set.

    Hex masks (e.g. ``0x1200a9``) are also accepted: each set bit is
    mapped to the corresponding SDDL 2-letter code via the standard
    ADS_RIGHTS_ENUM values.
    """
    result: list[str] = []
    for part in rights.split("|"):
        part = part.strip().upper()
        if part.startswith("0X"):
            try:
                mask = int(part, 16)
            except ValueError:
                continue
            for bit, code in _HEX_RIGHTS_MAP:
                if mask & bit:
                    result.append(code)
            continue
        i = 0
        while i + 1 < len(part):
            code = part[i:i + 2]
            if code in _VALID_SDDL_RIGHTS:
                result.append(code)
                i += 2
            else:
                i += 1
    return result


def _parse_ace_string(ace_str: str) -> SddlAce | None:
    parts = ace_str.split(";")
    # SDDL conditional ACEs (Windows 8+) have 7+ fields where the 7th+
    # is a conditional expression (e.g. ``(XA;;GW;;;S-1-5-11;(WIN://OAFD))``).
    # We accept the ACE using the first 6 fields and ignore the conditional
    # expression — SddlAce has no field for it.
    if len(parts) < 6:
        return None
    ace_type_raw = parts[0].strip()
    ace_type = ACE_TYPE_MAP.get(ace_type_raw.upper())
    if ace_type is None:
        return None
    return SddlAce(
        ace_type=ace_type,
        flags=parts[1].strip(),
        rights=parts[2].strip(),
        object_guid=parts[3].strip(),
        inherit_object_guid=parts[4].strip(),
        trustee_sid=parts[5].strip(),
    )


def _find_section_starts(sddl: str) -> dict[str, int]:
    """Find the start positions of O:, G:, D:, S: sections in SDDL.

    Uses parenthesis-depth tracking so that SIDs containing D/S/G/O
    characters (e.g. ``S-1-5-18`` inside the Owner value) are not
    mistaken for section headers. Only characters at depth 0 followed
    by ``:`` are considered section markers.
    """
    sections: dict[str, int] = {}
    depth = 0
    i = 0
    while i < len(sddl):
        ch = sddl[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth < 0:
                depth = 0
        elif depth == 0 and ch in "OGDS" and i + 1 < len(sddl) and sddl[i + 1] == ":":
            sections.setdefault(ch, i)
        i += 1
    return sections


def _extract_aces(text: str) -> list[SddlAce]:
    """Extract ACEs from a parenthesized ACE list like (A;;GA;;;SID)(D;;GR;;;SID)."""
    aces: list[SddlAce] = []
    depth = 0
    ace_start = -1
    for i, ch in enumerate(text):
        if ch == "(":
            if depth == 0:
                ace_start = i + 1
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth < 0:
                depth = 0
            if depth == 0 and ace_start >= 0:
                ace_str = text[ace_start:i]
                ace = _parse_ace_string(ace_str)
                if ace is not None:
                    aces.append(ace)
                ace_start = -1
    return aces


def _acl_control_flags(raw: str) -> str:
    """Extract the ACL control flags preceding the ACE list.

    In ``D:PAI(A;;GR;;;WD)`` the flags are ``PAI`` (``P`` = protected /
    inheritance blocked, ``AI`` = auto-inherited, ``AR`` = auto-inherit
    required). GPMC emits flags on nearly every GPO DACL; a flagless ACL
    (``D:(A;;...)``) yields ``""``.
    """
    head, _, _ = raw.partition("(")
    return head.strip()


def parse_sddl(sddl: str) -> SddlAcl:
    """Parse an SDDL string into owner, group, DACL, and SACL ACEs."""
    if len(sddl) > 1_048_576:
        warnings.warn(
            f"SDDL exceeds 1MB cap ({len(sddl)} bytes); returning empty ACL",
            stacklevel=1,
        )
        return SddlAcl(owner_sid=None, group_sid=None, dacl=(), sacl=())

    owner_sid: str | None = None
    group_sid: str | None = None
    dacl: list[SddlAce] = []
    sacl: list[SddlAce] = []
    dacl_flags = ""
    sacl_flags = ""

    sections = _find_section_starts(sddl)
    section_order = sorted(sections.items(), key=lambda kv: kv[1])

    for idx, (sec_type, sec_start) in enumerate(section_order):
        value_start = sec_start + 2
        value_end = len(sddl)
        if idx + 1 < len(section_order):
            value_end = section_order[idx + 1][1]

        raw = sddl[value_start:value_end]

        if sec_type == "O":
            owner_sid = raw.strip() or None
        elif sec_type == "G":
            group_sid = raw.strip() or None
        elif sec_type == "D":
            dacl = _extract_aces(raw)
            dacl_flags = _acl_control_flags(raw)
        elif sec_type == "S":
            sacl = _extract_aces(raw)
            sacl_flags = _acl_control_flags(raw)

    return SddlAcl(
        owner_sid=owner_sid,
        group_sid=group_sid,
        dacl=tuple(dacl),
        sacl=tuple(sacl),
        dacl_flags=dacl_flags,
        sacl_flags=sacl_flags,
    )
