"""Shared authorization primitives for SDDL parsing and broad-trustee recognition.

This module is the shared substrate for ``detection`` (MS16-072) and
``topology`` (security-filtering / scope honesty). It intentionally does not
model Windows ACL evaluation; it only centralizes the duplicated SDDL parser
and trustee/rights normalization so the two predicates stop drifting.
"""

from __future__ import annotations

import warnings
from typing import Iterable

from gpo_lens.model import SddlAce, SddlAcl

__all__ = [
    "ACE_TYPE_MAP",
    "AU_SID",
    "DOMAIN_COMPUTERS_RID_SUFFIX",
    "DOMAIN_SID_PREFIX",
    "EVERYONE_SID",
    "MS16_072_TRUSTEES",
    "SCOPE_BROAD_TRUSTEES",
    "applies_broadly",
    "broad_trustee_key",
    "is_allow_ace_type",
    "is_deny_ace_type",
    "parse_sddl",
    "parse_sddl_rights",
]

AU_SID = "s-1-5-11"
EVERYONE_SID = "s-1-1-0"
DOMAIN_SID_PREFIX = "s-1-5-21-"
DOMAIN_COMPUTERS_RID_SUFFIX = "-515"

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
    "AU": "audit_success",
    "OU": "audit_object",
    "AL": "alarm",
}

_VALID_SDDL_RIGHTS = {
    "GA", "GR", "GW", "GX", "RC", "SD", "WD", "WO", "RP", "WP",
    "CC", "DC", "LC", "LO", "DT", "CR", "FA", "FR", "FW", "FX",
    "KA", "KR", "KW", "KX",
}


def broad_trustee_key(
    trustee: str,
    sid: str | None,
    broad_names: Iterable[str] = SCOPE_BROAD_TRUSTEES,
) -> str | None:
    """Canonical key for a broad-application trustee, or None.

    Collapses name and SID forms of Authenticated Users, Domain Computers,
    and (optionally) Everyone to a single key. Domain Computers is only
    recognized by SID when it matches ``S-1-5-21-...-515``.
    """
    names = set(broad_names)
    t = trustee.strip().lower()
    s = (sid or "").strip().lower()
    name_key = _NAME_TO_KEY.get(t)
    if name_key is not None and t in names:
        return name_key
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


def parse_sddl_rights(rights: str) -> list[str]:
    """Extract individual 2-letter SDDL right codes from a rights string.

    SDDL rights may be pipe-separated (``GR|GW``) or concatenated
    (``RPWP``) or both. We split on ``|`` first, then walk each part
    extracting consecutive 2-letter codes from the known set.
    """
    result: list[str] = []
    for part in rights.split("|"):
        part = part.strip().upper()
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
    if len(parts) != 6:
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


def _extract_aces(text: str) -> list["SddlAce"]:
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
            if depth == 0 and ace_start >= 0:
                ace_str = text[ace_start:i]
                ace = _parse_ace_string(ace_str)
                if ace is not None:
                    aces.append(ace)
                ace_start = -1
    return aces


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
        elif sec_type == "S":
            sacl = _extract_aces(raw)

    return SddlAcl(
        owner_sid=owner_sid,
        group_sid=group_sid,
        dacl=tuple(dacl),
        sacl=tuple(sacl),
    )
