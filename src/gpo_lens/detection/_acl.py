"""ACL scans: deny ACEs and excessive writers."""

from __future__ import annotations

from typing import TYPE_CHECKING

from gpo_lens.authz import (
    WRITE_RIGHTS,
    canonical_sddl_sid,
    has_write_right,
    is_allow_ace_type,
    is_default_writer_sid,
    is_deny_ace_type,
    parse_sddl,
    parse_sddl_rights,
    resolve_principal,
)
from gpo_lens.model import DenyAce, ExcessiveWriter

if TYPE_CHECKING:
    from gpo_lens.model import Estate


_is_default_writer_sid = is_default_writer_sid


def deny_aces(estate: Estate) -> list[DenyAce]:
    """Scan GPO SDDL strings for deny ACEs."""
    results: list[DenyAce] = []
    for g in estate.gpos:
        if not g.sddl:
            continue
        acl = parse_sddl(g.sddl)
        for ace in acl.dacl:
            if is_deny_ace_type(ace.ace_type):
                canon_sid = canonical_sddl_sid(ace.trustee_sid or "")
                rp = resolve_principal(estate, canon_sid)
                results.append(
                    DenyAce(
                        gpo_id=g.id,
                        gpo_name=g.name,
                        trustee_sid=canon_sid,
                        rights=ace.rights,
                        flags=ace.flags,
                        acl_section="dacl",
                        trustee_name=rp.name,
                    )
                )
        for ace in acl.sacl:
            if is_deny_ace_type(ace.ace_type):
                canon_sid = canonical_sddl_sid(ace.trustee_sid or "")
                rp = resolve_principal(estate, canon_sid)
                results.append(
                    DenyAce(
                        gpo_id=g.id,
                        gpo_name=g.name,
                        trustee_sid=canon_sid,
                        rights=ace.rights,
                        flags=ace.flags,
                        acl_section="sacl",
                        trustee_name=rp.name,
                    )
                )
    return results


def excessive_writers(
    estate: Estate,
    threshold: int = 5,
) -> list[ExcessiveWriter]:
    """Find trustees with write access to >= *threshold* GPOs.

    Default writers (Domain Admins S-1-5-21-*-512, Enterprise Admins
    S-1-5-21-*-519, LocalSystem S-1-5-18, BUILTIN\\Administrators
    S-1-5-32-544) are excluded from the report.
    """
    writer_map: dict[str, dict[str, set[str]]] = {}
    for g in estate.gpos:
        if not g.sddl:
            continue
        acl = parse_sddl(g.sddl)
        for ace in acl.dacl:
            if not is_allow_ace_type(ace.ace_type):
                continue
            if not has_write_right(ace.rights):
                continue
            sid = canonical_sddl_sid(ace.trustee_sid or "")
            if not sid:
                continue
            entry = writer_map.setdefault(sid, {})
            gpo_entry = entry.setdefault(g.id, set())
            for r in parse_sddl_rights(ace.rights):
                if r in WRITE_RIGHTS:
                    gpo_entry.add(r)

    results: list[ExcessiveWriter] = []
    for sid, gpo_rights in sorted(writer_map.items()):
        if _is_default_writer_sid(sid):
            continue
        if len(gpo_rights) < threshold:
            continue
        all_rights: set[str] = set()
        for rights_set in gpo_rights.values():
            all_rights |= rights_set
        rp = resolve_principal(estate, sid)
        results.append(
            ExcessiveWriter(
                trustee_sid=sid,
                gpo_count=len(gpo_rights),
                gpo_names=tuple(sorted(estate.gpo_names.get(gid_, gid_) for gid_ in gpo_rights)),
                rights=tuple(sorted(all_rights)),
                trustee_name=rp.name,
            )
        )

    results.sort(key=lambda w: w.gpo_count, reverse=True)
    return results
