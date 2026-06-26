"""Delegation / permissions audit composition over an Estate."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from gpo_lens.detection import (
    DenyAce,
    ExcessiveWriter,
    deny_aces,
    excessive_writers,
    has_ms16_072_read,
)

if TYPE_CHECKING:
    from gpo_lens.model import DelegationEntry, Estate, Gpo

from gpo_lens.authz import (
    is_default_writer as _is_default_writer,
)
from gpo_lens.authz import (
    is_default_writer_sid as _is_default_writer_sid,
)
from gpo_lens.authz import (
    resolve_principal as _resolve_principal,
)


@dataclass(frozen=True)
class DelegationAudit:
    """Deep-dive delegation analysis."""

    privilege_rollup: dict[str, list[str]]
    orphaned_sids: list[tuple[Gpo, str]]
    broad_writers: list[tuple[Gpo, DelegationEntry]]
    deny_aces: list[DenyAce]
    excessive_writers: list[ExcessiveWriter]


@dataclass(frozen=True)
class DelegationRollupEntry:
    """One trustee's delegation across the estate (estate-wide rollup)."""

    trustee: str               # display name from delegation entry
    trustee_sid: str           # canonical SID (lowercase, or "")
    resolved_name: str         # resolved name (or SID if unresolved)
    is_resolved: bool          # True if SID was resolved to a name
    is_unknown_sid: bool       # True if SID is not well-known or collected
    is_default_writer: bool    # True if trustee is a default GPO writer
    gpo_count: int             # number of GPOs with non-Read rights
    gpo_names: tuple[str, ...]  # sorted GPO names
    permissions: tuple[str, ...]  # distinct permission labels


_READ_PERMISSIONS = frozenset({
    "read",
    "apply group policy",
})


def _is_read_only(permission: str) -> bool:
    """True if the permission confers only Read/Apply (no write/edit)."""
    p = permission.strip().lower()
    if p in _READ_PERMISSIONS:
        return True
    return False


def delegation_rollup(estate: Estate) -> list[DelegationRollupEntry]:
    """Estate-wide per-trustee delegation rollup.

    Inverts the per-GPO delegation entries into a per-trustee view: for each
    trustee, lists all GPOs they hold non-Read rights on, with their
    permissions and resolved identity status.

    Trustees are keyed by SID (canonical lowercase) when a SID is available,
    falling back to the trustee display name. Unknown SIDs (not well-known
    and not in the collected principal map) are flagged.

    Results are sorted by ``gpo_count`` descending (breadth-first), then by
    trustee name.
    """
    class _Acc:
        __slots__ = ("trustee", "sid", "gpos", "permissions")
        def __init__(self) -> None:
            self.trustee: str = ""
            self.sid: str = ""
            self.gpos: set[str] = set()
            self.permissions: set[str] = set()

    by_key: dict[str, _Acc] = {}

    for g in estate.gpos:
        for d in g.delegation:
            if not d.allowed:
                continue
            if _is_read_only(d.permission):
                continue

            sid = (d.trustee_sid or "").strip().lower()
            key = sid or d.trustee.strip().lower()
            if not key:
                continue

            acc = by_key.setdefault(key, _Acc())
            if not acc.trustee:
                acc.trustee = d.trustee.strip()
            if not acc.sid:
                acc.sid = sid
            acc.gpos.add(g.name)
            acc.permissions.add(d.permission)

    results: list[DelegationRollupEntry] = []
    for acc in by_key.values():
        sid = acc.sid
        trustee_name = acc.trustee

        if sid:
            principal = _resolve_principal(estate, sid)
            resolved_name = principal.name
            is_resolved = principal.resolved
            is_unknown = principal.principal_type == "Unresolved"
            is_default = _is_default_writer_sid(sid)
        else:
            resolved_name = trustee_name
            is_resolved = bool(trustee_name)
            is_unknown = not trustee_name
            is_default = _is_default_writer(trustee_name)

        results.append(DelegationRollupEntry(
            trustee=trustee_name,
            trustee_sid=sid,
            resolved_name=resolved_name,
            is_resolved=is_resolved,
            is_unknown_sid=is_unknown,
            is_default_writer=is_default,
            gpo_count=len(acc.gpos),
            gpo_names=tuple(sorted(acc.gpos)),
            permissions=tuple(sorted(acc.permissions)),
        ))

    results.sort(key=lambda e: (-e.gpo_count, e.resolved_name.lower()))
    return results


def delegation_deep_dive(estate: Estate) -> DelegationAudit:
    """Estate-wide delegation audit."""
    rollup: dict[str, list[str]] = {}
    orphaned: list[tuple[Gpo, str]] = []
    broad: list[tuple[Gpo, DelegationEntry]] = []

    for g in estate.gpos:
        for d in g.delegation:
            if not d.allowed:
                continue
            if (not d.trustee or d.trustee.strip() == "") and d.trustee_sid:
                orphaned.append((g, d.trustee_sid))

            if "write" in d.permission.lower() or "edit" in d.permission.lower():
                trustee_name = d.trustee.strip()
                rollup.setdefault(trustee_name, []).append(g.name)
                if not _is_default_writer(trustee_name):
                    broad.append((g, d))

    return DelegationAudit(
        privilege_rollup=rollup,
        orphaned_sids=orphaned,
        broad_writers=broad,
        deny_aces=deny_aces(estate),
        excessive_writers=excessive_writers(estate),
    )


def permissions_audit(estate: Estate) -> list[tuple[Gpo, str]]:
    """Audit delegation for common security issues."""
    issues: list[tuple[Gpo, str]] = []
    for g in estate.gpos:
        if not has_ms16_072_read(g.delegation):
            issues.append((g, "No Authenticated Users / Domain Computers Read (MS16-072)"))

        writers = [d for d in g.delegation if d.allowed and "write" in d.permission.lower()]
        if len(writers) > 3:
            issues.append((g, f"{len(writers)} principals have write/modify permissions"))

        if not g.delegation:
            issues.append((g, "No delegation entries"))

    return issues
