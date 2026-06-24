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

# ---------------------------------------------------------------------------
# Security / hygiene helpers (used by permissions_audit, delegation_deep_dive)
# ---------------------------------------------------------------------------

from gpo_lens.authz import is_default_writer as _is_default_writer


@dataclass(frozen=True)
class DelegationAudit:
    """Deep-dive delegation analysis."""

    privilege_rollup: dict[str, list[str]]  # trustee -> GPO names with edit rights
    orphaned_sids: list[tuple[Gpo, str]]    # (Gpo, orphaned_sid)
    broad_writers: list[tuple[Gpo, DelegationEntry]]  # non-default editor with write
    deny_aces: list[DenyAce]                # deny ACEs found in SDDL
    excessive_writers: list[ExcessiveWriter]  # trustees with write across many GPOs


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
