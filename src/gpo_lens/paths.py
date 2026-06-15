"""Case-insensitive SYSVOL path resolution.

A copied SYSVOL keeps Windows' original casing, which varies in the wild: the
default GPOs ship as ``MACHINE``/``USER`` (upper-case) while most others use
``Machine``/``User``. On a case-sensitive (Linux) analysis host a literal
``base / "Machine"`` therefore silently misses real data. These helpers resolve
a child by case-insensitive name and tolerate unreadable directories (a copied
SYSVOL can contain folders the analysis account cannot enter).

Pure stdlib, read-only.
"""

from __future__ import annotations

from pathlib import Path


def ci_child(parent: Path, name: str) -> Path | None:
    """Return ``parent``'s child named ``name`` (case-insensitive), or ``None``.

    Tries the literal path first (fast, and correct on case-insensitive hosts),
    then falls back to a case-insensitive scan. Returns ``None`` if the parent
    is unreadable or no child matches.
    """
    direct = parent / name
    try:
        if direct.exists():
            return direct
        target = name.lower()
        for child in parent.iterdir():
            if child.name.lower() == target:
                return child
    except OSError:
        return None
    return None


def ci_path(base: Path, *parts: str) -> Path | None:
    """Resolve a chain of children case-insensitively.

    Returns ``None`` if any segment is missing or unreadable.
    """
    cur = base
    for part in parts:
        nxt = ci_child(cur, part)
        if nxt is None:
            return None
        cur = nxt
    return cur
