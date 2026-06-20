"""Pure helpers for normalization and parsing."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any


def localname(tag: str) -> str:
    """Strip XML namespace prefix from a tag: ``{ns}local`` → ``local``."""
    return tag.split("}")[-1] if "}" in tag else tag


def canonical_guid(raw: str) -> str:
    """Lowercase and strip surrounding braces and whitespace.

    ``"{31B2F340-016D-11D2-945F-00C04FB984F9}"`` →
    ``"31b2f340-016d-11d2-945f-00c04fb984f9"``.
    """
    cleaned = raw.strip().strip("{}").strip()
    # Validate: 32 hex digits optionally with hyphens
    bare = cleaned.replace("-", "")
    if len(bare) != 32 or not all(c in "0123456789abcdefABCDEF" for c in bare):
        raise ValueError(f"Not a valid GUID: {raw!r}")
    return cleaned.lower()


def load_json(path: str | Path) -> Any:
    """Read JSON using ``encoding="utf-8-sig"`` so a PowerShell 5.1 UTF-8 BOM is tolerated."""
    with open(path, "r", encoding="utf-8-sig") as f:
        return json.load(f)


def parse_bool(text: str | None) -> bool:
    """``"true"`` → True, ``"false"``/None → False (case-insensitive)."""
    if text is None:
        return False
    return text.strip().lower() == "true"


def parse_dt(text: str | None) -> datetime | None:
    """ISO-8601 datetime; None/empty → None."""
    if not text:
        return None
    # The report uses e.g. 2026-03-10T16:32:00
    return datetime.fromisoformat(text)


def parse_int(text: str | None) -> int | None:
    """None/empty/non-numeric → None."""
    if text is None:
        return None
    text = text.strip()
    if not text:
        return None
    try:
        return int(text)
    except ValueError:
        return None
