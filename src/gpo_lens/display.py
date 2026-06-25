"""Table renderer and other display helpers.

One place for column-width calculation so the CLI doesn't hand-roll
format strings every time.
"""

from __future__ import annotations

import dataclasses
import datetime
from collections.abc import Sequence
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from gpo_lens.queries import SettingsDiffRow


def serialize_result(result: object) -> object:
    """Recursively convert dataclass instances to plain dicts for JSON serialization.

    Handles ``datetime``/``date`` (→ ISO 8601 string), ``Enum`` (→ ``.value``),
    ``set``/``frozenset`` (→ sorted list), and ``bytes`` (→ hex string) so the
    output is always JSON-serialisable — the CLI's ``json.dumps(...,
    default=str)`` masks these, but ``JSONResponse`` has no ``default`` hook.
    """
    if isinstance(result, Enum):
        return result.value
    if isinstance(result, (datetime.datetime, datetime.date)):
        return result.isoformat()
    if dataclasses.is_dataclass(result) and not isinstance(result, type):
        # Manually recurse through fields instead of ``dataclasses.asdict`` so
        # that nested datetime/Enum values are converted, not passed through.
        return {
            f.name: serialize_result(getattr(result, f.name))
            for f in dataclasses.fields(result)
        }
    if isinstance(result, list):
        return [serialize_result(item) for item in result]
    if isinstance(result, dict):
        return {k: serialize_result(v) for k, v in result.items()}
    if isinstance(result, tuple):
        # Tuples preserve order — they are positional records, not unordered.
        return [serialize_result(item) for item in result]
    if isinstance(result, (set, frozenset)):
        # Sets have non-deterministic iteration order; sort for stable output.
        # ``_set_sort_key`` provides a total order across mixed types (a set
        # may legally contain ``{1, "a", None}`` which would otherwise raise).
        return [serialize_result(item) for item in sorted(result, key=_set_sort_key)]
    if isinstance(result, (bytes, bytearray)):
        return result.hex()
    return result


def _set_sort_key(item: object) -> tuple[int, str]:
    """Total-ordering key for mixed-type collections (set/frozenset).

    ``sorted()`` requires a total order; a set may legally contain mixed types
    (e.g. ``{1, "a"}``), which would raise ``TypeError`` under default
    comparison. Group by type-rank then by string form.
    """
    if item is None:
        return (0, "")
    if isinstance(item, bool):
        return (1, str(item))
    if isinstance(item, (int, float)):
        return (2, str(item))
    return (3, str(item))


def render_table(
    headers: list[str],
    rows: list[Sequence[str]],
    max_col_width: int | None = None,
) -> str:
    """Render a table to a string.

    Parameters
    ----------
    headers: column titles
    rows: list of rows (each a sequence of string-convertible values)
    max_col_width: if given, truncate any cell wider than this.

    Returns
    -------
    str
        The formatted table string.
    """
    if not rows:
        return "No results.\n"

    def _clip(text: str) -> str:
        if max_col_width is not None and len(text) > max_col_width:
            return text[: max_col_width - 1] + "\u2026"
        return text

    str_rows = [[_clip(str(cell)) for cell in row] for row in rows]
    clipped_headers = [_clip(h) for h in headers]
    ncols = len(headers)

    widths = [len(h) for h in clipped_headers]
    for row in str_rows:
        padded = row + [""] * (ncols - len(row))
        for i, cell in enumerate(padded):
            widths[i] = max(widths[i], len(cell))

    parts = []
    for col in range(ncols):
        parts.append("{:<" + str(widths[col]) + "}")
    fmt = "  ".join(parts)

    lines = []
    lines.append(fmt.format(*clipped_headers))
    lines.append("  ".join("-" * w for w in widths))
    for row in str_rows:
        padded = row + [""] * (ncols - len(row))
        lines.append(fmt.format(*padded))
    return "\n".join(lines) + "\n"


def render_settings_diff(
    added: list[SettingsDiffRow],
    removed: list[SettingsDiffRow],
    modified: list[SettingsDiffRow],
) -> str:
    parts: list[str] = []
    if added:
        parts.append(f"Added ({len(added)}):")
        for row in added:
            parts.append(
                f"  [{row.cse}] {row.side}/{row.gpo_name}: "
                f"{row.identity} = {row.new_value or ''}"
            )
    if removed:
        parts.append(f"Removed ({len(removed)}):")
        for row in removed:
            parts.append(
                f"  [{row.cse}] {row.side}/{row.gpo_name}: "
                f"{row.identity} = {row.old_value or ''}"
            )
    if modified:
        parts.append(f"Modified ({len(modified)}):")
        for row in modified:
            parts.append(
                f"  [{row.cse}] {row.side}/{row.gpo_name}: "
                f"{row.identity}: {row.old_value or ''} -> {row.new_value or ''}"
            )
    if not parts:
        return "No differences found.\n"
    return "\n".join(parts) + "\n"
