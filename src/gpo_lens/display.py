"""Table renderer and other display helpers.

One place for column-width calculation so the CLI doesn't hand-roll
format strings every time.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Sequence
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from gpo_lens.queries import SettingsDiffRow


def serialize_result(result: object) -> object:
    """Recursively convert dataclass instances to plain dicts for JSON serialization."""
    if dataclasses.is_dataclass(result) and not isinstance(result, type):
        return dataclasses.asdict(result)
    if isinstance(result, list):
        return [serialize_result(item) for item in result]
    if isinstance(result, dict):
        return {k: serialize_result(v) for k, v in result.items()}
    if isinstance(result, tuple):
        return [serialize_result(item) for item in result]
    return result


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
