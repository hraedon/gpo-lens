"""Table renderer and other display helpers.

One place for column-width calculation so the CLI doesn't hand-roll
format strings every time.
"""

from __future__ import annotations

from typing import Sequence


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

    # Convert everything to strings and optionally truncate
    str_rows = [[_clip(str(cell)) for cell in row] for row in rows]
    clipped_headers = [_clip(h) for h in headers]
    ncols = len(headers)

    # Compute column widths (after clipping)
    widths = [len(h) for h in clipped_headers]
    for row in str_rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))

    # Build format strings
    parts = []
    for col in range(ncols):
        parts.append("{:<" + str(widths[col]) + "}")
    fmt = "  ".join(parts)

    lines = []
    lines.append(fmt.format(*clipped_headers))
    lines.append("  ".join("-" * w for w in widths))
    for row in str_rows:
        lines.append(fmt.format(*row))
    return "\n".join(lines) + "\n"
