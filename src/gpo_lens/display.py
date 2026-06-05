"""Table renderer and other display helpers.

One place for column-width calculation so the CLI doesn't hand-roll
format strings every time.
"""

from __future__ import annotations

from typing import Sequence


def render_table(headers: list[str], rows: list[Sequence[str]]) -> str:
    """Render a table to a string.

    Parameters
    ----------
    headers: column titles
    rows: list of rows (each a sequence of string-convertible values)

    Returns
    -------
    str
        The formatted table string.
    """
    if not rows:
        return "No results.\n"

    # Convert everything to strings
    str_rows = [[str(cell) for cell in row] for row in rows]
    headers_str = [str(h) for h in headers]
    ncols = len(headers)

    # Compute column widths
    widths = [len(h) for h in headers]
    for row in str_rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))

    # Build format strings
    parts = []
    for col in range(ncols):
        parts.append("{:<" + str(widths[col]) + "}")
    fmt = "  ".join(parts)

    lines = []
    lines.append(fmt.format(*headers))
    lines.append("  ".join("-" * w for w in widths))
    for row in str_rows:
        lines.append(fmt.format(*row))
    return "\n".join(lines) + "\n"
