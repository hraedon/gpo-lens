"""Guard test: inline Registry-CSE comparisons must use normalize.is_registry_cse().

The ``_REGISTRY_CSES`` constant and inline ``in ("Registry", ...)`` /
``== "Registry"`` checks were duplicated across merge.py, danger.py,
ingest.py, detection.py, and queries/_admx_coverage.py — all independently
susceptible to the same case-sensitivity bug. They are now centralized in
:func:`gpo_lens.normalize.is_registry_cse`. This test prevents the
duplication from creeping back.
"""

from __future__ import annotations

import pathlib

SRC_DIR = pathlib.Path(__file__).resolve().parent.parent / "src" / "gpo_lens"

_HARD_FORBIDDEN = (
    "_REGISTRY_CSES",
    'in ("Registry"',
    'in ("registry"',
    '== "Registry"',
)

_SOFT_FORBIDDEN = '== "registry"'
_SOFT_ALLOWED = ".lower()"


def test_no_inline_registry_cse_checks() -> None:
    offenders: list[str] = []
    for py_file in SRC_DIR.rglob("*.py"):
        if py_file.name == "normalize.py":
            continue
        for lineno, line in enumerate(
            py_file.read_text(encoding="utf-8").splitlines(), start=1
        ):
            for pattern in _HARD_FORBIDDEN:
                if pattern in line:
                    rel = py_file.relative_to(SRC_DIR)
                    offenders.append(
                        f"{rel}:{lineno}: found {pattern!r} in {line.strip()!r}"
                    )
            if _SOFT_FORBIDDEN in line and _SOFT_ALLOWED not in line:
                rel = py_file.relative_to(SRC_DIR)
                offenders.append(
                    f"{rel}:{lineno}: found {_SOFT_FORBIDDEN!r} "
                    f"without .lower() in {line.strip()!r}"
                )
    assert not offenders, (
        "Inline Registry-CSE checks found — use normalize.is_registry_cse() "
        f"instead: {offenders}"
    )
