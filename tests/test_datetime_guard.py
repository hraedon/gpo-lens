"""Guard test: datetime.fromisoformat must appear only in normalize.py.

store.py previously had its own _iso_to_dt wrapper (WI-3). That duplication
is now collapsed — store.py imports normalize.parse_dt instead. This test
prevents the duplication from creeping back.
"""

from __future__ import annotations

import pathlib

SRC_DIR = pathlib.Path(__file__).resolve().parent.parent / "src" / "gpo_lens"


def test_fromisoformat_only_in_normalize() -> None:
    offenders: list[str] = []
    for py_file in SRC_DIR.rglob("*.py"):
        if py_file.name == "normalize.py":
            continue
        text = py_file.read_text(encoding="utf-8")
        if "fromisoformat" in text:
            offenders.append(str(py_file.relative_to(SRC_DIR)))
    assert not offenders, (
        f"datetime.fromisoformat found outside normalize.py: {offenders}"
    )
