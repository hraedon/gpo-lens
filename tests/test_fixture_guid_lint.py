"""Guard: no bare hyphenated GUIDs in test fixtures.

GPO identifiers must be canonical (lowercase, no hyphens, no braces) per
``normalize.canonical_guid``.  Braced GUIDs ({GUID}) are allowed — they
simulate real GPO XML / collector output.  ``test_normalize.py`` is exempt
because it exercises ``canonical_guid`` with hyphenated input.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

_HYPHENATED_GUID = re.compile(
    r"(?<!\{)[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)

_EXEMPT = {"test_normalize.py"}


def test_no_bare_hyphenated_guids_in_test_files() -> None:
    tests_dir = Path(__file__).parent
    violations: list[str] = []
    for py in sorted(tests_dir.rglob("*.py")):
        if py.name in _EXEMPT:
            continue
        source = py.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(py))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                continue
            for m in _HYPHENATED_GUID.finditer(node.value):
                violations.append(f"{py.name}:{node.lineno}: {m.group()}")
    assert not violations, (
        "Bare hyphenated GUIDs found in test files — use canonical form "
        "(lowercase, no hyphens):\n  " + "\n  ".join(violations)
    )


def test_pattern_catches_hyphenated_literal() -> None:
    bare = "-".join(["11111111", "1111", "1111", "1111", "111111111111"])
    assert _HYPHENATED_GUID.search(bare)
    assert not _HYPHENATED_GUID.search("{" + bare + "}")
    assert not _HYPHENATED_GUID.search(bare.replace("-", "").lower())
