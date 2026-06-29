"""Pure unit tests — no samples required, always run."""

from __future__ import annotations

import json
from pathlib import Path

import pytest


def test_canonical_guid_strips_braces_and_lowercases():
    from gpo_lens.normalize import canonical_guid

    braced = "{31B2F340-016D-11D2-945F-00C04FB984F9}"
    bare = "31b2f340016d11d2945f00c04fb984f9"
    assert canonical_guid(braced) == bare
    assert canonical_guid(bare) == bare
    # The three input forms across collector outputs must collapse to one key.
    assert canonical_guid("31B2F340-016D-11D2-945F-00C04FB984F9") == bare


def test_canonical_guid_strips_hyphens():
    """Hyphenated and non-hyphenated forms must collapse to the same key."""
    from gpo_lens.normalize import canonical_guid

    hyphenated = "31B2F340-016D-11D2-945F-00C04FB984F9"
    non_hyphenated = "31B2F340016D11D2945F00C04FB984F9"
    expected = "31b2f340016d11d2945f00c04fb984f9"
    assert canonical_guid(hyphenated) == expected
    assert canonical_guid(non_hyphenated) == expected
    assert canonical_guid(hyphenated) == canonical_guid(non_hyphenated)


def test_canonical_guid_non_standard_hyphen_positions():
    """GUIDs with hyphens in non-standard positions must still normalize."""
    from gpo_lens.normalize import canonical_guid

    # Non-standard hyphen placement (not the 8-4-4-4-12 pattern)
    weird = "31B2-F340-016D-11D2-945F-00C0-4FB9-84F9"
    standard = "31B2F340-016D-11D2-945F-00C04FB984F9"
    expected = "31b2f340016d11d2945f00c04fb984f9"
    assert canonical_guid(weird) == expected
    assert canonical_guid(weird) == canonical_guid(standard)


def test_canonical_guid_rejects_garbage():
    from gpo_lens.normalize import canonical_guid

    with pytest.raises(ValueError):
        canonical_guid("not-a-guid")


def test_load_json_tolerates_utf8_bom(tmp_path):
    from gpo_lens.normalize import load_json

    p = tmp_path / "bom.json"
    # PowerShell 5.1 Set-Content -Encoding UTF8 writes a BOM; a plain utf-8 load
    # would raise. utf-8-sig must succeed.
    p.write_bytes(b"\xef\xbb\xbf" + json.dumps({"ok": True}).encode("utf-8"))
    assert load_json(p) == {"ok": True}


def test_load_json_tolerates_utf8_bom_in_fixture():
    from gpo_lens.normalize import load_json

    fixture_dir = Path(__file__).parent / "fixtures"
    ou_tree = fixture_dir / "ou-tree.json"
    # The fixture generator writes ou-tree.json with a UTF-8 BOM prefix
    assert ou_tree.read_bytes()[:3] == b"\xef\xbb\xbf"
    data = load_json(ou_tree)
    assert isinstance(data, list)
    assert data[0]["Name"] == "fakefixture.local"


def test_parse_bool():
    from gpo_lens.normalize import parse_bool

    assert parse_bool("true") is True
    assert parse_bool("True") is True
    assert parse_bool("false") is False
    assert parse_bool(None) is False


def test_parse_dt_malformed_returns_none():
    """A malformed timestamp must not crash estate ingestion."""
    from gpo_lens.normalize import parse_dt

    assert parse_dt("not-a-date") is None
    assert parse_dt("2026-13-99T99:99:99") is None


def test_parse_int_float_string():
    """PowerShell's ConvertTo-Json can emit floats for integer fields."""
    from gpo_lens.normalize import parse_int

    assert parse_int("3.0") == 3
    assert parse_int("3.5") == 3  # int(float()) truncation
