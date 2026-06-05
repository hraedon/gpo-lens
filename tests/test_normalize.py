"""Pure unit tests — no samples required, always run."""

from __future__ import annotations

import json

import pytest


def test_canonical_guid_strips_braces_and_lowercases():
    from gpo_lens.normalize import canonical_guid

    braced = "{31B2F340-016D-11D2-945F-00C04FB984F9}"
    bare = "31b2f340-016d-11d2-945f-00c04fb984f9"
    assert canonical_guid(braced) == bare
    assert canonical_guid(bare) == bare
    # The three input forms across collector outputs must collapse to one key.
    assert canonical_guid("31B2F340-016D-11D2-945F-00C04FB984F9") == bare


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


def test_parse_bool():
    from gpo_lens.normalize import parse_bool

    assert parse_bool("true") is True
    assert parse_bool("True") is True
    assert parse_bool("false") is False
    assert parse_bool(None) is False
