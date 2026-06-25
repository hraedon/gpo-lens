"""Unit tests for display helpers."""

from __future__ import annotations

import dataclasses
import datetime
import enum
from typing import Any

from gpo_lens.display import render_table, serialize_result


def test_render_table_empty() -> None:
    assert render_table(["a"], []) == "No results.\n"


def test_render_table_basic() -> None:
    out = render_table(["id", "name"], [["1", "Alice"], ["2", "Bob"]])
    lines = out.strip().split("\n")
    assert lines[0] == "id  name "
    assert lines[1] == "--  -----"
    assert lines[2] == "1   Alice"
    assert lines[3] == "2   Bob"


def test_render_table_unicode() -> None:
    out = render_table(["名"], [["值"]])
    assert "名" in out
    assert "值" in out


def test_render_table_long_cell() -> None:
    out = render_table(["x"], [["verylongstringindeed"]])
    assert "verylongstringindeed" in out


def test_render_table_truncation() -> None:
    out = render_table(
        ["id", "description"],
        [["1", "this is a very long description"]],
        max_col_width=10,
    )
    # Header "description" (11 chars) clipped to 10 -> "descripti\u2026"
    assert "descripti\u2026" in out
    # Cell "this is a very long description" clipped to 10 -> "this is a\u2026"
    assert "this is a\u2026" in out


def test_render_settings_diff_empty() -> None:
    from gpo_lens.display import render_settings_diff

    out = render_settings_diff([], [], [])
    assert "No differences" in out


def test_render_settings_diff_added() -> None:
    from gpo_lens.display import render_settings_diff
    from gpo_lens.queries import SettingsDiffRow

    row = SettingsDiffRow(
        gpo_id="aaa", gpo_name="Test", side="Computer", cse="Security",
        identity="X", display_name="X", change_type="added",
        old_value=None, new_value="1",
    )
    out = render_settings_diff([row], [], [])
    assert "Added (1):" in out
    assert "X = 1" in out


def test_render_settings_diff_modified() -> None:
    from gpo_lens.display import render_settings_diff
    from gpo_lens.queries import SettingsDiffRow

    row = SettingsDiffRow(
        gpo_id="aaa", gpo_name="Test", side="Computer", cse="Security",
        identity="X", display_name="X", change_type="modified",
        old_value="1", new_value="2",
    )
    out = render_settings_diff([], [], [row])
    assert "Modified (1):" in out
    assert "1 -> 2" in out


def test_render_settings_diff_none_values() -> None:
    from gpo_lens.display import render_settings_diff
    from gpo_lens.queries import SettingsDiffRow

    added_row = SettingsDiffRow(
        gpo_id="aaa", gpo_name="Test", side="Computer", cse="Security",
        identity="X", display_name="X", change_type="added",
        old_value=None, new_value=None,
    )
    removed_row = SettingsDiffRow(
        gpo_id="bbb", gpo_name="Test", side="User", cse="Registry",
        identity="Y", display_name="Y", change_type="removed",
        old_value=None, new_value=None,
    )
    out = render_settings_diff([added_row], [removed_row], [])
    assert "None" not in out


# --- serialize_result -------------------------------------------------------

def test_serialize_result_primitives_passthrough() -> None:
    assert serialize_result(None) is None
    assert serialize_result(42) == 42
    assert serialize_result("x") == "x"
    assert serialize_result(3.14) == 3.14
    assert serialize_result(True) is True


def test_serialize_result_enum() -> None:
    class Color(enum.Enum):
        RED = "red"

    assert serialize_result(Color.RED) == "red"


def test_serialize_result_datetime() -> None:
    dt = datetime.datetime(2026, 1, 2, 3, 4, 5)
    assert serialize_result(dt) == "2026-01-02T03:04:05"
    d = datetime.date(2026, 1, 2)
    assert serialize_result(d) == "2026-01-02"


def test_serialize_result_dataclass_recurses() -> None:
    @dataclasses.dataclass
    class Inner:
        flag: bool
        when: datetime.datetime

    @dataclasses.dataclass
    class Outer:
        name: str
        inner: Inner

    inner = Inner(flag=True, when=datetime.datetime(2026, 1, 1))
    out = serialize_result(Outer(name="x", inner=inner))
    assert out == {"name": "x", "inner": {"flag": True, "when": "2026-01-01T00:00:00"}}


def test_serialize_result_tuple_becomes_list() -> None:
    out = serialize_result((1, "a", None))
    assert out == [1, "a", None]


def test_serialize_result_set_becomes_sorted_list() -> None:
    """Sets must serialize (sorted for stable output) — regression test."""
    out = serialize_result({3, 1, 2})
    assert out == [1, 2, 3]


def test_serialize_result_frozenset_becomes_sorted_list() -> None:
    out = serialize_result(frozenset({"b", "a"}))
    assert out == ["a", "b"]


def test_serialize_result_bytes_become_hex() -> None:
    assert serialize_result(b"\x00\xff") == "00ff"
    assert serialize_result(bytearray(b"\xab")) == "ab"


def test_serialize_result_set_of_dataclasses() -> None:
    """Nested dataclasses inside a set must also serialize."""
    @dataclasses.dataclass(frozen=True)
    class Item:
        label: str

    # frozenset so the items are hashable; serialize_result must still recurse.
    out = serialize_result(frozenset({Item("a"), Item("b")}))
    assert isinstance(out, list)
    assert all(isinstance(item, dict) and set(item) == {"label"} for item in out)
    assert sorted(item["label"] for item in out) == ["a", "b"]


def test_serialize_result_dict_recurses() -> None:
    out = serialize_result({"k": {"nested": (1, 2)}})
    assert out == {"k": {"nested": [1, 2]}}


def test_serialize_result_mixed_set_does_not_crash() -> None:
    """A set with mixed types must not raise under sorted()."""
    # True == 1 in Python, so {1, True} collapses; use distinct values.
    out = serialize_result({1, "a", None, 2})
    assert isinstance(out, list)
    assert len(out) == 4
    # None sorts first per _set_sort_key.
    assert out[0] is None


def test_serialize_result_empty_set() -> None:
    assert serialize_result(set()) == []


def test_serialize_result_single_element_set() -> None:
    assert serialize_result({42}) == [42]


def test_serialize_result_set_of_bytes_sorts_by_hex() -> None:
    """Bytes within a set must sort deterministically (by hex string form)."""
    out = serialize_result({b"\xff", b"\x00", b"\x10"})
    assert out == ["00", "10", "ff"]


def test_serialize_result_set_of_numeric_types() -> None:
    """Mixed numeric types sort by string form (deterministic, not numeric)."""
    # _set_sort_key returns (2, str(item)) for numbers, so "10" < "2" lexically.
    out = serialize_result({2, 10})
    assert out == [10, 2]


def test_serialize_result_is_json_serialisable() -> None:
    """End-to-end: the output must round-trip json.dumps without default=str."""
    import json

    @dataclasses.dataclass
    class Token:
        sids: frozenset[str]
        raw: bytes
        when: datetime.datetime
        level: enum.IntEnum
    # Use a concrete IntEnum instance.
    class Level(enum.IntEnum):
        LOW = 1

    payload: Any = {
        "tokens": [Token(sids=frozenset({"s-1", "s-2"}), raw=b"\x01\x02",
                          when=datetime.datetime(2026, 6, 25), level=Level.LOW)],
    }
    # Must not raise.
    dumped = json.dumps(serialize_result(payload))
    restored = json.loads(dumped)
    assert restored["tokens"][0]["sids"] == ["s-1", "s-2"]
    assert restored["tokens"][0]["raw"] == "0102"
    assert restored["tokens"][0]["level"] == 1
