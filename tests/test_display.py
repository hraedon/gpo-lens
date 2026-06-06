"""Unit tests for display helpers."""

from __future__ import annotations

from gpo_lens.display import render_table


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
