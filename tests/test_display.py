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
