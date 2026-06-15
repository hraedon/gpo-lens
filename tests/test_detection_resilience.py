"""Regression: GPP scanning must survive an unreadable SYSVOL subtree.

A copied SYSVOL can contain policy folders the analysis account cannot enter:
a security-filtered GPO copied with its ACLs intact, or — observed on a real
run-through — a Windows-produced zip extracted on Linux where a directory lost
its traversal (``x``) bit. ``_walk_gpp_xml`` must skip such subtrees, not crash
the whole ``doctor`` run. Coverage gaps are reported via collection-errors.json.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from gpo_lens.detection import (
    _scan_gpo_for_cpassword,
    _walk_gpp_xml,
    scan_local_groups,
    scan_scheduled_tasks,
)
from gpo_lens.model import Gpo

_SCHED_XML = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<ScheduledTasks><ImmediateTaskV2 name="t">'
    '<Properties action="C" runAs="SYSTEM"><Task><Actions>'
    '<Exec><Command>cmd.exe</Command></Exec>'
    '</Actions></Task></Properties></ImmediateTaskV2></ScheduledTasks>'
)


def _make_gpo(sysvol_path: str) -> Gpo:
    return Gpo(
        id="gpo-1", name="Partial GPO", domain="test.local",
        created=None, modified=None, read=None,
        computer_enabled=True, user_enabled=True,
        computer_ver_ds=None, computer_ver_sysvol=None,
        user_ver_ds=None, user_ver_sysvol=None,
        sddl=None, owner=None, filter_data_available=False,
        wmi_filter=None, sysvol_path=sysvol_path, settings=[],
    )


def _build_tree(base: Path) -> None:
    machine = base / "Machine" / "Preferences" / "ScheduledTasks"
    machine.mkdir(parents=True)
    (machine / "ScheduledTasks.xml").write_text(_SCHED_XML, encoding="utf-8")
    (base / "User" / "Preferences").mkdir(parents=True)


@pytest.mark.skipif(
    os.name != "posix" or os.geteuid() == 0,
    reason="chmod-based unreadable-dir test requires a non-root POSIX host",
)
def test_walk_skips_unreadable_side(tmp_path):
    base = tmp_path / "{GUID}"
    _build_tree(base)
    unreadable = base / "User"
    unreadable.chmod(0o000)  # drop traversal bit, as a broken extraction does
    try:
        gpo = _make_gpo(str(base))
        # Must not raise PermissionError, and must still find the readable side.
        found = [rel.as_posix() for _t, _abs, rel in _walk_gpp_xml(gpo)]
        assert any("Machine/Preferences" in p for p in found)
        assert _scan_gpo_for_cpassword(gpo) == []
    finally:
        unreadable.chmod(0o755)  # restore so tmp cleanup can recurse


_GROUPS_XML = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<Groups><Group name="Administrators (built-in)">'
    '<Properties action="U" groupSid="S-1-5-32-544" groupName="Administrators">'
    '<Members><Member name="HRAENET\\helpdesk" action="ADD" '
    'sid="S-1-5-21-1-2-3-1106"/></Members>'
    '</Properties></Group></Groups>'
)


def test_real_nested_cse_layout_is_parsed(tmp_path):
    """Real SYSVOL nests each CSE in its own subfolder: Preferences/<CSE>/<CSE>.xml.

    The flat fixtures used elsewhere hid this; a real export only works if the
    walker descends one level into the CSE subfolders.
    """
    base = tmp_path / "{GUID}"
    sched = base / "Machine" / "Preferences" / "ScheduledTasks"
    sched.mkdir(parents=True)
    (sched / "ScheduledTasks.xml").write_text(_SCHED_XML, encoding="utf-8")
    groups = base / "Machine" / "Preferences" / "Groups"
    groups.mkdir(parents=True)
    (groups / "Groups.xml").write_text(_GROUPS_XML, encoding="utf-8")

    gpo = _make_gpo(str(base))
    tasks = scan_scheduled_tasks(gpo)
    assert len(tasks) == 1
    mods = scan_local_groups(gpo)
    assert len(mods) == 1
    assert mods[0].side == "Computer"


def test_uppercase_side_dir_is_parsed(tmp_path):
    """Default GPOs ship as MACHINE/USER (upper-case). On a case-sensitive host
    the walker must still find them and assign the correct side."""
    base = tmp_path / "{GUID}"
    sched = base / "MACHINE" / "Preferences" / "ScheduledTasks"
    sched.mkdir(parents=True)
    (sched / "ScheduledTasks.xml").write_text(_SCHED_XML, encoding="utf-8")

    gpo = _make_gpo(str(base))
    tasks = scan_scheduled_tasks(gpo)
    assert len(tasks) == 1
    assert tasks[0].side == "Computer"


def test_walk_skips_side_raising_oserror(tmp_path, monkeypatch):
    """Deterministic (root-safe) variant: iterdir raises on the User side."""
    base = tmp_path / "{GUID}"
    _build_tree(base)
    gpo = _make_gpo(str(base))

    real_iterdir = Path.iterdir

    def fake_iterdir(self):
        if self.parent.name == "User":
            raise PermissionError(13, "Permission denied")
        return real_iterdir(self)

    monkeypatch.setattr(Path, "iterdir", fake_iterdir)
    found = [rel.as_posix() for _t, _abs, rel in _walk_gpp_xml(gpo)]
    assert any("Machine/Preferences" in p for p in found)
