"""Tests for Registry.pol → Setting augmentation (gap 4).

When a GPO report renders the Registry CSE as ``<Blocked/>``, the
authoritative values live in the binary ``Registry.pol``. These tests cover
``ingest.augment_blocked_registry_from_pol`` which resolves that gap.
"""

from __future__ import annotations

import struct

from gpo_lens.ingest import augment_blocked_registry_from_pol
from gpo_lens.model import Gpo, Setting

_HEADER = b"PReg\x01\x00\x00\x00"  # signature DWORD + version DWORD


def _preg_str(s: str) -> bytes:
    return s.encode("utf-16-le") + b"\x00\x00"


def _preg_record(key: str, value_name: str, type_code: int, data: bytes) -> bytes:
    # Real PReg format: UTF-16LE delimiters; type/size are 4-byte LE DWORDs;
    # data is immediately followed by the closing ']' (no separator).
    return b"".join([
        b"\x5b\x00",                       # '['
        _preg_str(key), b"\x3b\x00",       # key ';'
        _preg_str(value_name), b"\x3b\x00",  # value ';'
        struct.pack("<I", type_code), b"\x3b\x00",  # type ';'
        struct.pack("<I", len(data)), b"\x3b\x00",  # size ';'
        data,
        b"\x5d\x00",                       # ']'
    ])


def _make_gpo(sysvol_path: str | None, *, blocked_sides: tuple[str, ...] = ()) -> Gpo:
    settings: list[Setting] = []
    for side in blocked_sides:
        settings.append(Setting(
            gpo_id="gpo-1", side=side, cse="Registry",
            identity="Registry:blocked", display_name="(blocked extension)",
            display_value="", raw={"blocked": True},
            from_disabled_side=False, source_state="blocked",
        ))
    return Gpo(
        id="gpo-1", name="Blocked GPO", domain="test.local",
        created=None, modified=None, read=None,
        computer_enabled=True, user_enabled=True,
        computer_ver_ds=None, computer_ver_sysvol=None,
        user_ver_ds=None, user_ver_sysvol=None,
        sddl=None, owner=None, filter_data_available=False,
        wmi_filter=None, sysvol_path=sysvol_path,
        settings=settings,
    )


def test_blocked_registry_resolved_from_pol(tmp_path):
    base = tmp_path / "gpo-1"
    machine = base / "Machine"
    machine.mkdir(parents=True)
    pol = _HEADER + _preg_record(
        r"Software\Policies\Acme", "EnableTelemetry", 4, struct.pack("<I", 0),
    ) + _preg_record(
        r"Software\Policies\Acme", "Mode", 1,
        "Strict".encode("utf-16-le") + b"\x00\x00",
    )
    (machine / "Registry.pol").write_bytes(pol)

    gpo = _make_gpo(str(base), blocked_sides=("Computer",))
    augment_blocked_registry_from_pol([gpo])

    # Blocked placeholder removed; two real settings added.
    assert not any(s.source_state == "blocked" for s in gpo.settings)
    resolved = [s for s in gpo.settings if s.source_state == "registry_pol"]
    assert len(resolved) == 2
    ids = {s.identity for s in resolved}
    assert r"Software\Policies\Acme:EnableTelemetry" in ids
    # DWORD value decoded.
    by_id = {s.identity: s for s in resolved}
    assert by_id[r"Software\Policies\Acme:EnableTelemetry"].display_value == "0"
    assert by_id[r"Software\Policies\Acme:Mode"].display_value == "Strict"
    # Side preserved.
    assert all(s.side == "Computer" for s in resolved)


def test_blocked_kept_when_pol_absent(tmp_path):
    """No Registry.pol on disk → blocked placeholder is kept (we cannot resolve)."""
    base = tmp_path / "gpo-2"
    base.mkdir()
    gpo = _make_gpo(str(base), blocked_sides=("Computer",))
    augment_blocked_registry_from_pol([gpo])
    assert any(s.source_state == "blocked" for s in gpo.settings)
    assert not any(s.source_state == "registry_pol" for s in gpo.settings)


def test_no_blocked_extension_is_noop(tmp_path):
    """A GPO whose Registry extension rendered normally is untouched."""
    base = tmp_path / "gpo-3"
    (base / "Machine").mkdir(parents=True)
    (base / "Machine" / "Registry.pol").write_bytes(_HEADER)
    gpo = _make_gpo(str(base))  # no blocked sides
    n_before = len(gpo.settings)
    augment_blocked_registry_from_pol([gpo])
    assert len(gpo.settings) == n_before


def test_no_sysvol_path_is_noop(tmp_path):
    gpo = _make_gpo(None, blocked_sides=("Computer",))
    augment_blocked_registry_from_pol([gpo])
    # Nothing to walk → blocked placeholder untouched.
    assert any(s.source_state == "blocked" for s in gpo.settings)


def test_user_side_blocked_resolved_from_user_pol(tmp_path):
    base = tmp_path / "gpo-4"
    user = base / "User"
    user.mkdir(parents=True)
    pol = _HEADER + _preg_record(
        r"Software\Policies\Acme", "UserSetting", 4, struct.pack("<I", 1),
    )
    (user / "Registry.pol").write_bytes(pol)
    gpo = _make_gpo(str(base), blocked_sides=("User",))
    augment_blocked_registry_from_pol([gpo])
    resolved = [s for s in gpo.settings if s.source_state == "registry_pol"]
    assert len(resolved) == 1
    assert resolved[0].side == "User"


def test_partial_resolution_keeps_unresolved_side(tmp_path):
    """When only one side's .pol exists, the other side's placeholder is kept.

    This is the data-loss regression: previously, resolving ANY side dropped
    ALL blocked placeholders, including unresolved sides.
    """
    base = tmp_path / "gpo-5"
    machine = base / "Machine"
    machine.mkdir(parents=True)
    pol = _HEADER + _preg_record(
        r"Software\Policies\Acme", "Enable", 4, struct.pack("<I", 0),
    )
    (machine / "Registry.pol").write_bytes(pol)

    gpo = _make_gpo(str(base), blocked_sides=("Computer", "User"))
    augment_blocked_registry_from_pol([gpo])

    # Computer side resolved → placeholder removed, real settings added.
    comp_resolved = [
        s for s in gpo.settings
        if s.source_state == "registry_pol" and s.side == "Computer"
    ]
    assert len(comp_resolved) == 1
    # User side NOT resolved → placeholder KEPT.
    user_blocked = [
        s for s in gpo.settings
        if s.source_state == "blocked" and s.side == "User"
    ]
    assert len(user_blocked) == 1
