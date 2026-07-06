"""Shared test helpers for the gpo-lens test suite."""

from __future__ import annotations

from gpo_lens.model import Gpo


def _make_gpo(**kwargs) -> Gpo:
    defaults = {
        "id": "31b2f340016d11d2945f00c04fb984f9",
        "name": "Test GPO",
        "domain": "test.local",
        "created": None,
        "modified": None,
        "read": None,
        "computer_enabled": True,
        "user_enabled": True,
        "computer_ver_ds": None,
        "computer_ver_sysvol": None,
        "user_ver_ds": None,
        "user_ver_sysvol": None,
        "sddl": None,
        "owner": None,
        "filter_data_available": False,
        "wmi_filter": None,
        "sysvol_path": None,
    }
    defaults.update(kwargs)
    return Gpo(**defaults)
