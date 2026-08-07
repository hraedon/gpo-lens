"""Scanner functions — pure detection logic that scans an Estate for issues.

Re-export facade: preserves all existing ``from gpo_lens.detection import X``
imports after the split into ``_hygiene``, ``_gpp``, ``_acl``, and ``_admx``
submodules. The ``__all__`` list is the backward-compatible contract; every
name it listed before the split is still listed now, from the same sources.
"""

from __future__ import annotations

from gpo_lens.authz import parse_sddl  # noqa: F401
from gpo_lens.detection._acl import (  # noqa: F401
    _is_default_writer_sid,
    deny_aces,
    excessive_writers,
)
from gpo_lens.detection._admx import AdmxGap as AdmxGap  # noqa: F401
from gpo_lens.detection._admx import _is_raw_registry_path as _is_raw_registry_path  # noqa: F401
from gpo_lens.detection._admx import admx_gaps as admx_gaps  # noqa: F401
from gpo_lens.detection._gpp import (  # noqa: F401
    BrokenRef,
    IltHit,
    LocalGroupMod,
    ScheduledTaskInfo,
    _scan_gpp_xml_for_refs,
    _walk_gpp_xml,
    broken_refs,
    local_group_mods,
    scan_ilt,
    scan_local_groups,
    scan_scheduled_tasks,
    scheduled_tasks,
)
from gpo_lens.detection._hygiene import (  # noqa: F401
    CpasswordHit,
    _scan_gpo_for_cpassword,
    cpassword_scan,
    dangling_links,
    disabled_but_populated,
    empty_gpos,
    enforced_links,
    has_ms16_072_read,
    mask_cpassword,
    ms16_072_vulnerable,
    unlinked_gpos,
    version_skew,
)
from gpo_lens.model import DenyAce, ExcessiveWriter, SddlAce, SddlAcl  # noqa: F401

__all__ = [
    "AdmxGap",
    "BrokenRef",
    "CpasswordHit",
    "DenyAce",
    "ExcessiveWriter",
    "LocalGroupMod",
    "ScheduledTaskInfo",
    "SddlAce",
    "SddlAcl",
    "admx_gaps",
    "broken_refs",
    "cpassword_scan",
    "dangling_links",
    "deny_aces",
    "excessive_writers",
    "has_ms16_072_read",
    "local_group_mods",
    "mask_cpassword",
    "parse_sddl",
    "scan_ilt",
    "scan_local_groups",
    "scan_scheduled_tasks",
    "scheduled_tasks",
    "disabled_but_populated",
    "empty_gpos",
    "enforced_links",
    "ms16_072_vulnerable",
    "unlinked_gpos",
    "version_skew",
]
