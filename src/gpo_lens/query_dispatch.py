"""Centralized query dispatch for CLI and web ask commands."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from gpo_lens import merge as _merge
from gpo_lens import queries

_QUERY_DISPATCH: dict[str, Callable[..., Any]] = {
    "estate_summary": lambda **kw: queries.estate_summary(kw["estate"]),
    "estate_doctor": lambda **kw: queries.estate_doctor(kw["estate"]),
    "cpassword_scan": lambda **kw: queries.cpassword_scan(kw["estate"]),
    "unlinked_gpos": lambda **kw: queries.unlinked_gpos(kw["estate"]),
    "empty_gpos": lambda **kw: queries.empty_gpos(kw["estate"]),
    "version_skew": lambda **kw: queries.version_skew(kw["estate"]),
    "broken_refs": lambda **kw: queries.broken_refs(kw["estate"]),
    "enforced_links": lambda **kw: queries.enforced_links(kw["estate"]),
    "dangling_links": lambda **kw: queries.dangling_links(kw["estate"]),
    "ms16_072_vulnerable": lambda **kw: queries.ms16_072_vulnerable(kw["estate"]),
    "topology_crosscheck": lambda **kw: queries.topology_crosscheck(kw["estate"]),
    "disabled_but_populated": lambda **kw: queries.disabled_but_populated(kw["estate"]),
    "settings_at_som": lambda **kw: queries.settings_at_som(kw["estate"], kw["ou_path"]),
    "effective_scope": lambda **kw: queries.effective_scope(kw["estate"], kw["gpo_id"]),
    "orphaned_wmi_filters": lambda **kw: queries.orphaned_wmi_filters(kw["estate"]),
    "broken_wmi_refs": lambda **kw: queries.broken_wmi_refs(kw["estate"]),
    "stale_gpos": lambda **kw: queries.stale_gpos(kw["estate"]),
    "danger_findings": lambda **kw: queries.danger_findings(kw["estate"]),
    "principal_resultant": lambda **kw: _merge.principal_resultant(
        kw["estate"],
        kw["principal_sid"],
        computer_sid=kw.get("computer_sid") or None,
        dn=kw.get("dn") or None,
        computer_dn=kw.get("computer_dn") or None,
    ),
}

_QUERY_DESCRIPTIONS: dict[str, str] = {
    "estate_summary": "Overview of the estate (GPO count, domain, SOM count, etc.)",
    "estate_doctor": (
        "Health and hygiene findings across GPOs "
        "(cpassword, version skew, broken refs, etc.)"
    ),
    "cpassword_scan": "GPOs containing encrypted cpassword values",
    "unlinked_gpos": "GPOs that are not linked to any SOM",
    "empty_gpos": "GPOs that contain no settings",
    "version_skew": "GPOs where Active Directory and SYSVOL versions differ",
    "broken_refs": "GPOs with broken references (UNC paths, missing scripts, etc.)",
    "enforced_links": "GPO links that are enforced (NoOverride)",
    "dangling_links": "Links that point to GPOs which no longer exist",
    "ms16_072_vulnerable": "GPOs vulnerable to MS16-072 (missing Authenticated Users Read)",
    "topology_crosscheck": "Discrepancies between OU tree and SOM inheritance data",
    "disabled_but_populated": "GPO sides that are disabled but still contain settings",
    "settings_at_som": "Effective settings applied to a specific SOM (Scope of Management) path",
    "effective_scope": (
        "Effective scoping for a single GPO: links, security filtering, "
        "WMI filter, loopback (requires param: \"gpo_id\")"
    ),
    "orphaned_wmi_filters": "WMI filters defined but not referenced by any GPO",
    "broken_wmi_refs": "GPOs referencing a WMI filter that does not exist in the estate",
    "stale_gpos": "GPOs that are linked but have not been modified in over 2 years",
    "danger_findings": (
        "Curated, cited dangerous-configuration findings "
        "(GPO hijack paths, local-admin push, over-broad scope, dangerous values)"
    ),
    "principal_resultant": (
        "Principal resultant (RSoP) — effective policy for a given principal SID "
        "from the static snapshot (requires param: \"principal_sid\")"
    ),
}

QUERY_REQUIRED_PARAMS: dict[str, list[str]] = {
    "settings_at_som": ["ou_path"],
    "effective_scope": ["gpo_id"],
    "principal_resultant": ["principal_sid"],
}

# Optional params that a query accepts but does not require.  ``validate_params``
# passes these through (when present) so callers like the REST API can forward
# them without needing to know each query's signature individually.
QUERY_OPTIONAL_PARAMS: dict[str, list[str]] = {
    "principal_resultant": ["computer_sid", "dn", "computer_dn"],
}

_PARAM_VALIDATORS: dict[str, dict[str, type]] = {
    "settings_at_som": {"ou_path": str},
    "effective_scope": {"gpo_id": str},
    "principal_resultant": {
        "principal_sid": str,
        "computer_sid": str,
        "dn": str,
        "computer_dn": str,
    },
}


def validate_params(query_name: str, params: dict[str, object]) -> dict[str, object]:
    """Validate and filter params for a query. Raises ValueError on type mismatch."""
    if query_name not in _QUERY_DISPATCH:
        raise ValueError(f"Unknown query: {query_name}")
    required = set(QUERY_REQUIRED_PARAMS.get(query_name, []))
    optional = set(QUERY_OPTIONAL_PARAMS.get(query_name, []))
    expected = {"estate", *required, *optional}
    schema = _PARAM_VALIDATORS.get(query_name, {})
    validated: dict[str, object] = {}
    for key, value in params.items():
        if key == "estate":
            validated[key] = value
            continue
        if key not in expected:
            continue
        expected_type = schema.get(key)
        if expected_type and not isinstance(value, expected_type):
            raise ValueError(
                f"Parameter '{key}' must be {expected_type.__name__}, "
                f"got {type(value).__name__}"
            )
        validated[key] = value
    missing = required - set(validated.keys())
    if missing:
        raise ValueError(
            f"Query '{query_name}' requires parameter '{missing.pop()}'"
        )
    return validated


VALID_QUERIES: frozenset[str] = frozenset(_QUERY_DISPATCH.keys())


def dispatch_query(name: str, **kwargs: Any) -> Any:
    """Dispatch a named query with the given kwargs. Raises KeyError if name unknown."""
    return _QUERY_DISPATCH[name](**kwargs)
