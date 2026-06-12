"""Centralized query dispatch for CLI and web ask commands."""

from __future__ import annotations

from typing import Any, Callable

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
}

QUERY_REQUIRED_PARAMS: dict[str, list[str]] = {
    "settings_at_som": ["ou_path"],
}

VALID_QUERIES: frozenset[str] = frozenset(_QUERY_DISPATCH.keys())


def dispatch_query(name: str, **kwargs: Any) -> Any:
    """Dispatch a named query with the given kwargs. Raises KeyError if name unknown."""
    return _QUERY_DISPATCH[name](**kwargs)
