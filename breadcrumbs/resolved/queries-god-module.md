---
status: resolved
priority: medium
kind: design
created: 2026-06-19
resolved: 2026-06-22
---

# queries.py is a god module — re-export facade + composition logic in one file

## Problem

`src/gpo_lens/queries.py` (1093 lines, 70+ `__all__` names) serves two roles:

1. **Re-export facade** — it re-exports from `detection`, `topology`,
   `snapshot_diff`, and `danger` so callers can `from gpo_lens.queries import X`
   for anything.
2. **Composition logic** — it contains its own query functions: `search`,
   `conflicts`, `baseline_diff`, `estate_doctor`, `estate_summary`,
   `settings_dump`, `settings_diff`, `delegation_deep_dive`, `permissions_audit`,
   `topology_crosscheck`, `stale_gpos`, `broken_wmi_refs`, `orphaned_wmi_filters`,
   etc.

This creates a single file where "adding a query" means touching `__all__`, a
function body, and the re-export block. Import ownership is unclear: is
`conflicts` a detection thing or a queries thing? Both, depending on which line
you read.

## Risk

Medium. The file is manageable today but grows with every new query. The
re-export pattern means every module in the project transitively depends on
`queries.py`, making import cycles a constant risk (avoided only via
`TYPE_CHECKING` guards). Adding a new top-level query requires editing 3+ spots
in the same file.

## Suggested fix

Split into two concerns:

- **`queries/__init__.py`** (or a thin module): re-exports from `detection`,
  `topology`, `snapshot_diff`, `danger`. This is the backward-compatible import
  surface.
- **`queries/_compose.py`** (or similar): the composition functions that combine
  multiple scanners (estate_doctor, estate_summary, baseline_diff, search, etc.).

Callers that import from `gpo_lens.queries` continue to work unchanged. New code
can import directly from the real modules when it doesn't need the facade.

## Resolution (2026-06-22)

Split `queries.py` → `queries/` package. `__init__.py` is the re-export
facade (backward-compatible `__all__` preserved exactly); composition logic
moved into 8 thematic submodules: `_search`, `_delegation`, `_topology`,
`_wmi`, `_settings`, `_baseline`, `_summary`, `_doctor`. Generalized
`tests/_arch.py` (`module_source_path` → `module_source_paths`) so the
import-boundary AST walk covers every `.py` in a package, not just
`__init__.py`. Adversarial review: no critical findings; behavior
preservation, DAG, and boundary enforcement all pass. 1352 tests green,
86.79% coverage. AGENTS.md module map updated.
