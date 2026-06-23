---
status: active
priority: medium
kind: feature
created: 2026-06-23
---

# Estate-wide settings search ("which GPOs set X?")

## Problem
The query layer already has `queries.who_sets(estate, term)` and
`queries.search(estate, term, scope)` — full-text over settings, GPO names, and
delegation — but they are **CLI-only**. The web UI can only reach settings by
drilling into a specific GPO or OU. There is no "find every GPO that sets this
registry key / this CSE / this value" view.

## Risk
Not a defect, a capability gap: the tool is strong per-GPO and per-OU but thin
on cross-cutting estate-wide lookups (the same gap the Conflicts view just
closed for one question). An admin asking "who sets MaxTokenSize?" has to grep
the CLI or open GPOs one by one.

## Suggested fix
A `/search` route + template backed by `queries.search` (or a settings-scoped
variant), with the now-readable `identity` as the primary match field, results
grouped by GPO with deep-links, CSE/side facets, and the existing
filter/paginate helpers. Add to primary nav. Mirrors the Inventory/Conflicts
route shape.

## Context
Filed 2026-06-23 from the post-Conflicts assessment as item #2 of the
estate-wide-views direction. Lower-effort than Conflicts (logic exists, no
rollup needed) — mostly wiring `who_sets`/`search` to a template.
