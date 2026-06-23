---
status: active
priority: low
kind: enhancement
created: 2026-06-23
---

# CSE filter + in-table search on the Resultant / Effective settings view

## Problem
The OU/Resultant "Effective settings" table can be large (753 rows on one real
OU) and is paginated but not filterable. Now that setting identities are
human-readable (no more hashes), the table is worth scanning — but there is no
way to narrow it to a CSE (Registry / Security / Advanced Audit / …) or
text-search within it.

## Risk
Pure usability. 753 rows over many pages is hard to navigate when you are
looking for a specific setting or CSE family.

## Suggested fix
Add a CSE facet (dropdown of the CSEs present) + a search box to the
resultant/OU-detail settings table, reusing the existing `filter_*`/paginate
helpers. Cheap; the data and helpers already exist. Consider applying the same
filter to the GPO detail page's per-CSE settings sections.

## Context
Filed 2026-06-23 from the post-Conflicts assessment as item #4. Became worth
doing only after the readable-identity work made the table legible.
