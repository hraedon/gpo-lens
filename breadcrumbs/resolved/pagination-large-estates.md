---
status: resolved
priority: medium
kind: feature
created: 2026-06-17
resolved: 2026-06-17
---

# Pagination for large estates

Implemented server-side pagination (`?page=&per_page=`, default 50, capped at
200, `?per_page=all` to disable) on the dashboard findings table, OU list, and
OU effective-settings table via `_parse_pagination`/`_paginate` helpers and the
`_pagination.html` macro. GPO-detail pagination was deliberately deferred as
low-value (a single GPO rarely has enough settings to warrant it, and CSE
grouping is valuable navigation that pagination would disrupt).

Several pages render every row with no pagination:

- **Dashboard findings table** — hundreds of findings on a large estate
- **OU effective settings table** — dozens of settings per OU
- **Directory (OU list)** — 1000+ SOMs on a large estate
- **GPO detail settings tables** — hundreds of settings per GPO side

All are server-side rendered with no limit. Long pages are slow to
render, slow to scroll, and hard to navigate.

## Implementation sketch

- Add a `?page=N&per_page=M` query param to routes that render large
  tables (dashboard, ou_detail, ou_list, gpo_detail)
- Slice the result set in the route handler before passing to the
  template
- Add pagination controls (prev/next, page numbers) to the template
- Default per_page=50, capped at 200
- Keep the full set available via `?per_page=all` for Ctrl-F users

## Depends on

Nothing — all data is already computed; this is a presentation concern.
