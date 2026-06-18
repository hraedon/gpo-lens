---
status: resolved
priority: high
kind: feature
created: 2026-06-17
resolved: 2026-06-17
---

# Dashboard findings table: filtering, search, and sort

Implemented as server-side query params (`?severity=`, `?q=`, `?sort=`) on the
dashboard route, per the recommended option. Sort covers severity (asc/desc),
GPO name, and finding text. Filter state round-trips through pagination links.
Added `_filter_findings` helper + a filter form in `dashboard.html`.

The dashboard findings table renders every finding in a single flat table
with no client-side controls. For a 100+ GPO estate with hundreds of
findings, this is a wall of text with no way to:

- Filter by severity (show only critical/high)
- Search by GPO name or finding text
- Sort columns (by GPO, severity, finding)

## Implementation sketch

Options:
1. **Server-side query params** — `?severity=critical&q=cpassword` on the
   dashboard route. Clean, testable, works without JS. Requires re-fetch
   on each filter change.
2. **Client-side JS** — load all findings as JSON, filter/sort in the
   browser. Instant feedback, no server round-trip. Needs `script-src
   'self'` compliant JS (already the pattern via `upload.js`).
3. **Hybrid** — server-side for initial load, client-side for
   sort/filter within the loaded set.

Recommended: start with server-side query params (simplest, testable,
no CSP concerns), add client-side sort as a progressive enhancement.

## Depends on

Nothing — `estate_doctor()` already returns all findings with severity,
gpo_name, and summary fields.
