---
status: open
priority: medium
created: 2026-06-17
---

# In-app export of findings and data

The CLI has `gpo-lens report --output report.html` and `--json` output,
but the web UI has no way to download data. An analyst who finds
something in the web UI has to switch to CLI to export.

## Implementation sketch

- **Dashboard**: "Export findings" button → downloads CSV or JSON of
  the current findings table
- **GPO detail**: "Export this GPO" → JSON of the GPO's settings,
  links, delegation, metadata
- **OU detail**: "Export effective settings" → CSV of the settings-at-SOM
  table
- **Baseline diff**: "Export diff" → CSV of the diff entries

Implementation:
- New GET routes: `GET /export/findings?format=csv|json`,
  `GET /export/gpo/{gpo_id}?format=json`, etc.
- Use `StreamingResponse` for CSV to avoid building large strings in
  memory
- Requires VIEW permission (same as the pages themselves)
- No new JS needed — just `<a href="...">` links with `download` attr

## Depends on

Nothing — all data is already computed by existing query functions.
