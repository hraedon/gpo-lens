---
status: resolved
priority: medium
kind: design
created: 2026-06-19
resolved: 2026-06-22
---

# web/app.py monolith — all routes, middleware, and helpers in one create_app() closure

## Problem

`src/gpo_lens/web/app.py` defined every route handler, middleware function,
audit helper, and utility inside a single `create_app()` closure (1564 lines).
Adding a new page meant scrolling past 1000+ lines of unrelated handlers.

## Resolution

Extracted route handlers into a `web/routes/` package (one file per surface),
shared utilities into `web/_helpers.py`, and made `create_app()` a wiring-only
function (203 lines, down from ~1000+).

**Files created:**
- `web/_helpers.py` — pagination, filtering, CSV/JSON export, sanitization
- `web/routes/__init__.py` — package docstring
- `web/routes/dashboard.py` — home, healthz, api_version
- `web/routes/gpo.py` — gpo_detail, danger_list
- `web/routes/ou.py` — ou_list, ou_detail
- `web/routes/ingest.py` — ingest_get, ingest_post
- `web/routes/ask.py` — ask_get, ask_post
- `web/routes/changelog.py` — changelog
- `web/routes/baseline.py` — baseline_get, baseline_post
- `web/routes/export.py` — export_findings, export_gpo, export_ou
- `web/routes/resultant.py` — resultant_form, resultant_compute

**What stayed in app.py** (because tests patch them on `gpo_lens.web.app`):
- `_safe_extract` + `_MAX_UNCOMPRESSED_BYTES` (tests patch the constant and
  call the function; both must share the same module `__globals__`)
- Audit state (`_audit_logger`, `_audit_log_configured_path`, `_audit_lock`)
  and functions (`_audit`, `_ensure_audit_logger`, `_audit_log_path`)
- `_MAX_UPLOAD_BYTES` (route handlers look it up dynamically via
  `import gpo_lens.web.app as _app_module` at request time)
- `_FileLock`, middleware closures, `create_app()`
