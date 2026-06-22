---
status: open
priority: medium
kind: design
created: 2026-06-19
---

# web/app.py is 1483 lines — all routes, middleware, and helpers in one create_app() closure

## Problem

`src/gpo_lens/web/app.py` defines every route handler, middleware function,
audit helper, and utility inside a single `create_app()` closure. Adding a new
page means scrolling past 1000+ lines of unrelated handlers. The audit logging
helpers (`_audit`, `_ensure_audit_logger`) are module-level but the routes that
use them are closure-scoped, creating an awkward split.

The file also mixes concerns: CSV/JSON export helpers, pagination logic, CSRF
validation, security headers, and the audit logger all live alongside route
handlers.

## Risk

Low today (the web UI is stable and feature-complete for current scope). Becomes
real if more views are added — every new handler increases the cognitive load of
the single file and raises the chance of merge conflicts in multi-contributor
scenarios.

## Suggested fix

Extract route handlers into a `web/routes/` package (one file per surface:
`dashboard.py`, `gpo.py`, `ou.py`, `ingest.py`, `ask.py`, `changelog.py`,
`baseline.py`, `export.py`, `resultant.py`). Register them via
`app.include_router()` or by passing `app` to each module's `register()`.

Shared utilities (pagination, CSV response, JSON attachment, CSRF, audit logger)
move to `web/_helpers.py`. The `create_app()` function becomes a wiring-only
function (~50 lines).
