---
status: resolved
priority: medium
kind: defect
created: 2026-06-17
resolved: 2026-06-17
---

# GPO detail page omits per-GPO scope caveats

## Problem
The web GPO detail route (`/gpo/{gpo_id}` in `src/gpo_lens/web/app.py`) shows a
GPO's settings, links, and delegation but does **not** surface the per-GPO
scoping caveats that `queries.effective_scope(estate, gpo_id)` produces
(security filtering, WMI, loopback, ILT). This is the same "flag, don't
simulate" charter gap that was just fixed on the OU detail page (H2) and in the
report (H1) — the GPO detail page is the remaining view of the same class.

## Risk
A web user reading a single GPO's detail page sees its settings without the
scoping caveats, implying the settings apply unconditionally when scoping
mechanisms may narrow or block them. Inconsistent with the now-caveated OU
detail page and report.

## Suggested fix
Mirror the H2 fix: in the GPO detail route, call
`queries.effective_scope(estate, gpo_id)` (it returns caveats as part of its
result), pass them to the `gpo_detail.html` template, and render the same
"Scope caveats — flagged, not simulated" callout used on `ou_detail.html`.
Reuse the existing `.banner.warning.scope-caveats` style. Add a focused web
test asserting the callout renders for a caveat-bearing GPO in the fixture.

## Context
Surfaced during the 2026-06-17 web-caveats work (H2 agent report). Filed
instead of fixed inline because the session was wrapping up; it is a small,
isolated change (~route + template + one test).
