---
status: closed
priority: medium
created: 2026-06-09
---

# Estate Documentation Export

The `summary` command gives a one-screen overview.  What's missing is a
self-contained report suitable for handing to a manager, auditor, or
compliance team.

## Markdown report
Auto-generated markdown with:
- Executive summary (GPO count, SOM count, top-N hygiene findings)
- Per-OU section: effective settings, which GPO won, what's overridden
- Per-GPO section: settings list, links, delegation, version status
- Hygiene findings from `estate_doctor`
- Baseline compliance summary (if baseline loaded)

## HTML report
Same content as markdown but rendered as a standalone HTML file with
inline CSS (no external dependencies).  Suitable for emailing or archiving.

## Implementation sketch
- New `report.py` module with `generate_markdown(estate) -> str`
- `generate_html(estate) -> str` wraps markdown in HTML template
- CLI: `gpo-lens report [src] [--format md|html] [--output FILE]`
- Reuses existing query functions: `estate_summary`, `estate_doctor`,
  `settings_at_som`, `som_effective_gpos`, `precedence_conflicts`

## Depends on
Nothing — all data is already computed by existing queries.

## Resolution (2026-06-10)
Implemented in `src/gpo_lens/report.py`:
- `generate_markdown(estate)` and `generate_html(estate)` as public API
- `generate_report()` dispatcher and `write_report()` file writer
- Per-GPO sections with settings (capped at 50), links, delegation, version/skew status
- Precedence conflicts section via `queries.precedence_conflicts()`
- Executive summary with top-10 findings
- HTML uses `html.escape()` for XSS safety, inline CSS, print media queries
- CLI: `gpo-lens report [src] [--format md|html] [--output FILE]` (stdout if no --output)
- 27 tests in `tests/test_report.py` covering markdown, HTML, CLI integration, escaping
