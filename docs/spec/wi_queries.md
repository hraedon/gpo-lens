# Work Item: Queries (Tier-1 deterministic analysis)

## Dependencies

- `interface_ref`: `model`

## Notes

Pure functions over an `Estate` (or equivalently a loaded snapshot). No I/O, no
AI. Each returns plain dataclasses/tuples suitable for CLI rendering and, later,
JSON/web. Module: `src/gpo_lens/queries.py`.

The calibration numbers in `tests/` (measured from the real exports) are the
acceptance bar — e.g. the work export has 8 disabled-but-populated sides.

---

## AC-01: Unlinked GPOs
`unlinked_gpos(estate) -> list[Gpo]` — GPOs with no `links`. These apply nowhere.

## AC-02: Empty GPOs
`empty_gpos(estate) -> list[Gpo]` — GPOs with no `settings` on either side.
(Define "empty" as zero parsed settings; a GPO with only `<Blocked/>` extensions
and no readable settings counts as empty but is also reported by AC-05.)

## AC-03: Disabled-but-populated
`disabled_but_populated(estate) -> list[tuple[Gpo, Side]]` — each (GPO, side)
where that side's `*_enabled` is False but it has ≥1 setting with
`from_disabled_side=True`. Work export must yield 8 such (GPO, side) pairs.

## AC-04: Who sets X
`who_sets(estate, term: str) -> list[Setting]` — settings whose `display_name`,
`identity`, or `display_value` contains `term` (case-insensitive substring).
Results carry their `gpo_id` so the caller can name the GPO.

## AC-05: Conflict surface
`conflicts(estate) -> list[Conflict]` where `Conflict` groups settings sharing
`(cse, side, identity)` across **two or more distinct GPOs** with **two or more
distinct `display_value`s**. Each `Conflict` lists the contributing
`(gpo_id, display_value)` pairs. This is the cross-estate conflict surface; it
makes no precedence/winner claim (that needs the topology layer, Tier 2.5).
Strongest for structured CSEs (`Security`); best-effort elsewhere, consistent
with the identity rules in `wi_ingest` AC-06.

## AC-06: Blocked extensions (hygiene)
`blocked_extensions(estate) -> list[tuple[Gpo, Side, str]]` — (GPO, side, cse)
where an extension was `<Blocked/>` / unreadable. Surfaces report-generation gaps
rather than asserting the GPO is empty.
