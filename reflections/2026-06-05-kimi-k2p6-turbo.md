---
model: accounts/fireworks/routers/kimi-k2p6-turbo
datetime: 2026-06-05T00:00Z
project: gpo-lens
---

# Session Reflection — 2026-06-05

**Work summary:** Implemented three security/hygiene queries (version-skew, MS16-072 delegation audit, cpassword scan) and wired them into the CLI. Added 18 new unit tests and 5 calibration tests. Fixed two latent bugs: the `ingest.py` parser couldn't handle the newer `TrusteePermissions` nested XML structure (was silently producing empty delegation lists), and the `store.py` `som_link` PK was missing the `target` column causing duplicate-key errors on ingest for the work domain. MS16-072 query logic was initially wrong — required both `Read` and `Apply Group Policy` when Microsoft guidance says only `Read` matters. Fixed after user correction.

---

## On the project

The architecture is solid. The spec-driven approach (AC-01, AC-02, etc.) makes it clear what each module must do. The separation of ingest (pure parsers), queries (pure functions), and store (SQLite round-trip) is clean. The model is already carrying enough fields for later tiers without reshaping.

One concern: the calibration tests are the real acceptance bar, but they depend on sample data that isn't in the repo. When the samples are absent, the test suite runs but only tests trivial cases. The parser XML bug I found would never have been caught by unit tests alone — it only surfaced when running against the real `WORK-DOMAIN.local` export.

## On the work done

The three queries were straightforward to implement. The `cpassword` scan walking SYSVOL GPP XML is the most involved — it handles 16 GPP file types and skips broken XML gracefully. The `ms16_072` query was the trickiest because the correct logic depends on understanding Microsoft guidance (only `Read` matters, not `Apply Group Policy`). I initially got this wrong and the user corrected me.

I'm confident in the final query logic. The ingest parser fix for delegation is also correct — I verified by inspecting the actual XML structure in the sample exports.

## On what remains

Next natural steps (in dependency order):

1. **Tier 2.5 — Topology queries**: Resolve "all settings effective at OU X" and "settings overridden in the inheritance chain" using already-ingested `Som` + `SomLink` data. This is the biggest remaining gap in the deterministic core.
2. **Tier 2 — Baseline diff**: Diff against a Microsoft Security Baseline. Needs a new ingest path for baseline GPO backups and a crosswalk (registry path → ADMX policy name → CIS recommendation). Large.
3. **Broken-reference / orphan inventory**: SYSVOL file scans for dead UNC paths, dead OU links, etc. Can build on the existing `sysvol_path` field.
4. **Web frontend**: Charter mentions this, but it's deferred until core + store exist. We're not there yet.

## Gaps to flag

- `tests/test_calibration.py` line 105-108: MS16-072 work calibration asserts `== 112` flagged GPOs. This is a hardcoded number from the current export. If the work domain's permissions change, this test will break. Consider relaxing to a range or just asserting `> 0`.
- `src/gpo_lens/ingest.py` line 197-237: The delegation parser now handles both `TrusteePermissions` (new) and `Permission` (old) XML structures. The old structure is not tested — no sample data uses it. If someone has an older export, this path is untested.
- `src/gpo_lens/queries.py` line 142-147: MS16-072 query only checks `Read` permission. This is correct per Microsoft guidance, but the user noted that computers *are* getting policies in the lab domain despite the flag. The query is about SYSVOL read access, not about whether the GPO is applied. This semantic gap might confuse users — the CLI output should probably explain this.
- `src/gpo_lens/store.py` line 120: The `som_link` PK now includes `target`. This was a schema fix. Existing databases created before this change will need to be rebuilt (or the schema won't match). This is acceptable for a pre-1.0 tool, but worth noting.
- `tests/test_queries.py`: No tests for the `TrusteePermissions` XML path in the unit tests. The unit tests only test the query logic, not the parser. A parser-specific unit test with a synthetic XML snippet would be valuable.
