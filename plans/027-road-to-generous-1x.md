# Plan 027 — Road to the generous 1.0: land, harden, complete, deploy

**Status:** In progress. Proposed 2026-07-14; status reconciled with `main`
2026-08-07.

| Phase | State |
|---|---|
| Phase 0 — land the findings program | **Done.** Merged; v1.0.0 → v1.1.0. |
| Phase 1 — pay the sharp Plan 024 debt | **Done** bar one doc residual (WI-1.5). Landed as `34f890b`; tagged v1.1.0. |
| Phase 2 — execute Plan 025 | **In progress.** WI-1/2/3 merged 2026-08-07; WI-4/5/6 open. |
| Phase 3 — operational generosity + docs | **Not started.** WI-086 unbegun: `deploy/` still contains only `iis`. |

**Depends on:** Plans 023 and 024 — both **merged to `main`** (023 via PR #1 on
the pre-republish remote, 024 as `b21b30d`). Plan 025 is **partially shipped**
(WI-1/2/3 in; WI-4/5/6 remaining, and they are the bulk of what is left).
Plan 026 remains explicitly deferred by this plan.

**Strategic role:** v1.0.0 shipped 2026-07-06 and is load-bearing at work, but
the version number outran the product vision: the web reimagining program
(023/024/025) turns gpo-lens from "a set of analysis pages" into "a tool that
answers the operator's four questions". This plan is the orchestration layer —
it sequences the already-reviewed plans into a deployable path and defines the
finish line, after which gpo-lens is *maintained*, not *driven*.

> **On reading this document.** Until 2026-08-07 the text above still said the
> program was "roughly one-third landed and none of it is on `main`", which had
> been false since Phase 0 merged. A plan that misreports its own state is worse
> than no plan: it is the map people orient from. When a phase lands, edit this
> header in the same change.

## Definition of done ("generous 1.0")

The milestone is complete when all of the following hold:

1. Everything currently on `plan/023-web-reimagining` is merged, CI-validated,
   and running at work.
2. The known-sharp Plan 024 debt (prose fingerprints, post-LIMIT filtering) is
   paid — these are correctness issues, not polish.
3. Plan 025 is shipped: Briefing / Findings / Explore / History / Tools IA,
   snapshot axis, omnisearch, dossier + setting page, narration demoted,
   deterministic exports — deployed to work with old bookmarks intact.
4. A non-IIS deployment path exists (WI-086), so the tool is generous to
   operators who don't run Windows infrastructure.
5. Docs describe the product that exists (README, deploy guides, CHANGELOG).

Explicitly **out**: Plan 026 (all phases — it is a two-product program paced
by gpo-studio's own roadmap; at most, its Phase 0 contract freeze may run in
parallel when gpo-studio needs it), WI-059 multi-estate comparison, and any
new analysis engines. "Generous" means finishing what's designed, not
designing more.

---

## Phase 0 — Land the findings program (branch → main) — **DONE**

*Completed. The branch merged, CI ran green including the identifier gate, and
the release went out as v1.1.0. The description below is kept as the record of
what the phase was for; its WIs are closed.*

The branch holds 7 commits / ~7,100 insertions (settings ledger, GPO-vs-GPO
compare, findings lifecycle v0.1, the full Plan 024 v2 engine, least-priv
triage, lifecycle-backed inbox) and has **never run in CI** — the workflow
only triggers on `main` pushes and PRs. Local state verified 2026-07-14:
pytest green (exit 0, ~2,500 tests), ruff clean, mypy strict clean.

- **WI-0.1 — Reconcile WI state with reality.** WI-091 (CLI ingest wiring) and
  WI-090 (inbox reads from `finding` table) are code-complete on the branch —
  verify each against its breadcrumb acceptance line and close. WI-087
  (PENDING-REGISTA-WI drain) appears done (file gone) — close after review.
- **WI-0.2 — Adversarial review of the in_review queue** (WI-080, WI-082,
  WI-083) per the standing workflow. These shipped in v1.0.0; the review is
  overdue bookkeeping, not a merge blocker.
- **WI-0.3 — Open the PR.** First CI run for this work, including the
  **identifier gate** — the gate that caught the last leak ran only on `main`
  pushes, so 7k lines of agent-written code have never been scanned by it
  (the local pre-commit hook is the only line of defense so far). Treat a
  gate failure here as a stop-everything event given this repo's history.
  *Local pre-verification 2026-07-14: the gate passed against the branch
  tree with the real denylist, and a denylist sweep of all seven branch
  commit messages plus full patch content found zero hits. CI remains the
  authoritative check, but no leak is expected.*
- **WI-0.4 — Merged-whole code review** (`/code-review` on the PR). Plan 024
  got two adversarial rounds in isolation; the merged branch as a unit has
  not been reviewed.
- **WI-0.5 — Merge; push the straggler.** Local `main` carries one unpushed
  commit (80d8974, a reflection) — push it with or before the merge.

**AC:** branch merged to main, CI green including identifier gate and 85%
coverage gate; WI-087/090/091 closed; WI-080/082/083 reviewed.

## Phase 1 — Pay the sharp Plan 024 debt → v1.1.0 — **DONE** (one doc residual)

*Landed as `34f890b` ("Plan 027 Phase 1 — typed identity, complete filters,
indexes") and tagged v1.1.0. Per-item state is marked inline below. Both
correctness bugs are paid; the only thing outstanding is one line of
documentation in WI-1.5.*

All items below are documented in the 2026-07-12 and 2026-07-14 reflections;
two are correctness bugs waiting for the right input.

- **WI-1.1 — DONE. Structured detector dimensions.** The candidate adapter derives
  identity dimensions by parsing prose (`summary.split()[0]`,
  `findings.py:~1413`). Any wording change churns finding identity — falsely
  resolving real findings and minting "new" ones. This is the exact failure
  class WI-089 fixed, one layer down. Detectors emit typed dimension fields;
  the adapter stops reading prose. Property test: fingerprints invariant
  under summary/detail rewording.
  *Done: dimensions are declared typed fields; `test_doctor_fingerprint_
  invariant_under_rewording` and its danger twin hold the property. A related
  gap in `subject_key` — not `dimensions` — was closed separately on
  2026-08-07; see WI-1.5.*
- **WI-1.2 — DONE. Push `claim_level`/`triage_status` filters into SQL.**
  `finding_inbox` applies `LIMIT` before Python-side filtering — a filtered
  page on a large estate can silently truncate results. Correctness, not
  performance.
  *Done: `_inbox_predicate` builds one `WHERE` shared by `finding_inbox` and
  `finding_inbox_count`, so a page and its total cannot disagree about what
  "matching" means. Every filter lands in SQL; `LIMIT`/`OFFSET` now bound the
  matching set rather than a pre-filter superset.*
- **WI-1.3 — DONE. Indexes + N+1.** Indexes on `first_seen_run_id`,
  `last_seen_run_id`, `resolved_run_id`, `series_key`; batch
  `load_triage_status_map` (currently one query per occurrence).
  *Done: all four indexes exist (`idx_finding_first_seen_run`,
  `idx_finding_last_seen_run`, `idx_finding_resolved_run`,
  `idx_finding_series_key`); `load_triage_status_map` folds the whole event log
  in one query.*
- **WI-1.4 — DONE. Legacy Plan 023 rows: decide and enforce.** Rows predating the
  v2 engine have NULL run IDs and no observations. Either migrate them
  (exact provenance only — never synthesize) or explicitly exclude them from
  v2 queries with a visible "pre-lifecycle finding" marker. Mixed-mode
  ambiguity is the enemy; pick one and test it.
  *Decided: **exclude**. `_inbox_predicate` admits only rows carrying
  evaluation-run provenance. Every deployed ingest path runs the v2 engine, and
  the Plan 023 writer is now test-only (`_legacy_findings`), so no deployed
  store holds provenance-less rows.*
- **WI-1.5 — Small knives:** `detail` column stores `summary` (give
  `FindingCandidate` a real `detail` or drop the column write);
  `snapshot_scoped` OccurrenceState is modeled but never produced (produce it
  for lifecycle-less rules per Plan 023's risk note, or delete the state);
  inline `hashlib` import; document the single-estate-per-store assumption
  (2026-07-12 reflection, last gap).
  *Done: `FindingCandidate.detail` is real and the column stores it, falling
  back to the summary only when a detector supplies none; the inline `hashlib`
  import is gone; `snapshot_scoped` is now **produced** — the adapter marks a
  GPO-less finding that declares no `subject_key` as `subject_stable=False`
  (persisted, schema v9) and the inbox reports it as `snapshot_scoped` rather
  than letting a prose-keyed identity churn silently. `test_doctor_contract.py`
  fails if a new GPO-less detector omits its `subject_key`.*
  **RESIDUAL — the single-estate-per-store assumption is still undocumented.**
  A store holds exactly one estate; nothing in `README`, `AGENTS.md`, or
  `docs/spec/wi_store.md` says so, and `docs/design/multi-domain-forest.md`
  describes only the *future* WI-059 shape. This is the last open Phase 1 item.
- **WI-1.6 — DONE. Tag v1.1.0. Deploy lab IIS → soak → work.** Real-estate exposure
  has caught what fixtures missed three separate times in this repo; the
  deploy gate is part of the phase, not an afterthought. Watch the ingest
  lifecycle block specifically — it is try/except-logged, so a silent
  failure never surfaces in tests (drive the e2e findings flow post-deploy).

**AC:** rewording property test green; filtered inbox provably complete
(fixture with >LIMIT findings); v1.1.0 at work with findings flow verified
end-to-end against the real estate.

## Phase 2 — Execute Plan 025 (the reimagining completion) → v1.2.x — **IN PROGRESS**

*Steps 1–3 merged 2026-08-07. Steps 4–6 are open and are the bulk of the
remaining work on this plan. Sequencing gate 3 still holds: primary navigation
is untouched until step 4, so the new destinations exist but nothing has been
taken away yet.*

Plan 025 already carries the design detail and acceptance criteria; this
phase just binds its sequence to deployment checkpoints and slots in the
Plan 023 primitives that Plan 025 assumes but which don't exist yet.

Order (per Plan 025 §10, with the missing primitives made explicit):

1. **DONE — Findings inbox + occurrence view on the v2 core queries** (025 WI-1) —
   the current inbox reads the `finding` table directly; move it onto
   `finding_inbox`/`finding_history`/`accepted_risk_register`.
2. **DONE — Briefing home** (025 WI-2) — golden-tested deterministic prose deltas.
3. **PARTIAL — Explore primitives** (under 025 WI-3, originally 023 WI-2/3/7/8):
   dossier completion (verdict strip, scope & control panel, history tab —
   the ledger and GPO-vs-GPO compare already exist), setting-centric page,
   global snapshot axis ("as of snapshot N" everywhere), omnisearch.
   *Checkpoint: deploy — dossier usable, nothing removed.*
   *`/explore` and the Tools directory shipped. The "primary pages link to
   filtered workbenches" half is deliberately deferred: category→workbench deep
   links ride with step 4's route inventory.*
4. **OPEN — Staged nav migration + route inventory + redirects** (025 WI-4) — work
   bookmarks must not break; 302 first, permanent only after observation.
   *Checkpoint: deploy — Briefing becomes home, old nav still present; then
   the reversible nav switch at work.*
5. **OPEN — Narration demotion** (025 WI-5) — `/ask` to Tools; "explain these
   facts" actions fed only the page's deterministic payload.
6. **OPEN — Deterministic exports** (025 WI-6) — Markdown/CSV, provenance-bearing,
   golden-tested; shares the redaction fixture corpus.

Version tags at each deployment checkpoint (v1.2.0, v1.2.x). Each checkpoint:
lab IIS first, then work, with the reversibility Plan 025 §10 requires.

**AC:** Plan 025 §12 checklist complete; every pre-025 URL reaches equivalent
information (route-inventory test); work deployment on the new IA with the
rollback flag exercised at least once in lab.

## Phase 3 — Operational generosity + docs → the milestone tag — **NOT STARTED**

*Nothing here has begun. `deploy/` contains only `iis`, so criterion 4 of the
definition of done is unmet. See `plans/028-module-decomposition.md`, which
scopes WI-3.1 alongside the source-file decomposition it shares a release with.*

- **WI-3.1 — WI-086: Docker/systemd deployment option.** Container image +
  compose example + systemd unit; same loopback-XOR-token auth model with the
  reverse-proxy guidance translated from the IIS README (the
  `proxy_headers=False` + scheme-only forwarding lesson generalizes). No new
  auth machinery — document the boundary honestly like the IIS docs do.
- **WI-3.2 — Docs pass.** README feature tour matches the shipped IA;
  deploy READMEs (IIS + new non-IIS); CHANGELOG consolidated; plan statuses
  updated (022 marked done/superseded, 023/024/025 marked shipped; 013/015/016
  statuses reconciled with what actually shipped — 016's Splunk attribution
  is in `src/` but the plan still says "proposed").
- **WI-3.3 — Close the loop.** WI-085 closed (xdist landed; the "CI times
  out at 120s" lore is dead), WI-059 re-confirmed post-1.0, final adversarial
  review sweep of anything in_review, tag the milestone release, update the
  work deployment.

**AC:** a new operator can deploy without IIS from docs alone; no plan file
claims "proposed" for shipped work; zero open non-deferred WIs.

---

## Sequencing rationale and risks

- **Phase 0 before anything:** unmerged work rots, and the identifier gate
  has a blind spot exactly where this repo has been burned twice.
- **Phase 1 before Plan 025:** the inbox becomes the primary destination in
  Phase 2 — building it on prose-keyed fingerprints and truncating filters
  would ship a lying inbox to a posture tool's home page. Plan 024's own AC
  ("core queries complete before Plan 025 makes the inbox primary") says the
  same.
- **Deployment pin — DISCHARGED.** The work instance was to stay on **v1.0.0
  until v1.1.0**, because the Phase 0 merge put two known correctness bugs
  (WI-1.1 prose-keyed fingerprints, WI-1.2 post-LIMIT filter truncation) onto
  `main`. Both are fixed and v1.1.0 is tagged, so the pin no longer binds and
  `main` is deployable again.
- **Fingerprint churn is the top product risk** (WI-1.1, WI-1.4): a bad
  identity migration silently corrupts lifecycle history at work. Both WIs
  carry one-time re-key effects — batch them into the same release (v1.1.0)
  so operators see one re-key event, not two, and state it in the changelog
  exactly as the WI-089 entry did.
- **Nav migration is the top operational risk**: the work instance has real
  users with real bookmarks. The route-inventory test and the reversible
  flag are load-bearing, not ceremony.
- **Scope guard:** anything that smells like a new engine (multi-estate,
  Studio interop, object-level RSoP) is out. The finish line only exists if
  it doesn't move.
