# Plan 027 — Road to the generous 1.0: land, harden, complete, deploy

**Status:** Proposed 2026-07-14

**Depends on:** Plans 023/024 (implemented on `plan/023-web-reimagining`,
unmerged), Plan 025 (proposed, the bulk of remaining work), Plan 026
(explicitly deferred by this plan).

**Strategic role:** v1.0.0 shipped 2026-07-06 and is load-bearing at work, but
the version number outran the product vision: the web reimagining program
(023/024/025) that turns gpo-lens from "a set of analysis pages" into "a tool
that answers the operator's four questions" is roughly one-third landed and
none of it is on `main`. This plan is the orchestration layer — it sequences
the already-reviewed plans into a deployable path and defines the finish line,
after which gpo-lens is *maintained*, not *driven*.

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

## Phase 0 — Land the findings program (branch → main)

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

## Phase 1 — Pay the sharp Plan 024 debt → v1.1.0

All items below are documented in the 2026-07-12 and 2026-07-14 reflections;
two are correctness bugs waiting for the right input.

- **WI-1.1 — Structured detector dimensions.** The candidate adapter derives
  identity dimensions by parsing prose (`summary.split()[0]`,
  `findings.py:~1413`). Any wording change churns finding identity — falsely
  resolving real findings and minting "new" ones. This is the exact failure
  class WI-089 fixed, one layer down. Detectors emit typed dimension fields;
  the adapter stops reading prose. Property test: fingerprints invariant
  under summary/detail rewording.
- **WI-1.2 — Push `claim_level`/`triage_status` filters into SQL.**
  `finding_inbox` applies `LIMIT` before Python-side filtering — a filtered
  page on a large estate can silently truncate results. Correctness, not
  performance.
- **WI-1.3 — Indexes + N+1.** Indexes on `first_seen_run_id`,
  `last_seen_run_id`, `resolved_run_id`, `series_key`; batch
  `load_triage_status_map` (currently one query per occurrence).
- **WI-1.4 — Legacy Plan 023 rows: decide and enforce.** Rows predating the
  v2 engine have NULL run IDs and no observations. Either migrate them
  (exact provenance only — never synthesize) or explicitly exclude them from
  v2 queries with a visible "pre-lifecycle finding" marker. Mixed-mode
  ambiguity is the enemy; pick one and test it.
- **WI-1.5 — Small knives:** `detail` column stores `summary` (give
  `FindingCandidate` a real `detail` or drop the column write);
  `snapshot_scoped` OccurrenceState is modeled but never produced (produce it
  for lifecycle-less rules per Plan 023's risk note, or delete the state);
  inline `hashlib` import; document the single-estate-per-store assumption
  (2026-07-12 reflection, last gap).
- **WI-1.6 — Tag v1.1.0. Deploy lab IIS → soak → work.** Real-estate exposure
  has caught what fixtures missed three separate times in this repo; the
  deploy gate is part of the phase, not an afterthought. Watch the ingest
  lifecycle block specifically — it is try/except-logged, so a silent
  failure never surfaces in tests (drive the e2e findings flow post-deploy).

**AC:** rewording property test green; filtered inbox provably complete
(fixture with >LIMIT findings); v1.1.0 at work with findings flow verified
end-to-end against the real estate.

## Phase 2 — Execute Plan 025 (the reimagining completion) → v1.2.x

Plan 025 already carries the design detail and acceptance criteria; this
phase just binds its sequence to deployment checkpoints and slots in the
Plan 023 primitives that Plan 025 assumes but which don't exist yet.

Order (per Plan 025 §10, with the missing primitives made explicit):

1. **Findings inbox + occurrence view on the v2 core queries** (025 WI-1) —
   the current inbox reads the `finding` table directly; move it onto
   `finding_inbox`/`finding_history`/`accepted_risk_register`.
2. **Briefing home** (025 WI-2) — golden-tested deterministic prose deltas.
3. **Explore primitives** (under 025 WI-3, originally 023 WI-2/3/7/8):
   dossier completion (verdict strip, scope & control panel, history tab —
   the ledger and GPO-vs-GPO compare already exist), setting-centric page,
   global snapshot axis ("as of snapshot N" everywhere), omnisearch.
   *Checkpoint: deploy — dossier usable, nothing removed.*
4. **Staged nav migration + route inventory + redirects** (025 WI-4) — work
   bookmarks must not break; 302 first, permanent only after observation.
   *Checkpoint: deploy — Briefing becomes home, old nav still present; then
   the reversible nav switch at work.*
5. **Narration demotion** (025 WI-5) — `/ask` to Tools; "explain these
   facts" actions fed only the page's deterministic payload.
6. **Deterministic exports** (025 WI-6) — Markdown/CSV, provenance-bearing,
   golden-tested; shares the redaction fixture corpus.

Version tags at each deployment checkpoint (v1.2.0, v1.2.x). Each checkpoint:
lab IIS first, then work, with the reversibility Plan 025 §10 requires.

**AC:** Plan 025 §12 checklist complete; every pre-025 URL reaches equivalent
information (route-inventory test); work deployment on the new IA with the
rollback flag exercised at least once in lab.

## Phase 3 — Operational generosity + docs → the milestone tag

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
- **Deployment pin:** the work instance stays on **v1.0.0 until v1.1.0**.
  The Phase 0 merge puts two known correctness bugs (WI-1.1 prose-keyed
  fingerprints, WI-1.2 post-LIMIT filter truncation) onto `main`, so no
  work deployment may be cut from `main` between the merge and the v1.1.0
  tag.
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
