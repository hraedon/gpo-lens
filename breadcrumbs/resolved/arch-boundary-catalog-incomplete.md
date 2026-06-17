---
status: resolved
resolved: 2026-06-17
priority: low
kind: design
created: 2026-06-17
---

# AGENTS.md import-boundary list omits topology / registry_pol / paths

## Problem

The architecture test was hardened this session to AST-based enforcement over
a single-sourced catalog in `tests/_arch.py` (was regex-based, duplicated).
That catalog intentionally mirrors AGENTS.md's authoritative *Import boundary*
list, which names 12 core modules:

`model, normalize, ingest, store, queries, detection, admx_parser, display,
report, events, sinks, query_dispatch`

But the codebase also has modules that are clearly core (no narration/web
dependency — verified to import only stdlib + `gpo_lens.model`/`.detection`):
`topology.py`, `registry_pol.py`, `paths.py`. The old (pre-hardening) regex
tests actually listed 13 including `topology`; the new test dropped it to match
AGENTS.md. So `topology`/`registry_pol`/`paths` could today import
`narration`/`web` and the boundary test would **not** catch it.

## Risk

A real boundary violation in `topology.py` (the largest core-adjacent module,
778 lines) or `registry_pol.py` would go unenforced. The deterministic-core
invariant is the project's central guarantee.

## Suggested fix

Decide whether `topology`, `registry_pol`, `paths` are core (they should be —
they hold deterministic parse/query logic with no AI/web). If yes, add them to
the AGENTS.md *Import boundary* list AND to `CORE_MODULES` in
`tests/_arch.py`. Single source of truth = AGENTS.md.

## Context

Raised during the 2026-06-17 architecture-test hardening (M4). Widening scope
required changing AGENTS.md, which is a doc/contract decision — deferred rather
than made silently by the implementing agent.
