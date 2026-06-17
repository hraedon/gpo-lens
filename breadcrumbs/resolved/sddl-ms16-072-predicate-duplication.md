---
status: resolved
resolved: 2026-06-17
priority: high
kind: design
created: 2026-06-17
---

# SDDL / MS16-072 read predicate is duplicated and drifting

## Problem

"Does this GPO grant read/apply to a broad trustee (Authenticated Users /
Domain Computers)?" is answered in two places with **different rule sets**:

- `src/gpo_lens/detection.py` — `_has_ms16_072_read` /
  `_READ_IMPLYING_PERMISSIONS` (`{"read", "edit settings",
  "edit settings, delete, modify security", "full control"}`) drives the
  MS16-072 vulnerability finding.
- `src/gpo_lens/topology.py` — `is_security_filtered` /
  `security_filtering_detail` / `_grants_read_or_apply` /
  `_SDDL_READ_OR_APPLY_RIGHTS` drives the scope-honesty caveats
  (`has_au_read` / `has_dc_read`) and the SDDL fallback added for WI-019.

The two recognize overlapping but non-identical trustee/permission sets and
parse SDDL independently (`_sddl_ace_broad_key`/`_broad_key` in topology vs.
`_trustee_matches_ms16_072` in detection).

## Risk

A maintainer will eventually "fix the drift" by re-using one implementation in
the other, silently changing either (a) which GPOs are flagged MS16-072
vulnerable — a real security-detection false negative/positive — or (b) which
GPOs are reported as `is_security_filtered` for potentially thousands of GPOs
in the topology views. Two sources of truth for a security predicate is a
latent correctness trap.

## Suggested fix

Extract a single `authz.py` module with named constants
(`BROAD_TRUSTEES`, `READ_OR_APPLY_RIGHTS`, `MS16_072_TRUSTEES`,
`MS16_072_RIGHTS`) and small typed helpers that take a parsed ACE / delegation
entry and return an answer. Both `detection` and `topology` consume it. Before
merging, add edge-case tests for both semantics (deny-ACE precedence, object
ACEs, concatenated rights, "edit settings" implying read) so the unification
proves behavior-preserving rather than silently picking one side.

## Context

Raised during the 2026-06-17 cross-review (kimi + adversarial reviewers). Not
touched in that session because unifying two subtly different security
predicates needs explicit behavior-preservation coverage first — too risky for
a quick fix.
