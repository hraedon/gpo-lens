# Spec drift: docs/spec/ lags behind implementation

## Problem

The work-item specs in `docs/spec/wi_*.md` document the original Tier-1 design.
The codebase has since added Tier-2.5 and Tier-3 commands not reflected in the specs:

- `som`, `dangling`, `enforced` — topology queries (Tier 2.5)
- `loopback`, `wmi` — feature-flag queries
- `settings-at`, `som-conflicts`, `precedence-conflicts` — chain-aware resolution (Plan 009)
- `broken-refs` — reference inventory
- `diff` — snapshot diff (not documented in `wi_cli.md`)
- `cpassword --show-secrets` — new flag

## Risk

New contributors (and LLM agents directed by the specs) assume the documented
surface is complete and may miss or mis-implement features.

## Suggested fix

- Audit each `docs/spec/wi_*.md` against the current CLI commands and query signatures.
- Update AC lists to include the new commands with signatures and acceptance criteria.
- Consider whether to retire specs for completed work items vs. keep them as living docs.

## When to resolve

Before the next major feature is added, or before any external contributor joins.
