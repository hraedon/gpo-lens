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

## Resolution

All three spec files audited and updated against current implementation:

- `wi_queries.md`: Added AC-07 through AC-50 covering version skew, MS16-072,
  permissions audit, cpassword scan, search, estate summary, snapshot diff,
  Tier 2.5 topology queries (SOM effective GPOs, dangling/enforced links,
  SOM/precedence conflicts, settings-at), feature-flag queries (loopback,
  WMI-filtered), security/hygiene queries (broken refs, ADMX gaps), and
  topology crosscheck.

- `wi_cli.md`: Added AC-05 through AC-42 covering diff, cpassword --show-secrets,
  search, show, summary, REPL, and all Tier 2.5 / feature-flag / hygiene
  subcommands.

- `wi_store.md`: Updated AC-01 to include wmi_filter and ou_tree tables; updated
  AC-02/03 to reflect wmi_filters and ou_tree round-trip.

- `wi_ingest.md`: Added AC-12 (parse_wmi_filters) and AC-13 (parse_ou_tree).
