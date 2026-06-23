---
status: active
priority: medium
kind: feature
created: 2026-06-23
---

# Estate-wide delegation / "who can edit GPOs" view

## Problem
Per-GPO delegation entries are collected and stored (`gpo.delegation`,
`DelegationEntry`) and shown on the GPO detail page, and `authz`/the danger
detectors already reason about excessive-writer / broad-trustee ACEs. But there
is no estate-wide governance view answering "which principals can edit which
GPOs?" or "who has write/link rights across the estate?" from one screen.

## Risk
Capability gap, not a defect. Delegation is a real attack-surface and audit
question (a single over-privileged trustee across many GPOs is invisible unless
you open each GPO). The data is already in hand.

## Suggested fix
A `/delegation` route that inverts the per-GPO delegation into a per-trustee
rollup: trustee -> the GPOs they hold non-Read rights on, with the permission
and an allow/deny flag, sortable by breadth (most GPOs first, echoing the
Conflicts "blast radius" framing). Surface the existing excessive-writer /
broad-trustee danger signals inline. Deep-link trustees and GPOs.

## Context
Filed 2026-06-23 from the post-Conflicts assessment as item #3 of the
estate-wide-views direction. Pairs conceptually with
[[estate-wide-settings-search]] — both invert per-GPO data into an estate-wide
lens.
