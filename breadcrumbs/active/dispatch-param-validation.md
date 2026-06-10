---
status: open
priority: medium
kind: defect
created: 2026-06-10
---

# _QUERY_DISPATCH silently drops unknown params and defaults ou_path to empty string

## Problem

The `settings_at_som` entry in `_QUERY_DISPATCH` does `kw.get("ou_path", "")`,
silently returning an empty string when the LLM forgets the parameter. This
produces a misleading empty result instead of an error. Additionally, all
dispatch lambdas accept `**kw` and silently ignore any unexpected params the LLM
might return.

## Risk

An `ask` user could type "show me settings for OU=Servers" and get zero results
with no indication of why — the LLM routed correctly but dropped the param.

## Fix direction

Add a per-query params schema, e.g. `_QUERY_REQUIRED_PARAMS = {"settings_at_som": ["ou_path"]}`,
and validate before dispatch. Return an error if required params are missing.
Warn on unexpected params.

## Files

- `src/gpo_lens/cli/_narration.py:13-49` — `_QUERY_DISPATCH` lambdas
