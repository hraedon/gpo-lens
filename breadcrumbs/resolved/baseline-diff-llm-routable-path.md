---
status: resolved
resolved: 2026-06-17
priority: medium
kind: defect
created: 2026-06-17
---

# baseline_diff is LLM-routable with an arbitrary filesystem path

## Problem

The `baseline_diff` query accepts a `baseline_path` parameter. In the web
`/ask` flow that parameter is sourced from the LLM's routing response
(`src/gpo_lens/web/app.py` `/ask` handler), so a prompt-injection in the user's
question can cause the LLM to return an arbitrary `baseline_path`. The server
then calls `ingest.load_baseline_from_zip(baseline_path)`, which opens and
decompresses a zip at that path.

Mitigations already present: `load_baseline_from_zip` requires a valid zip
with `gpreport.xml` entries, has a 2 GB decompression cap, and errors are
caught. So this is not a zip-bomb RCE.

## Risk

Residual: a **file-existence oracle** (distinguish "file not found" vs
"invalid zip" from the error message), and if the host has a large legitimate
zip at a known path (e.g. a previous upload), the LLM could be tricked into
processing it and leaking contents via the narration response. Low likelihood
but it crosses a trust boundary (LLM-controlled → filesystem read).

## Suggested fix

Pick one:
- Restrict `baseline_path` to a known uploads/baselines directory (resolve +
  `is_relative_to` check) before opening, OR
- Remove `baseline_diff` from the LLM-routable query set in
  `query_dispatch`/`narration` (it's CLI-oriented with a user-chosen path; the
  `/ask` flow arguably shouldn't route to it at all).

## Context

Raised during the 2026-06-17 adversarial security review (M5). Requires a
small design decision (uploads dir vs. drop from routable set), so deferred
rather than fixed inline.
