---
status: open
priority: high
kind: bug
created: 2026-06-10
---

# report subcommand --db argument shadows parent parser's --db

## Problem

The `report` subparser in `_core.py:306-308` re-declares `--db` with the same
default (`DEFAULT_DB`) as the top-level parser (`_core.py:55`). When a user runs
`gpo-lens --db my.db report`, argparse applies the subparser's default after the
parent parser has already set the value, silently overwriting `my.db` with
`./gpo-lens.sqlite3`.

This was discovered when new `--admx-dir` tests failed because the test DB
(created with `init_db` including `wmi_filter`/`ou_tree` tables) was ignored in
favor of a stale local `gpo-lens.sqlite3` from before those tables existed.

## Fix

Remove the duplicate `--db` argument from the report subparser. The report
command should inherit `args.db` from the top-level parser like every other
subcommand. The `--since` help text already says "requires --db" which implies
the top-level flag.

## Files

- `src/gpo_lens/cli/_core.py:306-308` — remove the `p.add_argument("--db", ...)` line
- `tests/test_cli.py::TestReportAdmx` — move `--db` back to top-level position in subprocess args
