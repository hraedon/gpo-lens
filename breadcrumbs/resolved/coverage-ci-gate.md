---
status: resolved
priority: medium
kind: design
created: 2026-06-20
resolved: 2026-06-20
---

# No coverage measurement in CI — coverage regressions are invisible

## Problem

`pytest-cov` is not in dev dependencies and the CI workflow (`ci.yml`) runs
`pytest -q` without `--cov`. The overall coverage is ~87% (measured manually),
but CI never tracks it. A module can drop from 95% to 40% coverage and the
build stays green. This is especially risky for CLI wrapper modules (many are
at 12-50% coverage) and for new features that ship without adequate tests.

The `danger_rules.toml` calibration gap (WI-032) is an example of what happens
when coverage is invisible — rules can silently produce zero findings because
no test validates them against real data, and coverage doesn't flag the gap.

## Suggested fix

1. Add `pytest-cov>=5.0` to `[dev]` extras in `pyproject.toml`.
2. Add `--cov=src --cov-report=term-missing --cov-fail-under=85` to
   `[tool.pytest.ini_options] addopts`.
3. Optionally add a coverage badge to README (using `coverage-badge` or
   GitHub Actions badge).

The 85% threshold is a floor, not a target — it prevents regressions without
forcing coverage of trivial stubs (`__main__.py`, `__init__.py`).
