---
status: resolved
priority: low
kind: design
created: 2026-06-19
resolved: 2026-06-20
---

# admx duck-type parameter uses `object` — no mypy-verified contract

## Problem

`danger_findings()`, `estate_doctor()`, `evaluate_danger_rules()`, and
`baseline_diff()` all accept `admx: object | None` and use duck-typing
(`getattr(admx, "resolve_display_name", None)`) to call the resolver. This
avoids importing `admx_parser` in the hot path, but it means mypy can't verify
the contract. If `resolve_display_name`'s signature changes (e.g. new required
parameter), nothing catches the mismatch until runtime.

The pattern is used in 4 call sites across `danger.py`, `queries.py`, and
`web/app.py`.

## Risk

Low. The resolver interface is stable (one method, one parameter). But the
duck-typing means a typo in the method name (e.g. `resolve_displayname`) would
silently produce `None` at runtime rather than a clear type error.

## Suggested fix

Define a `Protocol` class for the resolver interface:

```python
# In model.py or a shared _protocols.py
from typing import Protocol

class AdmxResolver(Protocol):
    def resolve_display_name(self, identity: str) -> str | None: ...
```

Replace `admx: object | None` with `admx: AdmxResolver | None` in all 4 call
sites. The existing `admx_parser.PolicyDefinitions` class already satisfies the
protocol (structural subtyping). Mypy then verifies the contract at every call
site.
