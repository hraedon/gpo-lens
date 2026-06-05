# AGENTS.md

Conventions and quick reference for agents (and humans) working on gpo-lens.

## What this is

Local-first, **read-only** Group Policy analysis. The tool ingests *copies* of a
GPO estate (it never touches live AD) and answers questions about it. The
deterministic core has **no AI in the truth path** — any future LLM layer only
narrates facts the core computed. See `README.md` for the full charter.

## Orient

1. **Read the model.** `docs/tier1-normalized-model.md` — the normalized data
   model, mapped against two real exports, with the join-key and parser gotchas.
   The dataclasses in `src/gpo_lens/model.py` are the concrete contract.
2. **Read the spec.** `docs/spec/wi_*.md` — one file per work item, with explicit
   acceptance criteria (`AC-NN`) and exact function signatures. **The spec is the
   contract.** Implement to the ACs.
3. **Validate against reality.** `tests/` encodes the *measured* numbers from the
   real exports (e.g. work domain = 129 GPOs, 8 disabled-but-populated sides,
   1,551 SOMs). Your implementation is correct when those pass. The sample exports
   live in `samples/` (gitignored — never commit them; WORK-DOMAIN.local is a real work
   domain's SYSVOL). Sample-dependent tests skip if `samples/` is absent.

## Hard rules

- **Read-only.** No code writes to or connects to Active Directory. Input is
  files only.
- **No AI in the deterministic core.** Tiers 1–2.5 must run with zero model calls.
- **Flag, don't simulate.** Topology resolution is OU-level; never claim
  object-level RSoP (no per-user security/WMI/loopback evaluation).
- **Canonical GPO id everywhere:** lowercase, braces stripped. All cross-input
  joins use it (see `normalize.canonical_guid`).
- **BOM-tolerant JSON:** collector JSON may carry a UTF-8 BOM (PowerShell 5.1).
  Always load with `utf-8-sig`.

## Build / test / lint

```bash
uv venv && uv pip install -e ".[dev]"
.venv/bin/pytest -q            # unit + calibration tests (sample tests skip if samples/ absent)
.venv/bin/pytest -q -m samples # calibration tests against the real exports (needs samples/)
.venv/bin/ruff check .
.venv/bin/mypy src
```

Slice 1 is **stdlib-only** (`xml.etree.ElementTree`, `json`, `sqlite3`,
`argparse`) — keep it dependency-free so the core stays portable/air-gappable.

## Collectors

`scripts/Export-GpoEstate.ps1` produces the inputs (read-only PowerShell, run on
a DC/RSAT box). The tool consumes its output dir.
