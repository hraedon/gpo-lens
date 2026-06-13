# gpo-lens

Local-first, read-only Group Policy analysis. Ingests copies of a GPO estate
(never touches live AD) and answers questions about it. The deterministic core
has no AI in the truth path — the LLM layer only narrates facts the core
already computed.

## Quick start

```powershell
# On a DC or RSAT box, export the estate (read-only, no changes):
scripts/Export-GpoEstate.ps1 -OutputDir C:\GpoExport
```

```bash
# Copy the export to your analysis machine, then:
gpo-lens ingest C:\GpoExport
gpo-lens doctor
# Optional: set GPO_LENS_API_KEY for AI narration (ask, doctor --explain). Without it, narration silently degrades to raw deterministic output.
```

## What it does

- **Tier 1 — Hygiene scans.** cpassword detection, MS16-072 traps, version
  skew, broken references, unlinked and empty GPOs, disabled-but-populated
  sides.
- **Tier 2 — Baseline comparison.** Diff your estate against a Microsoft
  Security Baseline (shipped as GPO backups). ADMX crosswalk resolves registry
  paths back to policy names.
- **Tier 2.5 — OU-level topology.** Per-OU settings-at-SOM, precedence
  ordering, conflict surface (same setting, different values). Flags loopback
  but does not simulate per-user RSoP.
- **Tier 3 — AI narration (optional).** `doctor --explain` and natural-language
  `ask` command. Narrates verified facts only; never the source of truth.
  Requires `GPO_LENS_API_KEY`; degrades gracefully without it.

## Install

```bash
uv pip install -e .
# or
pip install -e .
```

## Key commands

| Command | What it does |
|---------|-------------|
| `doctor` | Prioritized health findings |
| `doctor --explain` | AI-powered explanation of findings |
| `ask "..."` | Natural-language GPO question |
| `summary` | Estate overview |
| `ingest <path>` | Parse collector output into DB |
| `baseline-diff` | Compare against MS baseline |
| `diff` | Full snapshot diff |
| `diff-settings` | Per-setting snapshot diff |
| `changelog` | Version-aware change log |
| `report --output report.html --format html` | Export audit-ready HTML report |
| `repl` | Interactive Python REPL with the estate loaded |
| `settings-at <som>` | Effective settings at a SOM path |
| `loopback` | GPOs that configure loopback processing |
| `wmi` | GPOs with WMI filters attached |
| `wmi-filters` | List WMI filters with query text |
| `broken-refs` | Detect broken references in settings |
| `admx-gaps` | Settings with raw key paths (no ADMX policy name) |
| `topology-check` | Cross-check OU tree against inheritance |
| `delegation` | Delegation deep-dive audit |

## Design principles

- **Deterministic core.** No AI in the truth path. Parse, normalize, query —
  all pure and verifiable.
- **Read-only.** Never touches live AD. Input is file copies only.
- **Zero runtime dependencies.** Stdlib-only core (`xml.etree.ElementTree`,
  `json`, `sqlite3`, `argparse`) — portable and air-gappable.
- **Air-gappable.** No network required for core features.
- **Flag, don't simulate.** Topology resolution is OU-level; never claims
  object-level RSoP (no per-user security/WMI/loopback evaluation). Scoping
  mechanisms (loopback, security filtering, WMI filters, item-level targeting)
  are flagged with caveats, not simulated.

## Limits

- **Single-domain estates.** The `Estate` model holds one domain's GPOs, SOMs,
  and WMI filters. Multi-domain or multi-forest estates are not supported.
- **Site-level GPO links.** The collector exports OU/domain inheritance only.
  Sites are a real GPO scoping mechanism but are not captured. Extending the
  collector for site links is additive and deferred until needed.
- **Per-user/object RSoP simulation.** The tool resolves settings at the OU
  level and flags scoping mechanisms (loopback, security filtering, WMI, ILT)
  with caveats. It does not simulate per-user effective policy.

## Development

```bash
uv venv && uv pip install -e ".[dev]"
pytest -q
ruff check .
mypy src
```

See [`AGENTS.md`](AGENTS.md) for conventions, module map, and build details.
See [`docs/`](docs/) for the normalized model spec and per-work-item specs.
