# gpo-lens

A local-first, read-only analysis tool for Group Policy. You feed it *copies*
of your GPO estate; it gives you searchable settings, conflict and topology
analysis, baseline comparison, hygiene/security scans, and a change log over
time. Deterministic core; an optional LLM layer only ever *narrates* facts the
core already computed.

> **Status:** promoted from idea to real project 2026-06-05. Charter settled;
> Tier-1 normalized model designed against real exports — see
> [`docs/tier1-normalized-model.md`](docs/tier1-normalized-model.md). Next:
> implement the ingest + first queries. Name is provisional.

## Why this exists

GPO is a critical, omnipresent need with frozen tooling. Microsoft's attention
moved to Intune years ago, stranding on-prem Group Policy with aging first-party
tools and a few expensive commercial holdouts:

- **AGPM** (change history + rollback) is effectively dead.
- **Policy Analyzer** does value-diffing well but has no topology/inheritance
  view and is painful to use.
- **GPMC** has the inheritance tab but won't roll up "set more than once across
  the resolved chain" into one view.
- **Change Auditor / Netwrix** (attributed change log) are expensive commercial.
- `cpassword` scanning lives only in *pentest* tooling.

The defensible niche: **queryable + narratable + scriptable, in one local tool**,
covering the gaps between those tools rather than re-implementing any one of them.

## Design principles

1. **Deterministic core, no AI in the truth path.** Parse → normalized model →
   queries are pure and verifiable. The LLM layer (Tier 3) only narrates
   already-computed facts. This makes outputs checkable by a domain expert and
   keeps the core usable where AI tooling is banned.
2. **Eats exports, never touches live AD.** Input is copies the user produces
   with PowerShell. The tool never binds to a domain controller — read-only by
   construction, safe to run anywhere (incl. air-gapped).
3. **Local-first.** Embedded store (SQLite). Portability/air-gap beats a server DB.
4. **Read-only analysis.** Never writes or remediates GPOs.
5. **Flag, don't simulate.** Stay at OU/topology level; never claim object-level
   effective policy (RSoP).

## Inputs

| Input | Produced by | Powers |
|-------|-------------|--------|
| SYSVOL `Policies` folder copy | file copy | security/hygiene scans (cpassword, broken-refs, version skew) |
| Per-GPO XML reports | `Get-GPOReport -ReportType Xml` | settings, conflict, baseline analysis |
| Per-OU inheritance dumps | `Get-GPInheritance` | topology / OU-scoped resolution + precedence |
| GPO metadata | `Get-GPO` | versions, timestamps, replication-skew |

The user's original instinct to feed *both* a policies folder and GPO copies was
correct — they serve different feature families.

## Tiers

- **Tier 1 — Ingest / normalize / query (deterministic, no AI).** Parse inputs
  into one normalized model; deterministic search + hygiene queries (unlinked,
  empty, disabled-but-populated, "who sets setting X"), plus the cross-estate
  **conflict surface** (same setting, different values).
- **Tier 2 — Baseline diff.** Diff the estate against one imported Microsoft
  Security Baseline (ships as GPO backups). Hard part is the **crosswalk**
  (registry path vs ADMX policy name vs CIS recommendation #); scope to one
  baseline first.
- **Tier 2.5 — Topology layer.** OU-scoped resolution via `Get-GPInheritance`
  (which already orders links with block-inheritance + enforced applied):
  "all settings in scope at OU X" + "settings set more than once in that chain"
  with precedence winner vs overridden. Explicitly assumes security/WMI filters
  pass — OU-level, **not** object-level.
- **Tier 3 — LLM narration (optional, additive).** Natural-language search +
  plain-English "what does this do / why does this value matter" + narrated,
  prioritized remediation. Narrates verified facts only; never the source of truth.

## Feature backlog (all greenlit; built in dependency order)

- **Change log over time** — Level 1 snapshot diff (now), Level 2 version-aware
  (cheap add), Level 3 event-attributed who/when (ambitious; requires auditing
  enabled in advance; cannot reconstruct unlogged past). Replaces dead AGPM.
- **`cpassword` / GPP secret scan (MS14-025)** — defensive detection of lingering
  GPP-stored secrets in SYSVOL XML. Today only in pentest tooling.
- **Delegation audit + MS16-072 trap** — roll up permissions; flag GPOs missing
  Authenticated Users / Domain Computers read (silent non-apply).
- **Broken-reference / orphan inventory** — links to dead OUs; scripts/MSIs/drives
  to dead UNC paths; SYSVOL↔AD GPO mismatches.
- **Version-skew / replication health** — GPC vs GPT version mismatch.
- **ADMX-resolution gaps** — settings surfacing as raw "Extra Registry Settings"
  (incomplete Central Store).
- **Auto-generated estate documentation.**
- **Loopback awareness (flag, not simulate)** — detect loopback-enabled GPOs +
  mode (merge/replace); annotate OU views with the user-config settings loopback
  pulls into scope. Required for the OU conflict view to be *honest* on the user
  side (replace drops a chain; merge adds one).
- **[Stretch] GPO ↔ Intune conflict** — co-management overlap. Needs Graph/Intune
  export + a brutal CSP crosswalk. Genuinely unserved; later, separately scoped.

## Normalized model must carry (designed in from day one)

Per GPO: resolved settings **partitioned User vs Computer**, metadata
(versions, timestamps), security descriptor / delegation, references to raw
SYSVOL files (cpassword, broken-refs), external resource references (UNC/MSI),
loopback flag + mode. Designing for this now means every backlog feature is an
additive query, not a model reshape.

## Architecture

```
inputs (copies) ──► deterministic core (pure lib) ──► embedded store (SQLite, snapshot history)
                              │                                  │
                              ▼                                  ▼
                        Tier 3 LLM (optional, narrates)     web frontend (reads core + store)
```

The "over time" change-log requirement is what turns this from a stateless CLI
into core + store + service. Web frontend accepted on that basis.

### Stack (decided 2026-06-05)

**Python analysis core + PowerShell collectors, hosted on IIS.** Python chosen
for portfolio consistency (`cert-watch` patterns reusable), web/embedded-store
ergonomics, and existing agent-directing muscle memory. Collectors are
PowerShell regardless — the exports *are* cmdlet output.

### Windows hosting — inherited from cert-watch (`/projects/cert-watch/deploy/iis/`)

gpo-lens is the same shape as cert-watch (ASGI + SQLite + in-process scheduler,
fronted by IIS), so it reuses these hard-won lessons rather than relearning the
Python-on-Windows jank:

- **HttpPlatformHandler** hosting model (Microsoft-signed; IIS supervises the
  process; no third-party wrapper) — best for locked-down hosts. ARR + NSSM is
  the fallback.
- **Shared Python install:** Python 3.14+ Install Manager is per-user under
  `%LocalAppData%`, untraversable by the IIS app-pool virtual account. Copy the
  runtime to `C:\ProgramData\gpo-lens\python\` and build the venv from it
  (cert-watch's `install-windows.ps1` approach).
- **Unlock `system.webServer/handlers`** at server level (`appcmd unlock`) or get
  `0x80070021`.
- **ACL the real Python dir** (venv `python.exe` is a symlink) plus data/secrets,
  or IIS hangs with "Access is denied."
- **In-process snapshot scheduler ⇒ always-running pool:** `idleTimeout=0`,
  `startMode=AlwaysRunning`, no periodic recycle — else scheduled snapshots stop.
- **No Managed Code** app pool; persist secret/signing keys to files (survive
  recycles); `%PROGRAMDATA%\gpo-lens` for SQLite DB + WAL; `TRUST_PROXY` +
  forwarded headers + Secure cookies behind IIS.
- **Replicate `Verify-Install.ps1`:** read-only end-state verifier, exits
  non-zero — fits the read-only/verifiable ethos and gates change control.

## Non-goals

- Object-level effective policy (RSoP): per-user merge of security/WMI/loopback.
- Live AD mutation; any GPO writes or remediation.
- Full per-user loopback simulation (we flag + annotate only).
- Covering every baseline/framework at once (one baseline first).

## Strategic placement

Personal / corpus project and an agent-directing vehicle: inputs and outputs are
checkable by a domain expert, and it decomposes into independently-verifiable
milestones. A work pitch is **deferred and bounded**: Tiers 1–2.5 need *no AI*,
so the deterministic core is exactly the subset usable in an environment where
agent tooling is currently banned — that core, not the LLM layer, is the
eventual pitch surface.

## Open questions

- Final name (`gpo-lens` is a placeholder).
- Web frontend approach (server-rendered like cert-watch vs SPA) — minor; defer
  until the core + store exist.

## First slice (next artifact)

1. Ingest a folder of `Get-GPOReport` XML → normalized model (designed to carry
   the full field set above, even where v1 only populates settings).
2. A handful of deterministic queries: unlinked, empty, conflicts, "who sets X."

Zero AI dependency; every output checkable against the source XML.
