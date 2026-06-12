# Tier-1 normalized model

The deterministic core's data model. Designed against two real exports —
`WORK-DOMAIN.local` (work, 100+ GPOs, 1,000+ SOMs — the mess, and the reason we wanted a
work extract) and `lab.example.com` (lab, 12 GPOs, 28 SOMs, clean) — so the field
mappings below are observed, not guessed.

Goal: ingest the collector outputs into a normalized model that (a) answers the
Tier-1 queries deterministically and (b) already carries the fields every later
feature needs, so nothing reshapes. Settings come from the **GPO report XML**;
raw-file references come from **SYSVOL**; topology comes from **GPInheritance**.

## The join key (get this right first)

Every input identifies a GPO differently:

| Source | GUID form |
|--------|-----------|
| `AllGPOs.xml` `GPO/Identifier/Identifier` | `{31B2F340-016D-11D2-945F-00C04FB984F9}` (braced, upper) |
| `gp-inheritance.json` `InheritedGpoLinks[].GpoId` | `31b2f340-016d-11d2-945f-00c04fb984f9` (bare, lower) |
| `SYSVOL-Policies\` folder name | `{31B2F340-…}` (braced, upper) |
| `gpo-metadata.json` `Id` | GUID (case varies) |

**Canonical key = lowercase, braces stripped.** Normalize on ingest; join on that.
Getting this wrong silently breaks the report↔topology↔SYSVOL joins.

## Parser gotchas (observed)

- **BOM:** PowerShell 5.1 `Set-Content -Encoding UTF8` writes a UTF-8 BOM. Read all
  JSON as `utf-8-sig` (or have the collector emit `utf8NoBOM` on PS7 — but the
  loader must tolerate BOM regardless, since we can't pin the admin's PS version).
- **Namespaced XML:** root is `{…}report`; match by localname, not prefix.
- **`<Blocked/>` ExtensionData:** some `ExtensionData/Extension` contain only a
  `<Blocked/>` element (extension present but unreadable in-report). Tolerate;
  flag the setting source as `blocked`, don't crash.

## Entities

### Gpo
One per `GPO` element. Carries everything later features need.

| Field | Source |
|-------|--------|
| `id` (canonical) | `Identifier/Identifier` → normalized |
| `name` | `Name` |
| `domain` | `Identifier/Domain` |
| `created`, `modified`, `read` | `CreatedTime`, `ModifiedTime`, `ReadTime` |
| `computer_enabled`, `user_enabled` | `Computer/Enabled`, `User/Enabled` (bool) |
| `computer_ver_ds`, `computer_ver_sysvol` | `Computer/VersionDirectory`, `Computer/VersionSysvol` |
| `user_ver_ds`, `user_ver_sysvol` | `User/Version*` |
| `sddl`, `owner` | `SecurityDescriptor/SDDL`, `/Owner` |
| `filter_data_available` | `FilterDataAvailable` |
| `wmi_filter` | `gpo-metadata.json` (report WMI lives elsewhere) |
| `sysvol_path` | matched SYSVOL folder (for raw-file scans) |

> Version-skew detector (later) = `*_ver_ds != *_ver_sysvol`. (0 cases in both
> samples — feature is valid, just no positives here.)

### GpoLink
One per `GPO/LinksTo` (repeating; a GPO had 4 in the home lab).

| Field | Source | Note |
|-------|--------|------|
| `gpo_id` | parent | |
| `som_name`, `som_path` | `SOMName`, `SOMPath` | |
| `link_enabled` | `Enabled` | |
| `enforced` | **`NoOverride`** | this is the enforced flag |

### Setting (the heterogeneous one)
One per leaf setting inside `Computer|User / ExtensionData / Extension`. Each CSE
(`ExtensionData/Name`: Registry, Security, Local Users and Groups, Printers,
Public Key, …) has a **different child schema**, so we do *not* fully schematize
every CSE in Tier-1. Instead:

| Field | How |
|-------|-----|
| `gpo_id`, `side` | parent (`Computer`/`User`) |
| `cse` | `ExtensionData/Name` |
| `identity` | CSE-specific natural key (see below) |
| `display_name` | human-readable label |
| `display_value` | flattened value/state for search + conflict |
| `raw` | preserved CSE-specific subtree (JSON blob) — lossless |
| `from_disabled_side` | true if this side's `Enabled=false` but settings exist |
| `source_state` | `normal` \| `blocked` (the `<Blocked/>` case) |

**`identity` per CSE** (for conflict detection — "same setting"):
- *Security* → `Type` + `Name` (observed: `<Account Name="LockoutBadCount" Type="Account Lockout">`).
- *Administrative Templates / Registry* → registry key + value name (or policy name).
- *GPP (Windows Registry, Local Users and Groups, Printers, Drives…)* → CSE-native
  key; conflict identity here is best-effort, scoped conservatively.

`from_disabled_side` matters: the home lab has **several disabled-but-populated sides** —
settings authored then the side switched off. They must be flagged, not silently
counted as active.

### Som (topology — from `gp-inheritance.json`)
One per SOM record (1,000+ in the home lab — must scale).

| Field | Source |
|-------|--------|
| `path`, `name`, `container_type` | `Path`, `Name`, `ContainerType` |
| `inheritance_blocked` | `GpoInheritanceBlocked` (12 true in lab, 3 at work) |
| `links[]` | `InheritedGpoLinks[]`: `{gpo_id, order, enabled, enforced, target}` |

This is the resolved, ordered, block/enforced-aware chain — the platform already
did the precedence walk. The topology layer (Tier 2.5) consumes it directly.

### Delegation (from `SecurityDescriptor/Permissions`)
Per-trustee permission rows. Powers the delegation audit and the **MS16-072**
check: flag GPOs whose trustees lack Authenticated Users / Domain Computers read.

### FileRef / GppSecretRef (from SYSVOL — captured now, scanned later)
Record `sysvol_path` per GPO now; the cpassword scan (MS14-025) and broken-ref
inventory walk the GPP XML (`Groups.xml`, `Services.xml`, `Drives.xml`,
`ScheduledTasks.xml`, `DataSources.xml`). Both sample domains have carriers;
**neither has a live cpassword** (clean) — good negative-path test data.

## Tier-1 queries → entities

| Query | Uses |
|-------|------|
| unlinked GPOs | `Gpo` ⟕ `GpoLink` (no links) |
| empty GPOs | `Gpo` with no `Setting` |
| disabled-but-populated | `Setting.from_disabled_side` |
| "who sets X" | `Setting` by `identity`/`display_name` |
| conflict surface | `Setting` grouped by `identity`, >1 distinct `display_value` across GPOs |

## Calibration (proves the model against reality)

| Signal | work (WORK-DOMAIN.local) | lab (lab.example.com) |
|--------|-------------------:|---------------------:|
| GPOs | 100+ | ~12 |
| duplicate display names | 0 | 0 |
| one-side-disabled GPOs | many (33 user / 12 computer off) | 0 |
| disabled-but-populated sides | 6 | 0 |
| top CSEs | Registry, Security, Windows Registry, Printers, Public Key | Registry, Security, Public Key |
| SOMs | 1,000+ | ~30 |
| inheritance-blocked SOMs | 12 | 3 |
| loopback configured | yes (31 hits) | — |
| version skew | 0 | 0 |
| live cpassword | 0 | 0 |

## Open mappings to verify against more data

- Admin-template (`Registry` CSE) leaf shape when **not** `<Blocked/>` — need a
  non-blocked sample to pin the policy/registry identity precisely.
- GPP conflict identity (Tier-2.5) — define per-CSE natural keys.
- `gpo-metadata.json` `Id` casing — confirm normalization covers it.
