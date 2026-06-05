# Work Item: Ingest (collector outputs → normalized model)

## Dependencies

- `interface_ref`: `model` (`src/gpo_lens/model.py` — the dataclasses are fixed)
- Reference: `docs/tier1-normalized-model.md` (field mappings, join key, gotchas)

## Notes

Parse the read-only collector outputs into an `Estate`. Two modules:

- `src/gpo_lens/normalize.py` — pure helpers (guid, BOM-safe JSON, parsers).
- `src/gpo_lens/ingest.py` — the parsers that build model objects.

Element names below are **observed** in the real exports, not assumed. The XML
report root is `{<ns>}report`; **match elements by localname, not namespace
prefix** (use `tag.split('}')[-1]`). The same parser handles `AllGPOs.xml` (many
`<GPO>`) and `reports/<name>.xml` (one `<GPO>`): iterate every `GPO` element.

All functions are pure and deterministic. No network, no AD, no writes.

---

## AC-01: Canonical GPO id
`normalize.canonical_guid(raw: str) -> str` lowercases and strips surrounding
braces and whitespace. `"{31B2F340-016D-11D2-945F-00C04FB984F9}"` →
`"31b2f340-016d-11d2-945f-00c04fb984f9"`; an already-bare lowercase guid is
returned unchanged. Raises `ValueError` on input that is not a 32-hex-digit guid
(with or without braces/hyphens).

## AC-02: BOM-safe JSON load
`normalize.load_json(path) -> Any` reads JSON using `encoding="utf-8-sig"` so a
PowerShell 5.1 UTF-8 BOM is tolerated. (The collector JSON in `samples/` has a
BOM — a plain `utf-8` load raises `JSONDecodeError`; this must not.)

## AC-03: Scalar parsers
In `normalize`:
- `parse_bool(text: str | None) -> bool` — `"true"`→True, `"false"`/None→False
  (case-insensitive).
- `parse_dt(text: str | None) -> datetime | None` — ISO-8601 (the report uses
  e.g. `2026-03-10T16:32:00`); None/empty → None.
- `parse_int(text: str | None) -> int | None` — None/empty/non-numeric → None.

## AC-04: Parse GPOs from a report
`ingest.parse_report(xml_path: str | Path) -> list[Gpo]` returns one `Gpo` per
`GPO` element, populating every `model.Gpo` field:

| Gpo field | Source element (under `GPO`) |
|-----------|------------------------------|
| `id` | `Identifier/Identifier` → `canonical_guid` |
| `name` | `Name` |
| `domain` | `Identifier/Domain` |
| `created`/`modified`/`read` | `CreatedTime`/`ModifiedTime`/`ReadTime` → `parse_dt` |
| `computer_enabled`/`user_enabled` | `Computer/Enabled`/`User/Enabled` → `parse_bool` |
| `*_ver_ds` | `<Side>/VersionDirectory` → `parse_int` |
| `*_ver_sysvol` | `<Side>/VersionSysvol` → `parse_int` |
| `sddl`/`owner` | `SecurityDescriptor/SDDL`/`/Owner` |
| `filter_data_available` | `FilterDataAvailable` → `parse_bool` |
| `wmi_filter`/`sysvol_path` | left None here (set by AC-09/AC-10) |

`links`, `settings`, `delegation` populated per AC-05/06/07.

## AC-05: Parse links
For each `GPO/LinksTo`, append a `GpoLink`: `som_name`=`SOMName`,
`som_path`=`SOMPath`, `link_enabled`=`parse_bool(Enabled)`,
**`enforced`=`parse_bool(NoOverride)`**. A GPO with no `LinksTo` yields an empty
list (this is the unlinked-GPO signal).

## AC-06: Parse settings
For each side (`Computer`, `User`) and each `ExtensionData` under it:
- `cse = ExtensionData/Name`.
- For each `Extension` child, walk its direct child elements as setting blocks.
- If an `Extension` contains only a `<Blocked/>` element, emit exactly one
  **marker** `Setting` for it: `display_name="(blocked extension)"`,
  `display_value=""`, `identity=f"{cse}:blocked"`, `raw={"blocked": True}`,
  `source_state="blocked"`. (This keeps "a side has content" detectable even when
  the report couldn't render it — observed in `Default Domain Policy` — so the
  disabled-but-populated and blocked-extension queries are exact. Do not crash.)
- Each setting block → a `Setting`:
  - `side`, `cse` as above; `raw = element_to_dict(block)` (AC-06a).
  - `from_disabled_side = (not <Side>/Enabled) and block present`.
  - **identity / display by CSE:**
    - `Security`: block is `<Account>`/`<SecurityOptions>`/etc. with attributes
      `Name`, `Type`, and one of `SettingBoolean`/`SettingNumber`/`SettingString`.
      `identity = f"{Type}:{Name}"`, `display_name = Name`,
      `display_value = ` the present `Setting*` value as string.
    - `Registry`, `Windows Registry`: identity from registry coordinates when
      present (`KeyName`/`Key` + `ValueName`/`Name`); else fall to generic.
    - **Generic fallback** (any other CSE or shape):
      `identity = f"{cse}:{block_localname}:{stable_hash(raw)}"`,
      `display_name = block_localname`, `display_value = ` first non-empty text/attr.
- Note: perfect per-CSE identity is a Tier-2.5 concern; slice 1 must be correct
  for `Security` (clean keys) and not crash on anything else.

### AC-06a: element → dict
`ingest.element_to_dict(elem) -> dict` recursively renders an element as
`{"@attr": ..., "tag": <localname>, "text": ..., "children": [...]}` (or an
equivalent lossless nested form). Deterministic ordering.

## AC-07: Parse delegation
From `SecurityDescriptor/Permissions`, emit a `DelegationEntry` per trustee/right:
`trustee` (display name), `trustee_sid` (SID if present, else None),
`permission` (normalized label — at minimum preserve the report's permission/
right name), `allowed` (Allow vs Deny). Goal: enough to later detect a GPO
lacking Authenticated Users / Domain Computers apply/read. If `PermissionsPresent`
is false, emit none.

## AC-08: Parse topology
`ingest.parse_inheritance(json_path) -> list[Som]`: one `Som` per record in
`gp-inheritance.json` (a JSON array). `path`/`name`/`container_type`/
`inheritance_blocked` from the like-named keys; for each `InheritedGpoLinks[]`
entry append a `SomLink` with `gpo_id=canonical_guid(GpoId)`, `order=Order`,
`enabled=Enabled`, `enforced=Enforced`, `target=Target`. Must handle the work
export's 1,551 records without pathological slowdown.

## AC-09: Merge metadata
`ingest.merge_metadata(json_path, gpos: list[Gpo]) -> None` reads
`gpo-metadata.json` and, joining on `canonical_guid(Id)`, sets each GPO's
`wmi_filter` (the `WmiFilter` name or None) and back-fills version fields if a
report value was missing. Unmatched metadata rows are ignored (logged at debug).

## AC-10: Attach SYSVOL paths
`ingest.attach_sysvol_paths(sysvol_dir, gpos) -> None` matches each GPO to its
`SYSVOL-Policies/{GUID}` directory by canonical id and sets `sysvol_path` (absolute).
Missing dir → leave None (do not error). No file *contents* are read here.

## AC-11: Load a full estate
`ingest.load_estate(sample_dir: str | Path) -> Estate` orchestrates the above for
one extracted export directory: parse `AllGPOs.xml` → gpos; `gp-inheritance.json`
→ soms; merge `gpo-metadata.json`; attach `SYSVOL-Policies/` if present (optional).
`Estate.domain` = the GPOs' common domain. Tolerates a missing optional input
(metadata/sysvol) by skipping that enrichment; a missing `AllGPOs.xml` raises
`FileNotFoundError`.
