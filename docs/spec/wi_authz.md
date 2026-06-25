# Work Item: Authorization primitives (SDDL parsing + principal resolution)

## Dependencies

- `interface_ref`: `model` (`SddlAce`, `SddlAcl`, `ResolvedPrincipal`,
  `Estate`).
- Consumers: `detection` (MS16-072, deny_aces, excessive_writers,
  `_is_default_writer_sid`, `_has_write_right`), `topology`
  (security-filtering, scope honesty), `danger` (SDDL-derived findings),
  `merge` (security-gate SDDL evaluation), `ingest.parse_principals`
  (loads `principals.json`).
- Reference: `plans/020-principal-resolution.md` (Phase A — static
  resolver + collected map + wiring). The SDDL parser pre-dates Plan 020
  (it was in `queries.py` / `detection.py` and was centralized here to
  stop drift — see the module docstring).

## Notes

This module is the **shared substrate** for SDDL parsing and
broad-trustee recognition. It is a **core module**
(`tests/_arch.py::CORE_MODULES`); no `narration`/`web` imports, no I/O,
no model calls. Everything is pure over its arguments.

The module **intentionally does not model Windows ACL evaluation** —
it only parses SDDL strings and recognizes well-known trustees. Verdict
logic (does this ACE apply? is this GPO security-filtered? is this
trustee a default writer?) lives in `detection`, `topology`, `danger`,
and `merge`. `authz` provides the **vocabulary** those callers share.

### Charter stance — SID is canonical

Per Plan 020 decision 2, **the SID is the source of truth; the name is
a point-in-time annotation.** Every resolver returns the original SID
alongside any resolved name. Detectors (`danger`, `topology`, `merge`)
key on SID — names are added only for display legibility and never
change a verdict (Plan 020 decision 4 / AC-5). A name can drift (rename,
delete) between collection runs; the SID cannot.

### Drift / known simplifications vs Plan 020

- **The plan called for one resolver with two fallbacks; the
  implementation has two resolvers.** `resolve_well_known(sid)` covers
  the static table only (no `Estate` argument — for callers like
  `authz.is_default_writer_sid` that work on a bare SID). 
  `resolve_principal(estate, sid)` is the full resolver: well-known
  table → `estate.principals` → unresolved fallback (AC-09). Both are
  public. The split is deliberate — `resolve_well_known` is the
  dependency-free tier.
- **The SDDL parser pre-dates Plan 020 and was moved here from
  `queries.py` / `detection.py`.** Plan 020 didn't spec the parser; the
  ACs below (AC-01..AC-08) formalize its current behavior. The
  `1_048_576`-byte SDDL cap (AC-08) is the only parser-specific
  invariant the plan didn't contemplate — it's a defensive bound
  against pathological inputs.
- **`_BUILTIN_WELL_KNOWN` has duplicate name mappings** for RIDs 554/555
  (both `"BUILTIN\\Pre-Windows 2000 Compatible Access"`) and aliases
  `ps`/`ao`-`so`-`po` are aliased redundantly (548 → Account Operators
  via both `br` and `ao`; 549 via both `bf` and `so`; 550 via both `bp`
  and `po`). These mirror Microsoft's well-known SID table exactly —
  they are not bugs, just deliberate duplication.
- **`_MANDATORY_LABEL_WELL_KNOWN` is the only "always-absolute" SDDL
  prefix table.** Mandatory-label SIDs (`S-1-16-*`) carry no
  domain-relative RID; the whole SID is the key. BUILTIN
  (`S-1-5-32-*`) strips the prefix and looks up the RID; domain
  (`S-1-5-21-*`) does the same. The lookup shape differs by SID family
  — see AC-10.
- **`parse_sddl_rights` walks 2-char codes from a known set.** An
  unknown 2-char code advances by **one** character (not two), so
  `RPWP` parses as `["RP", "WP"]` but `RXQR` (no `Q*` right) advances
  past `RX` cleanly and then errors on `QR` — silently dropped. This is
  the parse rule; never assume a single unknown code aborts the parse.
- **`parse_sddl` accepts SDDL strings even when malformed ACEs are
  embedded.** A bad ACE (wrong field count, unknown type) is silently
  dropped by `_parse_ace_string` returning `None`; the surrounding ACEs
  still parse (`test_parse_sddl_malformed_ace`).
- **`parse_sddl`'s section detection uses parenthesis-depth tracking**
  to avoid treating `D`, `S`, `G`, `O` characters *inside* a SID
  (e.g. `S-1-5-18` in the Owner position) as section headers. The
  `_find_section_starts` helper is the load-bearing defense against this
  misparse; if it breaks, Owner SID parsing breaks with it.
- **DACL flags prefix (e.g. `D:PAI`, `D:AR`, `S:AU`) is consumed but
  not exposed.** `parse_sddl` does not return DACL/SACL flags
  separately — only the ACEs after them are parsed. Callers cannot
  inspect whether `D:PAI` (protected + inherit-only) was set.
- **`resolve_principal` always lowercases the SID** before storing it
  on `ResolvedPrincipal.sid`. A caller passing `"S-1-5-11"` gets
  `sid="s-1-5-11"` back. This matches the canonical-GPO-id convention
  (AGENTS.md: lowercase, braces stripped) but is a one-way normalization
  — the original case is lost.

## Module map

`src/gpo_lens/authz.py` — stdlib-only (`warnings`, `typing`). Core
module (`tests/_arch.py`); pure functions, no I/O.

| Public surface | Role |
|----------------|------|
| `ACE_TYPE_MAP` (`dict[str, str]`) | SDDL ACE-type code → normalized label (7 entries, AC-02). |
| `READ_OR_APPLY_RIGHTS` (`frozenset[str]`) | SDDL right codes that convey read or apply access (`GA,GR,CC,CR,RP`). |
| `AU_SID`, `EVERYONE_SID`, `DOMAIN_SID_PREFIX`, `DOMAIN_COMPUTERS_RID_SUFFIX` | SID constants used by `broad_trustee_key`. |
| `DEFAULT_WRITER_NAMES` (`frozenset[str]`) | Default GPO writer trustee names (Admins, SYSTEM, placeholder identities). |
| `DEFAULT_WRITER_SID_SUFFIXES` (`frozenset[str]`) | SID suffixes for default writers (`-512`, `-519`). |
| `READ_IMPLYING_PERMISSIONS` (`frozenset[str]`) | GPMC grouped-permission labels that confer the READ access right. |
| `MS16_072_TRUSTEES` (`frozenset[str]`) | MS16-072 read-trustee name set (`{authenticated users, domain computers}`). |
| `SCOPE_BROAD_TRUSTEES` (`frozenset[str]`) | Scope-honesty broad-trustee name set (adds `everyone`). |
| `resolve_well_known(sid) -> str \| None` | Static well-known SID/RID → name (no Estate). |
| `resolve_principal(estate, sid) -> ResolvedPrincipal` | Full resolver: well-known → collected → unresolved. |
| `broad_trustee_key(trustee, sid, broad_names=SCOPE_BROAD_TRUSTEES) -> str \| None` | Canonical key for a broad trustee. |
| `applies_broadly(grants) -> bool` | Allow/deny set logic over trustee keys. |
| `is_allow_ace_type(ace_type) -> bool`, `is_deny_ace_type(ace_type) -> bool` | ACE-type predicates. |
| `is_default_writer(trustee) -> bool`, `is_default_writer_sid(sid) -> bool` | Default-writer predicates (name-based and SID-based). |
| `permission_implies_read(permission) -> bool` | True if a GPMC grouped-permission label confers READ. |
| `permission_implies_apply(permission) -> bool` | True if a GPMC grouped-permission label confers APPLY. |
| `SddlApplyAce` (frozen dataclass) | An allow ACE in the SDDL DACL that grants read/apply rights. |
| `iter_sddl_apply_aces(sddl, broad_names=SCOPE_BROAD_TRUSTEES) -> list[SddlApplyAce]` | Extract allow ACEs with read/apply rights from SDDL. |
| `parse_sddl_rights(rights) -> list[str]` | Extract 2-char SDDL right codes from a rights string. |
| `parse_sddl(sddl) -> SddlAcl` | Parse SDDL string → owner/group/DACL/SACL. |

`__all__` exports every public name above. Private load-bearing helpers:
`_ABSOLUTE_WELL_KNOWN`, `_BUILTIN_WELL_KNOWN`, `_DOMAIN_RID_WELL_KNOWN`,
`_MANDATORY_LABEL_WELL_KNOWN`, `_NAME_TO_KEY`, `_VALID_SDDL_RIGHTS`,
`_SDDL_SID_ALIASES`, `_BUILTIN_PREFIX`, `_MANDATORY_PREFIX`,
`_parse_ace_string`, `_find_section_starts`, `_extract_aces`.

---

## AC-01: Module purity and import boundary

`authz.py` is a core module. It imports only from `gpo_lens.model`
(`ResolvedPrincipal`, `SddlAce`, `SddlAcl`, and `Estate` under
`TYPE_CHECKING`) and the stdlib (`warnings`, `typing`). It must never
import `gpo_lens.narration` or `gpo_lens.web`
(`tests/_arch.py::forbidden_imports_in("authz")`). No I/O, no model
calls, no environment reads.

## AC-02: `ACE_TYPE_MAP` and the ACE-type predicates

`ACE_TYPE_MAP: dict[str, str]` has exactly these 7 entries:

| SDDL code | Normalized label |
|-----------|------------------|
| `"A"` | `"allow"` |
| `"D"` | `"deny"` |
| `"OA"` | `"object_allow"` |
| `"OD"` | `"object_deny"` |
| `"AU"` | `"audit_success"` |
| `"OU"` | `"audit_object"` |
| `"AL"` | `"alarm"` |

`is_allow_ace_type(ace_type)` returns `True` iff `ace_type in ("allow",
"object_allow")`. `is_deny_ace_type(ace_type)` returns `True` iff
`ace_type in ("deny", "object_deny")`. Audit/alarm types are neither
allow nor deny. These predicates operate on the **normalized label**
(after `ACE_TYPE_MAP` lookup), not on the raw SDDL code.

## AC-03: `parse_sddl_rights` — 2-char code extraction

```python
def parse_sddl_rights(rights: str) -> list[str]: ...
```

- Splits the input on `"|"`, then walks each part left-to-right
  extracting consecutive 2-char codes from `_VALID_SDDL_RIGHTS` (the
  24-code set: `GA GR GW GX RC SD WD WO RP WP CC DC LC LO DT CR FA FR
  FW FX KA KR KW KX`).
- When a 2-char window is in the set: append, advance by 2.
- When it isn't: advance by **1** (see Notes — never abort on unknown).
- Each part is `.strip().upper()`-ed before walking; output codes are
  uppercase.
- Empty string returns `[]`. `"GA"` returns `["GA"]`. `"RPWP"` returns
  `["RP", "WP"]`. `"GR|GW"` returns `["GR", "GW"]`.

## AC-04: `parse_sddl` — section detection

```python
def parse_sddl(sddl: str) -> SddlAcl: ...
```

`_find_section_starts` walks the SDDL string tracking parenthesis depth.
A character `ch ∈ "OGDS"` at depth 0 followed by `":"` starts a section
— this avoids misinterpreting `O`/`D`/`S`/`G` characters inside a SID
or ACE. `sections.setdefault(ch, i)` keeps the **first** occurrence of
each header.

For each detected section, in order of position:

- `"O"` → `owner_sid = raw.strip() or None`.
- `"G"` → `group_sid = raw.strip() or None`.
- `"D"` → `dacl = _extract_aces(raw)`.
- `"S"` → `sacl = _extract_aces(raw)`.

Section value runs from `sec_start + 2` to the next section's start
(or end of string). A `D:PAI(...)` prefix has its `PAI` flags consumed
as part of the value but ignored by `_extract_aces` (only parenthesized
ACEs are extracted). Missing sections leave the field as `None` (Owner/
Group) or `[]` (DACL/SACL).

## AC-05: `parse_sddl` — ACE extraction and tolerance

`_extract_aces(text)` walks `text` tracking parenthesis depth. Each
parenthesized group at depth 0..1 is one ACE candidate:

- `ace_str = text[open+1 : close]` (the contents between parens).
- `_parse_ace_string(ace_str)` splits on `";"`; if the result is not
  exactly 6 fields or the first field isn't in `ACE_TYPE_MAP`, return
  `None` (the ACE is **silently dropped**, `test_parse_sddl_malformed_ace`).
- Otherwise build `SddlAce(ace_type=ACE_TYPE_MAP[type_raw.upper()],
  flags=parts[1].strip(), rights=parts[2].strip(),
  object_guid=parts[3].strip(), inherit_object_guid=parts[4].strip(),
  trustee_sid=parts[5].strip())`.

Field values are **not validated** beyond the type-code lookup — any
string is accepted for `rights`/`flags`/`trustee_sid`. Empty fields
become `""`. Type-code lookup is `.upper()`-tolerant (`"a"` works like
`"A"`).

## AC-06: `parse_sddl` — return value and empty input

`parse_sddl` returns `SddlAcl(owner_sid, group_sid, dacl, sacl)` where
`dacl` and `sacl` are `tuple[SddlAce, ...]` (immutable). Empty input
`""` returns `SddlAcl(owner_sid=None, group_sid=None, dacl=(), sacl=())`
(`test_parse_sddl_empty`). Order of ACEs in `dacl`/`sacl` follows the
order they appear in the SDDL string. A SDDL with only `O:` and no
`D:`/`S:` produces empty tuples for both.

## AC-07: `parse_sddl` — section-order independence

Sections are processed in **position order**, not in the canonical `O
G D S` order. A SDDL string `D:(A;;GA;;;S-1-5-18)O:S-1-5-18` parses
the same as `O:S-1-5-18D:(A;;GA;;;S-1-5-18)`. This matches real-world
SDDL where section order is conventional but not guaranteed.

## AC-08: `parse_sddl` — 1MB defensive cap

If `len(sddl) > 1_048_576` (1 MiB), emit
`warnings.warn(f"SDDL exceeds 1MB cap ({len(sddl)} bytes); returning
empty ACL", stacklevel=1)` and return `SddlAcl(owner_sid=None,
group_sid=None, dacl=(), sacl=())`. This is a defensive bound against
pathological input; real GPO SDDL strings are kilobytes at most. The
warning is observable; nothing is raised.

## AC-09: `resolve_principal` — three-tier resolution

```python
def resolve_principal(estate: Estate, sid: str) -> ResolvedPrincipal: ...
```

The SID is `strip().lower()`-ed once (`canonical`). Then, in order:

1. **Well-known table** (AC-10): if `resolve_well_known(canonical)` is
   not None, return `ResolvedPrincipal(sid=canonical, name=wk, sam=wk,
   principal_type="WellKnown", domain="", resolved=True)`. The static
   table takes **precedence** over the collected map
   (`test_resolve_principal_well_known_takes_precedence_over_collected`).
2. **Collected map**: if `estate.principals.get(canonical)` is not None,
   return the stored `ResolvedPrincipal` as-is.
3. **Unresolved fallback**: return `ResolvedPrincipal(sid=canonical,
   name=canonical, sam="", principal_type="Unresolved", domain="",
   resolved=False)`. The raw SID is preserved as `name` so a display
   surface is never blank (Plan 020 decision 3 / AC-3).

The returned `sid` is always the **lowercased canonical** form. The
`name` may equal the SID (unresolved case) or be the resolved name.

## AC-10: `resolve_well_known` — static table, no Estate

```python
def resolve_well_known(sid: str) -> str | None: ...
```

Pure, no `Estate`. `sid.strip().lower()`. Resolution order:

1. **SDDL alias table** `_SDDL_SID_ALIASES` (e.g. `"da"` →
   `"Domain Admins"`, `"co"` → `"Creator Owner"`, `"wd"` →
   `"Everyone"`). Real SDDL emits these for the domain the object lives
   in (`O:DA` not `S-1-5-21-...-512`); resolving them is load-bearing
   for the danger owner-nonadmin check
   (`test_resolve_well_known_domain_relative_sddl_aliases`).
2. **Absolute well-known** `_ABSOLUTE_WELL_KNOWN` (15 entries,
   `S-1-1-0` through `S-1-5-1000`).
3. **Mandatory label** `_MANDATORY_LABEL_WELL_KNOWN` for SIDs starting
   with `S-1-16-` — the whole SID is the key (8 entries).
4. **BUILTIN** `_BUILTIN_WELL_KNOWN` for SIDs starting with `S-1-5-32-`
   — strip the prefix, look up the trailing RID (29 entries, RID as
   string).
5. **Domain-relative** `_DOMAIN_RID_WELL_KNOWN` for SIDs starting with
   `S-1-5-21-` and split into ≥7 dash-separated parts — look up the
   trailing RID (13 entries: `512` Domain Admins through `527`
   Enterprise Key Admins).
6. Otherwise return `None`.

Lookup is case-insensitive throughout. Unknown RIDs in a known family
return None (e.g. `S-1-5-32-999`, `S-1-5-21-123-456-789-99999`,
`S-1-9-0` — `test_resolve_well_known_returns_none_for_unknown_sids`).

## AC-11: `broad_trustee_key` — canonical trustee key

```python
def broad_trustee_key(
    trustee: str,
    sid: str | None,
    broad_names: Iterable[str] = SCOPE_BROAD_TRUSTEES,
) -> str | None: ...
```

Collapses a `(trustee_name, sid)` pair to one of three canonical keys,
or `None` if neither form is broad. Both fields are
`.strip().lower()`-ed. Resolution order:

1. **By name**: `_NAME_TO_KEY.get(trustee_lower)` if the trustee name is
   `"authenticated users"`, `"domain computers"`, or `"everyone"`, **and**
   that lowercased name is in the `broad_names` set. Returns the key
   (`authenticated_users` / `domain_computers` / `everyone`).
2. **By SID** (matched only if the corresponding trustee name is in
   `broad_names`):
   - `sid == AU_SID ("s-1-5-11")` + `"authenticated users" in broad_names`
     → `"authenticated_users"`.
   - `sid == EVERYONE_SID ("s-1-1-0")` + `"everyone" in broad_names` →
     `"everyone"`.
   - `sid.startswith("s-1-5-21-") and sid.endswith("-515")` + `"domain
     computers" in broad_names` → `"domain_computers"`.

The Domain Computers SID check requires the `s-1-5-21-` domain-SID
prefix — an arbitrary SID ending in `-515` does not match (WI-029
tightening). Pass `MS16_072_TRUSTEES` as `broad_names` to exclude
`Everyone` (used by the MS16-072 detector). Returns `None` for any
non-broad trustee.

## AC-12: `applies_broadly` — allow/deny set logic

```python
def applies_broadly(
    grants: Iterable[tuple[str | None, bool]],
) -> bool: ...
```

Iterates `grants` and partitions by `allowed`:

- `allowed: set[str]` — keys with `is_allowed=True`.
- `denied: set[str]` — keys with `is_allowed=False`.

`None` keys are ignored. Returns True iff **any** key in `allowed` is
**not** in `denied`. Deny precedence is per-trustee only — a deny on
`Everyone` does not block an allow on `Authenticated Users` (cross-
trustee set relationships are not modeled; see the `is_security_filtered`
docstring in `topology.py`). Empty input returns False.

## AC-13: `ResolvedPrincipal` dataclass shape

Defined in `model.py`, re-exported through `authz`:

| Field | Type | Notes |
|-------|------|-------|
| `sid` | `str` | Always lowercased canonical form. |
| `name` | `str` | Resolved name, or the raw SID when unresolved. Never blank. |
| `sam` | `str` | sAMAccountName; `""` for WellKnown/Unresolved. |
| `principal_type` | `str` | One of `"Group" "User" "Computer" "WellKnown" "Unresolved"`. |
| `domain` | `str` | NetBIOS domain or `""`. |
| `resolved` | `bool` | False iff the unresolved fallback was used. |

`@dataclass(frozen=True)` — hashable, suitable as a dict value or set
member. The shape is the contract for `principals.json` ingestion (see
`ingest.parse_principals`) and for every SDDL-derived display surface.

## AC-14: Determinism

- All functions are pure over their explicit arguments.
- SID/name canonicalization is deterministic: `strip().lower()` is the
  single normalization (no Unicode case-folding beyond `str.lower`).
- All dict lookups are by exact string equality after canonicalization.
- `_extract_aces` and `_parse_ace_string` produce ACEs in source order;
  `parse_sddl`'s output tuples preserve that order.
- The well-known tables (`_ABSOLUTE_WELL_KNOWN`, `_BUILTIN_WELL_KNOWN`,
  `_DOMAIN_RID_WELL_KNOWN`, `_MANDATORY_LABEL_WELL_KNOWN`,
  `_SDDL_SID_ALIASES`) are module-level constants. Extending or
  renaming a key is a behavior change for every consumer.
