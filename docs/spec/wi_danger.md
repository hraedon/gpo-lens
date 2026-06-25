# Work Item: Dangerous-configuration detectors (Plan 018 Phase B)

## Dependencies

- `interface_ref`: `model` (`DangerFinding` re-exported from here; `SEVERITY_ORDER`,
  `Estate`, `AdmxResolver` Protocol, `ResolvedPrincipal`)
- `interface_ref`: `authz` (`parse_sddl`, `parse_sddl_rights`, `is_allow_ace_type`,
  `resolve_principal`)
- `interface_ref`: `detection` (`scan_local_groups`, `_has_write_right`,
  `_is_default_writer_sid` — private helpers promoted to cross-module contract)
- `interface_ref`: `admx_parser` (`PolicyDefinitions` satisfies `AdmxResolver`;
  passed in by the caller, never imported)
- Reference: `plans/018-admx-policy-names-and-dangerous-config-detectors.md`
  (the "what" — Phase B). This spec formalizes the testable acceptance
  criteria for the implemented surface.
- Decision-record (Plan 018 §B.0–B.6): B.0 inclusion bar (known attack
  primitive or boundary-weakening, with citation), B.1 two-bucket split,
  B.2 minimal-mechanism (typed detectors + TOML data table), B.3 frame as
  fact-about-GPO, B.5 calibration discipline, B.6 AC-6..AC-11.

## Notes

This module is the curated, cited dangerous-configuration surface. It is a
**core module**: no I/O except reading the rules TOML (`load_danger_rules`),
no model calls, no `narration`/`web` imports (architectural boundary enforced
by `tests/_arch.py`, which lists `danger` in `CORE_MODULES`).

Two buckets, matched to their mechanics (Plan 018 §B.1):

- **Bucket 2 — structural / attack-path**: typed detectors reusing the
  SDDL/delegation/GPP parse from `authz` / `detection`. Three functions:
  `gpo_writable_by_nonadmin`, `local_admin_push`, `overbroad_apply_group_policy`.
- **Bucket 1 — setting-value dangers**: a small cited TOML data table +
  one pure evaluator `evaluate_danger_rules`. The shipped table lives at
  `src/gpo_lens/danger_rules.toml` (see AC-16).

Both emit one typed `DangerFinding` carrying a required `reference`. Findings
are framed as **facts about the GPO** (Plan 018 §B.3 "Flag, don't
simulate") — they make no per-principal effective-state claim. Overridden
dangers are still worth flagging because the override is fragile.

### Drift / known simplifications vs Plan 018

- **Drift — shipped rules file is a single TOML, not a directory.** Plan 018
  §B.2 specified `src/gpo_lens/danger_rules/*.toml` (a subdirectory of
  rule files). The implementation ships a single file,
  `src/gpo_lens/danger_rules.toml`, and exposes drop-in overrides via the
  `GPO_LENS_DANGER_RULES_DIR` environment variable instead (AC-13). Same
  capability, different shape — documented here, not "fixed."
- **Drift — Bucket 1 calibration is a measured zero.** Plan 018 §B.5 / AC-11
  require a calibration test with a known-good expected count for every
  shipped check. The shipped Bucket 1 rules target raw `HKLM\...`
  registry-preference identities, but both sample estates use
  ADMX-managed `Registry:Policy:*` identities, so the rules produce zero
  findings on the calibration estates
  (`tests/test_calibration.py::test_danger_bucket1_work/lab`). This is
  documented in the test comment as "an expected, measured fact, not a
  rule defect" — the rules are correct, they just don't fire on these
  particular estates. Bucket 2 calibration asserts 35 findings on the
  work estate (AC-03/AC-04 contributors only).
- **Severity is not validated by the loader.** `_load_rules_file` accepts
  any string for `severity`. Tests are internally inconsistent
  (`test_load_danger_rules_ships_cited_set` excludes `"info"`;
  `test_shipped_rules_parse` allows it). The runtime sort (AC-15) buckets
  any unknown severity to rank 99 — i.e. *last* — so an unknown severity
  is observable but not fatal.
- **Invalid-predicate entries are silently dropped (no warning).** This
  differs from the missing-fields and non-dict-entry cases, which emit a
  `warnings.warn` (AC-14). The shipped table uses only `equals` and `in`.
- **`danger_findings` does not accept a `rules_path` argument.** Callers
  must call `load_danger_rules(path)` themselves and pass `rules=...`.
  This is the only way to evaluate a non-default rules file through the
  aggregate.
- **`overbroad_apply_group_policy` skips the SDDL fallback whenever
  delegation is non-empty, even if the delegation has no over-broad
  hit.** This is intentional (the delegation list is treated as
  authoritative when present) and is asserted by
  `test_no_sddl_fallback_when_delegation_populated`. A GPO with both a
  populated delegation *and* an over-broad SDDL ACE that is not reflected
  in delegation will not be flagged — surface delegation truthfully in
  the collector if you need the SDDL fallback to apply.
- **The `_format_trustee` helper is private** but is the cross-module
  rendering contract for trustee display: `"name (sid)"` when resolved,
  raw SID when unresolved. Tests assert both forms.

## Module map

`src/gpo_lens/danger.py` — core module. No `narration`/`web` imports
(`tests/_arch.py`). Reads `danger_rules.toml` and the
`GPO_LENS_DANGER_RULES_DIR` directory; otherwise pure.

| Public surface | Role |
|----------------|------|
| `ComplianceMapping` (frozen dataclass) | One compliance framework control mapping. Fields: `framework` (e.g. `"CIS"`, `"STIG"`, `"NIST-800-171"`), `control_id` (e.g. `"18.6.2"`, `"WN10-CC-000038"`). |
| `DangerFinding` (frozen dataclass) | One finding. Fields: `check_id, severity, title, gpo_id, gpo_name, detail, reference, compliance, remediation`. `compliance` is a `tuple[ComplianceMapping, ...]` (default `()`). `remediation` is a `str` (default `""`). |
| `DangerRule` (frozen dataclass) | One cited TOML rule. Fields: `id, title, severity, applies, identity, predicate, value, reference, compliance, remediation`. `compliance` is a `tuple[ComplianceMapping, ...]` (default `()`). `remediation` is a `str` (default `""`). |
| `gpo_writable_by_nonadmin(estate) -> list[DangerFinding]` | Bucket 2 — non-admin write ACEs and non-admin Owner. |
| `local_admin_push(estate) -> list[DangerFinding]` | Bucket 2 — local Administrators group membership adds. |
| `overbroad_apply_group_policy(estate) -> list[DangerFinding]` | Bucket 2 — Everyone/Anonymous apply scope. |
| `evaluate_danger_rules(estate, rules, admx=None) -> list[DangerFinding]` | Bucket 1 — pure rule evaluator. |
| `load_danger_rules(rules_path=None) -> list[DangerRule]` | Load shipped + env-drop-in rules. |
| `danger_findings(estate, *, admx=None, rules=None) -> list[DangerFinding]` | Aggregate — run all four detectors and sort. |

`__all__` exports exactly: `ComplianceMapping`, `DangerFinding`, `DangerRule`,
`danger_findings`, `evaluate_danger_rules`, `gpo_writable_by_nonadmin`,
`load_danger_rules`, `local_admin_push`, `overbroad_apply_group_policy`.

Module-private but load-bearing (cross-module contract via `detection`):
`_load_rules_file`, `_format_trustee`, `_predicate_matches`, `_side_matches`,
`_identity_matches`, `_resolve_display_name`, `_parse_compliance`,
`_BROAD_APPLY_SIDS`, `_REGISTRY_CSES`, `_VALID_PREDICATES`,
`_REQUIRED_RULE_FIELDS`, `_BUCKET2_COMPLIANCE`, `_BUCKET2_REMEDIATION`,
`_GPO_MODIFY_REF`, `_LOCAL_ADMIN_REF`, `_APPLY_GP_REF`.

---

## AC-01: Module purity and import boundary

`danger.py` is a core module. It imports only from `gpo_lens.authz`,
`gpo_lens.detection`, `gpo_lens.model`, the stdlib (`os`, `tomllib`,
`warnings`, `dataclasses`, `pathlib`, `typing`), and — under
`TYPE_CHECKING` only — `gpo_lens.model`'s `AdmxResolver` / `Estate` for
type hints. It must never import `gpo_lens.narration` or `gpo_lens.web`
(enforced by `tests/_arch.py::forbidden_imports_in("danger")`).

The `admx: AdmxResolver | None` parameter is passed in by the caller; the
module never parses ADMX files itself and never imports `admx_parser` at
runtime (only under `TYPE_CHECKING`). `PolicyDefinitions` satisfies the
`AdmxResolver` Protocol (`tests/test_danger.py::TestAdmxResolverProtocol`).

## AC-02: `DangerFinding`, `DangerRule`, and `ComplianceMapping` dataclass shapes

Both `DangerFinding` and `DangerRule` are `@dataclass(frozen=True)`.
`ComplianceMapping` is also `@dataclass(frozen=True)`.

`ComplianceMapping` fields (all `str`):

| Field | Meaning |
|-------|---------|
| `framework` | Compliance framework name, e.g. `"CIS"`, `"STIG"`, `"NIST-800-171"`. Must be non-empty (validated at load time). |
| `control_id` | The framework's control identifier, e.g. `"18.6.2"`, `"WN10-CC-000038"`, `"3.1.2"`. Must be non-empty (validated at load time). |

`DangerFinding` fields:

| Field | Type | Source |
|-------|------|--------|
| `check_id` | `str` | The detector's stable identifier (e.g. `"gpo_writable_nonadmin"`, `"wdigest_creds"`). |
| `severity` | `str` | One of `"critical" "high" "medium" "low"` for shipped detectors; not validated by the loader. |
| `title` | `str` | Short human-readable headline. |
| `gpo_id` | `str` | Canonical GPO id, or `""` for estate-wide findings (AC-12). |
| `gpo_name` | `str` | GPO display name, or `""`. |
| `detail` | `str` | Free-form detail string. May embed resolved principal names (AC-03/AC-04). |
| `reference` | `str` | External citation URL. Always non-empty for shipped detectors. |
| `compliance` | `tuple[ComplianceMapping, ...]` | Compliance framework control mappings (default `()`). Propagated from the `DangerRule` for Bucket 1 findings, or from `_BUCKET2_COMPLIANCE` for Bucket 2 findings. |
| `remediation` | `str` | Concise, actionable fix guidance (default `""`). Propagated from the `DangerRule` for Bucket 1 findings, or from `_BUCKET2_REMEDIATION` for Bucket 2 findings. |

`DangerRule` fields:

| Field | Type | Meaning |
|--------|------|---------|
| `id` | `str` | Stable rule identifier (unique within the loaded set; drop-ins override by id — AC-13). |
| `title` | `str` | Headline copied to the finding. |
| `severity` | `str` | Copied to the finding; not validated. |
| `applies` | `str` | Side selector: `"Machine"`, `"User"`, or `"Both"` (AC-09). |
| `identity` | `str` | Raw registry identity (`HKLM\...:valueName`) **or** an ADMX policy display name (AC-10). |
| `predicate` | `str` | One of `equals in min max present absent` (AC-11). |
| `value` | `str` | Always coerced to `str` at load time (AC-14). |
| `reference` | `str` | External citation URL. |
| `compliance` | `tuple[ComplianceMapping, ...]` | Parsed from `[[rules.compliance]]` sub-tables in the TOML (default `()`). |
| `remediation` | `str` | Optional remediation text loaded from the `remediation` key in the TOML rule (default `""`). |

### Compliance TOML format

Each rule may carry zero or more `[[rules.compliance]]` sub-tables:

```toml
[[rules]]
id = "wdigest_creds"
# ... required fields ...
[[rules.compliance]]
framework = "CIS"
control_id = "18.6.2"
[[rules.compliance]]
framework = "STIG"
control_id = "WN10-CC-000038"
```

The `_parse_compliance(raw, path)` function validates each entry:
rejects non-table entries, entries with non-string `framework`/`control_id`,
and entries with empty or whitespace-only `framework`/`control_id` (each
rejected with a `warnings.warn`). Bucket 2 structural checks use the
`_BUCKET2_COMPLIANCE` constant (not TOML) — STIG is omitted for
`gpo_writable_nonadmin`, `gpo_owner_nonadmin`, and `local_admin_push` because
there is no direct Windows 10 endpoint STIG for GPO permission checks (these
are AD-level concerns).

### Remediation text

Each rule may carry an optional `remediation` string in the TOML:

```toml
[[rules]]
id = "wdigest_creds"
# ... required fields ...
remediation = "Set UseLogonCredential to 0. ..."
```

The loader reads `remediation` via `str(entry.get("remediation", ""))`,
defaulting to `""` when absent. The text is propagated to `DangerFinding`
via `evaluate_danger_rules` (both present and absent findings) and to the
CLI / web UI for display.

Bucket 2 structural checks use the `_BUCKET2_REMEDIATION` constant dict
(not TOML) — keyed by `check_id`, with one concise remediation string per
detector (`gpo_writable_nonadmin`, `gpo_owner_nonadmin`,
`local_admin_push`, `overbroad_apply_gp`). The text is attached at finding
creation time via `remediation=_BUCKET2_REMEDIATION.get(check_id, "")`.

## AC-03: `gpo_writable_by_nonadmin` — DACL write-ACE detection

```python
def gpo_writable_by_nonadmin(estate: Estate) -> list[DangerFinding]: ...
```

For each GPO with non-empty `g.sddl`:

1. Parse via `parse_sddl(g.sddl)` (returns `SddlAcl`).
2. For each ACE in `acl.dacl`:
   - Skip if `not is_allow_ace_type(ace.ace_type)` — both `"A"` (allow)
     and `"OA"` (object-allow) pass; deny ACEs are skipped
     (`test_detects_object_allow_ace`, `test_ignores_real_default_gpo_dacl`).
   - Skip if `not _has_write_right(ace.rights)` — the write-rights set is
     `{"GA", "GW", "WD", "WO", "SD", "DT", "WP", "DC", "CC"}`
     (defined in `detection.py:_WRITE_RIGHTS`). Generic Read (`GR`)
     alone does not qualify (`test_ignores_read_only_ace`).
   - Skip if `ace.trustee_sid` is empty or
     `_is_default_writer_sid(ace.trustee_sid)` returns True (AC-05).
   - Otherwise emit one `DangerFinding`:
     - `check_id="gpo_writable_nonadmin"`, `severity="high"`.
     - `title="GPO writable by a non-admin trustee"`.
     - `detail=f"Trustee {trustee_display} has write access ({ace.rights}) to this GPO — a GPO-hijack primitive"`.
     - `reference=_GPO_MODIFY_REF` = `https://attack.mitre.org/techniques/T1484/001/`.

The trustee is rendered via `_format_trustee(estate, sid)`:

- If `resolve_principal(estate, sid).resolved` → `f"{name} ({sid})"`
  (`test_detail_shows_resolved_name_with_sid`).
- Else → the raw SID string, with no `" (sid)"` suffix
  (`test_detail_unresolved_shows_sid_only`). This avoids the redundant
  `"sid (sid)"` form when the principal is unknown.

GPOs without `sddl` produce no findings (`test_no_sddl_no_finding`).
Finding order within a GPO is: Owner finding first (AC-04), then DACL
findings in `acl.dacl` iteration order. GPO iteration follows
`estate.gpos` order.

## AC-04: `gpo_writable_by_nonadmin` — non-admin Owner check

Same function as AC-03. After parsing the SDDL, if `acl.owner_sid` is set
and `not _is_default_writer_sid(acl.owner_sid)`:

- Emit `DangerFinding(check_id="gpo_owner_nonadmin", severity="high",
  title="GPO owned by a non-admin trustee", detail=f"GPO Owner is
  {owner_display} — the Owner implicitly holds WRITE_DAC and can
  escalate to full control", reference=_GPO_MODIFY_REF)`.

The owner is rendered via `_format_trustee` (same rules as AC-03).
`test_detects_nonadmin_owner` and `test_owner_detail_shows_resolved_name`
assert both the SDDL-owner-string form (`O:<sid>...`) and the resolved-name
detail. A GPO whose Owner is a default writer (e.g. `O:DA` alias → Domain
Admins) produces no owner finding (`test_ignores_admin_owner`,
`test_ignores_real_default_gpo_dacl`).

## AC-05: Default-writer SID set and write-rights set

`detection._is_default_writer_sid(sid)` returns True when:

- `resolve_well_known(sid)` matches one of
  `{"BUILTIN\\Administrators", "Domain Admins", "Enterprise Admins",
  "SYSTEM", "Creator Owner", "Creator Group", "Owner Rights"}`, **or**
- `sid.lower()` starts with `"s-1-5-21-"` and ends with `"-512"` (Domain
  Admins) or `"-519"` (Enterprise Admins).

The Creator Owner / Creator Group / Owner Rights entries are deliberate:
no security principal ever authenticates as those placeholder identities,
so a write ACE for them is not a hijack primitive. Flagging them produced
a finding on every real GPO and buried the signal
(`test_ignores_real_default_gpo_dacl` is the regression test).

`detection._has_write_right(rights)` returns True when
`parse_sddl_rights(rights)` intersects
`{"GA", "GW", "WD", "WO", "SD", "DT", "WP", "DC", "CC"}`.

Both helpers live in `detection.py` and are shared with
`detection.excessive_writers`. They are private (`_`-prefixed) but are a
cross-module contract: renaming or narrowing them silently changes
`danger.py` output.

## AC-06: `local_admin_push`

```python
def local_admin_push(estate: Estate) -> list[DangerFinding]: ...
```

For each GPO, iterate `detection.scan_local_groups(g)` (which walks
`Preferences/LocalUsersAndGroups.xml` and `Preferences/Groups.xml`).
For each `LocalGroupMod`:

- The group is "admin" if
  `(mod.group_sid and mod.group_sid.upper() == "S-1-5-32-544")` **or**
  `"ADMIN" in (mod.group_name or "").upper()`.
- The mod is a push only if `mod.members_added` is non-empty — a group
  that only removes members does not qualify
  (`test_ignores_admin_group_with_no_adds`).

For each qualifying push, append
`f"adds {', '.join(mod.members_added)} to '{mod.group_name}'"` to a
per-GPO list. If the list is non-empty, emit **one** `DangerFinding`
(deduplicated across groups within the GPO):

- `check_id="local_admin_push"`, `severity="high"`.
- `title="GPO pushes local Administrators membership"`.
- `detail="; ".join(pushes)`.
- `reference=_LOCAL_ADMIN_REF` = `https://attack.mitre.org/techniques/T1078/003/`.

Non-admin groups (e.g. `Remote Desktop Users`, RID `S-1-5-32-555`) produce
no finding (`test_ignores_non_admin_group`).

## AC-07: `overbroad_apply_group_policy` — delegation path

```python
def overbroad_apply_group_policy(estate: Estate) -> list[DangerFinding]: ...
```

For each GPO, scan `g.delegation` first. A delegation entry qualifies when
**all** are true:

- `d.allowed` is True (`test_ignores_denied`).
- `"apply group policy" in (d.permission or "").lower()` — case-insensitive
  substring.
- `(d.trustee_sid or "").lower() in _BROAD_APPLY_SIDS` where
  `_BROAD_APPLY_SIDS = {"s-1-1-0", "s-1-5-7", "wd", "an"}` — Everyone,
  Anonymous, and their SDDL alias forms.

On the first qualifying entry for the GPO, emit one finding, set
`found=True`, and `break` out of the delegation loop. Then `continue` to
the next GPO (skipping the SDDL fallback — AC-08).

The finding is:

- `check_id="overbroad_apply_gp"`, `severity="medium"`.
- `title="GPO apply scope is over-broad (Everyone/Anonymous)"`.
- `detail=f"'Apply Group Policy' granted to {d.trustee or sid} ({sid})"`
  — note this branch uses `d.trustee or sid` directly, **not**
  `_format_trustee`, so the delegation list's stored name is used as-is
  (`test_overbroad_detail_shows_resolved_name`).
- `reference=_APPLY_GP_REF` (Microsoft security-filtering doc).

A non-broad trustee (e.g. `S-1-5-21-...-1000`) does not match
(`test_ignores_helpdesk_apply`).

## AC-08: `overbroad_apply_group_policy` — SDDL fallback path

If and only if the delegation scan produced no hit **and**
`g.delegation` is empty **and** `g.sddl` is non-empty, fall back to
parsing the SDDL:

1. `acl = parse_sddl(g.sddl)`.
2. For each ACE in `acl.dacl`:
   - Skip if `not is_allow_ace_type(ace.ace_type)`.
   - `sid = (ace.trustee_sid or "").lower()`; skip if not in
     `_BROAD_APPLY_SIDS`.
    - `rights = set(parse_sddl_rights(ace.rights))`; skip if
     `not (rights & READ_OR_APPLY_RIGHTS)` where
     `READ_OR_APPLY_RIGHTS = {"GA", "GR", "CC", "CR", "RP"}` (imported from `authz`).
   - Emit one finding, `break`.

The finding uses `_format_trustee(estate, ace.trustee_sid)` for the
trustee display (so the SDDL-fallback branch resolves SIDs through
`resolve_principal`, unlike the delegation branch):

- `detail=f"SDDL grants apply rights to {trustee_display} ({ace.rights})"`
  (`test_overbroad_sddl_fallback_detail_shows_resolved_name`).
- Other fields identical to AC-07.

**Verdict invariance:** principal resolution changes the *detail* string
but never the *set* of findings
(`test_overbroad_verdict_invariant_with_principals`). Same check_id +
same gpo_id set with and without `estate.principals` populated.

**SDDL fallback is suppressed whenever delegation is non-empty**, even if
delegation has no broad-apply hit (`test_no_sddl_fallback_when_delegation_populated`,
see also Notes).

## AC-09: `evaluate_danger_rules` — registry-only, side-filtered

```python
def evaluate_danger_rules(
    estate: Estate,
    rules: list[DangerRule],
    admx: AdmxResolver | None = None,
) -> list[DangerFinding]: ...
```

Rules are evaluated only against Registry CSE settings. A setting is a
candidate when:

- `s.cse in ("Registry", "Windows Registry")` — the only CSEs bucketed
  as registry-like. Other CSEs (Security, Scripts, GPP, …) are skipped.
- `s.source_state != "blocked"` — settings whose `Registry.pol` could not
  be resolved from a `<Blocked/>` extension are skipped
  (`test_blocked_settings_skipped`). Unblocked is the default.
- `_side_matches(rule.applies, s.side)`:
  - `applies == "Both"` → any side.
  - `applies == "Machine"` → `s.side == "Computer"` only
    (`test_side_filter_machine_excludes_user`).
  - `applies == "User"` → `s.side == "User"` only.

The active-rules pass (all predicates except `absent`) iterates
`rules → estate.gpos → g.settings` in input order and emits one finding
per qualifying (rule, setting) pair (AC-11).

## AC-10: `evaluate_danger_rules` — identity match (raw + ADMX)

`_identity_matches(rule, setting_identity, admx)` returns True when
either:

1. `setting_identity.lower() == rule.identity.lower()` — direct
   case-insensitive registry-path match (`test_case_insensitive_identity`).
   Works without an ADMX source.
2. If `admx is not None`: `_resolve_display_name(admx, setting_identity)`
   returns a string equal to `rule.identity`. This is the policy-name-keyed
   path — the rule's `identity` is the ADMX display name
   (`test_admx_name_keyed_resolves`).

`_resolve_display_name` calls `admx.resolve_display_name(identity)` and
returns `None` for any non-string result, so a resolver that returns
`None`/raises-with-sentinel degrades cleanly.

**Graceful degradation (Plan 018 AC-9):** with `admx=None`, name-keyed
rules (whose `identity` is a display name, not a registry path) produce
**zero** matches — no crash, no silent all-match
(`test_admx_none_degrades_gracefully`).

## AC-11: `evaluate_danger_rules` — predicates

`_predicate_matches(rule, value: str) -> bool` dispatches on
`rule.predicate`. Value is the setting's `display_value` (always a string
in the normalized model; coerced via `.strip()`):

| Predicate | Behavior |
|-----------|----------|
| `"equals"` | `v.lower() == rule.value.strip().lower()` (case-insensitive equality). |
| `"in"`     | `rule.value` is comma-separated; `v.lower()` must be in `{x.strip().lower() for x in value.split(",")}`. |
| `"present"`| Always True — the setting exists and is unblocked. |
| `"min"`    | `float(v) >= float(rule.value)`; `ValueError` → False (non-numeric never matches). |
| `"max"`    | `float(v) <= float(rule.value)`; `ValueError` → False. |
| `"absent"` | Handled separately (AC-12), never reaches `_predicate_matches`. |

An unknown predicate (anything else) returns False from `_predicate_matches`
and is also rejected at TOML-load time (AC-14). `_VALID_PREDICATES` is the
single source of truth: `frozenset({"equals", "in", "min", "max",
"present", "absent"})`.

For each (rule, setting) match, emit a `DangerFinding` with:

- `check_id=rule.id`, `severity=rule.severity`, `title=rule.title`.
- `gpo_id=g.id`, `gpo_name=g.name`.
- `detail=f"{s.identity} = {s.display_value}"`.
- `reference=rule.reference`.
- `compliance=rule.compliance`, `remediation=rule.remediation`.

## AC-12: `evaluate_danger_rules` — `absent` predicate (estate-wide)

Rules with `predicate == "absent"` are split into a separate list before
the active-rules pass. For each absent rule:

1. Scan all GPOs' Registry CSE settings. Unlike the active-rules pass,
   `source_state == "blocked"` settings are **not** skipped — the rule
   asks "is this setting configured anywhere," and a blocked setting is
   still configured (its `Registry.pol` just couldn't be decoded).
2. If any setting's identity matches (`_identity_matches`, same as AC-10),
   set `found_any=True` and break out of both the settings loop and the
   GPO loop.
3. If no match was found, emit a single `DangerFinding`:
   - `gpo_id=""`, `gpo_name=""` — estate-wide finding, not anchored to a GPO.
   - `detail=f"Expected setting not found estate-wide: {rule.identity}"`.
   - Other fields from the rule (`compliance`, `remediation`).

Return value is `present_findings + absent_findings` — active-rule
findings first (in rule, GPO, setting order), then absent findings (in
rule order). This ordering is preserved into the aggregate (AC-15) only
for ties on `(severity, check_id, gpo_id)`.

## AC-13: `load_danger_rules` — file resolution and env drop-in

```python
def load_danger_rules(rules_path: Path | None = None) -> list[DangerRule]: ...
```

- If `rules_path is not None`: load **only** that file. No env-dir merge
  (`test_invalid_predicate_skipped_at_load` constructs a path and gets
  exactly that file's rules back). This is the testing/custom-rules hook.
- Else load the shipped file at
  `Path(__file__).resolve().parent / "danger_rules.toml"` via
  `_load_rules_file` (AC-14).
- Then consult `os.environ.get("GPO_LENS_DANGER_RULES_DIR")`. If unset or
  not a directory, return the shipped rules as-is.
- If it is a directory, iterate `sorted(env_path.glob("*.toml"))`
  (lexicographic filename order), load each via `_load_rules_file`, and
  merge by `rule.id` into a `dict[str, DangerRule]` initialized from the
  shipped rules. **Later files override earlier ones; drop-ins override
  shipped.** Returns `list(merged.values())` — insertion order is
  shipped rules first, then each env file's contributions in filename
  order, with overrides updating in place.

This is Plan 018 §B.2's drop-in-override mechanism. Note the drift in
Notes: Plan 018 specified a `danger_rules/` subdirectory; the
implementation uses a single shipped file + env-var directory.

## AC-14: `_load_rules_file` — validation behavior

```python
def _load_rules_file(path: Path) -> list[DangerRule]: ...
```

- On `OSError` or `tomllib.TOMLDecodeError`: return `[]` silently (no
  warning) (`test_malformed_toml_returns_empty`).
- `raw_rules = data.get("rules", [])`. If not a `list`, emit
  `warnings.warn(f"Skipping danger rules in {path.name} ('rules' must be
  an array)")` and return `[]` (`test_rules_not_a_list_returns_empty`).
- For each entry in `raw_rules`:
  - If not a `dict`: warn
    `f"Skipping non-table entry in {path.name} (got {type(entry).__name__})"`
    and continue (`test_non_dict_entry_skipped`). Other entries in the
    same file still load.
  - `predicate = entry.get("predicate", "")`. If
    `predicate not in _VALID_PREDICATES`: silently skip (no warning)
    (`test_invalid_predicate_skipped_at_load`).
  - `missing = _REQUIRED_RULE_FIELDS - entry.keys()` where
    `_REQUIRED_RULE_FIELDS = {"id", "title", "severity", "applies",
    "identity", "reference"}`. If non-empty, warn
    `f"Skipping danger rule in {path.name} (missing: {sorted(missing)})"`
    and continue. **Note `predicate` and `value` are not in the required
    set** — `predicate` defaults to `""` (which then fails the
    `_VALID_PREDICATES` check above), and `value` defaults to `""`
    (`test_missing_required_fields_skipped_with_warning`).
  - Construct `DangerRule(..., value=str(entry.get("value", "")), ...)`.
    `value` is always stringified. `remediation` is read via
    `str(entry.get("remediation", ""))` and defaults to `""`.
  - Unknown/extra fields are silently ignored (forward-compatible,
    `test_extra_fields_ignored`).

A single malformed entry never prevents the other entries in the same
file from loading (`test_missing_required_fields_skipped_with_warning`
loads the `complete` rule alongside the rejected `missing_fields` rule).

## AC-15: `danger_findings` — aggregation and sort

```python
def danger_findings(
    estate: Estate,
    *,
    admx: AdmxResolver | None = None,
    rules: list[DangerRule] | None = None,
) -> list[DangerFinding]: ...
```

- If `rules is None`: `rules = load_danger_rules()` (loads shipped + env
  drop-ins, AC-13). Otherwise use the provided list as-is.
- Run the four detectors in this order and extend a single list:
  1. `gpo_writable_by_nonadmin(estate)`
  2. `local_admin_push(estate)`
  3. `overbroad_apply_group_policy(estate)`
  4. `evaluate_danger_rules(estate, rules, admx)`
- Sort the combined list by
  `key=lambda f: (_SEVERITY_ORDER.get(f.severity, 99), f.check_id, f.gpo_id)`.
  `_SEVERITY_ORDER = {"critical":0, "high":1, "medium":2, "low":3,
  "info":4}` (imported from `model.SEVERITY_ORDER`). Unknown severities
  sort last at rank 99 (`test_aggregate_sorted_by_severity`).

`admx` is forwarded only to `evaluate_danger_rules`. The Bucket 2
detectors never consult ADMX. `rules` is forwarded only to
`evaluate_danger_rules` — Bucket 2 detectors ignore it.

**Integration (Plan 018 AC-10):** `queries.estate_doctor` wraps each
finding as a `DoctorFinding(category=f"danger:{check_id}", ...)` with a
`[ref: ...]` suffix on the detail, propagating `compliance` and
`remediation` from the `DangerFinding`; `queries.estate_summary` exposes
`danger_finding_count = len(danger_findings(estate))`
(`tests/test_danger.py::TestIntegration`).

## AC-16: Shipped rule set (`danger_rules.toml`)

The shipped table at `src/gpo_lens/danger_rules.toml` contains exactly
these 5 rules (validated by `test_danger_rules_loaded` and
`test_load_danger_rules_ships_cited_set`):

| id | severity | applies | predicate | value |
|----|----------|---------|-----------|-------|
| `wdigest_creds` | critical | Machine | equals | `1` |
| `smb_signing_disabled` | high | Machine | equals | `0` |
| `lm_hash_enabled` | high | Machine | equals | `0` |
| `autoadmin_logon` | critical | Machine | equals | `1` |
| `ntlmv1_allowed` | high | Machine | in | `0,1` |

Every rule has an `http`-prefixed `reference` (ATT&CK or Microsoft doc),
unique `id`, and `applies ∈ {"Machine","User","Both"}`. Identity values
target raw `HKLM\...:valueName` registry paths (case-insensitive at
match time). The set is the defensible core per Plan 018 §B.0 — adding a
rule requires a citation and a calibration test (§B.5; see also the
Bucket 1 calibration drift in Notes).

## AC-17: Determinism

- All four detectors are pure functions of `(estate, rules, admx)`. No
  randomness, no time, no environment reads inside the detectors
  themselves (`load_danger_rules` reads `GPO_LENS_DANGER_RULES_DIR` —
  that is the only env-var touch in the module).
- Iteration order is stable: `estate.gpos` order for Bucket 2; for
  Bucket 1, `rules → estate.gpos → g.settings` order. List construction
  is append-only.
- The aggregate sort (AC-15) fully determines final order; ties on
  `(severity, check_id, gpo_id)` preserve detector-evaluation insertion
  order (CPython 3.7+ stable sort).
- No model calls, no `narration`/`web` imports (`tests/_arch.py`).
