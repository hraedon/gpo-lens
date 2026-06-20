# Work Item: Merge model and principal resultant (Plan 021)

## Dependencies

- `interface_ref`: `model` (`src/gpo_lens/model.py` — `Setting`, `Gpo`, `Estate`, `DangerFinding`)
- `interface_ref`: `topology` (`som_effective_gpos`)
- `interface_ref`: `detection` (`scan_ilt`)
- `interface_ref`: `authz` (`resolve_principal`, SDDL helpers)
- Reference: `plans/021-snapshot-rsop-and-merge-model.md` (the "what"); this
  spec formalizes the "what + acceptance criteria."
- Decision-record (in Plan 021, not duplicated here): D1 OUs only, D2 ILT
  exclusion (never silent), D3 conditional dangers, D4 "resultant given
  collected inputs" labeling, D5 user+computer pair composition.

## Notes

This module is the deterministic resultant-set calculator. It is **pure**:
no I/O, no model calls, no narration/web imports (architectural boundary
enforced by `tests/_arch.py`). All inputs are explicit arguments; the
output is a stable, testable dataclass tree.

The `overridden_by` ordering is a known simplification (AC-16). It is
**not** a bug — the chain-order insertion is stable and reproducible —
but it is not sorted descending. If a future caller needs descending
order, sort at the call site rather than mutating the field semantics.

`merge_settings` (the no-exclusions wrapper) is the call-site-compatible
shorthand; `merge_settings_with_exclusions` is the full surface. Always
prefer the full surface in new code unless ILT-gated items are
explicitly uninteresting for the call site.

The 8 `CseMergeMode` enum members are referenced by string value
(`enum.value`) when persisted to JSON or rendered in CLI output.
Renaming a member without a value migration is a breaking change.

## Module map

`src/gpo_lens/merge.py` — pure, deterministic. No I/O, no model calls, no
narration/web imports (enforced by `_arch.py`).

| Public surface | Role |
|----------------|------|
| `CseMergeMode` (Enum) | Per-CSE resolution mode. 8 values, see AC-01. |
| `cse_merge_mode(cse, setting=None) -> CseMergeMode` | Resolve the mode for a CSE + optional setting. |
| `ChainEntry` | One GPO's contribution at a SOM, with `order`, `enforced`, `settings`. |
| `MergedSetting` | A setting that survived merge-resolution. |
| `ExcludedSetting` | An ILT-gated GPP item (decision 2). Listed, not dropped. |
| `MergeResult` | Container for `settings` + `excluded_settings`. |
| `merge_settings(chain_entries, *, ilt_gpo_ids=None) -> list[MergedSetting]` | Convenience wrapper, returns only surviving. |
| `merge_settings_with_exclusions(...) -> MergeResult` | Full result with exclusions. |
| `PrincipalToken` | A principal's expanded SID set + caveats. |
| `build_token(estate, principal_sid) -> PrincipalToken` | Expand token from group membership. |
| `ExcludedGpo`, `ConditionalDanger` | Auxiliary types. |
| `PrincipalResultant` | Full effective-policy outcome for a principal. |
| `principal_resultant(estate, sid, computer_sid=None, *, dn=None, computer_dn=None, danger=None) -> PrincipalResultant` | Compose: token + chain + gate + merge + conditional dangers. |

---

## AC-01: CSE merge mode taxonomy

`CseMergeMode` has exactly these 8 members with the listed string values:

| Member | Value | Used by |
|--------|-------|---------|
| `LAST_WRITER_WINS` | `"last_writer_wins"` | Registry, scripts, security, most single-value policies |
| `UNION` | `"union"` | Security options (multi-value allow/deny lists) |
| `AUTHORITATIVE_REPLACE` | `"authoritative_replace"` | Restricted Groups / "Members"; Folder Redirection when `display_value` contains "replace" |
| `ADDITIVE` | `"additive"` | Restricted Groups / "Member Of" (union across all chain entries) |
| `ACCUMULATE` | `"accumulate"` | All GPP CSEs (drives, files, registry, scheduled tasks, etc.); the action state machine (`_resolve_gpp_actions`) resolves each bucket; software installation |
| `SINGLE_WINNER` | `"single_winner"` | IPSec / wireless / wired network policy (first-or-enforced wins) |
| `MERGE_REPLACE_FLAG` | `"merge_replace_flag"` | Folder Redirection fallback when `setting=None` or `display_value` contains neither "replace" nor "merge" |
| `APPROXIMATE` | `"approximate"` | Unknown / unsupported CSE names (no clean model — flag and list values) |

The `cse_merge_mode(cse, setting=None)` function maps a CSE name string
(case-insensitive, whitespace-tolerant) to the appropriate mode. The shipped
CSE name lists (`_REGISTRY_CSES`, `_SCRIPTS_CSES`,
`_SEC_RESTRICTED_GROUPS_TYPES`, `_GPP_CSES`, `_IPSEC_WIRELESS_CSES`,
`_FOLDER_REDIRECTION_CSES`) must remain the canonical mapping source —
extending them is the only way to add new CSEs.

`MERGE_REPLACE_FLAG` is the Folder Redirection sentinel value used when the
setting's `display_value` cannot be parsed (e.g. a corrupted or
non-standard value). It signals "we don't know the policy intent, treat
as approximate" rather than being a real merge mode. Folder Redirection
with `setting=None` (called only from internal code paths) also returns
`MERGE_REPLACE_FLAG`.

## AC-02: `merge_settings_with_exclusions` bucket key

Settings are bucketed by the tuple `(cse, side, identity)` — same identity in
different CSEs is a different bucket. Settings with `from_disabled_side=True`
are dropped from the bucket (not even recorded as exclusions; they were never
applied). GPP CSEs additionally extract the `action` via `_extract_gpp_action`
and store it on the `_BucketItem`.

## AC-03: Last-writer-wins picks highest-order non-disabled

For `LAST_WRITER_WINS` buckets, the winner is the `_BucketItem` with the
largest `order` (latest in the precedence chain). `enforced` does not change
the winner within a single bucket — enforcement only blocks items contributed
by deeper SOMs *upstream*, not within the chain already arriving at this
SOM. The `overridden_by` list records the GPOs whose contributions lost
(in ascending chain order — see AC-16).

## AC-04: UNION deduplicates and preserves the highest-order winner

For `UNION` (e.g. security options), the surviving value is the
highest-order winner's value; `overridden_by` lists the rest. (Note: this
is the current behavior — Union here is *applied across ordered items*,
with the winner recorded. A literal set-union of values across chain is
not produced; that ambiguity is a known simplification documented in
Plan 021.)

`overridden_by` semantics differ by mode (see `_merge_bucket`):

- **LAST_WRITER_WINS / AUTHORITATIVE_REPLACE / SINGLE_WINNER / APPROXIMATE:**
  only items with strictly lower `order` than the winner appear. Same-order
  ties are *not* recorded as overridden.
- **UNION / ADDITIVE / ACCUMULATE:** every non-winning item whose `order`
  differs from the winner appears. Same-order ties (where `it.order ==
  winner.order`) are *not* recorded — the first encountered wins by
  insertion order, and the rest are silently absorbed into the winner.

## AC-05: ADDITIVE / AUTHORITATIVE_REPLACE for Restricted Groups

For CSE `restricted groups`, the *setting type* (Members vs Member Of)
selects the mode: `Members` → `AUTHORITATIVE_REPLACE`, `Member Of` →
`ADDITIVE`. The dispatch is `_restricted_groups_mode(setting)` and is the
single source of truth — Plan 018 + Plan 021 describe it in prose but the
AC is the function.

## AC-06: ACCUMULATE merges by identity but preserves each task

For `ACCUMULATE` (GPP scheduled tasks), each distinct task identity is its
own bucket — multiple scheduled tasks in different GPOs produce multiple
`MergedSetting` rows, not one. Each task's own bucket resolves by
last-writer-wins.

## AC-07: ACCUMULATE / GPP action state machine

For GPP items (mode = `ACCUMULATE`), the `action` is one of `Create`,
`Replace`, `Update`, `Delete`. Items are processed in precedence→order
(lowest `order` first):

- `Delete` flips a `deleted` flag, clears the current item, and stays
  sticky — a later `Create` at higher order does **not** resurrect the
  item (Delete is permanent within the chain).
- `Replace` clears `deleted` and sets the current item.
- `Update` sets the current item unless `deleted` is set.
- `Create` sets the current item only if `current is None and not deleted`.

If at the end `deleted` is True or no current item exists, the bucket
returns `None` (the item does not survive). A GPP item with no `action`
attribute defaults to `"Update"`.

## AC-08: ILT-gated GPP items go to `excluded_settings`

When a setting is in a GPO listed in `ilt_gpo_ids`, the setting is *not*
merged. It is recorded as an `ExcludedSetting` with `kind="ilt"`. The
resulting `MergeResult.settings` does not contain the ILT-gated setting,
but `MergeResult.excluded_settings` does. This is decision 2 — never
silently dropped, never carried as a conditional survivor.

`merge_settings(chain_entries)` (the no-exclusions wrapper) returns only
`.settings` and is the call-site-compatible shorthand.

## AC-09: APPROXIMATE flags without resolving

`APPROXIMATE` buckets produce a `MergedSetting` with `approximate=True` and
`winning_value` from the highest-order contributor. `overridden_by` follows
the LAST_WRITER_WINS rule (AC-04): only strictly lower-order items appear.
The `approximate=True` flag is the user-visible signal that the result is
not authoritative — the value is the highest-order contributor's, not a
computed one.

## AC-10: `build_token` always includes Authenticated Users + Everyone

`build_token(estate, sid)` returns a `PrincipalToken` whose `token_sids`
always contains `s-1-5-11` (Authenticated Users) and `s-1-1-0` (Everyone),
plus the principal's own SID, plus its transitive group membership
(expanded in both directions through `estate.group_members`). For
domain-local principals it also adds `Domain Users` (`-513`) or
`Domain Computers` (`-515`) based on `principal_type`.

Token caveats are emitted as `"unresolved group SID: <sid>"` for any
membership that cannot be resolved — this includes foreign-domain SIDs,
domain-relative RID suffixes that don't match a known group, and
genuinely-unknown SIDs. There is no separate `"foreign sid"` caveat
category; a foreign SID is just one cause of an unresolved-group caveat.

## AC-11: `_evaluate_security_gate` returns (passes, reason)

A GPO passes the gate if the principal's `token_sids` intersects the set
of SIDs granted Apply (Read+Apply Group Policy = `GA`, `GR`, `CC`, `CR`,
or `RP` rights) on its DACL. `_gpo_apply_trustee_sids` expands
domain-relative trustee names (via `name_to_sid` + `domain_sid`) before
the intersection.

If the GPO has delegation/SDDL data but no resolvable Apply trustees,
the gate **fails** with reason `"security filter: no resolvable Apply
trustee SIDs in token"`. If the GPO has neither delegation nor SDDL
data, the gate is unknown — it returns `(True, "no delegation/SDDL
data — security filtering state unknown")`. Unknown is *not* a failure;
the chain treats it as passing because absence-of-evidence is not
evidence-of-deny.

## AC-12: `principal_resultant` composes 4 stages in order

1. Build the user token (and, if `computer_sid` is given, the computer
   token; union them for gate evaluation).
2. Resolve the user's SOM path via `_resolve_som_path_for_principal`
   (most-specific match for `dn`, else domain root, else first non-site
   SOM).
3. Build the chain via `som_effective_gpos`. For a user+computer pair,
   the user chain comes from `dn` and contributes User-side settings;
   the computer chain comes from `computer_dn` and contributes
   Computer-side settings. Loopback (user-side from the computer's OU)
   is **deferred** and recorded as a caveat.
4. For each chain entry, evaluate `_evaluate_security_gate`. Gated
   GPOs go to `excluded` (with the gate reason). Surviving GPOs feed
   `merge_settings_with_exclusions`.

The `danger=` parameter lets a caller inject pre-computed
`DangerFinding` objects; otherwise `principal_resultant` calls
`danger_findings(estate)` itself. This is the WI-031 dependency-injection
contract.

## AC-13: Conditional dangers surface gated-GPO risks

A `ConditionalDanger` is emitted for each `DangerFinding` whose GPO is in
the `excluded` (gated) list OR has any setting in `excluded_settings`.
This is decision 3 — never silently hide a danger behind a gate. The
finding is surfaced so an operator can decide whether to investigate.

## AC-14: Caveat summary is deterministic and complete

`PrincipalResultant.caveat_summary` is a single human-readable string built
by `_build_caveat_summary`. It is **not** the only caveat channel — the
structured `token_caveats` list (AC-10), `excluded` list (AC-12), and
`conditional_dangers` list (AC-13) are surfaced separately to non-debug
callers (CLI and web).

The summary covers counts, in this stable order:

1. Header label `"Resultant given collected inputs"`.
2. Free-form `(label)` parenthetical when present — currently only set
   for loopback-deferred runs.
3. Total surviving settings count.
4. Approximate settings count (when > 0).
5. Conditional settings count (always 0 today — AC-19).
6. Excluded (gate-failed / WMI / ILT GPO) count.
7. ILT-excluded setting count.
8. Conditional danger count.
9. Token caveat count.
10. `"computer pair"` suffix when running a user+computer pair.

The summary is intentionally terse — names of specific loopback / unknown
GPOs are *not* in the summary string; they appear in the structured
`excluded` / `token_caveats` lists. The summary's job is to give the
operator a one-glance health check; the structured fields carry the
detail.

## AC-15: User+computer pair semantics (decision 5)

When `computer_sid is not None` and the principal type is `User`:
- Token is the union of user-token and computer-token.
- User-side chain from `dn`; computer-side chain from `computer_dn`.
- Loopback (user-side from computer OU) is deferred and recorded as a
  caveat, not silently merged.
- WMI/ILT gated contributors on either chain go to the same
  `excluded` / `excluded_settings` buckets.
- If a GPO is linked at a shared ancestor (e.g. the domain root) it
  appears in *both* chains; deduplication of `excluded` entries by
  `gpo_id` keeps the output free of duplicate gate reasons.

When the principal is a `Computer` (single-side run):
- The chain is taken from `dn`.
- `_collect_chain_entries(chain, side, ...)` filters settings to
  `target_side == "Computer"`. User-side settings from the same chain
  are dropped — the computer-only resultant is Computer-side only.
- This is the existing simplification; the only way to see User-side
  settings for a machine account is to run with `principal_type="User"`.

## AC-16: Determinism and purity

- No I/O, no network, no model calls, no narration/web imports (architectural
  boundary; enforced by `_arch.py`).
- All inputs are explicit. `merge_settings` and `merge_settings_with_exclusions`
  take the `chain_entries` directly; `principal_resultant` takes the `Estate`
  and SID(s). No globals, no environment variables, no time, no randomness.
- All output ordering is stable: chain order (input order), bucket
  iteration (insertion order in CPython 3.7+), tie-break by `gpo_id`.
- `merged_setting.overridden_by` is in chain (ascending) order — i.e. the
  order items were appended to the bucket during iteration, which is
  ascending precedence order. This matches `_merge_bucket` exactly and
  is a known simplification (not sorted descending).

## AC-17: Performance floor

`merge_settings_with_exclusions` over a chain of 50 GPOs / 2,000 settings
completes in < 50 ms on the typical sample estate (post-`samples/` ingest).
`principal_resultant` over the same chain completes in < 200 ms including
token build. Calibration in `tests/test_calibration.py` asserts these
budgets indirectly (via the larger `settings_at_som` fold test) — a
direct timing test is `tests/test_merge.py` (covered by the existing
`TestMergeSettingsLastWriterWins` and bucket tests).

## AC-18: Folder Redirection mode dispatch

`_folder_redirection_mode(setting)` returns:

- `AUTHORITATIVE_REPLACE` if `setting.display_value.lower()` contains
  `"replace"`.
- `ACCUMULATE` if it contains `"merge"`.
- `MERGE_REPLACE_FLAG` otherwise (unknown / unsupported display value).

`cse_merge_mode("folder redirection", setting)` defers to
`_folder_redirection_mode`; with `setting=None`, it returns
`MERGE_REPLACE_FLAG` as the safe fallback.

## AC-19: `MergedSetting.conditional` is reserved (always False)

`MergedSetting.conditional` is a frozen dataclass field reserved for
future use. Every code path sets it to `False`. Conditional items are
tracked via `ExcludedSetting` (AC-08) and `ConditionalDanger` (AC-13),
not via `MergedSetting.conditional`. `_build_caveat_summary` already
counts `s.conditional for s in settings`; today this is always 0.

## AC-20: Side discrimination in chain collection

`_collect_chain_entries` filters settings by `target_side`:

- A User-side chain run drops Computer-side settings (`s.side != "User"`).
- A Computer-side chain run drops User-side settings
  (`s.side != "Computer"`).
- A user+computer pair run collects User-side from the user's chain and
  Computer-side from the computer's chain separately (AC-15).

This is the mechanism behind AC-02's bucketing — `(cse, side, identity)`
distinct bucketing exists because settings are filtered by side before
they reach the bucketing loop.
