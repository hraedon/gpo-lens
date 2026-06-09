---
status: open
priority: medium
created: 2026-06-09
---

# Delegation Audit Deep-Dive

`ms16_072_vulnerable` and `permissions_audit` exist but are shallow.  The model
stores full `DelegationEntry` records including `trustee_sid` and `permission`,
and the raw SDDL is in `Gpo.sddl`.

## SDDL parsing
Parse the stored SDDL string to extract:
- Owner and primary group
- All ACE entries with trustee SID, access mask, ACE type (allow/deny/audit)
- Inheritance flags

Python's `ctypes` can call `ConvertStringSecurityDescriptorToSecurityDescriptor`
on Windows, or a pure-Python SDDL parser could be written (the format is
well-documented).  For air-gapped portability, pure-Python is preferred.

## Deny ACE detection
Flag GPOs with explicit deny ACEs that override intended access — these are
rare and usually indicate misconfiguration or security incident response.

## Estate-wide privilege rollup
Instead of per-GPO audit, produce a cross-estate view:
- "Which principals have Edit/Modify on how many GPOs?"
- "Which principals have Apply Group Policy across the estate?"
- Flag service accounts or user accounts with excessive GPO write access

## Implementation sketch
- Add `parse_sddl(sddl: str) -> list[SddlAce]` to a new `sddl.py` module
- Add `delegation_rollup(estate) -> list[DelegationRollupEntry]` to queries
- Add `cmd_delegation_audit` CLI command
- Wire SDDL parsing into `permissions_audit` for richer output

## Depends on
Nothing — SDDL is already stored in the model.
