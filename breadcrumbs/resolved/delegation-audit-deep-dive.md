---
status: resolved
priority: medium
created: 2026-06-09
resolved: 2026-06-10
---

# Delegation Audit Deep-Dive

**Resolved.** All items now implemented:

- `delegation_deep_dive()` and `gpo-lens delegation` CLI — privilege rollup (trustee → GPO names with edit rights), orphaned SID detection, non-default-editor flagging.
- MS16-072 and permissions-audit were already implemented before this session.
- Pure-Python SDDL parsing from `Gpo.sddl` — `parse_sddl()` in detection.py, `SddlAce`/`SddlAcl` dataclasses in model.py, `gpo-lens sddl` CLI.
- Deny ACE detection — `deny_aces()` scanner + `DenyAce` dataclass, wired into `delegation_deep_dive` and `estate_doctor`.
- Service-account / excessive-write-access rollup — `excessive_writers()` scanner + `ExcessiveWriter` dataclass, wired into `delegation_deep_dive` and `estate_doctor`, default-writer SIDs excluded.
