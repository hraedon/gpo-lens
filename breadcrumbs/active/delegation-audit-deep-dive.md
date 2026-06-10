---
status: partially-resolved
priority: medium
created: 2026-06-09
resolved: 2026-06-10
---

# Delegation Audit Deep-Dive

**Partially resolved.** What landed this session:

- `delegation_deep_dive()` and `gpo-lens delegation` CLI — privilege rollup (trustee → GPO names with edit rights), orphaned SID detection, non-default-editor flagging.
- MS16-072 and permissions-audit were already implemented before this session.

**Still open:**
- Pure-Python SDDL parsing from `Gpo.sddl` to extract owner, ACEs, deny flags.
- Deny ACE detection.
- Service-account / excessive-write-access rollup across the estate.
