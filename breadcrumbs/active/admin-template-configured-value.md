---
status: active
priority: medium
kind: enhancement
created: 2026-06-23
---

# Show configured value/data for Administrative-Templates settings, not just Enabled/Disabled

## Problem
In the web UI, Administrative-Templates policies (CSE `Registry`) show only their
**State** in the Value column -- `Enabled` / `Disabled` -- never the data the
policy actually configures. So "SSL Cipher Suite Order = Enabled" hides the
cipher list, "Select an active power plan = Enabled" hides which plan, a numeric
timeout policy hides the number, etc. (GPP `Windows Registry` settings already
show real data like `[REG_DWORD] 00000800`; this gap is specifically the
admin-template policies, which a user reasonably calls "registry settings".)

Observed on a real export: 40 `Registry` CSE settings, all reading `Enabled` or
`Disabled` with no configured value.

## Root cause
`ingest._parse_admin_template_policy` extracts only `<Name>`, `<State>`, and
`<Category>` from each `<Policy>` block, so `display_value` is just the state.
The configured value lives in the report XML's per-policy option sub-elements,
which are dropped: `<DropDownList>` (Name/Value), `<EditText>` / `<EditTextBox>`
(Value), `<Numeric>` (Value), `<ListBox>` (entries), `<Checkbox>` (State),
`<MultiText>`. (These vary per policy and several may co-exist.)

## Suggested fix
Parse the `<Policy>` option sub-elements into a compact value summary and put it
in `display_value` (keep `State` as a prefix or a separate signal), e.g.
`Enabled - Active Power Plan: Balanced` or `Enabled - [2 list entries]`. Handle
each option element shape; fall back to `State` alone when a policy has none.

A second, now-available source is the **SYSVOL `Registry.pol`** (collected since
the `$dom`/SYSVOL fixes): it holds the literal `key:value = data` the policy
writes. `registry_pol.py` already parses it and `augment_blocked_registry_from_pol`
is a precedent for correlating it in. Report-XML sub-elements are the
lower-effort path and are human-labelled; Registry.pol is the ground-truth
registry write. Consider which (or both) to surface.

Add a focused ingest test per option-element shape.

## Context
Filed 2026-06-23 from a user note while browsing the UI after the collector
fixes finally produced a full export with SYSVOL. The data the policies write is
now collectable; the UI just doesn't surface it for admin templates.
