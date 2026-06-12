"""CLI subcommands for delegation and permissions audit."""
from __future__ import annotations

import argparse

from gpo_lens import queries
from gpo_lens.cli._helpers import _get_estate, _print_table, _render_json


def cmd_perms(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    result = queries.permissions_audit(estate)
    if args.json:
        _render_json(
            [
                {"id": g.id, "name": g.name, "issue": desc}
                for g, desc in result
            ]
        )
    else:
        _print_table(
            ["id", "name", "issue"],
            [[g.id, g.name, desc] for g, desc in result],
        )


def cmd_delegation(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    audit = queries.delegation_deep_dive(estate)
    if args.json:
        _render_json({
            "privilege_rollup": {
                trustee: sorted(set(gpo_names))
                for trustee, gpo_names in audit.privilege_rollup.items()
            },
            "orphaned_sids": [
                {"gpo_id": g.id, "gpo_name": g.name, "sid": sid}
                for g, sid in audit.orphaned_sids
            ],
            "broad_writers": [
                {
                    "gpo_id": g.id,
                    "gpo_name": g.name,
                    "trustee": d.trustee,
                    "permission": d.permission,
                }
                for g, d in audit.broad_writers
            ],
            "deny_aces": [
                {
                    "gpo_id": d.gpo_id,
                    "gpo_name": d.gpo_name,
                    "trustee_sid": d.trustee_sid,
                    "rights": d.rights,
                    "flags": d.flags,
                }
                for d in audit.deny_aces
            ],
            "excessive_writers": [
                {
                    "trustee_sid": w.trustee_sid,
                    "gpo_count": w.gpo_count,
                    "gpo_names": w.gpo_names,
                    "rights": w.rights,
                }
                for w in audit.excessive_writers
            ],
        })
    else:
        print("Delegation Deep-Dive")
        print("=" * 60)
        if audit.deny_aces:
            print("\n--- Deny ACEs ---")
            for d in audit.deny_aces:
                flags_part = f" [{d.flags}]" if d.flags else ""
                print(f"  {d.gpo_name}: {d.trustee_sid} ({d.rights}){flags_part}")
        if audit.excessive_writers:
            print("\n--- Excessive Write Access ---")
            for w in audit.excessive_writers:
                print(f"  {w.trustee_sid}: {w.gpo_count} GPOs ({', '.join(w.rights)})")
                for name in w.gpo_names[:5]:
                    print(f"    - {name}")
                if len(w.gpo_names) > 5:
                    print(f"    ... and {len(w.gpo_names) - 5} more")
        if audit.orphaned_sids:
            print("\n--- Orphaned SIDs ---")
            for g, sid in audit.orphaned_sids:
                print(f"  {g.name}: {sid}")
        if audit.broad_writers:
            print("\n--- Non-Default Editors with Write Rights ---")
            for g, de in audit.broad_writers:
                print(f"  {g.name}: {de.trustee} ({de.permission})")
        if audit.privilege_rollup:
            print("\n--- Privilege Rollup ---")
            for trustee, gpo_names in sorted(audit.privilege_rollup.items()):
                print(f"  {trustee}: {', '.join(sorted(set(gpo_names)))}")
        if not (audit.orphaned_sids or audit.broad_writers or audit.privilege_rollup
                or audit.deny_aces or audit.excessive_writers):
            print("No delegation issues found.")


def cmd_sddl(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    if args.json:
        json_results: list[dict[str, object]] = []
        for g in estate.gpos:
            if not g.sddl:
                continue
            acl = queries.parse_sddl(g.sddl)
            json_results.append({
                "gpo_id": g.id,
                "gpo_name": g.name,
                "owner_sid": acl.owner_sid or "",
                "group_sid": acl.group_sid or "",
                "dacl": [
                    {
                        "ace_type": a.ace_type,
                        "flags": a.flags,
                        "rights": a.rights,
                        "object_guid": a.object_guid,
                        "inherit_object_guid": a.inherit_object_guid,
                        "trustee_sid": a.trustee_sid,
                    }
                    for a in acl.dacl
                ],
                "sacl": [
                    {
                        "ace_type": a.ace_type,
                        "flags": a.flags,
                        "rights": a.rights,
                        "object_guid": a.object_guid,
                        "inherit_object_guid": a.inherit_object_guid,
                        "trustee_sid": a.trustee_sid,
                    }
                    for a in acl.sacl
                ],
            })
        _render_json(json_results)
    else:
        found = False
        for g in estate.gpos:
            if not g.sddl:
                continue
            found = True
            acl = queries.parse_sddl(g.sddl)
            print(f"\n{g.name} ({g.id})")
            print(f"  Owner: {acl.owner_sid or 'N/A'}")
            for a in acl.dacl:
                flags = f" [{a.flags}]" if a.flags else ""
                print(f"  DACL {a.ace_type.upper()}: {a.trustee_sid} "
                      f"({a.rights}){flags}")
            for a in acl.sacl:
                flags = f" [{a.flags}]" if a.flags else ""
                print(f"  SACL {a.ace_type.upper()}: {a.trustee_sid} "
                      f"({a.rights}){flags}")
        if not found:
            print("No GPOs with SDDL data found.")
