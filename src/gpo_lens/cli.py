"""Command-line interface for gpo-lens."""

from __future__ import annotations

import argparse
import code
import json
import sqlite3
import sys
from pathlib import Path
from typing import Sequence

from gpo_lens import ingest, queries, store
from gpo_lens.display import render_table
from gpo_lens.model import Estate

DEFAULT_DB = "./gpo-lens.sqlite3"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_estate(args: argparse.Namespace) -> Estate:
    src = getattr(args, "src", None) or getattr(args, "sample_dir", None)
    if src:
        return ingest.load_estate(src)
    db = Path(args.db)
    if not db.exists():
        print(f"Database not found: {db}", file=sys.stderr)
        sys.exit(2)
    conn = sqlite3.connect(str(db))
    try:
        return store.load_estate(conn)
    finally:
        conn.close()


def _render_json(obj: object) -> None:
    print(json.dumps(obj, indent=2, default=str))


def _print_table(headers: list[str], rows: list[Sequence[str]]) -> None:
    print(render_table(headers, rows))


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_summary(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    s = queries.estate_summary(estate)
    if args.json:
        _render_json({
            "domain": s.domain,
            "gpo_count": s.gpo_count,
            "som_count": s.som_count,
            "wmi_filter_count": s.wmi_filter_count,
            "unlinked_count": s.unlinked_count,
            "empty_count": s.empty_count,
            "disabled_but_populated_count": s.disabled_but_populated_count,
            "conflict_count": s.conflict_count,
            "blocked_extension_count": s.blocked_extension_count,
            "version_skew_count": s.version_skew_count,
            "ms16_072_vulnerable_count": s.ms16_072_vulnerable_count,
            "cpassword_hit_count": s.cpassword_hit_count,
            "loopback_gpo_count": s.loopback_gpo_count,
            "wmi_filtered_gpo_count": s.wmi_filtered_gpo_count,
            "enforced_link_count": s.enforced_link_count,
            "dangling_link_count": s.dangling_link_count,
            "broken_ref_count": s.broken_ref_count,
            "admx_gap_count": s.admx_gap_count,
            "total_settings": s.total_settings,
            "total_delegation_entries": s.total_delegation_entries,
        })
    else:
        print(f"Domain: {s.domain}")
        print(f"GPOs: {s.gpo_count}  |  SOMs: {s.som_count}  |  WMI filters: {s.wmi_filter_count}")
        print(f"Settings: {s.total_settings}  |  Delegation entries: {s.total_delegation_entries}")
        print()
        issues = []
        if s.unlinked_count:
            issues.append(f"  Unlinked GPOs:           {s.unlinked_count}")
        if s.empty_count:
            issues.append(f"  Empty GPOs:              {s.empty_count}")
        if s.disabled_but_populated_count:
            issues.append(f"  Disabled-but-populated:  {s.disabled_but_populated_count}")
        if s.conflict_count:
            issues.append(f"  Setting conflicts:       {s.conflict_count}")
        if s.blocked_extension_count:
            issues.append(f"  Blocked extensions:      {s.blocked_extension_count}")
        if s.version_skew_count:
            issues.append(f"  Version skew:            {s.version_skew_count}")
        if s.ms16_072_vulnerable_count:
            issues.append(f"  MS16-072 vulnerable:     {s.ms16_072_vulnerable_count}")
        if s.cpassword_hit_count:
            issues.append(f"  cpassword hits (MS14-025): {s.cpassword_hit_count}")
        if s.loopback_gpo_count:
            issues.append(f"  Loopback GPOs:           {s.loopback_gpo_count}")
        if s.wmi_filtered_gpo_count:
            issues.append(f"  WMI-filtered GPOs:       {s.wmi_filtered_gpo_count}")
        if s.enforced_link_count:
            issues.append(f"  Enforced links:          {s.enforced_link_count}")
        if s.dangling_link_count:
            issues.append(f"  Dangling links:          {s.dangling_link_count}")
        if s.broken_ref_count:
            issues.append(f"  Broken references:       {s.broken_ref_count}")
        if s.admx_gap_count:
            issues.append(f"  ADMX gaps (raw reg keys): {s.admx_gap_count}")
        if issues:
            print("Hygiene & security:")
            for line in issues:
                print(line)
        else:
            print("No issues detected.")


def cmd_ingest(args: argparse.Namespace) -> None:
    estate = ingest.load_estate(args.sample_dir)
    conn = sqlite3.connect(args.db)
    try:
        store.init_db(conn)
        sid = store.save_estate(conn, estate)
        domain = estate.domain or "unknown"
        msg = f"{domain}, {len(estate.gpos)} GPOs, {len(estate.soms)} SOMs, snapshot={sid}"
        if args.json:
            _render_json(
                {
                    "domain": domain,
                    "gpo_count": len(estate.gpos),
                    "som_count": len(estate.soms),
                    "snapshot_id": sid,
                }
            )
        else:
            print(msg)
    finally:
        conn.close()


def cmd_unlinked(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    result = queries.unlinked_gpos(estate)
    if args.json:
        _render_json([{"id": g.id, "name": g.name} for g in result])
    else:
        _print_table(["id", "name"], [[g.id, g.name] for g in result])


def cmd_empty(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    result = queries.empty_gpos(estate)
    if args.json:
        _render_json([{"id": g.id, "name": g.name} for g in result])
    else:
        _print_table(["id", "name"], [[g.id, g.name] for g in result])


def cmd_disabled_populated(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    result = queries.disabled_but_populated(estate)
    if args.json:
        _render_json(
            [{"id": g.id, "name": g.name, "side": side} for g, side in result]
        )
    else:
        _print_table(
            ["id", "name", "side"],
            [[g.id, g.name, side] for g, side in result],
        )


def cmd_who_sets(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    result = queries.who_sets(estate, args.term)
    if args.json:
        _render_json(
            [
                {
                    "gpo_id": s.gpo_id,
                    "cse": s.cse,
                    "identity": s.identity,
                    "display_value": s.display_value,
                }
                for s in result
            ]
        )
    else:
        _print_table(
            ["gpo_id", "cse", "identity", "display_value"],
            [[s.gpo_id, s.cse, s.identity, s.display_value] for s in result],
        )


def cmd_conflicts(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    result = queries.conflicts(estate)
    if args.json:
        _render_json(
            [
                {
                    "cse": c.cse,
                    "side": c.side,
                    "identity": c.identity,
                    "display_name": c.display_name,
                    "entries": [
                        {"gpo_id": gid, "value": val} for gid, val in c.entries
                    ],
                }
                for c in result
            ]
        )
    else:
        rows: list[Sequence[str]] = []
        for c in result:
            for gid, val in c.entries:
                rows.append([c.cse, c.side, c.identity, gid, val])
        _print_table(["cse", "side", "identity", "gpo_id", "value"], rows)


def cmd_blocked(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    result = queries.blocked_extensions(estate)
    if args.json:
        _render_json(
            [
                {"id": g.id, "name": g.name, "side": side, "cse": cse}
                for g, side, cse in result
            ]
        )
    else:
        _print_table(
            ["id", "name", "side", "cse"],
            [[g.id, g.name, side, cse] for g, side, cse in result],
        )


def cmd_version_skew(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    result = queries.version_skew(estate)
    if args.json:
        _render_json(
            [{"id": g.id, "name": g.name, "side": side} for g, side in result]
        )
    else:
        _print_table(
            ["id", "name", "side"],
            [[g.id, g.name, side] for g, side in result],
        )


def cmd_ms16_072(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    result = queries.ms16_072_vulnerable(estate)
    if args.json:
        _render_json([{"id": g.id, "name": g.name} for g in result])
    else:
        _print_table(["id", "name"], [[g.id, g.name] for g in result])


def _mask_cpassword(cpw: str) -> str:
    if len(cpw) <= 4:
        return "****"
    return cpw[:4] + "****"


def cmd_cpassword(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    result = queries.cpassword_scan(estate)
    show = getattr(args, "show_secrets", False)
    if args.json:
        _render_json(
            [
                {
                    "gpo_id": h.gpo_id,
                    "gpo_name": h.gpo_name,
                    "file": h.file,
                    "tag": h.tag,
                    "cpassword": h.cpassword if show else _mask_cpassword(h.cpassword),
                }
                for h in result
            ]
        )
    else:
        _print_table(
            ["gpo_id", "file", "tag", "cpassword"],
            [
                [h.gpo_id, h.file, h.tag,
                 h.cpassword if show else _mask_cpassword(h.cpassword)]
                for h in result
            ],
        )


def cmd_search(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    results = queries.search(estate, args.term, scope=args.scope)
    if args.json:
        _render_json([{"gpo_id": r.gpo_id, "field": r.match_field,
                        "detail": r.detail} for r in results])
    else:
        for r in results:
            print(f"{r.gpo_id}\t{r.gpo_name}\t{r.match_field}\t{r.detail}")


def cmd_show(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    target = args.gpo_id
    gpo = None
    for g in estate.gpos:
        if g.id == target or g.name == target:
            gpo = g
            break
    if gpo is None:
        print(f"GPO {target} not found", file=sys.stderr)
        return
    if args.json or args.format == "json":
        _render_json({
            "id": gpo.id,
            "name": gpo.name,
            "domain": gpo.domain,
            "computer_enabled": gpo.computer_enabled,
            "user_enabled": gpo.user_enabled,
            "links": [
                {"som_name": link.som_name, "som_path": link.som_path,
                 "enabled": link.link_enabled, "enforced": link.enforced}
                for link in gpo.links
            ],
            "settings_count": len(gpo.settings),
            "delegation_count": len(gpo.delegation),
        })
    else:
        print(f"GPO: {gpo.name} ({gpo.id})")
        print(f"  Domain: {gpo.domain}")
        for s in gpo.settings[:100]:
            print(f"  [{s.cse}] {s.side}/{s.identity}: {s.display_value}")
        if len(gpo.settings) > 100:
            print(f"  ... ({len(gpo.settings) - 100} more settings)")


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


def cmd_diff(args: argparse.Namespace) -> None:
    conn = sqlite3.connect(args.db)
    diff = queries.snapshot_diff(conn, args.snapshot_a, args.snapshot_b)
    conn.close()
    if args.json:
        _render_json({
            "gpos_added": diff.gpos_added,
            "gpos_removed": diff.gpos_removed,
            "settings_changed": diff.settings_changed,
            "links_changed": diff.links_changed,
            "delegation_changed": diff.delegation_changed,
            "version_skew_changed": diff.version_skew_changed,
            "metadata_changes": [
                {"gpo_id": m.gpo_id, "field": m.field,
                 "old": m.old_value, "new": m.new_value}
                for m in diff.metadata_changes
            ],
            "wmi_filter_changes": [
                {"gpo_id": m.gpo_id, "field": m.field,
                 "old": m.old_value, "new": m.new_value}
                for m in diff.wmi_filter_changes
            ],
            "enabled_flips": [
                {"gpo_id": m.gpo_id, "field": m.field,
                 "old": m.old_value, "new": m.new_value}
                for m in diff.enabled_flips
            ],
        })
    else:
        if diff.gpos_added:
            print(f"GPOs added: {', '.join(diff.gpos_added)}")
        if diff.gpos_removed:
            print(f"GPOs removed: {', '.join(diff.gpos_removed)}")
        if diff.settings_changed:
            print(f"Settings changed: {', '.join(diff.settings_changed)}")
        if diff.links_changed:
            print(f"Links changed: {', '.join(diff.links_changed)}")
        if diff.delegation_changed:
            print(f"Delegation changed: {', '.join(diff.delegation_changed)}")
        if diff.version_skew_changed:
            print(f"Version skew changed: {', '.join(diff.version_skew_changed)}")
        for m in diff.metadata_changes:
            print(f"Metadata: {m.gpo_id}.{m.field}: {m.old_value} -> {m.new_value}")
        for m in diff.wmi_filter_changes:
            print(f"WMI filter: {m.gpo_id}: {m.old_value} -> {m.new_value}")
        for m in diff.enabled_flips:
            print(f"Enabled flip: {m.gpo_id}.{m.field}: {m.old_value} -> {m.new_value}")
        if not any([
            diff.gpos_added, diff.gpos_removed, diff.settings_changed,
            diff.links_changed, diff.delegation_changed, diff.version_skew_changed,
            diff.metadata_changes, diff.wmi_filter_changes, diff.enabled_flips,
        ]):
            print("No differences found.")


def cmd_snapshots(args: argparse.Namespace) -> None:
    conn = sqlite3.connect(args.db)
    result = store.list_snapshots(conn)
    if args.json:
        _render_json(
            [
                {"id": sid, "domain": domain, "taken_at": taken}
                for sid, domain, taken in result
            ]
        )
    else:
        _print_table(
            ["id", "domain", "taken_at"],
            [[str(sid), domain, str(taken)] for sid, domain, taken in result],
        )
    conn.close()


def cmd_repl(args: argparse.Namespace) -> None:
    """Drop into a Python REPL with the estate loaded."""
    estate = _get_estate(args)
    local_vars = {"estate": estate, "queries": queries}
    code.interact(
        banner="gpo-lens REPL — `estate` and `queries` are available",
        local=local_vars,
    )


def cmd_som(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    result = queries.som_effective_gpos(estate, args.som_path)
    if args.json:
        _render_json(
            [
                {
                    "gpo_id": r.gpo_id,
                    "gpo_name": r.gpo_name,
                    "order": r.order,
                    "enabled": r.enabled,
                    "enforced": r.enforced,
                    "target": r.target,
                }
                for r in result
            ]
        )
    else:
        _print_table(
            ["order", "gpo_id", "gpo_name", "enabled", "enforced", "target"],
            [
                [str(r.order), r.gpo_id, r.gpo_name,
                 str(r.enabled), str(r.enforced), r.target]
                for r in result
            ],
        )


def cmd_dangling(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    result = queries.dangling_links(estate)
    if args.json:
        _render_json(
            [
                {
                    "som_path": som.path,
                    "som_name": som.name,
                    "gpo_id": link.gpo_id,
                    "order": link.order,
                }
                for som, link in result
            ]
        )
    else:
        _print_table(
            ["som_path", "som_name", "gpo_id", "order"],
            [[som.path, som.name, link.gpo_id, str(link.order)]
             for som, link in result],
        )


def cmd_enforced(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    result = queries.enforced_links(estate)
    if args.json:
        _render_json(
            [
                {
                    "som_path": som.path,
                    "som_name": som.name,
                    "gpo_id": link.gpo_id,
                    "order": link.order,
                    "target": link.target,
                }
                for som, link in result
            ]
        )
    else:
        _print_table(
            ["som_path", "som_name", "gpo_id", "order", "target"],
            [
                [som.path, som.name, link.gpo_id, str(link.order), link.target]
                for som, link in result
            ],
        )


def cmd_loopback(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    result = queries.loopback_gpos(estate)
    if args.json:
        _render_json(
            [
                {
                    "id": g.id,
                    "name": g.name,
                    "side": s.side,
                    "cse": s.cse,
                    "identity": s.identity,
                    "display_value": s.display_value,
                }
                for g, s in result
            ]
        )
    else:
        _print_table(
            ["id", "name", "side", "cse", "identity", "display_value"],
            [
                [g.id, g.name, s.side, s.cse, s.identity, s.display_value]
                for g, s in result
            ],
        )


def cmd_som_conflicts(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    result = queries.som_conflicts(estate, args.som_path)
    if args.json:
        _render_json(
            [
                {
                    "som_path": c.som_path,
                    "cse": c.cse,
                    "side": c.side,
                    "identity": c.identity,
                    "display_name": c.display_name,
                    "winner": c.winner,
                    "entries": [
                        {"gpo_name": name, "value": value, "status": status}
                        for name, value, status in c.entries
                    ],
                }
                for c in result
            ]
        )
    else:
        # Flatten one row per entry
        rows: list[Sequence[str]] = []
        for c in result:
            for name, value, status in c.entries:
                rows.append(
                    [c.som_path, c.cse, c.side, c.identity, name, value, status]
                )
        _print_table(
            ["som_path", "cse", "side", "identity",
             "gpo_name", "value", "status"],
            rows,
        )


def cmd_precedence_conflicts(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    result = queries.precedence_conflicts(estate)
    if args.json:
        _render_json(
            [
                {
                    "som_path": som.path,
                    "som_name": som.name,
                    "conflicts": [
                        {
                            "cse": c.cse,
                            "side": c.side,
                            "identity": c.identity,
                            "display_name": c.display_name,
                            "winner": c.winner,
                            "entries": [
                                {"gpo_name": n, "value": v, "status": s}
                                for n, v, s in c.entries
                            ],
                        }
                        for c in conflicts
                    ],
                }
                for som, conflicts in result
            ]
        )
    else:
        rows: list[Sequence[str]] = []
        for som, conflicts in result:
            for c in conflicts:
                for name, value, status in c.entries:
                    rows.append(
                        [som.path, c.cse, c.side, c.identity,
                         name, value, status]
                    )
        _print_table(
            ["som_path", "cse", "side", "identity",
             "gpo_name", "value", "status"],
            rows,
        )


def cmd_broken_refs(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    result = queries.broken_refs(estate)
    if args.json:
        _render_json(
            [
                {
                    "gpo_id": r.gpo_id,
                    "gpo_name": r.gpo_name,
                    "ref_type": r.ref_type,
                    "ref_value": r.ref_value,
                    "detail": r.detail,
                }
                for r in result
            ]
        )
    else:
        _print_table(
            ["gpo_id", "gpo_name", "ref_type", "ref_value", "detail"],
            [
                [r.gpo_id, r.gpo_name, r.ref_type, r.ref_value, r.detail]
                for r in result
            ],
        )


def cmd_wmi(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    if args.json:
        _render_json(
            [
                {"id": g.id, "name": g.name, "wmi_filter": g.wmi_filter}
                for g in queries.wmi_filtered_gpos(estate)
            ]
        )
    else:
        _print_table(
            ["id", "name", "wmi_filter"],
            [[g.id, g.name, g.wmi_filter or ""] for g in queries.wmi_filtered_gpos(estate)],
        )


def cmd_wmi_filters(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    if args.json:
        _render_json(
            [{"name": wf.name, "query": wf.query} for wf in estate.wmi_filters]
        )
    else:
        _print_table(
            ["name", "query"],
            [[wf.name, wf.query] for wf in estate.wmi_filters],
        )


def cmd_topology_check(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    result = queries.topology_crosscheck(estate)
    if args.json:
        _render_json(
            [{"kind": d.kind, "ou_dn": d.ou_dn, "detail": d.detail} for d in result]
        )
    else:
        if not result:
            print("No discrepancies found.")
        else:
            _print_table(
                ["kind", "ou_dn", "detail"],
                [[d.kind, d.ou_dn, d.detail] for d in result],
            )


def cmd_admx_gaps(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    result = queries.admx_gaps(estate)
    if args.json:
        _render_json(
            [
                {
                    "gpo_id": r.gpo_id,
                    "gpo_name": r.gpo_name,
                    "side": r.side,
                    "identity": r.identity,
                    "key_path": r.key_path,
                    "value_name": r.value_name,
                }
                for r in result
            ]
        )
    else:
        if not result:
            print("No ADMX gaps found.")
        else:
            _print_table(
                ["gpo_id", "gpo_name", "side", "key_path", "value_name"],
                [
                    [r.gpo_id, r.gpo_name, r.side, r.key_path, r.value_name]
                    for r in result
                ],
            )


def cmd_settings_at(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    result = queries.settings_at_som(estate, args.som_path)
    if args.json:
        _render_json(
            [
                {
                    "cse": r.cse,
                    "side": r.side,
                    "identity": r.identity,
                    "display_name": r.display_name,
                    "display_value": r.display_value,
                    "winner_gpo_id": r.winner_gpo_id,
                    "winner_gpo_name": r.winner_gpo_name,
                    "overridden_by": [
                        {"gpo_name": n, "value": v} for n, v in r.overridden_by
                    ],
                    "enforced": r.enforced,
                }
                for r in result
            ]
        )
    else:
        if not result:
            print(f"No effective settings at {args.som_path}")
            return
        # Group by winner GPO for easier reading
        by_gpo: dict[str, list[queries.EffectiveSetting]] = {}
        for r in result:
            by_gpo.setdefault(r.winner_gpo_name, []).append(r)
        for gpo_name, settings in by_gpo.items():
            print(f"\n  [{gpo_name}]")
            for s in settings:
                enforced_flag = " [ENFORCED]" if s.enforced else ""
                print(
                    f"    [{s.cse}] {s.side}/{s.identity}{enforced_flag}\n"
                    f"      {s.display_name}: {s.display_value}"
                )
                if s.overridden_by:
                    for o_name, o_val in s.overridden_by:
                        print(f"      (overridden: {o_name} = {o_val})")


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="gpo-lens")
    parser.add_argument("--db", default=DEFAULT_DB, help="SQLite DB path")
    parser.add_argument("--json", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)

    def _add_src(p: argparse.ArgumentParser) -> None:
        p.add_argument("src", nargs="?", help="Sample directory (omit to use --db)")

    # summary
    p = sub.add_parser("summary", help="Estate health overview")
    _add_src(p)
    p.set_defaults(func=cmd_summary)

    # ingest
    p = sub.add_parser("ingest")
    p.add_argument("sample_dir")
    p.set_defaults(func=cmd_ingest)

    # analysis commands
    p = sub.add_parser("unlinked")
    _add_src(p)
    p.set_defaults(func=cmd_unlinked)

    p = sub.add_parser("empty")
    _add_src(p)
    p.set_defaults(func=cmd_empty)

    p = sub.add_parser("disabled-populated")
    _add_src(p)
    p.set_defaults(func=cmd_disabled_populated)

    p = sub.add_parser("who-sets")
    p.add_argument("term")
    _add_src(p)
    p.set_defaults(func=cmd_who_sets)

    p = sub.add_parser("conflicts")
    _add_src(p)
    p.set_defaults(func=cmd_conflicts)

    p = sub.add_parser("blocked")
    _add_src(p)
    p.set_defaults(func=cmd_blocked)

    p = sub.add_parser("version-skew")
    _add_src(p)
    p.set_defaults(func=cmd_version_skew)

    p = sub.add_parser("ms16-072")
    _add_src(p)
    p.set_defaults(func=cmd_ms16_072)

    p = sub.add_parser("cpassword")
    p.add_argument(
        "--show-secrets", action="store_true",
        help="Reveal full cpassword values (default: masked)",
    )
    _add_src(p)
    p.set_defaults(func=cmd_cpassword)

    # search
    p = sub.add_parser("search", help="Full-text search")
    p.add_argument("term")
    p.add_argument("--scope", default="all", choices=["all", "settings", "names", "delegation"])
    _add_src(p)
    p.set_defaults(func=cmd_search)

    # show
    p = sub.add_parser("show")
    p.add_argument("gpo_id")
    p.add_argument("--format", choices=["text", "json"], default="text")
    _add_src(p)
    p.set_defaults(func=cmd_show)

    p = sub.add_parser("perms")
    _add_src(p)
    p.set_defaults(func=cmd_perms)

    p = sub.add_parser("diff")
    p.add_argument("snapshot_a", type=int)
    p.add_argument("snapshot_b", type=int)
    p.set_defaults(func=cmd_diff)

    p = sub.add_parser("snapshots")
    p.set_defaults(func=cmd_snapshots)

    # topology commands
    p = sub.add_parser("som", help="Show effective GPOs at a SOM path")
    p.add_argument("som_path")
    _add_src(p)
    p.set_defaults(func=cmd_som)

    p = sub.add_parser("dangling", help="SOM links to non-existent GPOs")
    _add_src(p)
    p.set_defaults(func=cmd_dangling)

    p = sub.add_parser("enforced", help="All enforced (NoOverride) links")
    _add_src(p)
    p.set_defaults(func=cmd_enforced)

    # feature-flag commands
    p = sub.add_parser("loopback", help="GPOs that configure loopback processing")
    _add_src(p)
    p.set_defaults(func=cmd_loopback)

    p = sub.add_parser("wmi", help="GPOs with WMI filters attached")
    _add_src(p)
    p.set_defaults(func=cmd_wmi)

    p = sub.add_parser("wmi-filters", help="List WMI filters with query text")
    _add_src(p)
    p.set_defaults(func=cmd_wmi_filters)

    p = sub.add_parser(
        "topology-check",
        help="Cross-check ou-tree.json against gp-inheritance.json",
    )
    _add_src(p)
    p.set_defaults(func=cmd_topology_check)

    p = sub.add_parser(
        "admx-gaps",
        help="Flag Registry CSE settings with raw key paths (no ADMX policy name)",
    )
    _add_src(p)
    p.set_defaults(func=cmd_admx_gaps)

    # new Plan 009 command
    p = sub.add_parser(
        "settings-at",
        help="Show effective settings at a SOM path",
    )
    p.add_argument("som_path")
    _add_src(p)
    p.set_defaults(func=cmd_settings_at)

    # new Plan 007 commands
    p = sub.add_parser(
        "som-conflicts",
        help="Settings that conflict in the SOM chain",
    )
    p.add_argument("som_path")
    _add_src(p)
    p.set_defaults(func=cmd_som_conflicts)

    p = sub.add_parser(
        "precedence-conflicts",
        help="All precedence conflicts across the estate",
    )
    _add_src(p)
    p.set_defaults(func=cmd_precedence_conflicts)

    p = sub.add_parser(
        "broken-refs",
        help="Detect broken references in settings (UNC paths, etc.)",
    )
    _add_src(p)
    p.set_defaults(func=cmd_broken_refs)

    # REPL
    p = sub.add_parser("repl", help="Interactive Python REPL with the estate loaded")
    _add_src(p)
    p.set_defaults(func=cmd_repl)

    args = parser.parse_args(argv)
    if not hasattr(args, "func"):
        parser.print_help()
        return 1
    try:
        return args.func(args) or 0
    except SystemExit:
        raise
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    import sys

    sys.exit(main())
