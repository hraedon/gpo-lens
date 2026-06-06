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


def cmd_cpassword(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    result = queries.cpassword_scan(estate)
    if args.json:
        _render_json(
            [
                {
                    "gpo_id": h.gpo_id,
                    "gpo_name": h.gpo_name,
                    "file": h.file,
                    "tag": h.tag,
                    "cpassword": h.cpassword,
                }
                for h in result
            ]
        )
    else:
        _print_table(
            ["gpo_id", "file", "tag", "cpassword"],
            [[h.gpo_id, h.file, h.tag, h.cpassword] for h in result],
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
    _render_json(diff)
    conn.close()


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
    result = queries.wmi_filtered_gpos(estate)
    if args.json:
        _render_json(
            [
                {"id": g.id, "name": g.name, "wmi_filter": g.wmi_filter}
                for g in result
            ]
        )
    else:
        _print_table(
            ["id", "name", "wmi_filter"],
            [[g.id, g.name, g.wmi_filter or ""] for g in result],
        )


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="gpo-lens")
    parser.add_argument("--db", default=DEFAULT_DB, help="SQLite DB path")
    parser.add_argument("--json", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)

    # ingest
    p = sub.add_parser("ingest")
    p.add_argument("sample_dir")
    p.set_defaults(func=cmd_ingest)

    def _add_src(p: argparse.ArgumentParser) -> None:
        p.add_argument("src", nargs="?", help="Sample directory (omit to use --db)")

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
