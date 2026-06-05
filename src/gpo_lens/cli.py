"""Command-line interface for gpo-lens."""

from __future__ import annotations

import argparse
import code
import json
import sqlite3
import sys
from pathlib import Path

from gpo_lens import ingest, queries, store
from gpo_lens.display import render_table
from gpo_lens.model import Estate

DEFAULT_DB = "./gpo-lens.sqlite3"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_estate(args) -> Estate:
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


def _print_table(headers: list[str], rows: list) -> None:
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
        print(f"Snapshot {sid} saved ({len(estate.gpos)} GPOs, {len(estate.soms)} SOMs)")
    finally:
        conn.close()


def cmd_unlinked(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    for g in queries.unlinked_gpos(estate):
        print(f"{g.id}\t{g.name}")


def cmd_empty(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    for g in queries.empty_gpos(estate):
        print(f"{g.id}\t{g.name}")


def cmd_disabled_populated(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    for g, side in queries.disabled_but_populated(estate):
        print(f"{g.id}\t{g.name}\t{side}")


def cmd_who_sets(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    for s in queries.who_sets(estate, args.term):
        print(f"{s.gpo_id}\t{s.cse}\t{s.identity}\t{s.display_value}")


def cmd_conflicts(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    for c in queries.conflicts(estate):
        for gid, val in c.entries:
            print(f"CONFLICT {c.cse}/{c.side}/{c.identity}: {gid}={val}")


def cmd_blocked(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    for g, side, cse in queries.blocked_extensions(estate):
        print(f"{g.id}\t{g.name}\t{side}\t{cse}")


def cmd_version_skew(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    for g, side in queries.version_skew(estate):
        print(f"{g.id}\t{g.name}\t{side}")


def cmd_ms16_072(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    for g in queries.ms16_072_vulnerable(estate):
        print(f"{g.id}\t{g.name}")


def cmd_cpassword(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    for hit in queries.cpassword_scan(estate):
        print(f"{hit.gpo_id}\t{hit.file}\t{hit.tag}")


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
    if args.format == "json":
        _render_json({
            "id": gpo.id, "name": gpo.name, "domain": gpo.domain,
        })
    else:
        print(f"GPO: {gpo.name} ({gpo.id})")
        print(f"  Domain: {gpo.domain}")
        for s in gpo.settings:
            print(f"  [{s.cse}] {s.side}/{s.identity}: {s.display_value}")


def cmd_perms(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    for g, desc in queries.permissions_audit(estate):
        print(f"{g.id}\t{g.name}\t{desc}")


def cmd_diff(args: argparse.Namespace) -> None:
    conn = sqlite3.connect(args.db)
    diff = queries.snapshot_diff(conn, args.snapshot_a, args.snapshot_b)
    _render_json(diff)
    conn.close()


def cmd_snapshots(args: argparse.Namespace) -> None:
    conn = sqlite3.connect(args.db)
    for sid, domain, taken in store.list_snapshots(conn):
        print(f"{sid}\t{domain}\t{taken}")
    conn.close()


def cmd_repl(args: argparse.Namespace) -> None:
    """Drop into a Python REPL with the estate loaded."""
    estate = _get_estate(args)
    local_vars = {"estate": estate, "queries": queries}
    code.interact(
        banner="gpo-lens REPL — `estate` and `queries` are available",
        local=local_vars,
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

    # analysis commands
    sub.add_parser("unlinked").set_defaults(func=cmd_unlinked)
    sub.add_parser("empty").set_defaults(func=cmd_empty)
    sub.add_parser("disabled-populated").set_defaults(func=cmd_disabled_populated)

    p = sub.add_parser("who-sets")
    p.add_argument("term")
    p.set_defaults(func=cmd_who_sets)

    sub.add_parser("conflicts").set_defaults(func=cmd_conflicts)
    sub.add_parser("blocked").set_defaults(func=cmd_blocked)
    sub.add_parser("version-skew").set_defaults(func=cmd_version_skew)
    sub.add_parser("ms16-072").set_defaults(func=cmd_ms16_072)
    sub.add_parser("cpassword").set_defaults(func=cmd_cpassword)

    # search
    p = sub.add_parser("search", help="Full-text search")
    p.add_argument("term")
    p.add_argument("--scope", default="all", choices=["all", "settings", "names", "delegation"])
    p.set_defaults(func=cmd_search)

    # show
    p = sub.add_parser("show")
    p.add_argument("gpo_id")
    p.add_argument("--format", choices=["text", "json"], default="text")
    p.set_defaults(func=cmd_show)

    sub.add_parser("perms").set_defaults(func=cmd_perms)

    p = sub.add_parser("diff")
    p.add_argument("snapshot_a", type=int)
    p.add_argument("snapshot_b", type=int)
    p.set_defaults(func=cmd_diff)

    sub.add_parser("snapshots").set_defaults(func=cmd_snapshots)

    # REPL
    p = sub.add_parser("repl", help="Interactive Python REPL with the estate loaded")
    p.set_defaults(func=cmd_repl)

    args = parser.parse_args()
    if not hasattr(args, "func"):
        parser.print_help()
        return 1
    return args.func(args) or 0
