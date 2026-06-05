"""Command-line interface for gpo-lens."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any

from gpo_lens import ingest, queries, store
from gpo_lens.model import Estate, Gpo, Setting


DEFAULT_DB = "./gpo-lens.sqlite3"


def _get_estate(args: argparse.Namespace) -> Estate:
    """Return an estate from ``src`` if given, else from the latest DB snapshot."""
    if getattr(args, "src", None):
        return ingest.load_estate(args.src)
    db_path = Path(args.db)
    if not db_path.exists():
        print(f"Database not found: {db_path}", file=sys.stderr)
        sys.exit(2)
    conn = sqlite3.connect(db_path)
    try:
        return store.load_estate(conn)
    finally:
        conn.close()


def _render_json(rows: list[dict[str, Any]]) -> None:
    print(json.dumps(rows, indent=2))


def _render_table(headers: list[str], rows: list[list[str]]) -> None:
    if not rows:
        print("No results.")
        return
    # Compute widths
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))
    # Print header
    print("  ".join(h.ljust(w) for h, w in zip(headers, widths)))
    print("  ".join("-" * w for w in widths))
    for row in rows:
        print("  ".join(str(cell).ljust(w) for cell, w in zip(row, widths)))


def _gpo_rows(gpos: list[Gpo]) -> list[dict[str, Any]]:
    return [{"id": g.id, "name": g.name, "domain": g.domain} for g in gpos]


def _setting_rows(settings: list[Setting]) -> list[dict[str, Any]]:
    return [
        {
            "gpo_id": s.gpo_id,
            "side": s.side,
            "cse": s.cse,
            "identity": s.identity,
            "display_name": s.display_name,
            "display_value": s.display_value,
        }
        for s in settings
    ]


def _conflict_rows(conflicts: list[queries.Conflict]) -> list[dict[str, Any]]:
    return [
        {
            "cse": c.cse,
            "side": c.side,
            "identity": c.identity,
            "display_name": c.display_name,
            "entries": [{"gpo_id": gid, "display_value": val} for gid, val in c.entries],
        }
        for c in conflicts
    ]


def _cpassword_rows(hits: list[queries.CpasswordHit]) -> list[dict[str, Any]]:
    return [
        {
            "gpo_id": h.gpo_id,
            "gpo_name": h.gpo_name,
            "file": h.file,
            "tag": h.tag,
            "cpassword": h.cpassword,
        }
        for h in hits
    ]


def cmd_ingest(args: argparse.Namespace) -> int:
    try:
        estate = ingest.load_estate(args.sample_dir)
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    db_path = Path(args.db)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    try:
        store.init_db(conn)
        sid = store.save_estate(conn, estate)
    finally:
        conn.close()
    print(f"{estate.domain}, {len(estate.gpos)} GPOs, {len(estate.soms)} SOMs, snapshot={sid}")
    return 0


def cmd_unlinked(args: argparse.Namespace) -> int:
    estate = _get_estate(args)
    gpos = queries.unlinked_gpos(estate)
    if args.json:
        _render_json(_gpo_rows(gpos))
    else:
        _render_table(["ID", "Name", "Domain"], [[g.id, g.name, g.domain] for g in gpos])
    return 0


def cmd_empty(args: argparse.Namespace) -> int:
    estate = _get_estate(args)
    gpos = queries.empty_gpos(estate)
    if args.json:
        _render_json(_gpo_rows(gpos))
    else:
        _render_table(["ID", "Name", "Domain"], [[g.id, g.name, g.domain] for g in gpos])
    return 0


def cmd_disabled_populated(args: argparse.Namespace) -> int:
    estate = _get_estate(args)
    results = queries.disabled_but_populated(estate)
    if args.json:
        _render_json([{"gpo_id": g.id, "name": g.name, "side": side} for g, side in results])
    else:
        _render_table(
            ["ID", "Name", "Side"],
            [[g.id, g.name, side] for g, side in results],
        )
    return 0


def cmd_who_sets(args: argparse.Namespace) -> int:
    estate = _get_estate(args)
    settings = queries.who_sets(estate, args.term)
    if args.json:
        _render_json(_setting_rows(settings))
    else:
        _render_table(
            ["GPO ID", "Side", "CSE", "Identity", "Display Name", "Display Value"],
            [[s.gpo_id, s.side, s.cse, s.identity, s.display_name, s.display_value] for s in settings],
        )
    return 0


def cmd_conflicts(args: argparse.Namespace) -> int:
    estate = _get_estate(args)
    conflicts = queries.conflicts(estate)
    if args.json:
        _render_json(_conflict_rows(conflicts))
    else:
        rows: list[list[str]] = []
        for c in conflicts:
            for gid, val in c.entries:
                rows.append([c.cse, c.side, c.identity, c.display_name, gid, val])
        _render_table(
            ["CSE", "Side", "Identity", "Display Name", "GPO ID", "Display Value"],
            rows,
        )
    return 0


def cmd_blocked(args: argparse.Namespace) -> int:
    estate = _get_estate(args)
    results = queries.blocked_extensions(estate)
    if args.json:
        _render_json([{"gpo_id": g.id, "name": g.name, "side": side, "cse": cse} for g, side, cse in results])
    else:
        _render_table(
            ["ID", "Name", "Side", "CSE"],
            [[g.id, g.name, side, cse] for g, side, cse in results],
        )
    return 0


def cmd_version_skew(args: argparse.Namespace) -> int:
    estate = _get_estate(args)
    results = queries.version_skew(estate)
    if args.json:
        _render_json([{"gpo_id": g.id, "name": g.name, "side": side} for g, side in results])
    else:
        _render_table(
            ["ID", "Name", "Side"],
            [[g.id, g.name, side] for g, side in results],
        )
    return 0


def cmd_ms16_072(args: argparse.Namespace) -> int:
    estate = _get_estate(args)
    gpos = queries.ms16_072_vulnerable(estate)
    if args.json:
        _render_json(_gpo_rows(gpos))
    else:
        _render_table(["ID", "Name", "Domain"], [[g.id, g.name, g.domain] for g in gpos])
    return 0


def cmd_cpassword(args: argparse.Namespace) -> int:
    estate = _get_estate(args)
    hits = queries.cpassword_scan(estate)
    if args.json:
        _render_json(_cpassword_rows(hits))
    else:
        _render_table(
            ["GPO ID", "GPO Name", "File", "Tag", "cpassword"],
            [[h.gpo_id, h.gpo_name, h.file, h.tag, h.cpassword] for h in hits],
        )
    return 0


def cmd_snapshots(args: argparse.Namespace) -> int:
    db_path = Path(args.db)
    if not db_path.exists():
        print(f"Database not found: {db_path}", file=sys.stderr)
        return 2
    conn = sqlite3.connect(db_path)
    try:
        snaps = store.list_snapshots(conn)
    finally:
        conn.close()
    if args.json:
        _render_json([{"id": s[0], "domain": s[1], "taken_at": s[2].isoformat() if s[2] else None} for s in snaps])
    else:
        _render_table(
            ["ID", "Domain", "Taken At"],
            [[str(s[0]), s[1], s[2].isoformat() if s[2] else ""] for s in snaps],
        )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="gpo-lens")
    parser.add_argument("--db", default=DEFAULT_DB, help="SQLite database path")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text tables")
    sub = parser.add_subparsers(dest="command", required=True)

    # ingest
    p_ingest = sub.add_parser("ingest", help="Ingest a sample directory into the database")
    p_ingest.add_argument("sample_dir", help="Directory containing AllGPOs.xml, gp-inheritance.json, etc.")
    p_ingest.set_defaults(func=cmd_ingest)

    # analysis commands
    p_unlinked = sub.add_parser("unlinked", help="List unlinked GPOs")
    p_unlinked.add_argument("src", nargs="?", help="Sample directory (optional; reads DB if omitted)")
    p_unlinked.set_defaults(func=cmd_unlinked)

    p_empty = sub.add_parser("empty", help="List empty GPOs")
    p_empty.add_argument("src", nargs="?", help="Sample directory (optional; reads DB if omitted)")
    p_empty.set_defaults(func=cmd_empty)

    p_disabled = sub.add_parser("disabled-populated", help="List disabled-but-populated sides")
    p_disabled.add_argument("src", nargs="?", help="Sample directory (optional; reads DB if omitted)")
    p_disabled.set_defaults(func=cmd_disabled_populated)

    p_who = sub.add_parser("who-sets", help="Find settings matching a term")
    p_who.add_argument("term", help="Search term")
    p_who.add_argument("src", nargs="?", help="Sample directory (optional; reads DB if omitted)")
    p_who.set_defaults(func=cmd_who_sets)

    p_conflicts = sub.add_parser("conflicts", help="Show conflict surface")
    p_conflicts.add_argument("src", nargs="?", help="Sample directory (optional; reads DB if omitted)")
    p_conflicts.set_defaults(func=cmd_conflicts)

    p_blocked = sub.add_parser("blocked", help="List blocked extensions")
    p_blocked.add_argument("src", nargs="?", help="Sample directory (optional; reads DB if omitted)")
    p_blocked.set_defaults(func=cmd_blocked)

    p_skew = sub.add_parser("version-skew", help="List GPOs with GPC vs GPT version mismatch")
    p_skew.add_argument("src", nargs="?", help="Sample directory (optional; reads DB if omitted)")
    p_skew.set_defaults(func=cmd_version_skew)

    p_ms16 = sub.add_parser("ms16-072", help="Flag GPOs missing AU/DC read + apply (MS16-072 trap)")
    p_ms16.add_argument("src", nargs="?", help="Sample directory (optional; reads DB if omitted)")
    p_ms16.set_defaults(func=cmd_ms16_072)

    p_cpw = sub.add_parser("cpassword", help="Scan SYSVOL GPP XML for lingering cpassword secrets (MS14-025)")
    p_cpw.add_argument("src", nargs="?", help="Sample directory (optional; reads DB if omitted)")
    p_cpw.set_defaults(func=cmd_cpassword)

    # snapshots
    p_snaps = sub.add_parser("snapshots", help="List stored snapshots")
    p_snaps.set_defaults(func=cmd_snapshots)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
