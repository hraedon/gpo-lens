from __future__ import annotations

import argparse
import sys

from gpo_lens import __version__
from gpo_lens.cli._danger import cmd_danger
from gpo_lens.cli._delegation import cmd_delegation, cmd_perms, cmd_sddl
from gpo_lens.cli._diff import (
    cmd_baseline_diff,
    cmd_changelog,
    cmd_diff,
    cmd_diff_settings,
    cmd_snapshots,
)
from gpo_lens.cli._estate import cmd_ingest, cmd_summary
from gpo_lens.cli._events import cmd_events, cmd_events_export
from gpo_lens.cli._helpers import DEFAULT_DB, _set_json_kind
from gpo_lens.cli._hygiene import (
    cmd_blocked,
    cmd_broken_refs,
    cmd_cpassword,
    cmd_disabled_populated,
    cmd_doctor,
    cmd_empty,
    cmd_gpp_groups,
    cmd_gpp_tasks,
    cmd_ms16_072,
    cmd_unlinked,
    cmd_version_skew,
)
from gpo_lens.cli._narration import cmd_ask, cmd_explain_setting
from gpo_lens.cli._repl import cmd_repl
from gpo_lens.cli._report import cmd_report
from gpo_lens.cli._resultant import cmd_resultant
from gpo_lens.cli._serve import cmd_serve
from gpo_lens.cli._settings import (
    cmd_admx_gaps,
    cmd_conflicts,
    cmd_precedence_conflicts,
    cmd_search,
    cmd_settings_at,
    cmd_settings_diff,
    cmd_settings_dump,
    cmd_show,
    cmd_som_conflicts,
    cmd_who_sets,
)
from gpo_lens.cli._topology import (
    cmd_dangling,
    cmd_enforced,
    cmd_loopback,
    cmd_scope,
    cmd_sites,
    cmd_som,
    cmd_topology_check,
    cmd_wmi,
    cmd_wmi_filters,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="gpo-lens")
    parser.add_argument("--version", action="version", version=f"gpo-lens {__version__}")
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
    p.add_argument("--json", action="store_true")
    p.add_argument(
        "--diff-latest", action="store_true",
        help="After ingesting, diff against the previous snapshot and print the changelog",
    )
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

    p = sub.add_parser("delegation", help="Delegation deep-dive audit")
    _add_src(p)
    p.set_defaults(func=cmd_delegation)

    p = sub.add_parser("sddl", help="Parse and display SDDL for GPOs")
    _add_src(p)
    p.set_defaults(func=cmd_sddl)

    p = sub.add_parser("diff")
    p.add_argument("snapshot_a", type=int)
    p.add_argument("snapshot_b", type=int)
    p.set_defaults(func=cmd_diff)

    p = sub.add_parser("snapshots")
    p.set_defaults(func=cmd_snapshots)

    p = sub.add_parser("events", help="Query the append-only event log")
    p.add_argument("--since", help="Filter events by timestamp (ISO 8601 prefix)")
    p.add_argument(
        "--type", dest="event_type", help="Filter events by event_type (substring match)",
    )
    p.add_argument(
        "--limit", type=int, default=1000, help="Max events to return (default: 1000)",
    )
    p.set_defaults(func=cmd_events)

    # events-export
    p = sub.add_parser("events-export", help="Export events to NDJSON and/or Splunk HEC")
    p.add_argument("--ndjson", help="Path to write NDJSON output")
    p.add_argument("--since", help="Filter events by timestamp (ISO 8601 prefix)")
    p.add_argument(
        "--sink", choices=["hec"], help="External sink to send events to",
    )
    p.set_defaults(func=cmd_events_export)

    p = sub.add_parser(
        "diff-settings",
        help="Per-setting delta between two snapshots",
    )
    p.add_argument("snapshot_a", type=int)
    p.add_argument("snapshot_b", type=int)
    p.add_argument("--gpo-id", help="Filter to a specific GPO ID")
    p.add_argument("--side", help="Filter by side (Computer/User)")
    p.add_argument("--cse", help="Filter by CSE name")
    p.set_defaults(func=cmd_diff_settings)

    p = sub.add_parser(
        "changelog",
        help="Version-aware change log between two snapshots",
    )
    p.add_argument("snapshot_a", type=int)
    p.add_argument("snapshot_b", type=int)
    p.add_argument("--gpo-id", help="Filter to a specific GPO ID")
    p.add_argument("--side", help="Filter by side (Computer/User)")
    p.set_defaults(func=cmd_changelog)

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
        "sites",
        help="AD sites and their GPO links (lowest precedence; not resolved per-machine)",
    )
    _add_src(p)
    p.set_defaults(func=cmd_sites)

    p = sub.add_parser(
        "topology-check",
        help="Cross-check ou-tree.json against gp-inheritance.json",
    )
    _add_src(p)
    p.set_defaults(func=cmd_topology_check)

    p = sub.add_parser(
        "scope",
        help="Show effective scoping for a GPO (links, security filtering, WMI, loopback)",
    )
    p.add_argument("gpo", help="GPO name or canonical id")
    _add_src(p)
    p.set_defaults(func=cmd_scope)

    p = sub.add_parser(
        "admx-gaps",
        help="Flag Registry CSE settings with raw key paths (no ADMX policy name)",
    )
    p.add_argument("--admx-dir", help="PolicyDefinitions directory for crosswalk")
    _add_src(p)
    p.set_defaults(func=cmd_admx_gaps)

    p = sub.add_parser(
        "settings-at",
        help="Show effective settings at a SOM path",
    )
    p.add_argument("som_path")
    _add_src(p)
    p.set_defaults(func=cmd_settings_at)

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

    # Structured GPP audits
    p = sub.add_parser(
        "gpp-tasks",
        help="Inventory of scheduled tasks deployed by GPO (GPP ScheduledTasks.xml)",
    )
    _add_src(p)
    p.set_defaults(func=cmd_gpp_tasks)

    p = sub.add_parser(
        "gpp-groups",
        help="Local-group membership changes deployed by GPO (GPP Groups.xml)",
    )
    _add_src(p)
    p.set_defaults(func=cmd_gpp_groups)

    # settings-dump
    p = sub.add_parser(
        "settings-dump",
        help="Flat export of all settings (pipe-friendly)",
    )
    p.add_argument("--side", help="Filter by side (Computer/User)")
    p.add_argument("--cse", help="Filter by CSE (substring match)")
    p.add_argument("--gpo", dest="gpo_name", help="Filter by GPO name (substring match)")
    _add_src(p)
    p.set_defaults(func=cmd_settings_dump)

    # settings-diff
    p = sub.add_parser(
        "settings-diff",
        help="Diff two settings-dump JSON exports",
    )
    p.add_argument("file_a", help="First settings-dump JSON file")
    p.add_argument("file_b", help="Second settings-dump JSON file")
    p.add_argument("--side", help="Filter by side (Computer/User)")
    p.add_argument("--cse", help="Filter by CSE (substring match)")
    p.add_argument("--gpo", dest="gpo_id", help="Filter by GPO id (substring match)")
    p.set_defaults(func=cmd_settings_diff)

    # baseline-diff
    p = sub.add_parser(
        "baseline-diff",
        help="Diff estate settings against a baseline GPO backup",
    )
    _add_src(p)
    p.add_argument("baseline_dir", help="Baseline GPO directory or .zip file")
    p.add_argument(
        "--admx-dir", help="PolicyDefinitions directory for registry-to-policy crosswalk",
    )
    p.set_defaults(func=cmd_baseline_diff)

    # doctor
    p = sub.add_parser(
        "doctor",
        help="Run all hygiene checks and produce a prioritized findings report",
    )
    _add_src(p)
    p.add_argument(
        "--explain", action="store_true",
        help="Add an LLM-powered plain-English explanation of findings",
    )
    p.set_defaults(func=cmd_doctor)

    # report
    p = sub.add_parser("report", help="Generate estate documentation report")
    p.add_argument("--output", help="Output file path (default: stdout)")
    p.add_argument("--format", choices=["md", "html"], default="md")
    p.add_argument(
        "--baseline", help="Baseline JSON file for compliance comparison"
    )
    p.add_argument(
        "--since", type=int,
        help="Snapshot ID to diff against (requires --db)"
    )
    p.add_argument(
        "--max-settings", type=int, default=50,
        help="Max settings per GPO to display (default: 50)",
    )
    p.add_argument(
        "--admx-dir",
        help="PolicyDefinitions directory for registry-to-policy crosswalk (used with --baseline)",
    )
    _add_src(p)
    p.set_defaults(func=cmd_report)

    # ask
    p = sub.add_parser("ask", help="Ask a natural-language question about the estate")
    p.add_argument("question", help="Free-text question about the GPO estate")
    p.add_argument(
        "--no-narrate", action="store_true",
        help="Print raw query results as JSON without narration",
    )
    _add_src(p)
    p.set_defaults(func=cmd_ask)

    # explain-setting
    p = sub.add_parser(
        "explain-setting",
        help="Explain what a registry setting / GPO identity does",
    )
    p.add_argument(
        "identity",
        help="Registry path or setting identity (optionally 'key:value')",
    )
    p.add_argument(
        "--admx-dir", help="PolicyDefinitions directory for ADMX crosswalk",
    )
    p.set_defaults(func=cmd_explain_setting)

    # REPL
    p = sub.add_parser("repl", help="Interactive Python REPL with the estate loaded")
    _add_src(p)
    p.set_defaults(func=cmd_repl)

    # danger
    p = sub.add_parser(
        "danger",
        help="Scan for dangerous GPO configurations (curated, cited checks)",
    )
    p.add_argument("--json", action="store_true", help="JSON output")
    p.add_argument(
        "--admx-dir",
        help="PolicyDefinitions directory for policy-name-keyed rules",
    )
    _add_src(p)
    p.set_defaults(func=cmd_danger)

    # serve
    p = sub.add_parser("serve", help="Launch the web UI")
    p.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    p.add_argument("--port", type=int, default=8000, help="Bind port (default: 8000)")
    p.add_argument("--open", action="store_true", help="Open browser on start")
    p.add_argument("--root-path", default="", help="ASGI root_path for reverse-proxy mounting")
    p.add_argument(
        "--admx-dir",
        help="PolicyDefinitions directory for registry-to-policy crosswalk",
    )
    p.set_defaults(func=cmd_serve)

    # resultant (Plan 021)
    p = sub.add_parser(
        "resultant",
        help="Principal resultant (RSoP) — effective policy for a principal",
    )
    p.add_argument(
        "principal_sid",
        help="SID of the principal (user or computer) to compute resultant for",
    )
    p.add_argument("--computer-sid", default=None, help="Computer SID (for user+computer pair)")
    p.add_argument("--dn", default=None, help="Distinguished name of the principal (for SOM chain)")
    p.add_argument("--computer-dn", default=None, help="Computer DN (for user+computer SOM chain)")
    p.add_argument("--json", action="store_true", help="JSON output")
    _add_src(p)
    p.set_defaults(func=cmd_resultant)

    args = parser.parse_args(argv)
    if not hasattr(args, "func"):
        parser.print_help()
        return 1
    # Label every --json envelope with the active subcommand (the contract `kind`).
    _set_json_kind(getattr(args, "command", None))
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
    sys.exit(main())
