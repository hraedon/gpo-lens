"""CLI subcommand: danger — scan for dangerous GPO configurations."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from gpo_lens import queries
from gpo_lens.cli._helpers import _get_estate, _print_table, _render_json


def cmd_danger(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    admx = None
    admx_dir = getattr(args, "admx_dir", None)
    if admx_dir:
        if not Path(admx_dir).is_dir():
            print(
                f"Warning: --admx-dir not found or not a directory: {admx_dir}",
                file=sys.stderr,
            )
        else:
            from gpo_lens.admx_parser import parse_admx_dir

            admx = parse_admx_dir(admx_dir)
    findings = queries.danger_findings(estate, admx=admx)
    if args.json:
        _render_json(
            [
                {
                    "check_id": f.check_id,
                    "severity": f.severity,
                    "title": f.title,
                    "gpo_id": f.gpo_id,
                    "gpo_name": f.gpo_name,
                    "detail": f.detail,
                    "reference": f.reference,
                }
                for f in findings
            ]
        )
    else:
        if not findings:
            print("No dangerous configurations found.")
        else:
            _print_table(
                ["severity", "check_id", "gpo_name", "title", "reference"],
                [
                    [f.severity, f.check_id, f.gpo_name, f.title, f.reference]
                    for f in findings
                ],
            )
