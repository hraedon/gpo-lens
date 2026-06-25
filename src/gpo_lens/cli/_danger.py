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
                    "compliance": [
                        {"framework": c.framework, "control_id": c.control_id}
                        for c in f.compliance
                    ],
                    "remediation": f.remediation,
                }
                for f in findings
            ]
        )
    else:
        if not findings:
            print("No dangerous configurations found.")
        else:
            headers = [
                "severity", "check_id", "gpo_name", "title",
                "compliance", "reference", "remediation",
            ]
            rows: list[list[str]] = [
                [
                    f.severity,
                    f.check_id,
                    f.gpo_name,
                    f.title,
                    ", ".join(f"{c.framework}:{c.control_id}" for c in f.compliance)
                    or "—",
                    f.reference,
                    f.remediation or "—",
                ]
                for f in findings
            ]
            _print_table(headers, [list(r) for r in rows])
