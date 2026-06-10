from __future__ import annotations

import argparse

from gpo_lens import queries
from gpo_lens.cli._helpers import _get_estate, _print_table, _render_json


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
