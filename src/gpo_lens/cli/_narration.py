from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from typing import Callable

from gpo_lens import queries
from gpo_lens.cli._helpers import _get_estate, _render_json
from gpo_lens.detection import _mask_cpassword


def _serialize_result(result: object) -> object:
    if dataclasses.is_dataclass(result) and not isinstance(result, type):
        return dataclasses.asdict(result)
    if isinstance(result, list):
        return [_serialize_result(item) for item in result]
    if isinstance(result, dict):
        return {k: _serialize_result(v) for k, v in result.items()}
    if isinstance(result, tuple):
        return [_serialize_result(item) for item in result]
    return result


def cmd_ask(args: argparse.Namespace) -> int:
    from gpo_lens.narration import NarrationUnavailable, call_llm, route_question

    question: str = args.question
    raw_json: bool = args.no_narrate or getattr(args, "json", False)

    estate = _get_estate(args)

    try:
        routing = route_question(question)
    except NarrationUnavailable as exc:
        print(f"Error: {exc}", file=sys.stderr)
        print("Set GPO_LENS_API_KEY to use the ask command.", file=sys.stderr)
        return 1

    if "error" in routing:
        reason = routing.get("reason", "unknown")
        print(f"Cannot answer: {reason}", file=sys.stderr)
        return 1

    query_name = str(routing["query"])
    params = dict(routing.get("params", {}))  # type: ignore[call-overload]

    _QUERY_DISPATCH: dict[
        str, Callable[..., object]
    ] = {
        "estate_summary": lambda **kw: queries.estate_summary(
            kw["estate"]
        ),
        "estate_doctor": lambda **kw: queries.estate_doctor(
            kw["estate"]
        ),
        "cpassword_scan": lambda **kw: queries.cpassword_scan(
            kw["estate"]
        ),
        "unlinked_gpos": lambda **kw: queries.unlinked_gpos(
            kw["estate"]
        ),
        "empty_gpos": lambda **kw: queries.empty_gpos(kw["estate"]),
        "version_skew": lambda **kw: queries.version_skew(
            kw["estate"]
        ),
        "broken_refs": lambda **kw: queries.broken_refs(kw["estate"]),
        "enforced_links": lambda **kw: queries.enforced_links(
            kw["estate"]
        ),
        "dangling_links": lambda **kw: queries.dangling_links(
            kw["estate"]
        ),
        "ms16_072_vulnerable": lambda **kw: queries.ms16_072_vulnerable(
            kw["estate"]
        ),
        "topology_crosscheck": lambda **kw: queries.topology_crosscheck(
            kw["estate"]
        ),
        "disabled_but_populated": lambda **kw: queries.disabled_but_populated(
            kw["estate"]
        ),
        "settings_at_som": lambda **kw: queries.settings_at_som(
            kw["estate"], kw.get("ou_path", "")
        ),
    }

    if query_name not in _QUERY_DISPATCH:
        print(
            f"Error: query '{query_name}' not implemented yet",
            file=sys.stderr,
        )
        return 1

    call_kw: dict[str, object] = {"estate": estate, **params}
    query_result: object = _QUERY_DISPATCH[query_name](**call_kw)

    if query_name == "cpassword_scan":
        hits: list[queries.CpasswordHit] = query_result  # type: ignore[assignment]
        query_result = [
            dataclasses.replace(hit, cpassword=_mask_cpassword(hit.cpassword))
            for hit in hits
        ]

    serialized_result = _serialize_result(query_result)

    if raw_json:
        _render_json(serialized_result)
        return 0

    narration_text: str | None = None
    try:
        narration_text = call_llm(
            "You are a Group Policy analyst. The user asked a question about their "
            "GPO estate. Below are the raw query results as JSON. Answer the user's "
            "question clearly, referencing specific GPO names and values from the data.",
            f"Question: {question}\n\nQuery results:\n"
            + json.dumps(serialized_result, indent=2),
        )
    except NarrationUnavailable:
        narration_text = None
    except Exception as exc:
        print(f"Warning: narration failed: {exc}", file=sys.stderr)
        narration_text = None

    if narration_text is not None:
        print(narration_text)
        print("\n--- Raw results ---\n")
        _render_json(serialized_result)
    else:
        print("Narration unavailable. Raw results:")
        _render_json(serialized_result)
    return 0

