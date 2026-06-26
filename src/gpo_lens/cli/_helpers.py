"""Shared CLI helpers: estate loading, JSON rendering, default DB path."""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from gpo_lens import __version__, ingest, store
from gpo_lens.display import render_table
from gpo_lens.model import Estate

if TYPE_CHECKING:
    from gpo_lens.admx_parser import PolicyDefinitions

DEFAULT_DB = "./gpo-lens.sqlite3"

# Version of the machine-readable JSON output contract. Every `--json` payload
# is wrapped in a self-describing envelope carrying this number so downstream
# consumers can detect and adapt to contract evolution. Bump only on a
# breaking change to a `data` shape; additive fields keep the same version.
# See docs/spec/json-contract.md for the frozen shapes.
JSON_CONTRACT_VERSION = 1

# The current subcommand name, set once per invocation by the CLI entrypoint
# before dispatch. Used as the envelope `kind` so each payload is self-labelling.
_json_kind: str | None = None


def _set_json_kind(kind: str | None) -> None:
    """Record the active subcommand so `_render_json` can label its envelope."""
    global _json_kind
    _json_kind = kind


def _get_estate(args: argparse.Namespace) -> Estate:
    src = getattr(args, "src", None) or getattr(args, "sample_dir", None)
    if src:
        return ingest.load_estate(src)
    db = Path(args.db)
    if not db.exists():
        raise FileNotFoundError(f"Database not found: {db}")
    conn = sqlite3.connect(str(db))
    try:
        return store.load_estate(conn)
    finally:
        conn.close()


def _render_json(obj: object) -> None:
    """Print `obj` as the payload of the versioned JSON output envelope.

    The envelope is the frozen contract downstream tools consume: a stable
    `schema_version` + `kind` header with the command-specific payload under
    `data`. Volatile fields (`tool_version`, `generated_at`) are informational
    and must not be treated as part of the comparable shape.
    """
    envelope = {
        "schema_version": JSON_CONTRACT_VERSION,
        "kind": _json_kind,
        "tool_version": __version__,
        "generated_at": datetime.now(UTC).isoformat(),
        "data": obj,
    }
    print(json.dumps(envelope, indent=2, default=str))


def _print_table(headers: list[str], rows: list[Sequence[str]]) -> None:
    print(render_table(headers, rows))


def _get_admx(args: argparse.Namespace) -> PolicyDefinitions | None:
    """Resolve the ADMX resolver from CLI args or auto-detection.

    Priority:
    1. ``--admx-dir`` if provided and valid
    2. Auto-detect ``PolicyDefinitions`` in the export directory (``src``)
    3. ``None`` (no ADMX resolution)

    Prints a warning to stderr if ``--admx-dir`` is given but invalid.
    """
    from gpo_lens.admx_parser import find_admx_dir, parse_admx_dir

    admx_dir = getattr(args, "admx_dir", None)
    if admx_dir:
        if not Path(admx_dir).is_dir():
            print(
                f"Warning: --admx-dir not found or not a directory: {admx_dir}",
                file=sys.stderr,
            )
        else:
            return parse_admx_dir(admx_dir)

    src = getattr(args, "src", None) or getattr(args, "sample_dir", None)
    if src:
        auto = find_admx_dir(src)
        if auto is not None:
            return parse_admx_dir(auto)

    return None
