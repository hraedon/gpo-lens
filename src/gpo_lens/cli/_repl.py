"""CLI subcommand: interactive Python REPL."""
from __future__ import annotations

import argparse
import code

from gpo_lens import queries
from gpo_lens.cli._helpers import _get_estate


def cmd_repl(args: argparse.Namespace) -> None:
    estate = _get_estate(args)
    local_vars = {"estate": estate, "queries": queries}
    code.interact(
        banner="gpo-lens REPL — `estate` and `queries` are available",
        local=local_vars,
    )
