"""OU-tree / inheritance cross-check against the platform-resolved SOMs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from gpo_lens.model import Estate, Som


@dataclass(frozen=True)
class TopologyDiscrepancy:
    """One inconsistency between ``ou-tree.json`` and ``gp-inheritance.json``."""

    kind: str       # "block_mismatch", "ou_missing_from_soms", "gp_link_parse_failure"
    ou_dn: str
    detail: str


def topology_crosscheck(estate: Estate) -> list[TopologyDiscrepancy]:
    """Cross-check ``ou_tree`` against the platform-resolved ``soms``."""
    results: list[TopologyDiscrepancy] = []
    som_by_dn: dict[str, Som] = {s.path.lower(): s for s in estate.soms}

    for ou in estate.ou_tree:
        dn_lower = ou.dn.lower()
        som = som_by_dn.get(dn_lower)
        if som is None:
            if ou.gp_link:
                results.append(TopologyDiscrepancy(
                    kind="ou_missing_from_soms",
                    ou_dn=ou.dn,
                    detail="OU has gPLink but no matching SOM in gp-inheritance.json",
                ))
            continue

        raw_blocked = ou.gp_options == 1
        resolved_blocked = som.inheritance_blocked
        if raw_blocked != resolved_blocked:
            results.append(TopologyDiscrepancy(
                kind="block_mismatch",
                ou_dn=ou.dn,
                detail=(
                    f"ou-tree gPOptions={ou.gp_options} (blocked={raw_blocked}) "
                    f"vs gp-inheritance blocked={resolved_blocked}"
                ),
            ))

    return results
