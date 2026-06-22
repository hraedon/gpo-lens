"""One-command estate health overview."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from gpo_lens.danger import danger_findings
from gpo_lens.detection import (
    admx_gaps,
    broken_refs,
    cpassword_scan,
    dangling_links,
    disabled_but_populated,
    empty_gpos,
    enforced_links,
    ms16_072_vulnerable,
    scan_ilt,
    unlinked_gpos,
    version_skew,
)
from gpo_lens.queries._search import blocked_extensions, conflicts
from gpo_lens.queries._wmi import (
    broken_wmi_refs,
    orphaned_wmi_filters,
    stale_gpos,
)
from gpo_lens.topology import loopback_gpos, wmi_filtered_gpos

if TYPE_CHECKING:
    from gpo_lens.model import Estate


@dataclass(frozen=True)
class EstateSummary:
    """One-command estate health overview."""

    domain: str
    gpo_count: int
    som_count: int
    linked_site_count: int
    coverage_gap_count: int
    wmi_filter_count: int
    unlinked_count: int
    empty_count: int
    disabled_but_populated_count: int
    conflict_count: int
    blocked_extension_count: int
    version_skew_count: int
    ms16_072_vulnerable_count: int
    cpassword_hit_count: int
    loopback_gpo_count: int
    wmi_filtered_gpo_count: int
    enforced_link_count: int
    dangling_link_count: int
    broken_ref_count: int
    admx_gap_count: int
    broken_wmi_ref_count: int
    orphaned_wmi_filter_count: int
    ilt_gpo_count: int
    stale_gpo_count: int
    danger_finding_count: int
    total_settings: int
    total_delegation_entries: int


def estate_summary(
    estate: Estate, *, danger_count: int | None = None,
) -> EstateSummary:
    """One-command estate health overview.

    *danger_count* lets a caller that already computed danger findings
    (e.g. estate_doctor) pass the count in, avoiding a redundant
    ``danger_findings()`` evaluation (WI-031).  When ``None`` the count
    is computed here.
    """
    if danger_count is None:
        danger_count = len(danger_findings(estate))
    return EstateSummary(
        domain=estate.domain,
        gpo_count=len(estate.gpos),
        # OU/domain SOMs only; sites are a parallel axis counted separately.
        som_count=sum(1 for s in estate.soms if s.container_type != "site"),
        linked_site_count=sum(
            1
            for s in estate.soms
            if s.container_type == "site" and any(link.enabled for link in s.links)
        ),
        coverage_gap_count=len(estate.coverage_gaps),
        wmi_filter_count=len(estate.wmi_filters),
        unlinked_count=len(unlinked_gpos(estate)),
        empty_count=len(empty_gpos(estate)),
        disabled_but_populated_count=len(disabled_but_populated(estate)),
        conflict_count=len(conflicts(estate)),
        blocked_extension_count=len(blocked_extensions(estate)),
        version_skew_count=len(version_skew(estate)),
        ms16_072_vulnerable_count=len(ms16_072_vulnerable(estate)),
        cpassword_hit_count=len(cpassword_scan(estate)),
        loopback_gpo_count=len(loopback_gpos(estate)),
        wmi_filtered_gpo_count=len(wmi_filtered_gpos(estate)),
        enforced_link_count=len(enforced_links(estate)),
        dangling_link_count=len(dangling_links(estate)),
        broken_ref_count=len(broken_refs(estate)),
        admx_gap_count=len(admx_gaps(estate)),
        broken_wmi_ref_count=len(broken_wmi_refs(estate)),
        orphaned_wmi_filter_count=len(orphaned_wmi_filters(estate)),
        ilt_gpo_count=len(scan_ilt(estate)),
        stale_gpo_count=len(stale_gpos(estate)),
        danger_finding_count=danger_count,
        total_settings=sum(len(g.settings) for g in estate.gpos),
        total_delegation_entries=sum(len(g.delegation) for g in estate.gpos),
    )
