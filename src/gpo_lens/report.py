"""Report builder for estate documentation export."""

from __future__ import annotations

import html as html_lib
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from gpo_lens.model import Estate, Gpo, Som
    from gpo_lens.queries import (
        BaselineDiffEntry,
        DoctorFinding,
        EstateSummary,
    )
    from gpo_lens.snapshot_diff import ChangelogEntry

_SUMMARY_FIELDS: list[tuple[str, str]] = [
    ("Domain", "domain"),
    ("GPOs", "gpo_count"),
    ("SOMs", "som_count"),
    ("Sites with GPO links", "linked_site_count"),
    ("Coverage gaps (uncollected GPOs)", "coverage_gap_count"),
    ("WMI filters", "wmi_filter_count"),
    ("WMI-filtered GPOs", "wmi_filtered_gpo_count"),
    ("Unlinked GPOs", "unlinked_count"),
    ("Empty GPOs", "empty_count"),
    ("Disabled-but-populated", "disabled_but_populated_count"),
    ("Setting conflicts", "conflict_count"),
    ("Blocked extensions", "blocked_extension_count"),
    ("Version skew", "version_skew_count"),
    ("MS16-072 vulnerable", "ms16_072_vulnerable_count"),
    ("cpassword hits", "cpassword_hit_count"),
    ("Loopback GPOs", "loopback_gpo_count"),
    ("Enforced links", "enforced_link_count"),
    ("Dangling links", "dangling_link_count"),
    ("Broken references", "broken_ref_count"),
    ("Broken WMI references", "broken_wmi_ref_count"),
    ("Orphaned WMI filters", "orphaned_wmi_filter_count"),
    ("Item-level-targeting GPOs", "ilt_gpo_count"),
    ("Stale GPOs (>2y)", "stale_gpo_count"),
    ("ADMX gaps", "admx_gap_count"),
    ("Total settings", "total_settings"),
    ("Total delegation entries", "total_delegation_entries"),
]

_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")

_SEVERITY_COLOR = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#ca8a04",
    "low": "#2563eb",
    "info": "#6b7280",
}


# ---------------------------------------------------------------------------
# Shared data structures for GPO sections
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class _GpoSectionItem:
    label: str
    value: str


@dataclass(frozen=True)
class _GpoLinkItem:
    som_path: str
    enabled: bool
    enforced: bool


@dataclass(frozen=True)
class _GpoDelegationItem:
    trustee: str
    permission: str
    allowed: bool


@dataclass(frozen=True)
class _GpoSettingItem:
    cse: str
    side: str
    identity: str
    display_value: str
    flags: str


def _gpo_sections(
    gpo: Gpo,
) -> tuple[
    list[_GpoSectionItem],
    list[_GpoLinkItem],
    list[_GpoDelegationItem],
    list[_GpoSettingItem],
]:
    """Extract structured sections from a Gpo for format-agnostic rendering."""
    properties: list[_GpoSectionItem] = [
        _GpoSectionItem("ID", gpo.id),
        _GpoSectionItem("Domain", gpo.domain),
        _GpoSectionItem("Computer side", "Enabled" if gpo.computer_enabled else "Disabled"),
        _GpoSectionItem("User side", "Enabled" if gpo.user_enabled else "Disabled"),
    ]

    if gpo.description:
        properties.append(_GpoSectionItem("Description", gpo.description))

    if gpo.computer_ver_ds is not None or gpo.computer_ver_sysvol is not None:
        comp_skew = " **SKEW**" if gpo.computer_version_skew else ""
        properties.append(
            _GpoSectionItem(
                "Computer version",
                f"DS={gpo.computer_ver_ds}, SYSVOL={gpo.computer_ver_sysvol}{comp_skew}",
            )
        )
    if gpo.user_ver_ds is not None or gpo.user_ver_sysvol is not None:
        user_skew = " **SKEW**" if gpo.user_version_skew else ""
        properties.append(
            _GpoSectionItem(
                "User version",
                f"DS={gpo.user_ver_ds}, SYSVOL={gpo.user_ver_sysvol}{user_skew}",
            )
        )

    if gpo.wmi_filter:
        properties.append(_GpoSectionItem("WMI filter", gpo.wmi_filter))
    if gpo.owner:
        properties.append(_GpoSectionItem("Owner", gpo.owner))

    links = [
        _GpoLinkItem(link.som_path, link.link_enabled, link.enforced)
        for link in gpo.links
    ]

    delegation = [
        _GpoDelegationItem(d.trustee, d.permission, d.allowed)
        for d in gpo.delegation
    ]

    settings: list[_GpoSettingItem] = []
    for s in gpo.settings:
        flags = ""
        if s.from_disabled_side:
            flags += " [DISABLED SIDE]"
        if s.source_state == "blocked":
            flags += " [BLOCKED]"
        settings.append(
            _GpoSettingItem(
                s.cse, s.side, s.identity, s.display_value, flags
            )
        )

    return properties, links, delegation, settings


# ---------------------------------------------------------------------------
# Format-specific renderers for GPO sections
# ---------------------------------------------------------------------------

def _gpo_md(gpo: Gpo, *, max_settings: int = 50) -> str:
    parts: list[str] = []
    parts.append(f"### {_md_esc(gpo.name)}\n")

    properties, links, delegation, settings = _gpo_sections(gpo)

    for p in properties:
        parts.append(f"- **{_md_esc(p.label)}:** {_md_esc(p.value)}")

    if links:
        parts.append("")
        parts.append("**Links:**\n")
        for link in links:
            enabled = "enabled" if link.enabled else "disabled"
            enforced = " [ENFORCED]" if link.enforced else ""
            parts.append(f"- `{_md_code(link.som_path)}` ({enabled}{enforced})")

    if delegation:
        parts.append("")
        parts.append("**Delegation:**\n")
        for d in delegation:
            allowed = "Allow" if d.allowed else "Deny"
            parts.append(f"- {_md_esc(d.trustee)}: {_md_esc(d.permission)} ({allowed})")

    if settings:
        parts.append("")
        parts.append(f"**Settings** ({len(gpo.settings)}):\n")
        for s in settings[:max_settings]:
            parts.append(
                f"- `[{_md_code(s.cse)}] {_md_code(s.side)}/{_md_code(s.identity)}`: "
                f"{_md_esc(s.display_value)}{_md_esc(s.flags)}"
            )
        remaining = len(gpo.settings) - max_settings
        if remaining > 0:
            parts.append(f"- ... ({remaining} more settings)")

    parts.append("")
    return "\n".join(parts)



def _esc(text: str) -> str:
    return html_lib.escape(str(text))


def _md_esc(text: str | object) -> str:
    """Escape user-controlled text for safe inclusion in Markdown output.

    Prevents XSS when Markdown is rendered to HTML (most renderers pass
    raw HTML tags through).  Also escapes ampersands so entities are
    displayed literally rather than interpreted.
    """
    return html_lib.escape(str(text), quote=False)


def _md_code(text: str | object) -> str:
    r"""Escape text for use inside Markdown inline code (backtick) spans.

    Only escapes backticks (prevents breaking out of the code span).  HTML
    entities are NOT escaped here because CommonMark renderers escape code
    span content automatically — calling ``_md_esc`` would double-escape
    (``<`` → ``&lt;`` → ``&amp;lt;`` in the rendered output).
    """
    return str(text).replace("`", "&#96;")


def _md_table(text: str | object) -> str:
    """Escape text for use in Markdown table cells.

    Escapes HTML entities, pipe characters (column separators), and
    newlines (which would break table rows).
    """
    return _md_esc(str(text).replace("|", "\\|").replace("\n", " "))


def _gpo_html(gpo: Gpo, *, max_settings: int = 50) -> list[str]:
    parts: list[str] = []
    parts.append(f"<h3>{_esc(gpo.name)}</h3>")

    properties, links, delegation, settings = _gpo_sections(gpo)

    parts.append("<table>")
    parts.append("<tr><th>Property</th><th>Value</th></tr>")
    for p in properties:
        parts.append(f"<tr><td>{_esc(p.label)}</td><td>{_esc(p.value)}</td></tr>")
    parts.append("</table>")

    if links:
        parts.append("<p><strong>Links:</strong></p>")
        parts.append("<table>")
        parts.append("<tr><th>SOM Path</th><th>Enabled</th><th>Enforced</th></tr>")
        for link in links:
            enabled = "Yes" if link.enabled else "No"
            enforced = "Yes" if link.enforced else "No"
            parts.append(
                f"<tr><td><code>{_esc(link.som_path)}</code></td>"
                f"<td>{enabled}</td><td>{enforced}</td></tr>"
            )
        parts.append("</table>")

    if delegation:
        parts.append("<p><strong>Delegation:</strong></p>")
        parts.append("<table>")
        parts.append("<tr><th>Trustee</th><th>Permission</th><th>Allowed</th></tr>")
        for d in delegation:
            allowed = "Allow" if d.allowed else "Deny"
            parts.append(
                f"<tr><td>{_esc(d.trustee)}</td>"
                f"<td>{_esc(d.permission)}</td>"
                f"<td>{allowed}</td></tr>"
            )
        parts.append("</table>")

    if settings:
        parts.append(f"<p><strong>Settings</strong> ({len(gpo.settings)}):</p>")
        parts.append("<table>")
        parts.append("<tr><th>CSE</th><th>Side</th><th>Identity</th><th>Value</th></tr>")
        for s in settings[:max_settings]:
            parts.append(
                f"<tr><td>{_esc(s.cse)}</td><td>{_esc(s.side)}</td>"
                f"<td><code>{_esc(s.identity)}</code></td>"
                f"<td>{_esc(s.display_value)}{_esc(s.flags)}</td></tr>"
            )
        remaining = len(gpo.settings) - max_settings
        if remaining > 0:
            parts.append(
                f"<tr><td colspan='4'>... ({remaining} more settings)</td></tr>"
            )
        parts.append("</table>")

    return parts


# ---------------------------------------------------------------------------
# Shared section generators
# ---------------------------------------------------------------------------

def _summary_lines(summary: EstateSummary) -> list[tuple[str, str]]:
    """Return (label, value) pairs for the summary table."""
    return [(label, str(getattr(summary, attr))) for label, attr in _SUMMARY_FIELDS]


def _grouped_findings(findings: list[DoctorFinding]) -> dict[str, list[DoctorFinding]]:
    """Group findings by severity."""
    grouped: dict[str, list[DoctorFinding]] = {s: [] for s in _SEVERITY_ORDER}
    for f in findings:
        sev = f.severity if f.severity in grouped else "info"
        grouped.setdefault(sev, []).append(f)
    return grouped


def _baseline_categories(
    baseline: list[BaselineDiffEntry],
) -> tuple[
    list[BaselineDiffEntry],
    list[BaselineDiffEntry],
    list[BaselineDiffEntry],
    list[BaselineDiffEntry],
    int,
    float,
]:
    """Split baseline entries by status and compute compliance percentage."""
    compliant = [r for r in baseline if r.status == "compliant"]
    drift = [r for r in baseline if r.status == "drift"]
    missing = [r for r in baseline if r.status == "missing"]
    extra = [r for r in baseline if r.status == "extra"]
    total = len(compliant) + len(drift) + len(missing) + len(extra)
    pct = round(len(compliant) / total * 100, 1) if total else 0
    return compliant, drift, missing, extra, total, pct


# ---------------------------------------------------------------------------
# Markdown builders
# ---------------------------------------------------------------------------

def _summary_table_md(summary: EstateSummary) -> str:
    lines = [
        "| Metric | Value |",
        "|--------|-------|",
    ]
    for label, value in _summary_lines(summary):
        lines.append(f"| {_md_table(label)} | {_md_table(value)} |")
    return "\n".join(lines)


def _findings_md(findings: list[DoctorFinding]) -> list[str]:
    parts: list[str] = []
    if not findings:
        parts.append("No issues detected. Estate looks healthy.\n")
        return parts

    grouped = _grouped_findings(findings)
    for sev in _SEVERITY_ORDER:
        group = grouped.get(sev, [])
        if not group:
            continue
        parts.append(f"### {sev.upper()}\n")
        for f in group:
            parts.append(
                f"- **{_md_esc(f.category)}** — "
                f"{_md_esc(f.gpo_name or f.gpo_id or 'N/A')}: "
                f"{_md_esc(f.summary)}"
            )
            if f.detail:
                parts.append(f"  _{_md_esc(f.detail)}_")
            if f.remediation:
                parts.append(f"  **Remediation:** {_md_esc(f.remediation)}")
        parts.append("")
    return parts


def _topology_md(estate: Estate, soms_with_links: list[Som]) -> list[str]:
    from gpo_lens import queries

    parts: list[str] = []
    if not soms_with_links:
        parts.append("No SOMs with links.\n")
        return parts

    for som in soms_with_links:
        block = " [BLOCKED INHERITANCE]" if som.inheritance_blocked else ""
        parts.append(f"### {_md_esc(som.name)}{block}\n")
        parts.append(f"_Path:_ `{_md_code(som.path)}`\n")
        gpos = queries.som_effective_gpos(estate, som.path, _som=som)
        if not gpos:
            parts.append("- No linked GPOs\n")
        else:
            for g in gpos:
                enforced = " **[ENFORCED]**" if g.enforced else ""
                en = "enabled" if g.enabled else "disabled"
                parts.append(
                    f"- {g.order}. {_md_esc(g.gpo_name)} ({_md_esc(g.gpo_id)}) "
                    f"{en}{enforced} — target: `{_md_code(g.target)}`"
                )
            parts.append("")
        parts.append("")
    return parts


def _effective_settings_md(estate: Estate, soms_with_links: list[Som]) -> list[str]:
    from gpo_lens import queries

    parts: list[str] = []
    if not soms_with_links:
        parts.append("No SOMs with links.\n")
        return parts

    for som in soms_with_links:
        eff = queries.settings_at_som(estate, som.path)
        if not eff:
            continue
        block = " [BLOCKED INHERITANCE]" if som.inheritance_blocked else ""
        parts.append(f"### {_md_esc(som.name)}{block}\n")
        parts.append(f"_Path:_ `{_md_code(som.path)}`\n")
        caveats = queries.scope_caveats(estate, som.path)
        if caveats:
            parts.append("> **\u26a0 Scope caveats** (flagged, not simulated):")
            for c in caveats:
                parts.append(f"> - {_md_esc(c.strip())}")
            parts.append(">")
            parts.append("> Effective settings may differ \u2014 scoping not simulated.\n")
        for s in eff:
            parts.append(
                f"- `[{_md_code(s.cse)}] {_md_code(s.side)}/{_md_code(s.identity)}`: "
                f"{_md_esc(s.display_value)} (winner: {_md_esc(s.winner_gpo_name)})"
            )
            if s.overridden_by:
                for o_name, o_val in s.overridden_by:
                    parts.append(f"  - overridden: {_md_esc(o_name)} = {_md_esc(o_val)}")
        parts.append("")
    return parts


def _baseline_md(baseline: list[BaselineDiffEntry]) -> list[str]:
    parts: list[str] = []
    compliant, drift, missing, extra, total, pct = _baseline_categories(baseline)
    parts.append(f"**Compliance: {pct}%** ({len(compliant)} / {total})\n")

    for title, items in [("Drift", drift), ("Missing", missing), ("Extra", extra)]:
        if items:
            parts.append(f"### {title}\n")
            for r in items:
                name = r.admx_name or r.display_name or r.identity
                parts.append(f"- `[{_md_code(r.cse)}] {_md_code(r.side)}/{_md_code(name)}`")
                if r.status == "drift":
                    parts.append(f"  - Expected: `{_md_code(r.expected_value)}`")
                    parts.append(
                        f"  - Actual: `{_md_code(r.actual_value)}` "
                        f"(GPO: {_md_esc(r.gpo_id)})"
                    )
                elif r.status == "missing":
                    parts.append(f"  - Expected: `{_md_code(r.expected_value)}`")
                else:
                    parts.append(
                        f"  - Actual: `{_md_code(r.actual_value)}` "
                        f"(GPO: {_md_esc(r.gpo_id)})"
                    )
            parts.append("")
    return parts


def _changelog_md(changelog_entries: list[ChangelogEntry]) -> list[str]:
    parts: list[str] = []
    if not changelog_entries:
        parts.append("No changes found.\n")
        return parts

    for e in changelog_entries:
        prefix = "[DETAIL]" if e.kind == "settings_detail" else "[META]"
        parts.append(f"### {prefix} {_md_esc(e.gpo_name)} ({_md_esc(e.gpo_id)})\n")
        parts.append(f"*{_md_esc(e.summary)}*\n")
        if e.version_change:
            vc = e.version_change
            parts.append(
                f"Version change: DS {vc.old_ds or '?'} -> {vc.new_ds or '?'}, "
                f"SYSVOL {vc.old_sysvol or '?'} -> {vc.new_sysvol or '?'} "
                f"(edits: {vc.edit_count})\n"
            )
        for sc in e.setting_changes:
            parts.append(
                f"- `[{_md_code(sc.side)}/{_md_code(sc.cse)}] "
                f"{_md_code(sc.identity)}` — {_md_esc(sc.change_type)}"
            )
            if sc.old_value or sc.new_value:
                parts.append(
                    f"  - `{_md_code(sc.old_value or '')}` -> "
                    f"`{_md_code(sc.new_value or '')}`"
                )
        parts.append("")
    return parts


# ---------------------------------------------------------------------------
# HTML builders
# ---------------------------------------------------------------------------

def _badge(sev: str) -> str:
    color = _SEVERITY_COLOR.get(sev, "#6b7280")
    return (
        f'<span class="badge" style="background:{color};">'
        f"{_esc(sev.upper())}</span>"
    )


def _summary_table_html(summary: EstateSummary) -> list[str]:
    parts = ["<table>", "<tr><th>Metric</th><th>Value</th></tr>"]
    for label, value in _summary_lines(summary):
        parts.append(f"<tr><td>{_esc(label)}</td><td>{_esc(value)}</td></tr>")
    parts.append("</table>")
    return parts


def _findings_html(findings: list[DoctorFinding]) -> list[str]:
    parts: list[str] = []
    if not findings:
        parts.append("<p>No issues detected. Estate looks healthy.</p>")
        return parts

    grouped = _grouped_findings(findings)
    for sev in _SEVERITY_ORDER:
        group = grouped.get(sev, [])
        if not group:
            continue
        parts.append(f"<h3>{sev.upper()}</h3>")
        parts.append("<ul>")
        for f in group:
            detail = f"<br><small>{_esc(f.detail)}</small>" if f.detail else ""
            remediation = (
                f"<br><strong>Remediation:</strong> {_esc(f.remediation)}"
                if f.remediation else ""
            )
            parts.append(
                f"<li>{_badge(sev)} <strong>{_esc(f.category)}</strong> — "
                f"{_esc(f.gpo_name or f.gpo_id or 'N/A')}: "
                f"{_esc(f.summary)}"
                f"{detail}{remediation}</li>"
            )
        parts.append("</ul>")
    return parts


def _topology_html(estate: Estate, soms_with_links: list[Som]) -> list[str]:
    from gpo_lens import queries

    parts: list[str] = []
    if not soms_with_links:
        parts.append("<p>No SOMs with links.</p>")
        return parts

    for som in soms_with_links:
        block = (
            ' <span class="badge" style="background:#7c3aed;">'
            "BLOCKED</span>"
            if som.inheritance_blocked
            else ""
        )
        parts.append(f"<h3>{_esc(som.name)}{block}</h3>")
        parts.append(f"<p><em>Path:</em> <code>{_esc(som.path)}</code></p>")
        gpos = queries.som_effective_gpos(estate, som.path, _som=som)
        if not gpos:
            parts.append("<p>No linked GPOs.</p>")
        else:
            parts.append("<table>")
            parts.append(
                "<tr><th>Order</th><th>GPO</th><th>Enabled</th>"
                "<th>Enforced</th><th>Target</th></tr>"
            )
            for g in gpos:
                enabled = "Yes" if g.enabled else "No"
                enforced = "Yes" if g.enforced else "No"
                parts.append(
                    f"<tr><td>{g.order}</td>"
                    f"<td>{_esc(g.gpo_name)} ({_esc(g.gpo_id)})</td>"
                    f"<td>{enabled}</td><td>{enforced}</td>"
                    f"<td><code>{_esc(g.target)}</code></td></tr>"
                )
            parts.append("</table>")
    return parts


def _effective_settings_html(estate: Estate, soms_with_links: list[Som]) -> list[str]:
    from gpo_lens import queries

    parts: list[str] = []
    if not soms_with_links:
        parts.append("<p>No SOMs with links.</p>")
        return parts

    any_eff = False
    for som in soms_with_links:
        eff = queries.settings_at_som(estate, som.path)
        if not eff:
            continue
        any_eff = True
        block = (
            ' <span class="badge" style="background:#7c3aed;">'
            "BLOCKED</span>"
            if som.inheritance_blocked
            else ""
        )
        parts.append(f"<h3>{_esc(som.name)}{block}</h3>")
        parts.append(f"<p><em>Path:</em> <code>{_esc(som.path)}</code></p>")
        caveats = queries.scope_caveats(estate, som.path)
        if caveats:
            parts.append('<div class="caveats">')
            parts.append("<strong>\u26a0 Scope caveats</strong> "
                         "<em>(flagged, not simulated)</em>:<ul>")
            for c in caveats:
                parts.append(f"<li>{_esc(c.strip())}</li>")
            parts.append("</ul>")
            parts.append("<em>Effective settings may differ \u2014 "
                         "scoping mechanisms not simulated.</em>")
            parts.append("</div>")
        parts.append("<table>")
        parts.append(
            "<tr><th>CSE</th><th>Side</th><th>Identity</th>"
            "<th>Value</th><th>Winner GPO</th><th>Overridden</th></tr>"
        )
        for s in eff:
            overridden_parts = [
                f"{_esc(n)} = {_esc(v)}" for n, v in s.overridden_by
            ]
            overridden_text = "<br>".join(overridden_parts) if overridden_parts else ""
            parts.append(
                f"<tr><td>{_esc(s.cse)}</td><td>{_esc(s.side)}</td>"
                f"<td><code>{_esc(s.identity)}</code></td>"
                f"<td>{_esc(s.display_value)}</td>"
                f"<td>{_esc(s.winner_gpo_name)}</td>"
                f"<td>{overridden_text}</td></tr>"
            )
        parts.append("</table>")
    if not any_eff:
        parts.append("<p>No effective settings at any SOM.</p>")
    return parts


def _baseline_html(baseline: list[BaselineDiffEntry]) -> list[str]:
    parts: list[str] = []
    compliant, drift, missing, extra, total, pct = _baseline_categories(baseline)
    parts.append(
        f"<p><strong>Compliance: {pct}%</strong> "
        f"({len(compliant)} / {total})</p>"
    )

    for title, items in [("Drift", drift), ("Missing", missing), ("Extra", extra)]:
        if items:
            parts.append(f"<h3>{title}</h3><ul>")
            for r in items:
                name = r.admx_name or r.display_name or r.identity
                parts.append(
                    f"<li><code>[{_esc(r.cse)}] {_esc(r.side)}/{_esc(name)}</code>"
                )
                if r.status == "drift":
                    parts.append(
                        f"<br>Expected: <code>{_esc(r.expected_value)}</code><br>"
                        f"Actual: <code>{_esc(r.actual_value)}</code> "
                        f"(GPO: {_esc(r.gpo_id)})"
                    )
                elif r.status == "missing":
                    parts.append(
                        f" — Expected: <code>{_esc(r.expected_value)}</code>"
                    )
                else:
                    parts.append(
                        f" — Actual: <code>{_esc(r.actual_value)}</code> "
                        f"(GPO: {_esc(r.gpo_id)})"
                    )
                parts.append("</li>")
            parts.append("</ul>")
    return parts


def _changelog_html(changelog_entries: list[ChangelogEntry]) -> list[str]:
    parts: list[str] = []
    if not changelog_entries:
        parts.append("<p>No changes found.</p>")
        return parts

    for e in changelog_entries:
        prefix = "DETAIL" if e.kind == "settings_detail" else "META"
        parts.append(
            f"<h3>[{prefix}] {_esc(e.gpo_name)} ({_esc(e.gpo_id)})</h3>"
        )
        parts.append(f"<p><em>{_esc(e.summary)}</em></p>")
        if e.version_change:
            vc = e.version_change
            parts.append(
                f"<p>Version change: DS {vc.old_ds or '?'} -> {vc.new_ds or '?'}, "
                f"SYSVOL {vc.old_sysvol or '?'} -> {vc.new_sysvol or '?'} "
                f"(edits: {vc.edit_count})</p>"
            )
        if e.setting_changes:
            parts.append("<ul>")
            for sc in e.setting_changes:
                change = (
                    f"<code>[{_esc(sc.side)}/{_esc(sc.cse)}] "
                    f"{_esc(sc.identity)}</code>"
                    f" — {_esc(sc.change_type)}"
                )
                if sc.old_value or sc.new_value:
                    change += (
                        f"<br><code>{_esc(sc.old_value or '')}</code> -> "
                        f"<code>{_esc(sc.new_value or '')}</code>"
                    )
                parts.append(f"<li>{change}</li>")
            parts.append("</ul>")
    return parts


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_markdown(
    estate: Estate,
    *,
    baseline: list[BaselineDiffEntry] | None = None,
    changelog_entries: list[ChangelogEntry] | None = None,
    max_settings: int = 50,
) -> str:
    """Produce a self-contained markdown report for the estate."""
    return _generate_md(
        estate, baseline=baseline, changelog_entries=changelog_entries,
        max_settings=max_settings,
    )


def generate_html(
    estate: Estate,
    *,
    baseline: list[BaselineDiffEntry] | None = None,
    changelog_entries: list[ChangelogEntry] | None = None,
    max_settings: int = 50,
) -> str:
    """Wrap the report in a standalone HTML template with inline CSS."""
    return _generate_html(
        estate, baseline=baseline, changelog_entries=changelog_entries,
        max_settings=max_settings,
    )


def generate_report(
    estate: Estate,
    *,
    baseline: list[BaselineDiffEntry] | None = None,
    changelog_entries: list[ChangelogEntry] | None = None,
    format: str = "md",
    max_settings: int = 50,
) -> str:
    """Generate a report string in the requested format."""
    if format == "html":
        return generate_html(
            estate, baseline=baseline, changelog_entries=changelog_entries,
            max_settings=max_settings,
        )
    return generate_markdown(
        estate, baseline=baseline, changelog_entries=changelog_entries,
        max_settings=max_settings,
    )


def write_report(
    estate: Estate,
    out_path: str | Path,
    *,
    baseline: list[BaselineDiffEntry] | None = None,
    changelog_entries: list[ChangelogEntry] | None = None,
    format: str = "md",
    max_settings: int = 50,
) -> None:
    """Generate and write a report to disk."""
    text = generate_report(
        estate,
        baseline=baseline,
        changelog_entries=changelog_entries,
        format=format,
        max_settings=max_settings,
    )
    Path(out_path).write_text(text, encoding="utf-8")


# ---------------------------------------------------------------------------
# Internal report generators
# ---------------------------------------------------------------------------

def _generate_md(
    estate: Estate,
    *,
    baseline: list[BaselineDiffEntry] | None = None,
    changelog_entries: list[ChangelogEntry] | None = None,
    max_settings: int = 50,
) -> str:
    from gpo_lens import queries

    summary = queries.estate_summary(estate)
    findings = queries.estate_doctor(estate)
    soms_with_links = [
        som for som in estate.soms if som.links and som.container_type != "site"
    ]

    parts: list[str] = []
    parts.append(f"# Estate Report: {_md_esc(summary.domain)}\n")

    parts.append("## Executive Summary\n")
    parts.append(_summary_table_md(summary))
    parts.append("")

    top_n = 10
    if findings:
        parts.append(f"**Top {top_n} findings:**")
        for f in findings[:top_n]:
            parts.append(
                f"- [{f.severity.upper()}] {_md_esc(f.category)}: "
                f"{_md_esc(f.gpo_name or f.gpo_id or 'N/A')} - {_md_esc(f.summary)}"
            )
        parts.append("")

    parts.append("## Hygiene Findings\n")
    parts.extend(_findings_md(findings))

    parts.append("## Per-GPO Detail\n")
    for gpo in estate.gpos:
        parts.append(_gpo_md(gpo, max_settings=max_settings))

    prec_conflicts = queries.precedence_conflicts(estate)
    if prec_conflicts:
        parts.append("## Precedence Conflicts\n")
        for som, conflicts in prec_conflicts:
            parts.append(f"### {_md_esc(som.name)} (`{_md_code(som.path)}`)\n")
            for c in conflicts:
                label = c.display_name or c.identity
                parts.append(
                    f"- **{_md_esc(label)}** [{_md_esc(c.cse)} {_md_esc(c.side)}]: "
                    f"winner={_md_esc(c.winner)}"
                )
                for name, value, status in c.entries:
                    parts.append(f"  - {_md_esc(name)}: {_md_esc(value)} ({_md_esc(status)})")
            parts.append("")

    parts.append("## Topology\n")
    parts.extend(_topology_md(estate, soms_with_links))

    parts.append("## Per-OU Effective Settings\n")
    parts.extend(_effective_settings_md(estate, soms_with_links))

    if baseline is not None:
        parts.append("## Baseline Compliance\n")
        parts.extend(_baseline_md(baseline))

    if changelog_entries is not None:
        parts.append("## Change Log\n")
        parts.extend(_changelog_md(changelog_entries))

    return "\n".join(parts)


def _generate_html(
    estate: Estate,
    *,
    baseline: list[BaselineDiffEntry] | None = None,
    changelog_entries: list[ChangelogEntry] | None = None,
    max_settings: int = 50,
) -> str:
    from gpo_lens import queries

    summary = queries.estate_summary(estate)
    findings = queries.estate_doctor(estate)
    soms_with_links = [
        som for som in estate.soms if som.links and som.container_type != "site"
    ]

    body_parts: list[str] = []

    ts = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    body_parts.append(f"<h1>Estate Report: {_esc(summary.domain)}</h1>")
    body_parts.append(f"<p><small>Generated: {_esc(ts)}</small></p>")

    body_parts.append("<h2>Executive Summary</h2>")
    body_parts.extend(_summary_table_html(summary))

    if findings:
        body_parts.append("<p><strong>Top 10 findings:</strong></p>")
        body_parts.append("<ul>")
        for f in findings[:10]:
            body_parts.append(
                f"<li>{_badge(f.severity)} {_esc(f.category)}: "
                f"{_esc(f.gpo_name or f.gpo_id or 'N/A')} - "
                f"{_esc(f.summary)}</li>"
            )
        body_parts.append("</ul>")

    body_parts.append("<h2>Hygiene Findings</h2>")
    body_parts.extend(_findings_html(findings))

    body_parts.append("<h2>Per-GPO Detail</h2>")
    for gpo in estate.gpos:
        body_parts.extend(_gpo_html(gpo, max_settings=max_settings))

    prec_conflicts = queries.precedence_conflicts(estate)
    if prec_conflicts:
        body_parts.append("<h2>Precedence Conflicts</h2>")
        for som, conflicts in prec_conflicts:
            body_parts.append(f"<h3>{_esc(som.name)} (<code>{_esc(som.path)}</code>)</h3>")
            body_parts.append("<table>")
            body_parts.append(
                "<tr><th>Setting</th><th>CSE</th><th>Side</th>"
                "<th>GPO</th><th>Value</th><th>Status</th></tr>"
            )
            for c in conflicts:
                label = c.display_name or c.identity
                for name, value, status in c.entries:
                    body_parts.append(
                        f"<tr><td>{_esc(label)}</td>"
                        f"<td>{_esc(c.cse)}</td><td>{_esc(c.side)}</td>"
                        f"<td>{_esc(name)}</td><td>{_esc(value)}</td>"
                        f"<td>{_esc(status)}</td></tr>"
                    )
            body_parts.append("</table>")

    body_parts.append("<h2>Topology</h2>")
    body_parts.extend(_topology_html(estate, soms_with_links))

    body_parts.append("<h2>Per-OU Effective Settings</h2>")
    body_parts.extend(_effective_settings_html(estate, soms_with_links))

    if baseline is not None:
        body_parts.append("<h2>Baseline Compliance</h2>")
        body_parts.extend(_baseline_html(baseline))

    if changelog_entries is not None:
        body_parts.append("<h2>Change Log</h2>")
        body_parts.extend(_changelog_html(changelog_entries))

    body = "\n".join(body_parts)

    style = """\
:root {
  --critical: #dc2626;
  --high: #ea580c;
  --medium: #ca8a04;
  --low: #2563eb;
  --info: #6b7280;
}
body {
  font-family: system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
  line-height: 1.5;
  max-width: 960px;
  margin: 0 auto;
  padding: 1rem;
  color: #111827;
}
h1 { border-bottom: 2px solid #e5e7eb; padding-bottom: .3rem; }
h2 { margin-top: 2rem; }
table {
  border-collapse: collapse;
  width: 100%;
  margin-bottom: 1rem;
}
th, td {
  border: 1px solid #d1d5db;
  padding: .5rem .75rem;
  text-align: left;
}
th { background: #f3f4f6; }
.badge {
  display: inline-block;
  padding: .15rem .5rem;
  border-radius: .25rem;
  color: #fff;
  font-size: .75rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: .02em;
}
.caveats {
  background: #fff7ed;
  border-left: 4px solid var(--medium);
  padding: .5rem .75rem;
  margin: .5rem 0 1rem;
}
code {
  background: #f3f4f6;
  padding: .15rem .3rem;
  border-radius: .25rem;
  font-size: .9em;
}
@media print {
  body { max-width: none; padding: 0; color: #000; }
  h1, h2, h3 { page-break-after: avoid; }
  table { page-break-inside: avoid; }
  .badge { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
}"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Estate Report: {_esc(summary.domain)}</title>
<style>
{style}
</style>
</head>
<body>
{body}
</body>
</html>
"""
