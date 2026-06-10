"""Report builder for estate documentation export."""

from __future__ import annotations

import html as html_lib
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from gpo_lens.model import Estate, Gpo
    from gpo_lens.queries import (
        BaselineDiffEntry,
        ChangelogEntry,
        DoctorFinding,
        EstateSummary,
    )

_SUMMARY_FIELDS: list[tuple[str, str]] = [
    ("Domain", "domain"),
    ("GPOs", "gpo_count"),
    ("SOMs", "som_count"),
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


def _summary_table_md(summary: EstateSummary) -> str:
    lines = [
        "| Metric | Value |",
        "|--------|-------|",
    ]
    for label, attr in _SUMMARY_FIELDS:
        value = getattr(summary, attr)
        lines.append(f"| {label} | {value} |")
    return "\n".join(lines)


def _gpo_md(gpo: Gpo, *, max_settings: int = 50) -> str:
    parts: list[str] = []
    parts.append(f"### {gpo.name}\n")
    parts.append(f"- **ID:** `{gpo.id}`")
    parts.append(f"- **Domain:** {gpo.domain}")
    comp_status = "Enabled" if gpo.computer_enabled else "Disabled"
    user_status = "Enabled" if gpo.user_enabled else "Disabled"
    parts.append(f"- **Computer side:** {comp_status}")
    parts.append(f"- **User side:** {user_status}")

    if gpo.computer_ver_ds is not None or gpo.computer_ver_sysvol is not None:
        comp_skew = " **SKEW**" if gpo.computer_version_skew else ""
        parts.append(
            f"- **Computer version:** DS={gpo.computer_ver_ds}, "
            f"SYSVOL={gpo.computer_ver_sysvol}{comp_skew}"
        )
    if gpo.user_ver_ds is not None or gpo.user_ver_sysvol is not None:
        user_skew = " **SKEW**" if gpo.user_version_skew else ""
        parts.append(
            f"- **User version:** DS={gpo.user_ver_ds}, "
            f"SYSVOL={gpo.user_ver_sysvol}{user_skew}"
        )

    if gpo.wmi_filter:
        parts.append(f"- **WMI filter:** {gpo.wmi_filter}")
    if gpo.owner:
        parts.append(f"- **Owner:** {gpo.owner}")

    if gpo.links:
        parts.append("")
        parts.append("**Links:**\n")
        for link in gpo.links:
            enabled = "enabled" if link.link_enabled else "disabled"
            enforced = " [ENFORCED]" if link.enforced else ""
            parts.append(
                f"- `{link.som_path}` ({enabled}{enforced})"
            )

    if gpo.delegation:
        parts.append("")
        parts.append("**Delegation:**\n")
        for d in gpo.delegation:
            allowed = "Allow" if d.allowed else "Deny"
            parts.append(f"- {d.trustee}: {d.permission} ({allowed})")

    if gpo.settings:
        parts.append("")
        parts.append(f"**Settings** ({len(gpo.settings)}):\n")
        for s in gpo.settings[:max_settings]:
            disabled_flag = " [DISABLED SIDE]" if s.from_disabled_side else ""
            blocked_flag = " [BLOCKED]" if s.source_state == "blocked" else ""
            parts.append(
                f"- `[{s.cse}] {s.side}/{s.identity}`: "
                f"{s.display_value}{disabled_flag}{blocked_flag}"
            )
        remaining = len(gpo.settings) - max_settings
        if remaining > 0:
            parts.append(f"- ... ({remaining} more settings)")

    parts.append("")
    return "\n".join(parts)


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

    parts: list[str] = []
    parts.append(f"# Estate Report: {summary.domain}\n")

    parts.append("## Executive Summary\n")
    parts.append(_summary_table_md(summary))
    parts.append("")

    top_n = 10
    if findings:
        parts.append(f"**Top {top_n} findings:**")
        for f in findings[:top_n]:
            parts.append(
                f"- [{f.severity.upper()}] {f.category}: "
                f"{f.gpo_name or f.gpo_id or 'N/A'} - {f.summary}"
            )
        parts.append("")

    parts.append("## Hygiene Findings\n")
    if not findings:
        parts.append("No issues detected. Estate looks healthy.\n")
    else:
        grouped: dict[str, list[DoctorFinding]] = {s: [] for s in _SEVERITY_ORDER}
        for f in findings:
            sev = f.severity if f.severity in grouped else "info"
            grouped.setdefault(sev, []).append(f)
        for sev in _SEVERITY_ORDER:
            group = grouped.get(sev, [])
            if not group:
                continue
            parts.append(f"### {sev.upper()}\n")
            for f in group:
                parts.append(
                    f"- **{f.category}** — "
                    f"{f.gpo_name or f.gpo_id or 'N/A'}: {f.summary}"
                )
                if f.detail:
                    parts.append(f"  _{f.detail}_")
            parts.append("")

    parts.append("## Per-GPO Detail\n")
    for gpo in estate.gpos:
        parts.append(_gpo_md(gpo, max_settings=max_settings))

    prec_conflicts = queries.precedence_conflicts(estate)
    if prec_conflicts:
        parts.append("## Precedence Conflicts\n")
        for som, conflicts in prec_conflicts:
            parts.append(f"### {som.name} (`{som.path}`)\n")
            for c in conflicts:
                label = c.display_name or c.identity
                parts.append(
                    f"- **{label}** [{c.cse} {c.side}]: winner={c.winner}"
                )
                for name, value, status in c.entries:
                    parts.append(f"  - {name}: {value} ({status})")
            parts.append("")

    parts.append("## Topology\n")
    soms_with_links = [som for som in estate.soms if som.links]
    if not soms_with_links:
        parts.append("No SOMs with links.\n")
    else:
        for som in soms_with_links:
            block = " [BLOCKED INHERITANCE]" if som.inheritance_blocked else ""
            parts.append(f"### {som.name}{block}\n")
            parts.append(f"_Path:_ `{som.path}`\n")
            gpos = queries.som_effective_gpos(estate, som.path, _som=som)
            if not gpos:
                parts.append("- No linked GPOs\n")
            else:
                for g in gpos:
                    enforced = " **[ENFORCED]**" if g.enforced else ""
                    en = "enabled" if g.enabled else "disabled"
                    parts.append(
                        f"- {g.order}. {g.gpo_name} ({g.gpo_id}) {en}{enforced} "
                        f"— target: `{g.target}`"
                    )
                parts.append("")
            parts.append("")

    parts.append("## Per-OU Effective Settings\n")
    if not soms_with_links:
        parts.append("No SOMs with links.\n")
    else:
        for som in soms_with_links:
            eff = queries.settings_at_som(estate, som.path)
            if not eff:
                continue
            block = " [BLOCKED INHERITANCE]" if som.inheritance_blocked else ""
            parts.append(f"### {som.name}{block}\n")
            parts.append(f"_Path:_ `{som.path}`\n")
            for s in eff:
                parts.append(
                    f"- `[{s.cse}] {s.side}/{s.identity}`: "
                    f"{s.display_value} (winner: {s.winner_gpo_name})"
                )
                if s.overridden_by:
                    for o_name, o_val in s.overridden_by:
                        parts.append(f"  - overridden: {o_name} = {o_val}")
            parts.append("")

    if baseline is not None:
        parts.append("## Baseline Compliance\n")
        compliant = [r for r in baseline if r.status == "compliant"]
        drift = [r for r in baseline if r.status == "drift"]
        missing = [r for r in baseline if r.status == "missing"]
        extra = [r for r in baseline if r.status == "extra"]
        total = len(compliant) + len(drift) + len(missing) + len(extra)
        pct = round(len(compliant) / total * 100, 1) if total else 0
        parts.append(f"**Compliance: {pct}%** ({len(compliant)} / {total})\n")
        if drift:
            parts.append("### Drift\n")
            for r in drift:
                name = r.admx_name or r.display_name or r.identity
                parts.append(f"- `[{r.cse}] {r.side}/{name}`")
                parts.append(f"  - Expected: `{r.expected_value}`")
                parts.append(f"  - Actual: `{r.actual_value}` (GPO: {r.gpo_id})")
            parts.append("")
        if missing:
            parts.append("### Missing\n")
            for r in missing:
                name = r.admx_name or r.display_name or r.identity
                parts.append(
                    f"- `[{r.cse}] {r.side}/{name}` — "
                    f"Expected: `{r.expected_value}`"
                )
            parts.append("")
        if extra:
            parts.append("### Extra\n")
            for r in extra:
                name = r.admx_name or r.display_name or r.identity
                parts.append(
                    f"- `[{r.cse}] {r.side}/{name}` — "
                    f"Actual: `{r.actual_value}` (GPO: {r.gpo_id})"
                )
            parts.append("")

    if changelog_entries is not None:
        parts.append("## Change Log\n")
        if not changelog_entries:
            parts.append("No changes found.\n")
        else:
            for e in changelog_entries:
                prefix = "[DETAIL]" if e.kind == "settings_detail" else "[META]"
                parts.append(f"### {prefix} {e.gpo_name} ({e.gpo_id})\n")
                parts.append(f"*{e.summary}*\n")
                if e.version_change:
                    vc = e.version_change
                    parts.append(
                        f"Version change: DS {vc.old_ds} -> {vc.new_ds}, "
                        f"SYSVOL {vc.old_sysvol} -> {vc.new_sysvol} "
                        f"(edits: {vc.edit_count})\n"
                    )
                for sc in e.setting_changes:
                    parts.append(
                        f"- `[{sc.side}/{sc.cse}] {sc.identity}` — {sc.change_type}"
                    )
                    if sc.old_value or sc.new_value:
                        parts.append(
                            f"  - `{sc.old_value or ''}` -> `{sc.new_value or ''}`"
                        )
                parts.append("")

    return "\n".join(parts)


def _esc(text: str) -> str:
    return html_lib.escape(str(text))


def _gpo_html(gpo: Gpo, *, max_settings: int = 50) -> list[str]:
    g = gpo
    parts: list[str] = []
    parts.append(f"<h3>{_esc(g.name)}</h3>")
    parts.append("<table>")
    parts.append("<tr><th>Property</th><th>Value</th></tr>")
    parts.append(f"<tr><td>ID</td><td><code>{_esc(g.id)}</code></td></tr>")
    parts.append(f"<tr><td>Domain</td><td>{_esc(g.domain)}</td></tr>")
    comp_status = "Enabled" if g.computer_enabled else "Disabled"
    user_status = "Enabled" if g.user_enabled else "Disabled"
    parts.append(f"<tr><td>Computer side</td><td>{_esc(comp_status)}</td></tr>")
    parts.append(f"<tr><td>User side</td><td>{_esc(user_status)}</td></tr>")

    if g.computer_ver_ds is not None or g.computer_ver_sysvol is not None:
        skew = " <strong>SKEW</strong>" if g.computer_version_skew else ""
        parts.append(
            f"<tr><td>Computer version</td><td>DS={g.computer_ver_ds}, "
            f"SYSVOL={g.computer_ver_sysvol}{skew}</td></tr>"
        )
    if g.user_ver_ds is not None or g.user_ver_sysvol is not None:
        skew = " <strong>SKEW</strong>" if g.user_version_skew else ""
        parts.append(
            f"<tr><td>User version</td><td>DS={g.user_ver_ds}, "
            f"SYSVOL={g.user_ver_sysvol}{skew}</td></tr>"
        )

    if g.wmi_filter:
        parts.append(f"<tr><td>WMI filter</td><td>{_esc(g.wmi_filter)}</td></tr>")
    if g.owner:
        parts.append(f"<tr><td>Owner</td><td>{_esc(g.owner)}</td></tr>")
    parts.append("</table>")

    if g.links:
        parts.append("<p><strong>Links:</strong></p>")
        parts.append("<table>")
        parts.append("<tr><th>SOM Path</th><th>Enabled</th><th>Enforced</th></tr>")
        for link in g.links:
            enabled = "Yes" if link.link_enabled else "No"
            enforced = "Yes" if link.enforced else "No"
            parts.append(
                f"<tr><td><code>{_esc(link.som_path)}</code></td>"
                f"<td>{enabled}</td><td>{enforced}</td></tr>"
            )
        parts.append("</table>")

    if g.delegation:
        parts.append("<p><strong>Delegation:</strong></p>")
        parts.append("<table>")
        parts.append("<tr><th>Trustee</th><th>Permission</th><th>Allowed</th></tr>")
        for d in g.delegation:
            allowed = "Allow" if d.allowed else "Deny"
            parts.append(
                f"<tr><td>{_esc(d.trustee)}</td>"
                f"<td>{_esc(d.permission)}</td>"
                f"<td>{allowed}</td></tr>"
            )
        parts.append("</table>")

    if g.settings:
        parts.append(f"<p><strong>Settings</strong> ({len(g.settings)}):</p>")
        parts.append("<table>")
        parts.append("<tr><th>CSE</th><th>Side</th><th>Identity</th><th>Value</th></tr>")
        for s in g.settings[:max_settings]:
            flags = ""
            if s.from_disabled_side:
                flags += " [DISABLED SIDE]"
            if s.source_state == "blocked":
                flags += " [BLOCKED]"
            parts.append(
                f"<tr><td>{_esc(s.cse)}</td><td>{_esc(s.side)}</td>"
                f"<td><code>{_esc(s.identity)}</code></td>"
                f"<td>{_esc(s.display_value)}{_esc(flags)}</td></tr>"
            )
        remaining = len(g.settings) - max_settings
        if remaining > 0:
            parts.append(
                f"<tr><td colspan='4'>... ({remaining} more settings)</td></tr>"
            )
        parts.append("</table>")

    return parts


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

    def _badge(sev: str) -> str:
        color = _SEVERITY_COLOR.get(sev, "#6b7280")
        return (
            f'<span class="badge" style="background:{color};">'
            f"{_esc(sev.upper())}</span>"
        )

    body_parts: list[str] = []

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    body_parts.append(f"<h1>Estate Report: {_esc(summary.domain)}</h1>")
    body_parts.append(f"<p><small>Generated: {_esc(ts)}</small></p>")

    body_parts.append("<h2>Executive Summary</h2>")
    body_parts.append("<table>")
    body_parts.append("<tr><th>Metric</th><th>Value</th></tr>")
    for label, attr in _SUMMARY_FIELDS:
        value = getattr(summary, attr)
        body_parts.append(f"<tr><td>{_esc(label)}</td><td>{_esc(value)}</td></tr>")
    body_parts.append("</table>")

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
    if not findings:
        body_parts.append("<p>No issues detected. Estate looks healthy.</p>")
    else:
        grouped: dict[str, list[DoctorFinding]] = {
            s: [] for s in _SEVERITY_ORDER
        }
        for f in findings:
            sev = f.severity if f.severity in grouped else "info"
            grouped.setdefault(sev, []).append(f)
        for sev in _SEVERITY_ORDER:
            group = grouped.get(sev, [])
            if not group:
                continue
            body_parts.append(f"<h3>{sev.upper()}</h3>")
            body_parts.append("<ul>")
            for f in group:
                detail = (
                    f"<br><small>{_esc(f.detail)}</small>" if f.detail else ""
                )
                body_parts.append(
                    f"<li>{_badge(sev)} <strong>{_esc(f.category)}</strong> — "
                    f"{_esc(f.gpo_name or f.gpo_id or 'N/A')}: "
                    f"{_esc(f.summary)}"
                    f"{detail}</li>"
                )
            body_parts.append("</ul>")

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
    soms_with_links = [som for som in estate.soms if som.links]
    if not soms_with_links:
        body_parts.append("<p>No SOMs with links.</p>")
    else:
        for som in soms_with_links:
            block = (
                ' <span class="badge" style="background:#7c3aed;">'
                "BLOCKED</span>"
                if som.inheritance_blocked
                else ""
            )
            body_parts.append(f"<h3>{_esc(som.name)}{block}</h3>")
            body_parts.append(
                f"<p><em>Path:</em> <code>{_esc(som.path)}</code></p>"
            )
            gpos = queries.som_effective_gpos(estate, som.path, _som=som)
            if not gpos:
                body_parts.append("<p>No linked GPOs.</p>")
            else:
                body_parts.append("<table>")
                body_parts.append(
                    "<tr><th>Order</th><th>GPO</th><th>Enabled</th>"
                    "<th>Enforced</th><th>Target</th></tr>"
                )
                for g in gpos:
                    enabled = "Yes" if g.enabled else "No"
                    enforced = "Yes" if g.enforced else "No"
                    body_parts.append(
                        f"<tr><td>{g.order}</td>"
                        f"<td>{_esc(g.gpo_name)} ({_esc(g.gpo_id)})</td>"
                        f"<td>{enabled}</td><td>{enforced}</td>"
                        f"<td><code>{_esc(g.target)}</code></td></tr>"
                    )
                body_parts.append("</table>")

    body_parts.append("<h2>Per-OU Effective Settings</h2>")
    if not soms_with_links:
        body_parts.append("<p>No SOMs with links.</p>")
    else:
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
            body_parts.append(f"<h3>{_esc(som.name)}{block}</h3>")
            body_parts.append(
                f"<p><em>Path:</em> <code>{_esc(som.path)}</code></p>"
            )
            body_parts.append("<table>")
            body_parts.append(
                "<tr><th>CSE</th><th>Side</th><th>Identity</th>"
                "<th>Value</th><th>Winner GPO</th><th>Overridden</th></tr>"
            )
            for s in eff:
                overridden_parts = [
                    f"{_esc(n)} = {_esc(v)}" for n, v in s.overridden_by
                ]
                overridden_text = "<br>".join(overridden_parts) if overridden_parts else ""
                body_parts.append(
                    f"<tr><td>{_esc(s.cse)}</td><td>{_esc(s.side)}</td>"
                    f"<td><code>{_esc(s.identity)}</code></td>"
                    f"<td>{_esc(s.display_value)}</td>"
                    f"<td>{_esc(s.winner_gpo_name)}</td>"
                    f"<td>{overridden_text}</td></tr>"
                )
            body_parts.append("</table>")
        if not any_eff:
            body_parts.append("<p>No effective settings at any SOM.</p>")

    if baseline is not None:
        body_parts.append("<h2>Baseline Compliance</h2>")
        compliant = [r for r in baseline if r.status == "compliant"]
        drift = [r for r in baseline if r.status == "drift"]
        missing = [r for r in baseline if r.status == "missing"]
        extra = [r for r in baseline if r.status == "extra"]
        total = len(compliant) + len(drift) + len(missing) + len(extra)
        pct = round(len(compliant) / total * 100, 1) if total else 0
        body_parts.append(
            f"<p><strong>Compliance: {pct}%</strong> "
            f"({len(compliant)} / {total})</p>"
        )
        if drift:
            body_parts.append("<h3>Drift</h3><ul>")
            for r in drift:
                name = r.admx_name or r.display_name or r.identity
                body_parts.append(
                    f"<li><code>[{_esc(r.cse)}] {_esc(r.side)}/{_esc(name)}</code><br>"
                    f"Expected: <code>{_esc(r.expected_value)}</code><br>"
                    f"Actual: <code>{_esc(r.actual_value)}</code> "
                    f"(GPO: {_esc(r.gpo_id)})</li>"
                )
            body_parts.append("</ul>")
        if missing:
            body_parts.append("<h3>Missing</h3><ul>")
            for r in missing:
                name = r.admx_name or r.display_name or r.identity
                body_parts.append(
                    f"<li><code>[{_esc(r.cse)}] {_esc(r.side)}/{_esc(name)}</code> — "
                    f"Expected: <code>{_esc(r.expected_value)}</code></li>"
                )
            body_parts.append("</ul>")
        if extra:
            body_parts.append("<h3>Extra</h3><ul>")
            for r in extra:
                name = r.admx_name or r.display_name or r.identity
                body_parts.append(
                    f"<li><code>[{_esc(r.cse)}] {_esc(r.side)}/{_esc(name)}</code> — "
                    f"Actual: <code>{_esc(r.actual_value)}</code> "
                    f"(GPO: {_esc(r.gpo_id)})</li>"
                )
            body_parts.append("</ul>")

    if changelog_entries is not None:
        body_parts.append("<h2>Change Log</h2>")
        if not changelog_entries:
            body_parts.append("<p>No changes found.</p>")
        else:
            for e in changelog_entries:
                prefix = "DETAIL" if e.kind == "settings_detail" else "META"
                body_parts.append(
                    f"<h3>[{prefix}] {_esc(e.gpo_name)} ({_esc(e.gpo_id)})</h3>"
                )
                body_parts.append(f"<p><em>{_esc(e.summary)}</em></p>")
                if e.version_change:
                    vc = e.version_change
                    body_parts.append(
                        f"<p>Version change: DS {vc.old_ds} -> {vc.new_ds}, "
                        f"SYSVOL {vc.old_sysvol} -> {vc.new_sysvol} "
                        f"(edits: {vc.edit_count})</p>"
                    )
                if e.setting_changes:
                    body_parts.append("<ul>")
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
                        body_parts.append(f"<li>{change}</li>")
                    body_parts.append("</ul>")

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
