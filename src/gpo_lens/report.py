"""Report builder for estate documentation export."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from gpo_lens.model import Estate
    from gpo_lens.queries import (
        BaselineDiffEntry,
        ChangelogEntry,
        DoctorFinding,
        EstateSummary,
    )

_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")

_SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
}

_SEVERITY_COLOR = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#ca8a04",
    "low": "#2563eb",
    "info": "#6b7280",
}


def generate_report(
    estate: Estate,
    *,
    baseline: list[BaselineDiffEntry] | None = None,
    changelog_entries: list[ChangelogEntry] | None = None,
    format: str = "md",
) -> str:
    """Generate a report string in the requested format."""
    if format == "html":
        return _generate_html(
            estate, baseline=baseline, changelog_entries=changelog_entries
        )
    return _generate_md(
        estate, baseline=baseline, changelog_entries=changelog_entries
    )


def write_report(
    estate: Estate,
    out_path: str | Path,
    *,
    baseline: list[BaselineDiffEntry] | None = None,
    changelog_entries: list[ChangelogEntry] | None = None,
    format: str = "md",
) -> None:
    """Generate and write a report to disk."""
    text = generate_report(
        estate,
        baseline=baseline,
        changelog_entries=changelog_entries,
        format=format,
    )
    Path(out_path).write_text(text, encoding="utf-8")


def _summary_table_md(summary: EstateSummary) -> str:
    lines = [
        "| Metric | Value |",
        "|--------|-------|",
    ]
    fields = [
        ("Domain", summary.domain),
        ("GPOs", summary.gpo_count),
        ("SOMs", summary.som_count),
        ("WMI filters", summary.wmi_filter_count),
        ("Unlinked GPOs", summary.unlinked_count),
        ("Empty GPOs", summary.empty_count),
        ("Disabled-but-populated", summary.disabled_but_populated_count),
        ("Setting conflicts", summary.conflict_count),
        ("Blocked extensions", summary.blocked_extension_count),
        ("Version skew", summary.version_skew_count),
        ("MS16-072 vulnerable", summary.ms16_072_vulnerable_count),
        ("cpassword hits", summary.cpassword_hit_count),
        ("Loopback GPOs", summary.loopback_gpo_count),
        ("Enforced links", summary.enforced_link_count),
        ("Dangling links", summary.dangling_link_count),
        ("Broken references", summary.broken_ref_count),
        ("ADMX gaps", summary.admx_gap_count),
        ("Total settings", summary.total_settings),
        ("Total delegation entries", summary.total_delegation_entries),
    ]
    for label, value in fields:
        lines.append(f"| {label} | {value} |")
    return "\n".join(lines)


def _generate_md(
    estate: Estate,
    *,
    baseline: list[BaselineDiffEntry] | None = None,
    changelog_entries: list[ChangelogEntry] | None = None,
) -> str:
    from gpo_lens import queries

    summary = queries.estate_summary(estate)
    findings = queries.estate_doctor(estate)

    parts: list[str] = []
    parts.append(f"# Estate Report: {summary.domain}\n")

    parts.append("## Summary\n")
    parts.append(_summary_table_md(summary))
    parts.append("")

    parts.append("## Doctor Findings\n")
    if not findings:
        parts.append("No issues detected. Estate looks healthy.\n")
    else:
        grouped: dict[str, list[DoctorFinding]] = {s: [] for s in _SEVERITY_ORDER}
        for f in findings:
            grouped.setdefault(f.severity, []).append(f)
        for sev in _SEVERITY_ORDER:
            group = grouped.get(sev, [])
            if not group:
                continue
            parts.append(f"### {sev.upper()}\n")
            for f in group:
                emoji = _SEVERITY_EMOJI.get(sev, "")
                parts.append(
                    f"{emoji} **{f.category}** — "
                    f"{f.gpo_name or f.gpo_id or 'N/A'}: {f.summary}"
                )
                if f.detail:
                    parts.append(f"  <br>_{f.detail}_")
                parts.append("")
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
            gpos = queries.som_effective_gpos(estate, som.path)
            if not gpos:
                parts.append("- No linked GPOs\n")
            else:
                for g in gpos:
                    enforced = " **[ENFORCED]**" if g.enforced else ""
                    enabled = "✅" if g.enabled else "❌"
                    parts.append(
                        f"{enabled} {g.order}. {g.gpo_name} ({g.gpo_id}){enforced} "
                        f"— target: `{g.target}`"
                    )
                parts.append("")
            parts.append("")

    if baseline is not None:
        parts.append("## Baseline Compliance\n")
        compliant = [r for r in baseline if r.status == "compliant"]
        drift = [r for r in baseline if r.status == "drift"]
        missing = [r for r in baseline if r.status == "missing"]
        total = len(compliant) + len(drift) + len(missing)
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
                        f"Version change: DS {vc.old_ds} → {vc.new_ds}, "
                        f"SYSVOL {vc.old_sysvol} → {vc.new_sysvol} "
                        f"(edits: {vc.edit_count})\n"
                    )
                for sc in e.setting_changes:
                    parts.append(
                        f"- `[{sc.side}/{sc.cse}] {sc.identity}` — {sc.change_type}"
                    )
                    if sc.old_value or sc.new_value:
                        parts.append(
                            f"  - `{sc.old_value or ''}` → `{sc.new_value or ''}`"
                        )
                parts.append("")

    return "\n".join(parts)


def _generate_html(
    estate: Estate,
    *,
    baseline: list[BaselineDiffEntry] | None = None,
    changelog_entries: list[ChangelogEntry] | None = None,
) -> str:
    from gpo_lens import queries

    summary = queries.estate_summary(estate)
    findings = queries.estate_doctor(estate)

    def _badge(sev: str) -> str:
        color = _SEVERITY_COLOR.get(sev, "#6b7280")
        return (
            f'<span class="badge" style="background:{color};">'
            f"{sev.upper()}</span>"
        )

    body_parts: list[str] = []

    body_parts.append(f"<h1>Estate Report: {summary.domain}</h1>")

    body_parts.append("<h2>Summary</h2>")
    body_parts.append("<table>")
    body_parts.append("<tr><th>Metric</th><th>Value</th></tr>")
    rows = [
        ("Domain", summary.domain),
        ("GPOs", summary.gpo_count),
        ("SOMs", summary.som_count),
        ("WMI filters", summary.wmi_filter_count),
        ("Unlinked GPOs", summary.unlinked_count),
        ("Empty GPOs", summary.empty_count),
        ("Disabled-but-populated", summary.disabled_but_populated_count),
        ("Setting conflicts", summary.conflict_count),
        ("Blocked extensions", summary.blocked_extension_count),
        ("Version skew", summary.version_skew_count),
        ("MS16-072 vulnerable", summary.ms16_072_vulnerable_count),
        ("cpassword hits", summary.cpassword_hit_count),
        ("Loopback GPOs", summary.loopback_gpo_count),
        ("Enforced links", summary.enforced_link_count),
        ("Dangling links", summary.dangling_link_count),
        ("Broken references", summary.broken_ref_count),
        ("ADMX gaps", summary.admx_gap_count),
        ("Total settings", summary.total_settings),
        ("Total delegation entries", summary.total_delegation_entries),
    ]
    for label, value in rows:
        body_parts.append(f"<tr><td>{label}</td><td>{value}</td></tr>")
    body_parts.append("</table>")

    body_parts.append("<h2>Doctor Findings</h2>")
    if not findings:
        body_parts.append("<p>No issues detected. Estate looks healthy.</p>")
    else:
        grouped: dict[str, list[DoctorFinding]] = {
            s: [] for s in _SEVERITY_ORDER
        }
        for f in findings:
            grouped.setdefault(f.severity, []).append(f)
        for sev in _SEVERITY_ORDER:
            group = grouped.get(sev, [])
            if not group:
                continue
            body_parts.append(f"<h3>{sev.upper()}</h3>")
            body_parts.append("<ul>")
            for f in group:
                detail = (
                    f"<br><small>{f.detail}</small>" if f.detail else ""
                )
                body_parts.append(
                    f"<li>{_badge(sev)} <strong>{f.category}</strong> — "
                    f"{f.gpo_name or f.gpo_id or 'N/A'}: {f.summary}"
                    f"{detail}</li>"
                )
            body_parts.append("</ul>")

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
            body_parts.append(f"<h3>{som.name}{block}</h3>")
            body_parts.append(
                f"<p><em>Path:</em> <code>{som.path}</code></p>"
            )
            gpos = queries.som_effective_gpos(estate, som.path)
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
                        f"<td>{g.gpo_name} ({g.gpo_id})</td>"
                        f"<td>{enabled}</td><td>{enforced}</td>"
                        f"<td><code>{g.target}</code></td></tr>"
                    )
                body_parts.append("</table>")

    if baseline is not None:
        body_parts.append("<h2>Baseline Compliance</h2>")
        compliant = [r for r in baseline if r.status == "compliant"]
        drift = [r for r in baseline if r.status == "drift"]
        missing = [r for r in baseline if r.status == "missing"]
        total = len(compliant) + len(drift) + len(missing)
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
                    f"<li><code>[{r.cse}] {r.side}/{name}</code><br>"
                    f"Expected: <code>{r.expected_value}</code><br>"
                    f"Actual: <code>{r.actual_value}</code> "
                    f"(GPO: {r.gpo_id})</li>"
                )
            body_parts.append("</ul>")
        if missing:
            body_parts.append("<h3>Missing</h3><ul>")
            for r in missing:
                name = r.admx_name or r.display_name or r.identity
                body_parts.append(
                    f"<li><code>[{r.cse}] {r.side}/{name}</code> — "
                    f"Expected: <code>{r.expected_value}</code></li>"
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
                    f"<h3>[{prefix}] {e.gpo_name} ({e.gpo_id})</h3>"
                )
                body_parts.append(f"<p><em>{e.summary}</em></p>")
                if e.version_change:
                    vc = e.version_change
                    body_parts.append(
                        f"<p>Version change: DS {vc.old_ds} → {vc.new_ds}, "
                        f"SYSVOL {vc.old_sysvol} → {vc.new_sysvol} "
                        f"(edits: {vc.edit_count})</p>"
                    )
                if e.setting_changes:
                    body_parts.append("<ul>")
                    for sc in e.setting_changes:
                        change = (
                            f"<code>[{sc.side}/{sc.cse}] {sc.identity}</code>"
                            f" — {sc.change_type}"
                        )
                        if sc.old_value or sc.new_value:
                            change += (
                                f"<br><code>{sc.old_value or ''}</code> → "
                                f"<code>{sc.new_value or ''}</code>"
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
<title>Estate Report: {summary.domain}</title>
<style>
{style}
</style>
</head>
<body>
{body}
</body>
</html>"""
