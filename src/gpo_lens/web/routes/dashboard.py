"""Dashboard, health, and version routes.

Handlers are plain ``def`` (not ``async def``) so FastAPI runs them in its
threadpool, preventing synchronous SQLite from blocking the event loop
(Plan 022 WI-1).
"""

from __future__ import annotations

from collections import defaultdict

from fastapi import Depends, FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from gpo_lens.web._helpers import (
    _POSTURE_CATEGORY,
    _POSTURE_SPEC,
    _VALID_SORTS,
    base_qs,
    filter_findings,
    get_ro_conn,
    paginate,
    parse_pagination,
)
from gpo_lens.web.auth import Permission, Principal, requires


def register(app: FastAPI, templates: Jinja2Templates) -> None:

    @app.get("/healthz", name="healthz")
    def healthz() -> JSONResponse:
        # Unauthenticated liveness probe. Reveals nothing but liveness, so it
        # is safe for IIS/app-pool supervisors to poll without credentials.
        return JSONResponse({"status": "ok"})

    @app.get("/api/version", name="api_version")
    def api_version() -> JSONResponse:
        # Unauthenticated version surface. The version is already public via
        # pyproject.toml and the ``--version`` CLI flag; ops needs to confirm
        # the running build via curl without credentials.
        from gpo_lens import __version__

        return JSONResponse({"version": __version__, "name": "gpo-lens"})

    @app.get("/", response_class=HTMLResponse, name="home")
    def home(
        request: Request,
        severity: str = "",
        q: str = "",
        sort: str = "severity",
        category: str = "",
        _principal: Principal = Depends(requires(Permission.VIEW)),
    ) -> HTMLResponse:
        from gpo_lens.danger import danger_findings
        from gpo_lens.queries import EstateSummary, estate_doctor, estate_summary
        from gpo_lens.store import load_estate

        conn = get_ro_conn(app.state.db_path)
        try:
            try:
                estate = load_estate(conn)
                # WI-031: compute danger findings once, pass to both
                # estate_doctor and estate_summary (was 3x per render).
                _danger = danger_findings(estate, admx=app.state.admx)
                all_findings = estate_doctor(estate, admx=app.state.admx, danger=_danger)
                summary = estate_summary(estate, danger_count=len(_danger))
                # GPOs that exist as objects (so a detail page resolves). Some
                # findings (e.g. coverage gaps for unreadable GPOs) carry an id
                # with no backing GPO — those must not render as dead links.
                resolvable_gpo_ids = {g.id for g in estate.gpos}
            except ValueError:
                all_findings = []
                resolvable_gpo_ids = set()
                summary = EstateSummary(
                    domain="", gpo_count=0, som_count=0, linked_site_count=0,
                    coverage_gap_count=0,
                    wmi_filter_count=0, unlinked_count=0, empty_count=0,
                    disabled_but_populated_count=0, conflict_count=0,
                    blocked_extension_count=0, version_skew_count=0,
                    ms16_072_vulnerable_count=0, cpassword_hit_count=0,
                    loopback_gpo_count=0, wmi_filtered_gpo_count=0,
                    enforced_link_count=0, dangling_link_count=0,
                    broken_ref_count=0, admx_gap_count=0,
                    broken_wmi_ref_count=0, orphaned_wmi_filter_count=0,
                    ilt_gpo_count=0, stale_gpo_count=0,
                    danger_finding_count=0,
                    total_settings=0, total_delegation_entries=0,
                )
        finally:
            conn.close()

        # WI-025: filter / search / sort
        if sort not in _VALID_SORTS:
            sort = "severity"
        # The default view hides bulk informational findings (a large estate can
        # carry thousands of "enforced link" info rows that bury the actionable
        # ones over dozens of pages). An explicit severity overrides this; a
        # posture deep-link shows ALL of its category, since several cards
        # (enforced links, stale, item-level targeting) are themselves info-tone.
        if severity:
            effective_severity = severity
        elif category:
            effective_severity = "all"
        else:
            effective_severity = "critical,high,medium,low"
        findings = filter_findings(all_findings, effective_severity, q, sort, category)
        # When the actionable default is hiding info rows, tell the user how many
        # and give them a one-click way to see everything.
        info_hidden = (
            sum(1 for f in all_findings if f.severity == "info")
            if not severity and not category
            else 0
        )

        # WI-026: pagination
        page, per_page_int, per_page_raw = parse_pagination(request)
        page_findings, pag = paginate(findings, page, per_page_int, per_page_raw)
        findings_qs = base_qs(request, "page", "per_page")

        # Split indicators: fired (count > 0, shown as toned cards, worst first)
        # vs clear (count == 0, collapsed into one quiet "all clear" line).
        tone_rank = {"crit": 0, "warn": 1, "info": 2}
        fired = [
            {
                "attr": attr,
                "label": label,
                "value": getattr(summary, attr),
                "tone": tone,
                # Deep-link target into the findings table; None = non-clickable
                # (a few cards, e.g. conflicts, link to their own page instead).
                "category": _POSTURE_CATEGORY.get(attr),
            }
            for attr, label, tone in _POSTURE_SPEC
            if getattr(summary, attr)
        ]
        fired.sort(key=lambda i: tone_rank[i["tone"]])
        clear = [label for attr, label, _ in _POSTURE_SPEC if not getattr(summary, attr)]

        sev_counts: dict[str, int] = defaultdict(int)
        for f in all_findings:
            sev_counts[f.severity] += 1

        return templates.TemplateResponse(
            request,
            "dashboard.html",
            {
                "request": request,
                "findings": page_findings,
                "all_findings_count": len(all_findings),
                "filtered_findings_count": len(findings),
                "summary": summary,
                "resolvable_gpo_ids": resolvable_gpo_ids,
                "posture_fired": fired,
                "posture_clear": clear,
                "sev_counts": dict(sev_counts),
                # WI-025 filter state
                "f_severity": severity,
                "f_q": q,
                "f_sort": sort,
                "f_category": category,
                "info_hidden": info_hidden,
                "f_base_qs": findings_qs,
                # WI-026 pagination
                "pag": pag,
            },
        )
