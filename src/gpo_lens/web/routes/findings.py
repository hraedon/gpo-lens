"""WI-5: Findings inbox — unified findings page with triage annotations.

Replaces danger list / conflicts / delegation / admx-coverage / baseline /
golden as destinations. One inbox, default filter new + unacknowledged,
facets by category, severity, GPO, lifecycle state, triage state.

Handlers are plain ``def`` (not ``async def``) so FastAPI runs them in its
threadpool, preventing synchronous SQLite from blocking the event loop.
"""

from __future__ import annotations

import sqlite3
from typing import Any

from fastapi import Depends, FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from gpo_lens.web._helpers import (
    _MAX_SEARCH_LEN,
    get_ro_conn,
    get_rw_conn,
    paginate,
    parse_pagination,
)
from gpo_lens.web.auth import Permission, Principal, requires

_VALID_TRIAGE = {"open", "acknowledged", "accepted_risk"}


def register(app: FastAPI, templates: Jinja2Templates) -> None:

    @app.get("/findings", response_class=HTMLResponse, name="findings_inbox")
    def findings_inbox(
        request: Request,
        severity: str = "",
        category: str = "",
        triage: str = "",
        q: str = "",
        _principal: Principal = Depends(requires(Permission.VIEW)),
    ) -> HTMLResponse:
        from gpo_lens.findings import load_active_findings, load_finding_triage_map
        from gpo_lens.store import load_estate

        conn = get_ro_conn(app.state.db_path)
        try:
            active_findings = load_active_findings(conn)
            triage_map = load_finding_triage_map(conn)
            try:
                estate = load_estate(conn)
                from gpo_lens.danger import danger_findings

                danger = danger_findings(estate, admx=app.state.admx)
                from gpo_lens.queries import estate_doctor

                doctor_findings = estate_doctor(estate, admx=app.state.admx, danger=danger)
                resolvable_gpo_ids = {g.id for g in estate.gpos}
            except ValueError:
                doctor_findings = []
                resolvable_gpo_ids = set()
        finally:
            conn.close()

        # Build a lookup from doctor findings for current-snapshot evidence
        doctor_by_key: dict[str, Any] = {}
        for f in doctor_findings:
            from gpo_lens.findings import _finding_to_key_parts, finding_key

            rule_id, subject, _sev, detail = _finding_to_key_parts(f)
            key = finding_key(rule_id, subject, detail)
            doctor_by_key[key] = f

        # Merge lifecycle + triage + current evidence
        rows: list[dict[str, Any]] = []
        for af in active_findings:
            triage_state = triage_map.get(af.id, {}).get("status", "open")
            doctor_f = doctor_by_key.get(af.finding_key)
            detail = getattr(doctor_f, "detail", "") if doctor_f else ""
            remediation = getattr(doctor_f, "remediation", "") if doctor_f else ""
            rows.append({
                "id": af.id,
                "rule_id": af.rule_id,
                "severity": af.severity,
                "summary": af.summary,
                "gpo_id": af.gpo_id,
                "gpo_name": af.gpo_name,
                "first_seen_snapshot": af.first_seen_snapshot,
                "last_seen_snapshot": af.last_seen_snapshot,
                "predecessor_id": af.predecessor_id,
                "triage_state": triage_state,
                "detail": detail,
                "remediation": remediation,
                "is_new": af.first_seen_snapshot == af.last_seen_snapshot,
            })

        # Facet counts (from the full set, pre-filter)
        all_rows = rows

        # Apply filters
        if severity and severity != "all":
            wanted = {s.strip() for s in severity.split(",") if s.strip()}
            rows = [r for r in rows if r["severity"] in wanted]
        if category:
            rows = [
                r for r in rows
                if r["rule_id"] == category
                or r["rule_id"].startswith(category + ":")
            ]
        if triage and triage != "all":
            rows = [r for r in rows if r["triage_state"] == triage]
        q = (q or "")[:_MAX_SEARCH_LEN]
        if q:
            needle = q.lower()
            rows = [
                r for r in rows
                if needle in (r["gpo_name"] or "").lower()
                or needle in (r["summary"] or "").lower()
                or needle in (r["rule_id"] or "").lower()
            ]

        # Sort: new first, then by severity, then by GPO name
        sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        rows.sort(
            key=lambda r: (
                not r["is_new"],
                sev_rank.get(r["severity"], 9),
                (r["gpo_name"] or "").lower(),
            )
        )

        # Facet counts (from the full set, pre-filter)
        categories: dict[str, int] = {}
        for r in all_rows:
            cat = r["rule_id"]
            categories[cat] = categories.get(cat, 0) + 1

        page, per_page_int, per_page_raw = parse_pagination(request)
        page_rows, pag = paginate(rows, page, per_page_int, per_page_raw)

        return templates.TemplateResponse(
            request,
            "findings.html",
            {
                "request": request,
                "rows": page_rows,
                "all_count": len(active_findings),
                "filtered_count": len(rows),
                "resolvable_gpo_ids": resolvable_gpo_ids,
                "f_severity": severity,
                "f_category": category,
                "f_triage": triage,
                "f_q": q,
                "categories": sorted(categories.items()),
                "pag": pag,
            },
        )

    @app.post("/findings/{finding_id}/triage", response_model=None, name="findings_triage")
    def findings_triage(
        request: Request,
        finding_id: int,
        status: str = Form(...),
        note: str = Form(""),
        principal: Principal = Depends(requires(Permission.INGEST)),
    ) -> HTMLResponse | RedirectResponse:
        from gpo_lens.findings import triage_finding

        if status not in _VALID_TRIAGE:
            return HTMLResponse(
                "Invalid triage status", status_code=400
            )

        conn = get_rw_conn(app.state.db_path)
        try:
            triage_finding(conn, finding_id, status, note, principal.name)
        except sqlite3.IntegrityError:
            return HTMLResponse("Finding not found", status_code=404)
        finally:
            conn.close()

        return RedirectResponse(url=request.url_for("findings_inbox"), status_code=303)
