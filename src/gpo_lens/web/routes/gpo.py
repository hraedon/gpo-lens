"""GPO detail and danger-list routes."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from gpo_lens import topology
from gpo_lens.web._helpers import (
    _MAX_SEARCH_LEN,
    _VALID_GPO_SORTS,
    _VALID_GPO_STATUS,
    base_qs,
    filter_gpos,
    get_ro_conn,
    paginate,
    parse_pagination,
)
from gpo_lens.web.auth import Permission, Principal, requires


def register(app: FastAPI, templates: Jinja2Templates) -> None:

    @app.get("/inventory", response_class=HTMLResponse, name="gpo_list")
    async def gpo_list(
        request: Request,
        q: str = "",
        status: str = "",
        sort: str = "name",
        _principal: Principal = Depends(requires(Permission.VIEW)),
    ) -> HTMLResponse:
        from gpo_lens.store import load_estate

        conn = get_ro_conn(app.state.db_path)
        try:
            try:
                estate = load_estate(conn)
                all_gpos = list(estate.gpos)
            except ValueError:
                all_gpos = []
        finally:
            conn.close()

        if status and status not in _VALID_GPO_STATUS:
            status = ""
        if sort not in _VALID_GPO_SORTS:
            sort = "name"
        filtered = filter_gpos(all_gpos, q, status, sort)

        page, per_page_int, per_page_raw = parse_pagination(request)
        page_gpos, pag = paginate(filtered, page, per_page_int, per_page_raw)
        inv_qs = base_qs(request, "page", "per_page")
        return templates.TemplateResponse(
            request,
            "inventory.html",
            {
                "request": request,
                "gpos": page_gpos,
                "all_gpos_count": len(all_gpos),
                "filtered_count": len(filtered),
                "f_q": q,
                "f_status": status,
                "f_sort": sort,
                "f_base_qs": inv_qs,
                "pag": pag,
            },
        )

    @app.get("/gpo/{gpo_id}", response_class=HTMLResponse, name="gpo_detail")
    async def gpo_detail(
        request: Request,
        gpo_id: str,
        _principal: Principal = Depends(requires(Permission.VIEW)),
    ) -> HTMLResponse:
        from gpo_lens.normalize import canonical_guid
        from gpo_lens.store import load_estate

        try:
            gpo_id = canonical_guid(gpo_id)
        except ValueError:
            raise HTTPException(status_code=404, detail="Invalid GPO ID") from None

        conn = get_ro_conn(app.state.db_path)
        try:
            estate = load_estate(conn)
        finally:
            conn.close()

        gpo = estate.gpo_by_id(gpo_id)
        if gpo is None:
            raise HTTPException(status_code=404, detail="GPO not found")

        scope = topology.effective_scope(estate, gpo_id)
        caveats = scope.caveats if scope is not None else []

        disabled_sides: set[str] = set()
        if not gpo.computer_enabled and any(
            s.side == "Computer" and s.from_disabled_side for s in gpo.settings
        ):
            disabled_sides.add("Computer")
        if not gpo.user_enabled and any(
            s.side == "User" and s.from_disabled_side for s in gpo.settings
        ):
            disabled_sides.add("User")

        # Group settings by side, then by CSE (Client Side Extension). The CSE
        # grouping (Registry / Security / Scripts / ...) is valuable navigation
        # context and a single GPO rarely has enough settings to warrant
        # pagination, so this page is not paginated (unlike the dashboard / OU
        # views). See WI-026 — GPO detail pagination deferred as low value.
        settings_by_side: dict[str, dict[str, list[object]]] = defaultdict(
            lambda: defaultdict(list)
        )
        for s in gpo.settings:
            settings_by_side[s.side][s.cse].append(s)

        return templates.TemplateResponse(
            request,
            "gpo_detail.html",
            {
                "request": request,
                "gpo": gpo,
                "settings_by_side": dict(settings_by_side),
                "disabled_sides": disabled_sides,
                "caveats": caveats,
                "admx": app.state.admx,
            },
        )

    @app.get("/danger", response_class=HTMLResponse, name="danger_list")
    async def danger_list(
        request: Request,
        severity: str = "",
        q: str = "",
        _principal: Principal = Depends(requires(Permission.VIEW)),
    ) -> HTMLResponse:
        from gpo_lens.danger import danger_findings
        from gpo_lens.store import load_estate

        conn = get_ro_conn(app.state.db_path)
        try:
            try:
                estate = load_estate(conn)
                all_findings = danger_findings(estate, admx=app.state.admx)
                resolvable_gpo_ids = {g.id for g in estate.gpos}
            except ValueError:
                all_findings = []
                resolvable_gpo_ids = set()
        finally:
            conn.close()

        filtered: list[Any] = all_findings
        if severity and severity != "all":
            wanted = {s.strip() for s in severity.split(",") if s.strip()}
            filtered = [f for f in filtered if f.severity in wanted]
        q = (q or "")[:_MAX_SEARCH_LEN]
        if q:
            needle = q.lower()
            filtered = [
                f for f in filtered
                if needle in (f.gpo_name or "").lower()
                or needle in (f.title or "").lower()
                or needle in (f.check_id or "").lower()
            ]

        page, per_page_int, per_page_raw = parse_pagination(request)
        page_findings, pag = paginate(filtered, page, per_page_int, per_page_raw)
        base_qs_val = base_qs(request, "page", "per_page")

        return templates.TemplateResponse(
            request,
            "danger_list.html",
            {
                "request": request,
                "findings": page_findings,
                "all_findings_count": len(all_findings),
                "filtered_findings_count": len(filtered),
                "resolvable_gpo_ids": resolvable_gpo_ids,
                "f_severity": severity,
                "f_q": q,
                "f_base_qs": base_qs_val,
                "pag": pag,
            },
        )
