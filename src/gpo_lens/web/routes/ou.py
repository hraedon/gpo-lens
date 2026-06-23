"""OU list and detail routes."""

from __future__ import annotations

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from gpo_lens import queries, topology
from gpo_lens import store as _store
from gpo_lens.web._helpers import (
    _VALID_OU_SORTS,
    _VALID_OU_TYPES,
    base_qs,
    filter_soms,
    get_ro_conn,
    paginate,
    parse_pagination,
)
from gpo_lens.web.auth import Permission, Principal, requires


def register(app: FastAPI, templates: Jinja2Templates) -> None:

    @app.get("/ou", response_class=HTMLResponse, name="ou_list")
    async def ou_list(
        request: Request,
        q: str = "",
        type: str = "",
        sort: str = "name",
        _principal: Principal = Depends(requires(Permission.VIEW)),
    ) -> HTMLResponse:
        conn = get_ro_conn(app.state.db_path)
        try:
            estate = _store.load_estate(conn)
        finally:
            conn.close()

        if type and type not in _VALID_OU_TYPES:
            type = ""
        if sort not in _VALID_OU_SORTS:
            sort = "name"
        all_soms = list(estate.soms)
        filtered = filter_soms(all_soms, q, type, sort)

        page, per_page_int, per_page_raw = parse_pagination(request)
        page_soms, pag = paginate(filtered, page, per_page_int, per_page_raw)
        ou_qs = base_qs(request, "page", "per_page")
        return templates.TemplateResponse(
            request, "ou_list.html",
            {
                "soms": page_soms,
                "pag": pag,
                "all_soms_count": len(all_soms),
                "filtered_count": len(filtered),
                "f_q": q,
                "f_type": type,
                "f_sort": sort,
                "f_base_qs": ou_qs,
            },
        )

    @app.get("/ou/{path:path}", response_class=HTMLResponse, name="ou_detail")
    async def ou_detail(
        request: Request,
        path: str,
        _principal: Principal = Depends(requires(Permission.VIEW)),
    ) -> HTMLResponse:
        conn = get_ro_conn(app.state.db_path)
        try:
            estate = _store.load_estate(conn)
        finally:
            conn.close()

        target_som = None
        for som in estate.soms:
            if som.path.lower() == path.lower():
                target_som = som
                break

        if target_som is None:
            raise HTTPException(status_code=404, detail="OU not found")

        settings = queries.settings_at_som(estate, target_som.path)
        conflicts = queries.som_conflicts(estate, target_som.path)
        caveats = queries.scope_caveats(estate, target_som.path)

        gate_pairs = topology.gate_summaries(estate, target_som.path, _som=target_som)
        effective_gpos = [eg for eg, _ in gate_pairs]

        loopback_warning = any(gs.loopback_mode for _, gs in gate_pairs)

        page, per_page_int, per_page_raw = parse_pagination(request)
        page_settings, pag = paginate(settings, page, per_page_int, per_page_raw)
        settings_qs = base_qs(request, "page", "per_page")

        return templates.TemplateResponse(
            request, "ou_detail.html",
            {
                "som": target_som,
                "effective_gpos": effective_gpos,
                "gate_summaries": gate_pairs,
                "settings": page_settings,
                "settings_count": len(settings),
                "conflicts": conflicts,
                "loopback_warning": loopback_warning,
                "caveats": caveats,
                "pag": pag,
                "base_qs": settings_qs,
                "admx": app.state.admx,
            },
        )
