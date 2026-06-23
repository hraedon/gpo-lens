"""Estate-wide conflict surfacing.

Two lenses on the same data the per-OU view drills into:

* **resolved** — :func:`topology.precedence_conflict_rollup`: where co-linked
  GPOs actually fight in a resolved chain, de-duplicated to one row per root
  cause (winner + competitors), ranked by how many scopes it spreads to.
* **defined** — :func:`queries.conflicts`: settings assigned different values
  across the estate, regardless of whether the GPOs ever co-apply.

The resolved lens resolves every OU chain, so it is computed only when its tab
is the active view; the (cheap) defined lens backs the other tab.
"""

from __future__ import annotations

from typing import Any

from fastapi import Depends, FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from gpo_lens import topology
from gpo_lens.web._helpers import (
    _MAX_SEARCH_LEN,
    base_qs,
    get_ro_conn,
    paginate,
    parse_pagination,
)
from gpo_lens.web.auth import Permission, Principal, requires

_VALID_CONFLICT_VIEWS = {"resolved", "defined"}


def register(app: FastAPI, templates: Jinja2Templates) -> None:

    @app.get("/conflicts", response_class=HTMLResponse, name="conflicts")
    async def conflicts_page(
        request: Request,
        view: str = "resolved",
        q: str = "",
        _principal: Principal = Depends(requires(Permission.VIEW)),
    ) -> HTMLResponse:
        from gpo_lens.queries import conflicts as defined_conflicts
        from gpo_lens.store import load_estate

        if view not in _VALID_CONFLICT_VIEWS:
            view = "resolved"
        q = (q or "")[:_MAX_SEARCH_LEN]
        needle = q.lower()

        conn = get_ro_conn(app.state.db_path)
        try:
            try:
                estate = load_estate(conn)
                resolvable_gpo_ids = {g.id for g in estate.gpos}
                # The resolved rollup carries GPO names; the defined lens carries
                # ids. Map both ways so either can deep-link to a GPO detail page.
                gpo_names = {g.id: g.name for g in estate.gpos}
                gpo_id_by_name = {g.name: g.id for g in estate.gpos}
                # The defined count is cheap and shown on both tabs; the resolved
                # rollup resolves every OU chain, so only pay for it on its tab.
                defined_total = len(defined_conflicts(estate))
                rows: list[Any]
                if view == "resolved":
                    rows = list(topology.precedence_conflict_rollup(estate))
                    resolved_total = len(rows)
                    if needle:
                        rows = [
                            r for r in rows
                            if needle in r.identity.lower()
                            or needle in r.display_name.lower()
                            or needle in r.winner.lower()
                            or needle in r.cse.lower()
                        ]
                else:
                    rows = list(defined_conflicts(estate))
                    resolved_total = None  # not computed on this tab
                    if needle:
                        rows = [
                            r for r in rows
                            if needle in r.identity.lower()
                            or needle in r.display_name.lower()
                            or needle in r.cse.lower()
                        ]
            except ValueError:
                rows = []
                resolvable_gpo_ids = set()
                gpo_names = {}
                gpo_id_by_name = {}
                defined_total = 0
                resolved_total = 0 if view == "resolved" else None
        finally:
            conn.close()

        page, per_page_int, per_page_raw = parse_pagination(request)
        page_rows, pag = paginate(rows, page, per_page_int, per_page_raw)
        conflicts_qs = base_qs(request, "page", "per_page")

        return templates.TemplateResponse(
            request,
            "conflicts.html",
            {
                "request": request,
                "view": view,
                "rows": page_rows,
                "filtered_count": len(rows),
                "resolved_total": resolved_total,
                "defined_total": defined_total,
                "resolvable_gpo_ids": resolvable_gpo_ids,
                "gpo_names": gpo_names,
                "gpo_id_by_name": gpo_id_by_name,
                "f_q": q,
                "f_base_qs": conflicts_qs,
                "pag": pag,
            },
        )
