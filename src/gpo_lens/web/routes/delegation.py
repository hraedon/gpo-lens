"""Delegation rollup route — estate-wide trustee → GPO matrix."""

from __future__ import annotations

from fastapi import Depends, FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from gpo_lens import queries, store
from gpo_lens.web._helpers import get_ro_conn
from gpo_lens.web.auth import Permission, Principal, requires


def register(app: FastAPI, templates: Jinja2Templates) -> None:

    @app.get("/delegation", response_class=HTMLResponse, name="delegation")
    async def delegation(
        request: Request,
        _principal: Principal = Depends(requires(Permission.VIEW)),
    ) -> HTMLResponse:
        conn = get_ro_conn(app.state.db_path)
        try:
            estate = store.load_estate(conn)
            rollup = queries.delegation_rollup(estate)
        except ValueError:
            rollup = []
        finally:
            conn.close()
        unknown_count = sum(1 for e in rollup if e.is_unknown_sid)
        non_default_count = sum(1 for e in rollup if not e.is_default_writer)

        return templates.TemplateResponse(
            request,
            "delegation.html",
            {
                "request": request,
                "rollup": rollup,
                "total_trustees": len(rollup),
                "unknown_count": unknown_count,
                "non_default_count": non_default_count,
            },
        )
