"""Principal resultant (Plan 021) routes.

Handlers are plain ``def`` (not ``async def``) so FastAPI runs them in its
threadpool, preventing synchronous SQLite from blocking the event loop
(Plan 022 WI-1).
"""

from __future__ import annotations

import logging

from fastapi import Depends, FastAPI, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from gpo_lens import store as _store
from gpo_lens.web._helpers import get_ro_conn
from gpo_lens.web.auth import Permission, Principal, requires

_logger = logging.getLogger(__name__)


def register(app: FastAPI, templates: Jinja2Templates) -> None:
    # ------------------------------------------------------------------
    # Principal resultant (Plan 021)
    # ------------------------------------------------------------------

    @app.get("/resultant", response_class=HTMLResponse, name="resultant_form")
    def resultant_form(
        request: Request,
        _principal: Principal = Depends(requires(Permission.VIEW)),
    ) -> HTMLResponse:
        return templates.TemplateResponse(
            request,
            "resultant.html",
            {"request": request, "result": None, "error": None},
        )

    @app.post(
        "/resultant",
        response_class=HTMLResponse,
        response_model=None,
        name="resultant_compute",
    )
    def resultant_compute(
        request: Request,
        principal_sid: str = Form(""),
        computer_sid: str = Form(""),
        dn: str = Form(""),
        computer_dn: str = Form(""),
        _principal_auth: Principal = Depends(requires(Permission.VIEW)),
    ) -> HTMLResponse:
        from gpo_lens.merge import principal_resultant, resolve_principal_input

        principal_input = principal_sid.strip()
        if not principal_input:
            return templates.TemplateResponse(
                request,
                "resultant.html",
                {"request": request, "result": None,
                 "error": "A principal SID or name is required."},
            )
        conn = get_ro_conn(app.state.db_path)
        try:
            estate = _store.load_estate(conn)
        finally:
            conn.close()

        resolved_sid = resolve_principal_input(estate, principal_input)
        if resolved_sid is None:
            return templates.TemplateResponse(
                request,
                "resultant.html",
                {"request": request, "result": None,
                 "error": f"Could not resolve '{principal_input}' to a principal. "
                          "Enter a SID (S-1-...) or a known principal/group name."},
            )

        resolved_computer_sid: str | None = None
        comp_input = computer_sid.strip()
        if comp_input:
            resolved_computer_sid = resolve_principal_input(estate, comp_input)
            if resolved_computer_sid is None:
                return templates.TemplateResponse(
                    request,
                    "resultant.html",
                    {"request": request, "result": None,
                     "error": f"Could not resolve '{comp_input}' to a computer principal. "
                              "Enter a SID (S-1-...) or a known principal/group name."},
                )

        try:
            result = principal_resultant(
                estate,
                resolved_sid,
                computer_sid=resolved_computer_sid,
                dn=dn.strip() or None,
                computer_dn=computer_dn.strip() or None,
            )
        except Exception as exc:
            _logger.warning("resultant computation failed: %s", exc, exc_info=True)
            return templates.TemplateResponse(
                request,
                "resultant.html",
                {"request": request, "result": None,
                 "error": "Computation failed. Check the server log for details."},
            )
        return templates.TemplateResponse(
            request,
            "resultant.html",
            {"request": request, "result": result, "error": None},
        )
