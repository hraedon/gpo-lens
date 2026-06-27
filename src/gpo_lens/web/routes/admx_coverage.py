"""ADMX coverage route — estate-wide template inventory and gap detection."""

from __future__ import annotations

import logging
import sqlite3

from fastapi import Depends, FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from gpo_lens import queries, store
from gpo_lens.web._helpers import get_ro_conn
from gpo_lens.web.auth import Permission, Principal, requires

_logger = logging.getLogger(__name__)


def register(app: FastAPI, templates: Jinja2Templates) -> None:

    @app.get("/admx-coverage", response_class=HTMLResponse, name="admx_coverage")
    async def admx_coverage_route(
        request: Request,
        _principal: Principal = Depends(requires(Permission.VIEW)),
    ) -> HTMLResponse:
        conn = get_ro_conn(app.state.db_path)
        try:
            estate = store.load_estate(conn)
            report = queries.admx_coverage(estate, admx=app.state.admx)
        except (ValueError, sqlite3.Error) as exc:
            _logger.warning("admx-coverage failed: %s", exc)
            empty_summary = queries.AdmxCoverageSummary(
                total_policies=0,
                referenced_policies=0,
                unreferenced_policies=0,
                gap_count=0,
            )
            report = queries.AdmxCoverageReport(
                summary=empty_summary,
                referenced=[],
                unreferenced=[],
                gaps=[],
            )
        finally:
            conn.close()

        return templates.TemplateResponse(
            request,
            "admx_coverage.html",
            {"request": request, "report": report},
        )
