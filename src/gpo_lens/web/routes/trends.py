"""Trends route -- posture-over-time visualization."""

from __future__ import annotations

from fastapi import Depends, FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from gpo_lens.trend import compute_trend, sparkline
from gpo_lens.web._helpers import get_ro_conn
from gpo_lens.web.auth import Permission, Principal, requires


def register(app: FastAPI, templates: Jinja2Templates) -> None:

    @app.get("/trends", response_class=HTMLResponse, name="trends")
    async def trends(
        request: Request,
        _principal: Principal = Depends(requires(Permission.VIEW)),
    ) -> HTMLResponse:
        conn = get_ro_conn(app.state.db_path)
        try:
            points = compute_trend(conn)
        finally:
            conn.close()

        # Sparklines for key metrics.
        danger_spark = sparkline([p.danger_finding_count for p in points])
        cpassword_spark = sparkline([p.cpassword_hit_count for p in points])
        skew_spark = sparkline([p.version_skew_count for p in points])

        # Row tone: worse (danger increased) = red, better = green.
        row_tones: dict[int, str] = {}
        for i, p in enumerate(points):
            if i == 0:
                row_tones[p.snapshot_id] = ""
                continue
            prev = points[i - 1]
            if p.danger_finding_count > prev.danger_finding_count:
                row_tones[p.snapshot_id] = "worse"
            elif p.danger_finding_count < prev.danger_finding_count:
                row_tones[p.snapshot_id] = "better"
            else:
                row_tones[p.snapshot_id] = ""

        return templates.TemplateResponse(
            request,
            "trends.html",
            {
                "request": request,
                "points": points,
                "danger_spark": danger_spark,
                "cpassword_spark": cpassword_spark,
                "skew_spark": skew_spark,
                "row_tones": row_tones,
            },
        )
