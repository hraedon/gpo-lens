"""Export (data download) routes — WI-027.

Handlers are plain ``def`` (not ``async def``) so FastAPI runs them in its
threadpool, preventing synchronous SQLite from blocking the event loop
(Plan 022 WI-1).
"""

from __future__ import annotations

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import Response
from fastapi.templating import Jinja2Templates

from gpo_lens.display import serialize_result
from gpo_lens.web._helpers import (
    csv_response,
    get_ro_conn,
    json_attachment,
)
from gpo_lens.web.auth import Permission, Principal, requires


def register(app: FastAPI, templates: Jinja2Templates) -> None:
    # ------------------------------------------------------------------
    # Export (WI-027) — read-only data downloads for analysts who want the
    # raw data without dropping to the CLI. All require VIEW permission, the
    # same as the pages they mirror. Exports dump the *complete* dataset for
    # the view (not the filtered/paginated slice) so the download is a stable,
    # linkable artifact independent of session filter state.
    # ------------------------------------------------------------------

    @app.get("/export/findings", name="export_findings")
    def export_findings(
        request: Request,
        format: str = "csv",
        _principal: Principal = Depends(requires(Permission.VIEW)),
    ) -> Response:
        from gpo_lens.queries import estate_doctor
        from gpo_lens.store import load_estate

        if format not in ("csv", "json"):
            raise HTTPException(
                status_code=400, detail="format must be 'csv' or 'json'"
            )

        conn = get_ro_conn(app.state.db_path)
        try:
            try:
                estate = load_estate(conn)
                findings = estate_doctor(estate)
            except ValueError:
                findings = []
        finally:
            conn.close()

        if format == "json":
            payload = serialize_result(findings)
            return json_attachment(payload, "gpo-lens-findings.json")
        # default: csv
        rows = [
            [f.severity, f.category, f.gpo_id, f.gpo_name, f.summary, f.detail, f.remediation]
            for f in findings
        ]
        return csv_response(
            rows,
            ["severity", "category", "gpo_id", "gpo_name", "summary", "detail", "remediation"],
            "gpo-lens-findings.csv",
        )

    @app.get("/export/gpo/{gpo_id}", name="export_gpo")
    def export_gpo(
        request: Request,
        gpo_id: str,
        format: str = "json",
        _principal: Principal = Depends(requires(Permission.VIEW)),
    ) -> Response:
        from gpo_lens.normalize import canonical_guid
        from gpo_lens.store import load_estate

        # A GPO is a rich nested object (settings grouped by side/CSE, links,
        # delegation) that does not flatten to CSV sensibly — JSON only.
        if format != "json":
            raise HTTPException(
                status_code=400, detail="GPO export supports JSON format only"
            )

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

        payload = serialize_result(gpo)
        return json_attachment(payload, f"gpo-lens-{gpo_id}.json")

    @app.get("/export/ou/{path:path}", name="export_ou")
    def export_ou(
        request: Request,
        path: str,
        format: str = "csv",
        _principal: Principal = Depends(requires(Permission.VIEW)),
    ) -> Response:
        from gpo_lens import queries
        from gpo_lens import store as _store

        if format not in ("csv", "json"):
            raise HTTPException(
                status_code=400, detail="format must be 'csv' or 'json'"
            )

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
        if format == "json":
            payload = serialize_result(settings)
            return json_attachment(payload, "gpo-lens-ou-settings.json")
        # default: csv
        rows = [
            [
                s.cse, s.side, s.identity, s.display_name, s.display_value,
                s.winner_gpo_id, s.winner_gpo_name, ", ".join(
                    f"{name}={val}" for name, val in s.overridden_by
                ),
                "yes" if s.enforced else "no",
            ]
            for s in settings
        ]
        return csv_response(
            rows,
            [
                "cse", "side", "identity", "display_name", "display_value",
                "winner_gpo_id", "winner_gpo_name", "overridden_by", "enforced",
            ],
            "gpo-lens-ou-settings.csv",
        )
