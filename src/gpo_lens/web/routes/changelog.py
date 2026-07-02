"""Changelog route.

Handlers are plain ``def`` (not ``async def``) so FastAPI runs them in its
threadpool, preventing synchronous SQLite from blocking the event loop
(Plan 022 WI-1).
"""

from __future__ import annotations

from fastapi import Depends, FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from gpo_lens import queries
from gpo_lens import store as _store
from gpo_lens.web._helpers import get_ro_conn
from gpo_lens.web.auth import Permission, Principal, requires


def register(app: FastAPI, templates: Jinja2Templates) -> None:

    @app.get("/changelog", response_class=HTMLResponse, name="changelog")
    def changelog(
        request: Request,
        snap_a: str = "",
        snap_b: str = "",
        _principal: Principal = Depends(requires(Permission.VIEW)),
    ) -> HTMLResponse:
        conn = get_ro_conn(app.state.db_path)
        try:
            snapshots = _store.list_snapshots(conn)
            entries: list[queries.ChangelogEntry] = []
            settings_changes: list[queries.SnapshotSettingChange] = []
            snap_a_id = int(snap_a) if snap_a.isdigit() else None
            snap_b_id = int(snap_b) if snap_b.isdigit() else None
            if snap_a_id is not None and snap_b_id is not None:
                entries = queries.snapshot_changelog(conn, snap_a_id, snap_b_id)
                settings_changes = queries.snapshot_settings_diff(conn, snap_a_id, snap_b_id)
        finally:
            conn.close()

        return templates.TemplateResponse(
            request,
            "changelog.html",
            {
                "request": request,
                "snapshots": snapshots,
                "snap_a": snap_a_id,
                "snap_b": snap_b_id,
                "entries": entries,
                "settings_changes": settings_changes,
                "admx": app.state.admx,
            },
        )
