"""Ingest upload routes."""

from __future__ import annotations

import logging
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi import Depends, FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

# _MAX_UPLOAD_BYTES is an immutable int that tests patch on app.py *after*
# create_app() runs.  Importing it at module level would capture the original
# value; instead we look it up via the module reference at request time.
import gpo_lens.web.app as _app_module
from gpo_lens import events as _events
from gpo_lens import ingest as _ingest
from gpo_lens import store as _store
from gpo_lens.web._helpers import get_ro_conn, get_rw_conn, stream_upload_to_file

# _audit and _safe_extract reference module-level state on app.py that tests
# patch (e.g. _audit_logger, _MAX_UNCOMPRESSED_BYTES).  Importing the function
# objects is safe — their __globals__ remain app.py's module dict, so the
# patched values are visible at call time.
from gpo_lens.web.app import _audit, _safe_extract
from gpo_lens.web.auth import Permission, Principal, requires

_logger = logging.getLogger(__name__)


def register(app: FastAPI, templates: Jinja2Templates) -> None:

    @app.get("/ingest", response_class=HTMLResponse, name="ingest_get")
    async def ingest_get(
        request: Request,
        _principal: Principal = Depends(requires(Permission.VIEW)),
    ) -> HTMLResponse:
        conn = get_ro_conn(app.state.db_path)
        try:
            snapshots = _store.list_snapshots(conn)
        finally:
            conn.close()
        return templates.TemplateResponse(
            request, "ingest.html", {"snapshots": snapshots}
        )

    @app.post("/ingest", response_class=HTMLResponse, response_model=None, name="ingest_post")
    async def ingest_post(
        request: Request,
        file: UploadFile = File(...),
        principal: Principal = Depends(requires(Permission.INGEST)),
    ) -> HTMLResponse | RedirectResponse:
        lock = app.state.ingest_lock
        if not lock.acquire(blocking=False):
            _audit("ingest", principal, "failure", "another ingest in progress", request)
            return templates.TemplateResponse(
                request, "ingest.html",
                {"error": "Another ingest is in progress, please try again."},
                status_code=409,
            )

        try:
            with TemporaryDirectory() as tmpdir:
                zip_path = Path(tmpdir) / "upload.zip"
                # Look up _MAX_UPLOAD_BYTES at request time so test patches on
                # gpo_lens.web.app._MAX_UPLOAD_BYTES take effect.
                if await stream_upload_to_file(file, zip_path, _app_module._MAX_UPLOAD_BYTES):
                    _audit("ingest", principal, "failure", "upload exceeds size limit", request)
                    return templates.TemplateResponse(
                        request, "ingest.html",
                        {"error": "Upload exceeds 500MB limit."},
                        status_code=413,
                    )
                try:
                    extract_dir = Path(tmpdir) / "extracted"
                    extract_dir.mkdir()
                    _safe_extract(zip_path, extract_dir)
                except (
                    ValueError, zipfile.BadZipFile,
                    OSError, NotImplementedError, RuntimeError, MemoryError,
                ) as exc:
                    _logger.warning("Malformed zip upload: %s", exc)
                    _audit("ingest", principal, "failure", type(exc).__name__, request)
                    return templates.TemplateResponse(
                        request, "ingest.html",
                        {"error": "Malformed zip file. Please check the upload and try again."},
                        status_code=400,
                    )

                try:
                    estate = _ingest.load_estate(extract_dir)
                except (FileNotFoundError, ValueError, KeyError) as exc:
                    _logger.warning("Invalid estate data: %s", exc)
                    _audit("ingest", principal, "failure", type(exc).__name__, request)
                    return templates.TemplateResponse(
                        request, "ingest.html",
                        {"error": "Invalid estate data in upload."},
                        status_code=400,
                    )

                rw_conn = get_rw_conn(app.state.db_path)
                try:
                    _store.init_db(rw_conn)
                    _store.save_estate(rw_conn, estate)
                    _events.append_event(
                        rw_conn, "audit.ingest",
                        {"principal": principal.name},
                    )
                finally:
                    rw_conn.close()

            filename = (file.filename or "unknown")[:256]
            _audit(
                "ingest", principal, "success",
                f"{filename} ({len(estate.gpos)} GPOs)", request,
            )
            return RedirectResponse(url=request.url_for("home"), status_code=303)
        finally:
            lock.release()

    @app.post(
        "/ingest/delete", response_class=HTMLResponse, response_model=None,
        name="ingest_delete",
    )
    async def ingest_delete(
        request: Request,
        snapshot_id: int = Form(...),
        principal: Principal = Depends(requires(Permission.INGEST)),
    ) -> HTMLResponse | RedirectResponse:
        # Removing an import is destructive but recoverable (re-upload the zip),
        # and the snapshot's rows cascade away. Gated on INGEST (same right as
        # creating one) and the same-origin CSRF middleware.
        lock = app.state.ingest_lock
        if not lock.acquire(blocking=False):
            _audit(
                "snapshot_delete", principal, "failure",
                "another ingest in progress", request,
            )
            conn = get_ro_conn(app.state.db_path)
            try:
                snapshots = _store.list_snapshots(conn)
            finally:
                conn.close()
            return templates.TemplateResponse(
                request, "ingest.html",
                {"snapshots": snapshots,
                 "error": "Another ingest operation is in progress. Try again."},
                status_code=409,
            )

        try:
            rw_conn = get_rw_conn(app.state.db_path)
            try:
                deleted = _store.delete_snapshot(rw_conn, snapshot_id)
                if deleted:
                    _events.append_event(
                        rw_conn, "audit.snapshot_delete",
                        {"principal": principal.name, "snapshot_id": snapshot_id},
                    )
            finally:
                rw_conn.close()

            if not deleted:
                _audit(
                    "snapshot_delete", principal, "failure",
                    f"snapshot {snapshot_id} not found", request,
                )
                conn = get_ro_conn(app.state.db_path)
                try:
                    snapshots = _store.list_snapshots(conn)
                finally:
                    conn.close()
                return templates.TemplateResponse(
                    request, "ingest.html",
                    {"snapshots": snapshots,
                     "error": f"Snapshot {snapshot_id} not found."},
                    status_code=404,
                )

            _audit(
                "snapshot_delete", principal, "success",
                f"snapshot {snapshot_id}", request,
            )
            return RedirectResponse(url=request.url_for("ingest_get"), status_code=303)
        finally:
            lock.release()
