"""
Vulnx vulnerability management UI (FastAPI).
"""

from __future__ import annotations

import asyncio
import csv
import io
import os
import subprocess
from datetime import datetime
from urllib.parse import quote
import threading
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import FastAPI, File, Form, Query, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from authlib.integrations.starlette_client import OAuth
from starlette.middleware.sessions import SessionMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

import db
from vulnx_scanner import (
    OLD_DATA_CSV_HEADER,
    old_data_csv_row,
    parse_vulnx_cli_fields,
    run_search,
)

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("DATA_DIR", str(BASE_DIR / "data")))
DB_PATH = DATA_DIR / "vulnx_ui.sqlite"
TEMPLATES = Jinja2Templates(directory=str(BASE_DIR / "templates"))

SCAN_LOCK = threading.Lock()
scheduler: BackgroundScheduler | None = None
SCAN_THREAD: threading.Thread | None = None
CURRENT_SCAN_RUN_ID: int | None = None
_CANCEL_LOCK = threading.Lock()
_CANCEL_REQUESTED_RUNS: set[int] = set()
oauth = OAuth()


def _cancel_requested(run_id: int) -> bool:
    # Fast path: in-memory stop request (avoids DB lock issues on stop endpoint).
    with _CANCEL_LOCK:
        if run_id in _CANCEL_REQUESTED_RUNS:
            return True
    # DB path: persisted stop request (survives transient app errors/restarts).
    with db.connect(DB_PATH) as conn:
        return db.is_scan_cancel_requested(conn, run_id)


def _finish_cancelled_run(conn: Any, run_id: int) -> None:
    totals = conn.execute(
        "SELECT findings_count, new_findings_count FROM scan_runs WHERE id = ?",
        (run_id,),
    ).fetchone()
    db.finish_scan_run(
        conn,
        run_id,
        "cancelled",
        "scan cancelled by user",
        int(totals["findings_count"]) if totals else 0,
        int(totals["new_findings_count"]) if totals else 0,
    )
    with _CANCEL_LOCK:
        _CANCEL_REQUESTED_RUNS.discard(run_id)


def _env_api_key() -> str | None:
    return os.environ.get("VULNX_API_KEY") or os.environ.get("PDCP_API_KEY")


def _is_keycloak_enabled() -> bool:
    return bool(
        os.environ.get("KEYCLOAK_SERVER_URL")
        and os.environ.get("KEYCLOAK_REALM")
        and os.environ.get("KEYCLOAK_CLIENT_ID")
        and os.environ.get("KEYCLOAK_CLIENT_SECRET")
    )


def _keycloak_metadata_url() -> str:
    base = os.environ.get("KEYCLOAK_SERVER_URL", "").rstrip("/")
    realm = os.environ.get("KEYCLOAK_REALM", "").strip()
    return f"{base}/realms/{realm}/.well-known/openid-configuration"


def _public_base_url(request: Request) -> str:
    env_url = (os.environ.get("PUBLIC_BASE_URL") or "").strip().rstrip("/")
    if env_url:
        return env_url
    return str(request.base_url).rstrip("/")


def _is_authenticated(request: Request) -> bool:
    if not _is_keycloak_enabled():
        return True
    return bool(request.session.get("user"))


def _configure_vulnx_auth() -> None:
    key = _env_api_key()
    if not key:
        return
    os.environ["PDCP_API_KEY"] = key
    try:
        subprocess.run(
            ["vulnx", "auth", "--api-key", key],
            capture_output=True,
            text=True,
            timeout=60,
            env=os.environ.copy(),
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass


def _scan_worker(run_id: int, software_ids: list[int], vuln_age_days: int) -> None:
    global CURRENT_SCAN_RUN_ID
    CURRENT_SCAN_RUN_ID = run_id
    err_note: str | None = None
    try:
        with SCAN_LOCK:
            with db.connect(DB_PATH) as conn:
                software_rows = [db.get_software_by_id(conn, sid) for sid in software_ids]
                software = [s for s in software_rows if s is not None]
                db.initialize_scan_progress(conn, run_id, len(software))
                if not software:
                    db.finish_scan_run(conn, run_id, "failed", "empty software list", 0, 0)
                    return

                for sw in software:
                    if _cancel_requested(run_id):
                        _finish_cancelled_run(conn, run_id)
                        return

                    db.set_scan_current_software(conn, run_id, sw.name)
                    hits, serr = run_search(
                        sw.name,
                        vuln_age_days,
                        cancel_check=lambda: _cancel_requested(run_id),
                    )
                    if serr:
                        if serr == "cancelled" or _cancel_requested(run_id):
                            _finish_cancelled_run(conn, run_id)
                            return
                        err_note = err_note or serr

                    if _cancel_requested(run_id):
                        _finish_cancelled_run(conn, run_id)
                        return

                    hits_count = 0
                    new_hits_count = 0
                    for hit in hits:
                        if _cancel_requested(run_id):
                            _finish_cancelled_run(conn, run_id)
                            return
                        hits_count += 1
                        kind = db.upsert_finding(
                            conn,
                            cve_id=hit.cve_id,
                            software_id=sw.id,
                            title=hit.title,
                            severity=hit.severity,
                            summary=hit.summary,
                            raw_output=hit.raw_output,
                            cvss_score=hit.cvss_score,
                            epss_score=hit.epss_score,
                            vuln_age_days=hit.vuln_age_days,
                            severity_rank=hit.severity_rank,
                            scan_run_id=run_id,
                        )
                        is_new = kind == "inserted"
                        if is_new:
                            new_hits_count += 1
                        fid = db.get_finding_id(conn, hit.cve_id, sw.id)
                        db.append_scan_finding(
                            conn,
                            scan_run_id=run_id,
                            finding_id=fid,
                            cve_id=hit.cve_id,
                            software_name=sw.name,
                            title=hit.title,
                            severity=hit.severity,
                            cvss_score=hit.cvss_score,
                            epss_score=hit.epss_score,
                            vuln_age_days=hit.vuln_age_days,
                            raw_output=hit.raw_output,
                            is_new=is_new,
                        )
                    db.increment_scan_progress(
                        conn,
                        run_id,
                        processed_software_inc=1,
                        findings_inc=hits_count,
                        new_findings_inc=new_hits_count,
                    )
                    conn.commit()

                totals = conn.execute(
                    "SELECT findings_count, new_findings_count FROM scan_runs WHERE id = ?",
                    (run_id,),
                ).fetchone()
                db.finish_scan_run(
                    conn,
                    run_id,
                    "completed",
                    err_note,
                    int(totals["findings_count"]) if totals else 0,
                    int(totals["new_findings_count"]) if totals else 0,
                )
    except Exception as e:
        with db.connect(DB_PATH) as conn:
            totals = conn.execute(
                "SELECT findings_count, new_findings_count FROM scan_runs WHERE id = ?",
                (run_id,),
            ).fetchone()
            db.finish_scan_run(
                conn,
                run_id,
                "failed",
                f"scan worker crashed: {e}",
                int(totals["findings_count"]) if totals else 0,
                int(totals["new_findings_count"]) if totals else 0,
            )
    finally:
        CURRENT_SCAN_RUN_ID = None


def start_scan_async(vuln_age_days: int, software_ids: list[int]) -> tuple[int | None, str | None]:
    global SCAN_THREAD
    with db.connect(DB_PATH) as conn:
        running = db.get_running_scan(conn)
        if running:
            return None, "Скан уже выполняется. Остановите текущий прогон или дождитесь завершения."
        if not software_ids:
            return None, "Список ПО пуст — добавьте записи или загрузите файл."
        run_id = db.start_scan_run(conn, vuln_age_days)
    with _CANCEL_LOCK:
        _CANCEL_REQUESTED_RUNS.discard(run_id)
    SCAN_THREAD = threading.Thread(
        target=_scan_worker,
        args=(run_id, software_ids, vuln_age_days),
        daemon=True,
        name=f"scan-run-{run_id}",
    )
    SCAN_THREAD.start()
    return run_id, None


def _scheduled_job() -> None:
    with db.connect(DB_PATH) as conn:
        age = int(db.get_setting(conn, "scan_vuln_age_days", "30") or "30")
        software_ids = [s.id for s in db.list_software(conn)]
    try:
        start_scan_async(max(1, age), software_ids)
    except Exception:
        pass


def apply_schedule() -> None:
    if not scheduler:
        return
    for job in scheduler.get_jobs():
        scheduler.remove_job(job.id)
    with db.connect(DB_PATH) as conn:
        mins = int(db.get_setting(conn, "scan_interval_minutes", "0") or "0")
    if mins <= 0:
        return
    scheduler.add_job(
        _scheduled_job,
        "interval",
        minutes=max(1, mins),
        id="periodic_scan",
        replace_existing=True,
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    global scheduler
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    db.init_db(DB_PATH)
    with db.connect(DB_PATH) as conn:
        db.terminate_all_running_scans(conn, "server restarted while scan was running")
    _configure_vulnx_auth()
    if _is_keycloak_enabled():
        oauth.register(
            name="keycloak",
            server_metadata_url=_keycloak_metadata_url(),
            client_id=os.environ.get("KEYCLOAK_CLIENT_ID"),
            client_secret=os.environ.get("KEYCLOAK_CLIENT_SECRET"),
            client_kwargs={"scope": "openid profile email"},
        )

    scheduler = BackgroundScheduler()
    apply_schedule()
    scheduler.start()

    yield
    if scheduler:
        scheduler.shutdown(wait=False)


app = FastAPI(title="Vulnx UI", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
app.add_middleware(
    SessionMiddleware,
    secret_key=os.environ.get("APP_SECRET_KEY", "change-me-in-prod"),
    same_site="lax",
    https_only=True,
)


@app.middleware("http")
async def keycloak_auth_guard(request: Request, call_next):
    if not _is_keycloak_enabled():
        return await call_next(request)
    path = request.url.path
    allow = (
        path.startswith("/static/")
        or path == "/health"
        or path.startswith("/auth/")
    )
    if allow or _is_authenticated(request):
        return await call_next(request)
    if path.startswith("/api/"):
        return JSONResponse({"detail": "Unauthorized"}, status_code=401)
    return RedirectResponse(url="/auth/login", status_code=303)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/auth/login")
async def auth_login(request: Request) -> RedirectResponse:
    if not _is_keycloak_enabled():
        return RedirectResponse(url="/", status_code=303)
    if _is_authenticated(request):
        return RedirectResponse(url="/", status_code=303)
    redirect_uri = f"{_public_base_url(request)}/auth/callback"
    client = oauth.create_client("keycloak")
    return await client.authorize_redirect(request, redirect_uri)


@app.get("/auth/callback")
async def auth_callback(request: Request) -> RedirectResponse:
    if not _is_keycloak_enabled():
        return RedirectResponse(url="/", status_code=303)
    client = oauth.create_client("keycloak")
    token = await client.authorize_access_token(request)
    userinfo = token.get("userinfo")
    if not userinfo:
        userinfo = await client.userinfo(token=token)
    request.session["user"] = {
        "sub": userinfo.get("sub"),
        "preferred_username": userinfo.get("preferred_username"),
        "email": userinfo.get("email"),
        "name": userinfo.get("name"),
    }
    return RedirectResponse(url="/", status_code=303)


@app.get("/auth/logout")
async def auth_logout(request: Request) -> RedirectResponse:
    request.session.clear()
    return RedirectResponse(url="/", status_code=303)


def _parse_optional_int_param(value: str | None) -> int | None:
    if value is None:
        return None
    v = value.strip()
    if not v:
        return None
    try:
        return int(v)
    except ValueError:
        return None


@app.get("/", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    q: str | None = None,
    status: str | None = None,
    scan_run: int | None = None,
    only_new: str | None = None,
    error: str | None = None,
    sort: str = "cvss",
    order: str = "desc",
    software_id: str | None = Query(None),
) -> Any:
    software_id_int = _parse_optional_int_param(software_id)
    query_string = request.url.query or ""
    with db.connect(DB_PATH) as conn:
        sw = db.list_software(conn)
        interval = db.get_setting(conn, "scan_interval_minutes", "0")
        age_default = db.get_setting(conn, "scan_vuln_age_days", "30")
        scans = db.list_recent_scans(conn, 25)
        running_scan = db.get_running_scan(conn)
        latest = db.latest_completed_scan(conn)
        latest_scan_id = int(latest["id"]) if latest else None
        stats = db.count_findings_by_status(conn)

        only_id: int | None = None
        effective_scan = scan_run if scan_run is not None else latest_scan_id
        if only_new == "1" and effective_scan is not None:
            only_id = effective_scan

        rows = db.fetch_findings(
            conn,
            q=q,
            status=status if status else None,
            only_new_from_scan=only_id,
            sort_by=sort,
            sort_order=order,
            software_id=software_id_int,
        )

        last_scan_label = "NEVER"
        if scans:
            last_scan_label = str(scans[0]["started_at"])

        if stats["new"] > 50:
            threat_level, threat_class = "CRITICAL", "threat-hot"
        elif stats["new"] > 0:
            threat_level, threat_class = "ELEVATED", "threat-warn"
        else:
            threat_level, threat_class = "MONITORING", "threat-ok"

    return TEMPLATES.TemplateResponse(
        "index.html",
        {
            "request": request,
            "software": sw,
            "findings": rows,
            "scans": scans,
            "q": q or "",
            "status_filter": status or "all",
            "scan_run": scan_run,
            "latest_scan_id": latest_scan_id,
            "only_new": only_new == "1",
            "scan_interval_minutes": interval,
            "scan_vuln_age_days": age_default,
            "page_error": error,
            "sort": sort,
            "order": order,
            "stats": stats,
            "last_scan_label": last_scan_label,
            "threat_level": threat_level,
            "threat_class": threat_class,
            "software_filter": software_id_int,
            "running_scan": running_scan,
            "query_string": query_string,
            "auth_enabled": _is_keycloak_enabled(),
            "auth_user": request.session.get("user"),
        },
    )


@app.get("/partial/vuln-panel", response_class=HTMLResponse)
async def partial_vuln_panel(
    request: Request,
    q: str | None = None,
    status: str | None = None,
    scan_run: int | None = None,
    only_new: str | None = None,
    sort: str = "cvss",
    order: str = "desc",
    software_id: str | None = Query(None),
) -> Any:
    software_id_int = _parse_optional_int_param(software_id)
    with db.connect(DB_PATH) as conn:
        sw = db.list_software(conn)
        latest = db.latest_completed_scan(conn)
        latest_scan_id = int(latest["id"]) if latest else None
        only_id: int | None = None
        effective_scan = scan_run if scan_run is not None else latest_scan_id
        if only_new == "1" and effective_scan is not None:
            only_id = effective_scan
        rows = db.fetch_findings(
            conn,
            q=q,
            status=status if status else None,
            only_new_from_scan=only_id,
            sort_by=sort,
            sort_order=order,
            software_id=software_id_int,
        )
    return TEMPLATES.TemplateResponse(
        "partials/vuln_panel.html",
        {
            "request": request,
            "software": sw,
            "findings": rows,
            "q": q or "",
            "status_filter": status or "all",
            "scan_run": scan_run,
            "only_new": only_new == "1",
            "sort": sort,
            "order": order,
            "software_filter": software_id_int,
            "query_string": request.url.query or "",
        },
    )


@app.post("/action/scan")
async def action_scan(
    vuln_age_days: int = Form(30),
) -> RedirectResponse:
    with db.connect(DB_PATH) as conn:
        ids = [s.id for s in db.list_software(conn)]
    run_result, err = start_scan_async(vuln_age_days, ids)
    if err or run_result is None:
        return RedirectResponse(url="/?error=" + quote(err), status_code=303)
    url = f"/?scan_run={run_result}&only_new=1"
    return RedirectResponse(url=url, status_code=303)


@app.post("/action/scan/one")
async def action_scan_one(
    software_id: int = Form(...),
    vuln_age_days: int = Form(30),
) -> RedirectResponse:
    run_result, err = start_scan_async(vuln_age_days, [software_id])
    if err or run_result is None:
        return RedirectResponse(url="/?error=" + quote(err), status_code=303)
    url = f"/?scan_run={run_result}&only_new=1&software_id={software_id}"
    return RedirectResponse(url=url, status_code=303)


@app.post("/action/settings")
async def action_settings(
    scan_interval_minutes: int = Form(0),
    scan_vuln_age_days: int = Form(30),
) -> RedirectResponse:
    with db.connect(DB_PATH) as conn:
        db.set_setting(conn, "scan_interval_minutes", str(max(0, scan_interval_minutes)))
        db.set_setting(conn, "scan_vuln_age_days", str(max(1, scan_vuln_age_days)))
    apply_schedule()
    return RedirectResponse(url="/", status_code=303)


@app.post("/software/add")
async def software_add(name: str = Form(...)) -> RedirectResponse:
    with db.connect(DB_PATH) as conn:
        db.upsert_software(conn, name.strip(), "manual")
    return RedirectResponse(url="/", status_code=303)


@app.post("/software/upload")
async def software_upload(file: UploadFile = File(...)) -> RedirectResponse:
    raw = await file.read()
    text = raw.decode("utf-8", errors="replace")
    lines = text.splitlines()
    with db.connect(DB_PATH) as conn:
        db.merge_software_lines(conn, lines, "upload")
    return RedirectResponse(url="/", status_code=303)


@app.post("/software/{software_id}/delete")
async def software_delete(software_id: int) -> RedirectResponse:
    with db.connect(DB_PATH) as conn:
        ok = db.delete_software(conn, software_id)
    if not ok:
        return RedirectResponse(url="/?error=" + quote("ПО не найдено."), status_code=303)
    return RedirectResponse(url="/", status_code=303)


@app.post("/action/scan/stop")
async def action_scan_stop() -> RedirectResponse:
    with db.connect(DB_PATH) as conn:
        running = db.get_running_scan(conn)
        if running:
            rid = int(running["id"])
            with _CANCEL_LOCK:
                _CANCEL_REQUESTED_RUNS.add(rid)
            try:
                db.request_cancel_scan(conn, rid)
            except Exception:
                # Keep UI responsive even when DB is temporarily locked.
                pass
    return RedirectResponse(url="/", status_code=303)


@app.post("/api/scan/stop")
async def api_scan_stop() -> JSONResponse:
    with db.connect(DB_PATH) as conn:
        running = conn.execute(
            "SELECT id FROM scan_runs WHERE status = 'running' ORDER BY id DESC"
        ).fetchall()
        run_ids = [int(r["id"]) for r in running]
        with _CANCEL_LOCK:
            for rid in run_ids:
                _CANCEL_REQUESTED_RUNS.add(rid)
        db_errors: list[str] = []
        for rid in run_ids:
            try:
                db.request_cancel_scan(conn, rid)
            except Exception as e:
                db_errors.append(f"{rid}: {e}")
    return JSONResponse(
        {
            "ok": True,
            "cancel_requested": len(run_ids) > 0,
            "run_ids": run_ids,
            "db_persisted": len(db_errors) == 0,
            "db_errors": db_errors[:3],
        }
    )


@app.get("/api/scan/status")
async def api_scan_status() -> JSONResponse:
    with db.connect(DB_PATH) as conn:
        running = db.get_running_scan(conn)
        if not running:
            return JSONResponse({"running": False})
        run_id = int(running["id"])
        new_rows = db.list_new_scan_findings(conn, run_id, 20)
        return JSONResponse(
            {
                "running": True,
                "run_id": run_id,
                "started_at": running["started_at"],
                "vuln_age_days": int(running["vuln_age_days"]),
                "processed_software": int(running["processed_software"] or 0),
                "total_software": int(running["total_software"] or 0),
                "findings_count": int(running["findings_count"] or 0),
                "new_findings_count": int(running["new_findings_count"] or 0),
                "current_software": running["current_software"] or "",
                "cancel_requested": bool(int(running["cancel_requested"] or 0)),
                "new_items": [
                    {
                        "cve_id": r["cve_id"],
                        "software_name": r["software_name"],
                        "severity": r["severity"] or "",
                        "title": r["title"] or "",
                    }
                    for r in new_rows
                ],
            }
        )


def _safe_next(url: str | None) -> str:
    if not url or not url.startswith("/") or url.startswith("//"):
        return "/"
    return url.split("#", 1)[0]


@app.post("/finding/{finding_id}/update")
async def finding_update(
    finding_id: int,
    status: str = Form(...),
    comment: str = Form(""),
    next: str = Form("/"),
) -> RedirectResponse:
    with db.connect(DB_PATH) as conn:
        db.update_finding_status(conn, finding_id, status, comment.strip() or None)
    return RedirectResponse(url=_safe_next(next), status_code=303)


@app.get("/export.csv")
async def export_csv(
    q: str | None = None,
    status: str | None = None,
    scan_run: int | None = None,
    only_new: str | None = None,
    sort: str = "cvss",
    order: str = "desc",
    software_id: str | None = Query(None),
) -> StreamingResponse:
    software_id_int = _parse_optional_int_param(software_id)
    only_id: int | None = None
    with db.connect(DB_PATH) as conn:
        if only_new == "1":
            eff = scan_run
            if eff is None:
                latest = db.latest_completed_scan(conn)
                eff = int(latest["id"]) if latest else None
            if eff is not None:
                only_id = eff
        rows = db.fetch_findings(
            conn,
            q=q,
            status=status if status else None,
            only_new_from_scan=only_id,
            sort_by=sort,
            sort_order=order,
            software_id=software_id_int,
        )

    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(list(OLD_DATA_CSV_HEADER))
    for r in rows:
        raw_full = r["raw_output"] or ""
        parsed = parse_vulnx_cli_fields(raw_full)
        w.writerow(old_data_csv_row(r, parsed, raw_full))
    buf.seek(0)
    fname = f"vuln_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


@app.get("/scan/{run_id}/export.csv")
async def export_scan_run_csv(run_id: int) -> StreamingResponse:
    with db.connect(DB_PATH) as conn:
        run = db.get_scan_run(conn, run_id)
        rows = db.list_scan_findings(conn, run_id)
    if run is None:
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["error"])
        w.writerow([f"scan run {run_id} not found"])
        buf.seek(0)
        return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv; charset=utf-8")

    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(
        [
            "scan_run_id",
            "seen_at",
            "is_new",
            "cve_id",
            "software",
            "severity",
            "title",
            "cvss_score",
            "epss_score",
            "vuln_age_days",
            "raw_output",
        ]
    )
    for r in rows:
        w.writerow(
            [
                run_id,
                r["seen_at"],
                "Yes" if int(r["is_new"] or 0) == 1 else "No",
                r["cve_id"],
                r["software_name"],
                r["severity"] or "",
                r["title"] or "",
                r["cvss_score"] if r["cvss_score"] is not None else "",
                r["epss_score"] if r["epss_score"] is not None else "",
                r["vuln_age_days"] if r["vuln_age_days"] is not None else "",
                r["raw_output"] or "",
            ]
        )
    buf.seek(0)
    fname = f"scan_{run_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )
