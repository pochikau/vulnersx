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


def _cancel_requested(run_id: int) -> bool:
    # Read cancel flag from a fresh DB connection so worker sees updates immediately.
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


def _env_api_key() -> str | None:
    return os.environ.get("VULNX_API_KEY") or os.environ.get("PDCP_API_KEY")


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
    err_note: str | None = None
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
                hits, serr = run_search(sw.name, vuln_age_days)
                if serr:
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
                # Persist frequently so cancellation and progress are immediately visible.
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


def start_scan_async(vuln_age_days: int, software_ids: list[int]) -> tuple[int | None, str | None]:
    global SCAN_THREAD
    with db.connect(DB_PATH) as conn:
        running = db.get_running_scan(conn)
        if running:
            return None, "Скан уже выполняется. Остановите текущий прогон или дождитесь завершения."
        if not software_ids:
            return None, "Список ПО пуст — добавьте записи или загрузите файл."
        run_id = db.start_scan_run(conn, vuln_age_days)
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
    _configure_vulnx_auth()

    scheduler = BackgroundScheduler()
    apply_schedule()
    scheduler.start()

    yield
    if scheduler:
        scheduler.shutdown(wait=False)


app = FastAPI(title="Vulnx UI", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


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
            db.request_cancel_scan(conn, int(running["id"]))
    return RedirectResponse(url="/", status_code=303)


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
