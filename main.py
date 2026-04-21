"""
Vulnx vulnerability management UI (FastAPI).
"""

from __future__ import annotations

import asyncio
import csv
import io
import os
import subprocess
from urllib.parse import quote
import threading
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import FastAPI, File, Form, Query, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

import db
from vulnx_scanner import run_search

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("DATA_DIR", str(BASE_DIR / "data")))
DB_PATH = DATA_DIR / "vulnx_ui.sqlite"
TEMPLATES = Jinja2Templates(directory=str(BASE_DIR / "templates"))

SCAN_LOCK = threading.Lock()
scheduler: BackgroundScheduler | None = None


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


def execute_scan(vuln_age_days: int) -> tuple[int | None, str | None]:
    """
    Runs a full inventory scan. Returns (scan_run_id, error_message).
    """
    with SCAN_LOCK:
        with db.connect(DB_PATH) as conn:
            software = db.list_software(conn)
            if not software:
                return None, "Список ПО пуст — добавьте записи или загрузите файл."

            run_id = db.start_scan_run(conn, vuln_age_days)

            new_count = 0
            total = 0
            err_note: str | None = None

            for sw in software:
                hits, serr = run_search(sw.name, vuln_age_days)
                if serr:
                    err_note = err_note or serr
                for hit in hits:
                    total += 1
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
                    if kind == "inserted":
                        new_count += 1

            db.finish_scan_run(conn, run_id, "completed", None, total, new_count)
            return run_id, err_note


def _scheduled_job() -> None:
    with db.connect(DB_PATH) as conn:
        age = int(db.get_setting(conn, "scan_vuln_age_days", "30") or "30")
    try:
        execute_scan(max(1, age))
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
    software_id: int | None = Query(None),
) -> Any:
    with db.connect(DB_PATH) as conn:
        sw = db.list_software(conn)
        interval = db.get_setting(conn, "scan_interval_minutes", "0")
        age_default = db.get_setting(conn, "scan_vuln_age_days", "30")
        scans = db.list_recent_scans(conn, 25)
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
            software_id=software_id,
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
            "software_filter": software_id,
        },
    )


@app.post("/action/scan")
async def action_scan(
    vuln_age_days: int = Form(30),
) -> RedirectResponse:
    def _run() -> tuple[int | None, str | None]:
        return execute_scan(vuln_age_days)

    run_result, err = await asyncio.to_thread(_run)
    if err and run_result is None:
        return RedirectResponse(url="/?error=" + quote(err), status_code=303)
    with db.connect(DB_PATH) as conn:
        last = db.latest_completed_scan(conn)
        rid = int(last["id"]) if last else None
    url = "/"
    if rid is not None:
        url = f"/?scan_run={rid}&only_new=1"
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
    software_id: int | None = Query(None),
) -> StreamingResponse:
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
            software_id=software_id,
        )

    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(
        [
            "cve_id",
            "software",
            "severity",
            "title",
            "cvss_score",
            "epss_score",
            "vuln_age_days",
            "status",
            "comment",
            "raw_output",
            "first_seen_scan_id",
            "last_seen_scan_id",
            "updated_at",
        ]
    )
    for r in rows:
        w.writerow(
            [
                r["cve_id"],
                r["software_name"],
                r["severity"] or "",
                r["title"] or "",
                r["cvss_score"] if r["cvss_score"] is not None else "",
                r["epss_score"] if r["epss_score"] is not None else "",
                r["vuln_age_days"] if r["vuln_age_days"] is not None else "",
                r["status"],
                r["comment"] or "",
                r["raw_output"] or "",
                r["first_seen_scan_id"],
                r["last_seen_scan_id"],
                r["updated_at"],
            ]
        )
    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="vulnx_findings.csv"'},
    )
