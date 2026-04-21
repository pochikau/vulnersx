"""SQLite persistence for software inventory and vulnerability findings."""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

SCHEMA = """
CREATE TABLE IF NOT EXISTS software (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL COLLATE NOCASE UNIQUE,
    source TEXT NOT NULL DEFAULT 'manual',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    vuln_age_days INTEGER NOT NULL,
    status TEXT NOT NULL,
    error TEXT,
    findings_count INTEGER DEFAULT 0,
    new_findings_count INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL,
    software_id INTEGER NOT NULL,
    title TEXT,
    severity TEXT,
    summary TEXT,
    status TEXT NOT NULL DEFAULT 'new',
    comment TEXT,
    first_seen_scan_id INTEGER NOT NULL,
    last_seen_scan_id INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (cve_id, software_id),
    FOREIGN KEY (software_id) REFERENCES software(id),
    FOREIGN KEY (first_seen_scan_id) REFERENCES scan_runs(id),
    FOREIGN KEY (last_seen_scan_id) REFERENCES scan_runs(id)
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_cve ON findings(cve_id);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_first_scan ON findings(first_seen_scan_id);
CREATE INDEX IF NOT EXISTS idx_software_name ON software(name);
"""


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@contextmanager
def connect(db_path: Path) -> Iterator[sqlite3.Connection]:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db(db_path: Path) -> None:
    with connect(db_path) as conn:
        conn.executescript(SCHEMA)
        cur = conn.execute("SELECT COUNT(*) FROM settings WHERE key = 'scan_interval_minutes'")
        if cur.fetchone()[0] == 0:
            conn.execute(
                "INSERT INTO settings (key, value) VALUES ('scan_interval_minutes', '0')"
            )
        cur = conn.execute("SELECT COUNT(*) FROM settings WHERE key = 'scan_vuln_age_days'")
        if cur.fetchone()[0] == 0:
            conn.execute(
                "INSERT INTO settings (key, value) VALUES ('scan_vuln_age_days', '30')"
            )


def get_setting(conn: sqlite3.Connection, key: str, default: str = "") -> str:
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row[0] if row else default


def set_setting(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )


@dataclass
class SoftwareRow:
    id: int
    name: str
    source: str
    created_at: str


def upsert_software(conn: sqlite3.Connection, name: str, source: str) -> int:
    name = name.strip()
    if not name:
        raise ValueError("empty software name")
    now = utc_now_iso()
    row = conn.execute("SELECT id FROM software WHERE name = ? COLLATE NOCASE", (name,)).fetchone()
    if row:
        conn.execute(
            "UPDATE software SET source = ? WHERE id = ?",
            (source, int(row["id"])),
        )
        return int(row["id"])
    cur = conn.execute(
        "INSERT INTO software (name, source, created_at) VALUES (?, ?, ?)",
        (name, source, now),
    )
    return int(cur.lastrowid)


def list_software(conn: sqlite3.Connection) -> list[SoftwareRow]:
    rows = conn.execute(
        "SELECT id, name, source, created_at FROM software ORDER BY name COLLATE NOCASE"
    ).fetchall()
    return [SoftwareRow(int(r["id"]), r["name"], r["source"], r["created_at"]) for r in rows]


def merge_software_lines(conn: sqlite3.Connection, lines: list[str], source: str) -> int:
    added = 0
    for raw in lines:
        line = raw.strip().strip('"').strip("'")
        if not line or line.startswith("#"):
            continue
        try:
            before = conn.execute(
                "SELECT id FROM software WHERE name = ? COLLATE NOCASE", (line,)
            ).fetchone()
            upsert_software(conn, line, source)
            if before is None:
                added += 1
        except ValueError:
            continue
    return added


def start_scan_run(conn: sqlite3.Connection, vuln_age_days: int) -> int:
    rid = conn.execute(
        """
        INSERT INTO scan_runs (started_at, vuln_age_days, status)
        VALUES (?, ?, 'running')
        """,
        (utc_now_iso(), vuln_age_days),
    ).lastrowid
    assert rid is not None
    return int(rid)


def finish_scan_run(
    conn: sqlite3.Connection,
    run_id: int,
    status: str,
    error: str | None,
    findings_count: int,
    new_findings_count: int,
) -> None:
    conn.execute(
        """
        UPDATE scan_runs SET completed_at = ?, status = ?, error = ?,
        findings_count = ?, new_findings_count = ?
        WHERE id = ?
        """,
        (utc_now_iso(), status, error, findings_count, new_findings_count, run_id),
    )


def upsert_finding(
    conn: sqlite3.Connection,
    *,
    cve_id: str,
    software_id: int,
    title: str | None,
    severity: str | None,
    summary: str | None,
    scan_run_id: int,
) -> str:
    """Returns 'inserted' or 'updated'."""
    now = utc_now_iso()
    cve_id = cve_id.strip().upper()
    row = conn.execute(
        "SELECT id, status FROM findings WHERE cve_id = ? AND software_id = ?",
        (cve_id, software_id),
    ).fetchone()
    if row is None:
        conn.execute(
            """
            INSERT INTO findings (
                cve_id, software_id, title, severity, summary, status, comment,
                first_seen_scan_id, last_seen_scan_id, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, 'new', NULL, ?, ?, ?, ?)
            """,
            (cve_id, software_id, title, severity, summary, scan_run_id, scan_run_id, now, now),
        )
        return "inserted"
    conn.execute(
        """
        UPDATE findings SET
            title = COALESCE(?, title),
            severity = COALESCE(?, severity),
            summary = COALESCE(?, summary),
            last_seen_scan_id = ?,
            updated_at = ?
        WHERE id = ?
        """,
        (title, severity, summary, scan_run_id, now, int(row["id"])),
    )
    return "updated"


def update_finding_status(
    conn: sqlite3.Connection, finding_id: int, status: str, comment: str | None
) -> None:
    if status not in ("new", "in_progress", "closed"):
        raise ValueError("invalid status")
    conn.execute(
        """
        UPDATE findings SET status = ?, comment = ?, updated_at = ? WHERE id = ?
        """,
        (status, comment, utc_now_iso(), finding_id),
    )


def fetch_findings(
    conn: sqlite3.Connection,
    *,
    q: str | None,
    status: str | None,
    only_new_from_scan: int | None,
) -> list[sqlite3.Row]:
    where: list[str] = ["1=1"]
    params: list[Any] = []
    if q:
        like = f"%{q.strip()}%"
        where.append("(f.cve_id LIKE ? OR s.name LIKE ?)")
        params.extend([like, like])
    if status and status != "all":
        where.append("f.status = ?")
        params.append(status)
    if only_new_from_scan is not None:
        where.append("f.first_seen_scan_id = ?")
        params.append(only_new_from_scan)
    sql = f"""
        SELECT f.*, s.name AS software_name
        FROM findings f
        JOIN software s ON s.id = f.software_id
        WHERE {' AND '.join(where)}
        ORDER BY f.updated_at DESC, f.cve_id
    """
    return conn.execute(sql, params).fetchall()


def latest_completed_scan(conn: sqlite3.Connection) -> sqlite3.Row | None:
    return conn.execute(
        """
        SELECT * FROM scan_runs WHERE status = 'completed' ORDER BY id DESC LIMIT 1
        """
    ).fetchone()


def list_recent_scans(conn: sqlite3.Connection, limit: int = 20) -> list[sqlite3.Row]:
    return conn.execute(
        """
        SELECT * FROM scan_runs ORDER BY id DESC LIMIT ?
        """,
        (limit,),
    ).fetchall()
