"""
Invoke `vulnx search` and parse JSON output into normalized vulnerability records.

Reuses the same query shape as the original app.py (severity + vuln-age + limit),
with machine-readable `--json` for ingestion.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)


@dataclass
class VulnHit:
    cve_id: str
    title: str | None
    severity: str | None
    summary: str | None


def _iter_json_blobs(raw: str) -> Iterator[Any]:
    raw = raw.strip()
    if not raw:
        return
    try:
        yield json.loads(raw)
        return
    except json.JSONDecodeError:
        pass
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            continue


def _walk_for_dicts(obj: Any) -> Iterator[dict[str, Any]]:
    if isinstance(obj, dict):
        yield obj
        for v in obj.values():
            yield from _walk_for_dicts(v)
    elif isinstance(obj, list):
        for item in obj:
            yield from _walk_for_dicts(item)


def _pick_str(d: dict[str, Any], *keys: str) -> str | None:
    for k in keys:
        v = d.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None


def _normalize_severity(v: Any) -> str | None:
    if isinstance(v, str) and v.strip():
        return v.strip().lower()
    return None


def _record_from_dict(d: dict[str, Any]) -> VulnHit | None:
    cve = _pick_str(d, "cve_id", "cveId", "id", "CVE_ID")
    if not cve:
        blob = json.dumps(d, ensure_ascii=False)
        m = CVE_RE.search(blob)
        if not m:
            return None
        cve = m.group(0).upper()
    else:
        cve = cve.upper()
        if not CVE_RE.fullmatch(cve):
            m = CVE_RE.search(cve)
            if not m:
                return None
            cve = m.group(0).upper()

    title = _pick_str(d, "title", "name", "summary_title")
    severity = _normalize_severity(d.get("severity")) or _normalize_severity(
        d.get("Severity")
    )

    summary_parts: list[str] = []
    for key in ("description", "summary", "text", "detail"):
        val = d.get(key)
        if isinstance(val, str) and val.strip():
            summary_parts.append(val.strip())
    summary = "\n".join(summary_parts) if summary_parts else None

    if not title:
        title = summary[:200] if summary else None

    return VulnHit(cve_id=cve, title=title, severity=severity, summary=summary)


def parse_vulnx_json(stdout: str) -> list[VulnHit]:
    seen: set[str] = set()
    out: list[VulnHit] = []
    for blob in _iter_json_blobs(stdout):
        for d in _walk_for_dicts(blob):
            rec = _record_from_dict(d)
            if rec is None:
                continue
            if rec.cve_id in seen:
                continue
            seen.add(rec.cve_id)
            out.append(rec)
    return out


def build_search_cmd(software: str, vuln_age_days: int, limit: int = 100) -> list[str]:
    age = max(1, int(vuln_age_days))
    return [
        "vulnx",
        "search",
        software,
        "--severity",
        "critical,high",
        "--vuln-age",
        f"<{age}",
        "--limit",
        str(limit),
        "--json",
        "--disable-update-check",
    ]


def run_search(
    software: str,
    vuln_age_days: int,
    *,
    timeout_sec: int = 600,
) -> tuple[list[VulnHit], str | None]:
    """
    Returns hits and optional error string (stderr or process failure).
    """
    cmd = build_search_cmd(software, vuln_age_days)
    env = os.environ.copy()
    api = env.get("VULNX_API_KEY") or env.get("PDCP_API_KEY")
    if api:
        env["PDCP_API_KEY"] = api

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return [], "timeout"
    except FileNotFoundError:
        return [], "vulnx binary not found in PATH"

    err = proc.stderr.strip() if proc.stderr else ""
    if proc.returncode != 0:
        msg = err or proc.stdout.strip() or f"exit {proc.returncode}"
        return [], msg

    hits = parse_vulnx_json(proc.stdout or "")
    return hits, (err if err else None)


def run_cli_software_file(input_path: Path, vuln_age_days: int = 190) -> int:
    """Drop-in style runner similar to the original app.py (stdout human readable)."""
    if not input_path.is_file():
        print(f"Файл {input_path} не найден", file=sys.stderr)
        return 1

    print(f"Запуск поиска уязвимостей для каждого ПО из {input_path}\n")
    with open(input_path, encoding="utf-8") as f:
        lines = f.readlines()

    for raw in lines:
        software = raw.strip().strip('"').strip("'")
        if not software:
            continue
        print(f"→ {software}")
        print("-" * 50)
        hits, err = run_search(software, vuln_age_days)
        if err:
            print(err, file=sys.stderr)
        for h in hits:
            print(f"  [{h.cve_id}] {h.severity or '?'} - {h.title or ''}")
        print("\n" + "═" * 60 + "\n")
    return 0


if __name__ == "__main__":
    p = Path(os.environ.get("VULNX_SOFTWARE_FILE", "software.txt"))
    age = int(os.environ.get("VULNX_VULN_AGE_DAYS", "190"))
    raise SystemExit(run_cli_software_file(p, age))
