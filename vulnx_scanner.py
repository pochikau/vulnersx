"""
Invoke `vulnx search` and capture full CLI-style text blocks per CVE, plus parsed metrics.

Uses plain text output (not --json) so the stored `raw_output` matches what users see in the terminal.
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

CVE_HEADER = re.compile(r"^\s*\[(CVE-\d{4}-\d+)\]\s+(.+?)\s*$", re.MULTILINE)
CVE_LINE = re.compile(r"^\s*\[(CVE-\d{4}-\d+)\]\s+(\S+)\s+-\s+(.+)\s*$")
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
CVSS_RE = re.compile(r"CVSS:\s*([\d.]+|N/A|—)", re.I)
EPSS_RE = re.compile(r"EPSS:\s*([\d.]+|N/A|—)", re.I)
AGE_RE = re.compile(r"Vuln Age:\s*(\d+)\s*d", re.I)


def strip_ansi(s: str) -> str:
    return ANSI_RE.sub("", s)


def _severity_rank(severity: str | None) -> int:
    if not severity:
        return 0
    m = severity.strip().lower()
    return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(m, 0)


@dataclass
class VulnHit:
    cve_id: str
    title: str | None
    severity: str | None
    summary: str | None
    raw_output: str
    cvss_score: float | None
    epss_score: float | None
    vuln_age_days: int | None
    severity_rank: int

    @staticmethod
    def from_block(block: str) -> VulnHit | None:
        block = block.strip()
        if not block:
            return None
        first = block.splitlines()[0].strip()
        m = CVE_LINE.match(first)
        cve_id: str
        severity: str | None
        title: str | None
        if m:
            cve_id = m.group(1).upper()
            severity = m.group(2).strip().lower()
            title = m.group(3).strip()
        else:
            mh = CVE_HEADER.match(first)
            if not mh:
                return None
            cve_id = mh.group(1).upper()
            rest = mh.group(2).strip()
            severity = None
            title = rest
            parts = rest.split(None, 1)
            if len(parts) >= 2 and parts[0].lower() in (
                "critical",
                "high",
                "medium",
                "low",
                "info",
                "unknown",
            ):
                severity = parts[0].lower()
                title = parts[1].lstrip("- ").strip()

        cvss: float | None = None
        cm = CVSS_RE.search(block)
        if cm and cm.group(1) not in ("N/A", "—"):
            try:
                cvss = float(cm.group(1))
            except ValueError:
                pass

        epss: float | None = None
        em = EPSS_RE.search(block)
        if em and em.group(1) not in ("N/A", "—"):
            try:
                epss = float(em.group(1))
            except ValueError:
                pass

        age: int | None = None
        am = AGE_RE.search(block)
        if am:
            try:
                age = int(am.group(1))
            except ValueError:
                pass

        sr = _severity_rank(severity)
        return VulnHit(
            cve_id=cve_id,
            title=title,
            severity=severity,
            summary=None,
            raw_output=block,
            cvss_score=cvss,
            epss_score=epss,
            vuln_age_days=age,
            severity_rank=sr,
        )


def split_cve_blocks(text: str) -> list[str]:
    text = strip_ansi(text)
    if not text.strip():
        return []
    lines = text.splitlines()
    blocks: list[list[str]] = []
    cur: list[str] = []
    for line in lines:
        if line.strip().startswith("[CVE-"):
            if cur:
                blocks.append("\n".join(cur).strip())
            cur = [line]
        else:
            if cur:
                cur.append(line)
    if cur:
        blocks.append("\n".join(cur).strip())
    return [b for b in blocks if b]


def parse_text_hits(stdout: str) -> list[VulnHit]:
    out: list[VulnHit] = []
    seen: set[str] = set()
    for block in split_cve_blocks(stdout):
        hit = VulnHit.from_block(block)
        if hit is None:
            continue
        if hit.cve_id in seen:
            continue
        seen.add(hit.cve_id)
        out.append(hit)
    return out


# --- Legacy JSON path (fallback) ---------------------------------------------

CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)


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


def _float_or_none(v: Any) -> float | None:
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str):
        try:
            return float(v)
        except ValueError:
            return None
    return None


def _int_or_none(v: Any) -> int | None:
    if isinstance(v, int):
        return v
    if isinstance(v, str) and v.isdigit():
        return int(v)
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
        if not re.fullmatch(r"CVE-\d{4}-\d+", cve, re.I):
            m = CVE_RE.search(cve)
            if not m:
                return None
            cve = m.group(0).upper()

    title = _pick_str(d, "title", "name", "summary_title")
    severity = _normalize_severity(d.get("severity")) or _normalize_severity(d.get("Severity"))
    cvss = _float_or_none(d.get("cvss_score")) or _float_or_none(d.get("cvss"))
    epss = _float_or_none(d.get("epss_score")) or _float_or_none(d.get("epss"))
    age = _int_or_none(d.get("age_in_days")) or _int_or_none(d.get("vuln_age_days"))

    summary_parts: list[str] = []
    for key in ("description", "summary", "text", "detail"):
        val = d.get(key)
        if isinstance(val, str) and val.strip():
            summary_parts.append(val.strip())
    summary = "\n".join(summary_parts) if summary_parts else None
    if not title:
        title = summary[:200] if summary else None

    lines = [f"[{cve}] {(severity or '?').title()} - {title or ''}"]
    if cvss is not None:
        lines.append(f"  ↳ CVSS: {cvss} | EPSS: {epss if epss is not None else 'N/A'} | Vuln Age: {age if age is not None else 'N/A'}d")
    raw_output = "\n".join(lines)
    sr = _severity_rank(severity)
    return VulnHit(
        cve_id=cve,
        title=title,
        severity=severity,
        summary=summary,
        raw_output=raw_output,
        cvss_score=cvss,
        epss_score=epss,
        vuln_age_days=age,
        severity_rank=sr,
    )


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


def build_search_cmd_text(software: str, vuln_age_days: int, limit: int = 100) -> list[str]:
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
        "--disable-update-check",
    ]


def build_search_cmd_json(software: str, vuln_age_days: int, limit: int = 100) -> list[str]:
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
    Text-first search; falls back to JSON if text yields no CVE blocks.
    """
    env = os.environ.copy()
    api = env.get("VULNX_API_KEY") or env.get("PDCP_API_KEY")
    if api:
        env["PDCP_API_KEY"] = api

    cmd_text = build_search_cmd_text(software, vuln_age_days)
    try:
        proc = subprocess.run(
            cmd_text,
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

    out = parse_text_hits(proc.stdout or "")
    if out:
        return out, (err if err else None)

    cmd_json = build_search_cmd_json(software, vuln_age_days)
    try:
        proc2 = subprocess.run(
            cmd_json,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            env=env,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return [], err or "fallback json failed"

    if proc2.returncode != 0:
        return [], err or proc2.stderr.strip() or "json search failed"

    hits = parse_vulnx_json(proc2.stdout or "")
    return hits, (err if err else None)


def run_cli_software_file(input_path: Path, vuln_age_days: int = 190) -> int:
    """CLI: print each software block (stdout)."""
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
            print(h.raw_output)
            print()
        print("\n" + "═" * 60 + "\n")
    return 0


if __name__ == "__main__":
    p = Path(os.environ.get("VULNX_SOFTWARE_FILE", "software.txt"))
    age = int(os.environ.get("VULNX_VULN_AGE_DAYS", "190"))
    raise SystemExit(run_cli_software_file(p, age))
