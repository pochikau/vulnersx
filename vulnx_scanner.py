"""
Invoke `vulnx search` and parse JSON (SearchResponse.results[]) into records.

API shape matches projectdiscovery/vulnx SearchResponse / Vulnerability (types.go).
"""

from __future__ import annotations

import json
import math
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)


@dataclass
class VulnHit:
    cve_id: str
    title: str | None
    severity: str | None
    summary: str  # human-readable block (CLI-style)
    detail: dict[str, Any] = field(default_factory=dict)


def _f(x: Any) -> str:
    if x is None:
        return ""
    if isinstance(x, float) and (math.isnan(x) or math.isinf(x)):
        return ""
    if isinstance(x, bool):
        return "✔" if x else "✘"
    return str(x)


def _fmt_float(x: Any, nd: int = 4) -> str:
    if x is None:
        return ""
    try:
        v = float(x)
        if math.isnan(v) or math.isinf(v):
            return ""
        return f"{v:.{nd}f}".rstrip("0").rstrip(".")
    except (TypeError, ValueError):
        return ""


def _exposure_hosts(v: dict[str, Any]) -> str:
    exp = v.get("exposure")
    if isinstance(exp, dict):
        mh = exp.get("max_hosts")
        if mh is not None:
            return str(mh)
        vals = exp.get("values") or []
        best = 0
        for item in vals:
            if not isinstance(item, dict):
                continue
            for key in ("max_hosts", "min_hosts"):
                try:
                    n = int(item.get(key) or 0)
                    best = max(best, n)
                except (TypeError, ValueError):
                    continue
        if best:
            return str(best)
    return ""


def _kev_sources(v: dict[str, Any]) -> str:
    out: list[str] = []
    for k in v.get("kev") or []:
        if isinstance(k, dict) and k.get("source"):
            out.append(str(k["source"]))
    if v.get("is_kev") and not out:
        return "CISA/KEV"
    return ", ".join(sorted(set(out))) if out else ""


def _affected_lines(v: dict[str, Any]) -> tuple[str, str]:
    vendors: list[str] = []
    products: list[str] = []
    for p in v.get("affected_products") or []:
        if not isinstance(p, dict):
            continue
        if p.get("vendor"):
            vendors.append(str(p["vendor"]))
        if p.get("product"):
            products.append(str(p["product"]))
    return ", ".join(sorted(set(vendors))), ", ".join(sorted(set(products)))


def _h1_reports(v: dict[str, Any]) -> str:
    h = v.get("h1")
    if isinstance(h, dict) and h.get("reports") is not None:
        return str(h["reports"])
    return ""


def format_vulnerability_block(v: dict[str, Any], software_query: str) -> str:
    """Readable block similar to vulnx CLI / old_data raw output."""
    cve = (v.get("cve_id") or "?").strip()
    sev = (v.get("severity") or "?").strip().title()
    name = (v.get("name") or "").strip() or (v.get("description") or "")[:200]
    line1 = f"[{cve}] {sev} - {name}".strip()

    cvss = _fmt_float(v.get("cvss_score"), 1)
    epss = _fmt_float(v.get("epss_score"), 4)
    epssp = _fmt_float(v.get("epss_percentile"), 2)
    age = v.get("age_in_days")
    age_s = "" if age is None else f"{age}d"

    kev_flag = bool(v.get("is_kev"))
    kev_src = _kev_sources(v)
    kev_txt = "✔" if kev_flag else "✘"
    if kev_src:
        kev_txt += f" ({kev_src})"

    prio = "IMMEDIATE" if sev.lower() == "critical" else "HIGH" if sev.lower() == "high" else "NORMAL"
    exploits = bool(v.get("is_poc")) or int(v.get("poc_count") or 0) > 0

    exp = _exposure_hosts(v)
    vendors, products = _affected_lines(v)
    patch = bool(v.get("is_patch_available"))
    pocs = int(v.get("poc_count") or 0)
    nuclei = bool(v.get("is_template"))
    h1 = _h1_reports(v)

    epss_band = ""
    try:
        epss_f = float(v.get("epss_score") or 0)
        if epss_f >= 0.75:
            epss_band = "HIGH"
        elif epss_f >= 0.35:
            epss_band = "MED"
        elif epss_f > 0:
            epss_band = "LOW"
    except (TypeError, ValueError):
        pass

    lines = [
        line1,
        f"  ↳ Priority: {prio} | {'EXPLOITS AVAILABLE' if exploits else 'No public exploits flag'} | Vuln Age: {age_s or '—'}",
        f"  ↳ CVSS: {cvss or '—'} | EPSS: {epss or '—'} ({epss_band or '—'}) | KEV: {kev_txt}",
        f"  ↳ Query software: {software_query} | Exposure: {exp or '—'}",
        f"  ↳ Vendors: {vendors or '—'} | Products: {products or '—'}",
        f"  ↳ Patch: {_f(patch)} | POCs: {pocs} | Nuclei Template: {_f(nuclei)} | HackerOne reports: {h1 or '—'}",
    ]
    authors = v.get("author")
    if isinstance(authors, list) and authors:
        lines.append(f"  ↳ Template Authors: {', '.join(str(a) for a in authors[:8])}")
    return "\n".join(lines).strip()


def _normalize_severity(s: Any) -> str | None:
    if isinstance(s, str) and s.strip():
        return s.strip().lower()
    return None


def _vulnerability_from_dict(v: dict[str, Any], software_query: str) -> VulnHit | None:
    cve = v.get("cve_id")
    if not isinstance(cve, str) or not cve.strip():
        blob = json.dumps(v, ensure_ascii=False)
        m = CVE_RE.search(blob)
        if not m:
            return None
        cve = m.group(0).upper()
    else:
        cve = cve.strip().upper()

    title = v.get("name")
    if not isinstance(title, str) or not title.strip():
        desc = v.get("description")
        title = desc[:300] if isinstance(desc, str) else None

    sev = _normalize_severity(v.get("severity"))
    block = format_vulnerability_block(v, software_query)
    return VulnHit(cve_id=cve, title=title.strip() if isinstance(title, str) else None, severity=sev, summary=block, detail=v)


def parse_vulnx_json(stdout: str, software_query: str = "") -> list[VulnHit]:
    raw = (stdout or "").strip()
    if not raw:
        return []

    data: Any
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return _legacy_parse(stdout, software_query)

    if isinstance(data, dict) and isinstance(data.get("results"), list):
        out: list[VulnHit] = []
        seen: set[str] = set()
        for item in data["results"]:
            if not isinstance(item, dict):
                continue
            hit = _vulnerability_from_dict(item, software_query)
            if hit is None or hit.cve_id in seen:
                continue
            seen.add(hit.cve_id)
            out.append(hit)
        if out:
            return out

    if isinstance(data, list):
        out = []
        seen = set()
        for item in data:
            if isinstance(item, dict):
                hit = _vulnerability_from_dict(item, software_query)
                if hit and hit.cve_id not in seen:
                    seen.add(hit.cve_id)
                    out.append(hit)
        if out:
            return out

    return _legacy_parse(stdout, software_query)


def _legacy_parse(stdout: str, software_query: str) -> list[VulnHit]:
    seen: set[str] = set()
    out: list[VulnHit] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            blob = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(blob, dict) and "results" in blob and isinstance(blob["results"], list):
            for item in blob["results"]:
                if isinstance(item, dict):
                    hit = _vulnerability_from_dict(item, software_query)
                    if hit and hit.cve_id not in seen:
                        seen.add(hit.cve_id)
                        out.append(hit)
        elif isinstance(blob, dict):
            hit = _vulnerability_from_dict(blob, software_query)
            if hit and hit.cve_id not in seen:
                seen.add(hit.cve_id)
                out.append(hit)
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

    hits = parse_vulnx_json(proc.stdout or "", software_query=software)
    return hits, (err if err else None)


def run_cli_software_file(input_path: Path, vuln_age_days: int = 190) -> int:
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
            print(h.summary)
            print()
        print("═" * 60 + "\n")
    return 0


if __name__ == "__main__":
    p = Path(os.environ.get("VULNX_SOFTWARE_FILE", "software.txt"))
    age = int(os.environ.get("VULNX_VULN_AGE_DAYS", "190"))
    raise SystemExit(run_cli_software_file(p, age))
