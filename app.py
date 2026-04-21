#!/usr/bin/env python3
"""CLI-обёртка над тем же движком, что и веб-интерфейс: построчный `vulnx search` по файлу ПО."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from vulnx_scanner import run_cli_software_file


def main() -> int:
    path = Path(os.environ.get("VULNX_SOFTWARE_FILE", "software.txt"))
    age = int(os.environ.get("VULNX_VULN_AGE_DAYS", "190"))
    return run_cli_software_file(path, age)


if __name__ == "__main__":
    raise SystemExit(main())
