#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Gl1tchb1rd

from __future__ import annotations

import hashlib
import os
import platform
import subprocess
import sys
import venv
from pathlib import Path

APP_NAME = "Server Analyzer"
APP_VERSION = "0.5.0"
ROOT = Path(__file__).resolve().parent
SYSTEM = ROOT / "_system"
RUNTIME = ROOT / "_runtime"
VENV = RUNTIME / "venv"
REQUIREMENTS = SYSTEM / "requirements.txt"
MARKER = RUNTIME / "requirements.sha256"


def _hide_windows(path: Path) -> None:
    if os.name == "nt" and path.exists():
        try:
            subprocess.run(["attrib", "+H", str(path)], check=False, capture_output=True)
        except OSError:
            pass


def _venv_python() -> Path:
    return VENV / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def _requirements_hash() -> str:
    return hashlib.sha256(REQUIREMENTS.read_bytes()).hexdigest()


def _ensure_runtime() -> Path:
    RUNTIME.mkdir(exist_ok=True)
    _hide_windows(SYSTEM)
    _hide_windows(RUNTIME)

    python = _venv_python()
    if not python.exists():
        print(f"[{APP_NAME}] Richte lokale Python-Umgebung ein …")
        venv.EnvBuilder(with_pip=True, clear=False).create(VENV)

    wanted = _requirements_hash()
    current = MARKER.read_text(encoding="ascii").strip() if MARKER.exists() else ""
    if current != wanted:
        print(f"[{APP_NAME}] Prüfe/installiere benötigte Abhängigkeiten …")
        subprocess.check_call([str(python), "-m", "pip", "install", "--upgrade", "pip"])
        subprocess.check_call([str(python), "-m", "pip", "install", "-r", str(REQUIREMENTS)])
        MARKER.write_text(wanted + "\n", encoding="ascii")
    return python


def main() -> int:
    if platform.system() != "Windows":
        print(
            f"{APP_NAME} {APP_VERSION} ist derzeit ausschließlich für Windows 10/11 freigegeben.\n"
            "Linux- und macOS-Unterstützung ist für eine spätere Hauptversion vorgesehen."
        )
        return 2
    if sys.version_info < (3, 11):
        print(f"{APP_NAME} benötigt Python 3.11 oder neuer.")
        return 2
    if not (SYSTEM / "app.py").is_file():
        print("Die Programmdaten unter _system fehlen oder sind unvollständig.")
        return 3

    try:
        python = _ensure_runtime()
    except Exception as exc:
        print(f"Abhängigkeiten konnten nicht eingerichtet werden: {exc}")
        return 4

    return subprocess.call([str(python), str(SYSTEM / "app.py")], cwd=str(ROOT))


if __name__ == "__main__":
    raise SystemExit(main())
