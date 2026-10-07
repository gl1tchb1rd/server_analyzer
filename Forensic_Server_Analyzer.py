#!/usr/bin/env python3
"""Forensic Server Analyzer - Windows bootstrap / starter.

The starter intentionally uses only the Python standard library. On first run it
creates a local virtual environment, installs/repairs dependencies and starts the
GUI from the technical _system directory.
"""
from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import traceback
import venv
from pathlib import Path

APP_NAME = "Forensic Server Analyzer"
MIN_PYTHON = (3, 11)
ROOT = Path(__file__).resolve().parent
SYSTEM_DIR = ROOT / "_system"
RUNTIME_DIR = ROOT / "_runtime"
VENV_DIR = RUNTIME_DIR / "venv"
REQUIREMENTS = SYSTEM_DIR / "requirements.txt"
WHEELS_DIR = SYSTEM_DIR / "wheels"
APP_SCRIPT = SYSTEM_DIR / "app.py"
STAMP_FILE = RUNTIME_DIR / "requirements.sha256"


def _message(title: str, message: str, error: bool = False) -> None:
    """Show a native dialog when possible; fall back to console output."""
    try:
        import tkinter as tk
        from tkinter import messagebox

        root = tk.Tk()
        root.withdraw()
        if error:
            messagebox.showerror(title, message)
        else:
            messagebox.showinfo(title, message)
        root.destroy()
    except Exception:
        print(f"{title}: {message}", file=sys.stderr if error else sys.stdout)


def _hide_technical_directories() -> None:
    if os.name != "nt":
        return
    for directory in (SYSTEM_DIR, RUNTIME_DIR):
        if directory.exists():
            try:
                subprocess.run(
                    ["attrib", "+H", str(directory)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
            except OSError:
                pass


def _venv_python() -> Path:
    if os.name == "nt":
        return VENV_DIR / "Scripts" / "python.exe"
    return VENV_DIR / "bin" / "python"


def _venv_pythonw() -> Path:
    if os.name == "nt":
        candidate = VENV_DIR / "Scripts" / "pythonw.exe"
        if candidate.exists():
            return candidate
    return _venv_python()


def _requirements_signature() -> str:
    h = hashlib.sha256()
    h.update(REQUIREMENTS.read_bytes())
    h.update(f"python={sys.version_info.major}.{sys.version_info.minor}".encode("ascii"))
    h.update(b"bootstrap=0.6.0")
    return h.hexdigest()


def _environment_healthy(python_exe: Path) -> bool:
    if not python_exe.exists():
        return False
    code = "import PySide6, lz4, zstandard, reportlab; print('ok')"
    try:
        proc = subprocess.run(
            [str(python_exe), "-c", code],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
            check=False,
        )
        return proc.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _install_requirements(python_exe: Path) -> None:
    print(f"[{APP_NAME}] Prüfe/Installiere benötigte Python-Pakete …")
    base_cmd = [
        str(python_exe), "-m", "pip", "install", "--disable-pip-version-check",
        "--prefer-binary", "-r", str(REQUIREMENTS),
    ]

    wheels = list(WHEELS_DIR.glob("*.whl")) if WHEELS_DIR.is_dir() else []
    if wheels:
        # First try completely offline. If the wheel folder is incomplete, fall
        # back to the configured pip source below.
        offline = base_cmd[:4] + ["--no-index", "--find-links", str(WHEELS_DIR)] + base_cmd[4:]
        proc = subprocess.run(offline, cwd=str(ROOT), check=False)
        if proc.returncode == 0:
            return
        print("Lokaler Wheel-Bestand ist nicht vollständig; versuche konfigurierte pip-Paketquelle …")

    cmd = base_cmd[:4] + ["--find-links", str(WHEELS_DIR)] + base_cmd[4:] if WHEELS_DIR.is_dir() else base_cmd
    subprocess.run(cmd, cwd=str(ROOT), check=True)


def _ensure_environment() -> Path:
    if not REQUIREMENTS.is_file() or not APP_SCRIPT.is_file():
        raise RuntimeError("Technische Programmdateien fehlen. Bitte das ZIP vollständig neu entpacken.")

    RUNTIME_DIR.mkdir(exist_ok=True)
    python_exe = _venv_python()
    signature = _requirements_signature()
    current_stamp = ""
    try:
        current_stamp = STAMP_FILE.read_text(encoding="ascii").strip()
    except OSError:
        pass

    needs_setup = current_stamp != signature or not _environment_healthy(python_exe)
    if needs_setup:
        if not python_exe.exists():
            print(f"[{APP_NAME}] Erster Start: lokale Python-Umgebung wird eingerichtet …")
            builder = venv.EnvBuilder(with_pip=True, clear=False, system_site_packages=True)
            builder.create(VENV_DIR)
            python_exe = _venv_python()
        _install_requirements(python_exe)
        if not _environment_healthy(python_exe):
            raise RuntimeError("Die benötigten Python-Abhängigkeiten konnten nicht vollständig eingerichtet werden.")
        STAMP_FILE.write_text(signature, encoding="ascii")

    _hide_technical_directories()
    return _venv_pythonw()


def main() -> int:
    if sys.version_info < MIN_PYTHON:
        _message(
            APP_NAME,
            f"Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]} oder neuer wird benötigt. "
            f"Gefunden wurde Python {sys.version_info.major}.{sys.version_info.minor}.",
            error=True,
        )
        return 2

    try:
        gui_python = _ensure_environment()
        env = os.environ.copy()
        env["PYTHONUTF8"] = "1"
        kwargs: dict[str, object] = {"cwd": str(ROOT), "env": env}
        if os.name == "nt":
            kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        subprocess.Popen([str(gui_python), str(APP_SCRIPT)], **kwargs)
        return 0
    except Exception as exc:
        details = "".join(traceback.format_exception_only(type(exc), exc)).strip()
        _message(
            APP_NAME,
            "Der Start bzw. die automatische Einrichtung ist fehlgeschlagen.\n\n"
            f"{details}\n\n"
            "Hinweis: Für den ersten Start wird eine freigegebene pip-Paketquelle oder ein vollständiger "
            "Offline-Wheel-Bestand unter _system\\wheels benötigt.",
            error=True,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
