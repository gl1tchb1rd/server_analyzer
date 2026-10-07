@echo off
setlocal EnableExtensions
cd /d "%~dp0"

echo ============================================================
echo Forensic Server Analyzer - Windows Portable Build
echo ============================================================
echo.

set "PYTHON=..\_runtime\venv\Scripts\python.exe"
if not exist "%PYTHON%" (
    echo Bitte zuerst ..\Forensic_Server_Analyzer.py starten, damit die lokale Umgebung eingerichtet wird.
    pause
    exit /b 1
)

echo Installiere Build-Abhaengigkeiten ...
"%PYTHON%" -m pip install --disable-pip-version-check -r requirements-build.txt
if errorlevel 1 goto :error

echo.
echo Erzeuge portable Programmmappe ...
"%PYTHON%" -m PyInstaller ^
  --noconfirm ^
  --clean ^
  --windowed ^
  --onedir ^
  --name Forensic_Server_Analyzer ^
  --distpath "..\Portable_Build" ^
  --workpath "..\_runtime\pyinstaller_build" ^
  --specpath "..\_runtime" ^
  --hidden-import=lz4.block ^
  --hidden-import=zstandard ^
  --collect-all=reportlab ^
  app.py
if errorlevel 1 goto :error

echo.
echo Fertig: ..\Portable_Build\Forensic_Server_Analyzer\Forensic_Server_Analyzer.exe
echo Die gesamte erzeugte Mappe muss zusammenbleiben.
pause
exit /b 0

:error
echo.
echo FEHLER beim Erstellen der EXE.
pause
exit /b 1
