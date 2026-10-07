# Third-party notices

Forensic Server Analyzer creates a local Python virtual environment on first run and may install the packages listed in `_system/requirements.txt`. These packages are independent third-party software and remain under their own licenses.

## Runtime dependencies

| Component | Purpose | License / licensing model |
|---|---|---|
| PySide6 / Qt for Python | GUI / Qt bindings | Qt open-source distribution: GNU LGPL v3 and/or GNU GPL v3 depending on component; commercial Qt licensing is also available |
| Shiboken6 / PySide6_Essentials / PySide6_Addons | Dependencies installed with PySide6 | Qt for Python / Qt licensing applies to the respective components |
| lz4 | LZ4 journal decompression | BSD 3-Clause |
| zstandard | Zstandard journal decompression | BSD 3-Clause |
| ReportLab | PDF report generation | BSD License |

## Optional build dependency

| Component | Purpose | License |
|---|---|---|
| PyInstaller | Optional creation of a portable Windows build | GPL-2.0-or-later with PyInstaller's special exception for generated bundles; some files are Apache-2.0 |

The standard source ZIP does **not** bundle these third-party Python packages. They are installed locally by `pip` when required. The exact copyright notices and license files supplied by the installed package versions remain authoritative and are included in/alongside those installed distributions where provided by their authors.

Qt/LGPL text is additionally provided under `_system/licenses/LGPL-3.0.txt` for convenience. This notice does not replace the license files distributed by the respective third-party projects.

Project source: https://github.com/gl1tchb1rd/server_analyzer
