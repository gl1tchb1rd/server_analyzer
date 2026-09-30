# Third-Party Notices

Server Analyzer ist selbst unter **GNU GPL-3.0-or-later** veröffentlicht.

Beim ersten Start kann der Starter die folgenden Open-Source-Pakete über `pip` in eine lokale `_runtime`-Umgebung nachladen. Diese Pakete sind **nicht Bestandteil des eigenen Server-Analyzer-Codes** und unterliegen ihren jeweiligen eigenen Lizenzbedingungen. Maßgeblich sind stets die Lizenz- und Copyrightdateien der konkret installierten Version.

| Komponente | Zweck | Lizenz |
|---|---|---|
| PySide6 / Qt for Python | Grafische Oberfläche | Qt Community: insbesondere LGPL-3.0/GPL-2.0/GPL-3.0; alternativ kommerzielle Qt-Lizenz |
| Shiboken6 / PySide6 Essentials/Addons | PySide6-Laufzeitkomponenten | Qt-for-Python-/Qt-Lizenzbedingungen |
| lz4 | Dekompression LZ4-komprimierter Journal-Daten | BSD-3-Clause |
| zstandard | Dekompression ZSTD-komprimierter Journal-Daten | BSD-3-Clause |
| ReportLab | PDF-Auswertungsberichte | BSD-Lizenz |
| cryptography | X.509-/TLS-Zertifikatsanalyse | Apache-2.0 OR BSD-3-Clause |

Offizielle Lizenzinformationen:

- Qt for Python / PySide6: https://doc.qt.io/qtforpython-6/
- Qt for Python – Third-party licenses: https://doc.qt.io/qtforpython-6/licenses.html
- lz4: https://pypi.org/project/lz4/
- zstandard: https://pypi.org/project/zstandard/
- ReportLab: https://docs.reportlab.com/developerfaqs/
- cryptography: https://pypi.org/project/cryptography/

## systemd Journal-Dateiformat

Der native Windows-Journalparser implementiert das öffentlich dokumentierte binäre systemd-Journalformat eigenständig. systemd-Code oder `libsystemd` werden nicht mitgeliefert oder gelinkt. Die Formatdokumentation von systemd steht unter LGPL-2.1-or-later; systemd selbst ist nicht Bestandteil dieser Distribution.

## Nachgeladene Pakete

Die Standarddistribution dieses Projekts enthält keine Kopie der oben genannten Python-Pakete. Der Starter installiert sie – sofern erforderlich und zulässig – aus der konfigurierten `pip`-Paketquelle in die lokale `_runtime`-Umgebung.

## Offline-Wheels / Binärdistribution

Werden später Wheels, Qt-Bibliotheken oder eine portable/gebündelte Binärdistribution zusammen mit Server Analyzer weitergegeben, müssen zusätzlich die für **genau diese mitgelieferten Versionen** geltenden Lizenztexte, Copyright- und Notice-Dateien der jeweiligen Pakete mit der Distribution erhalten bleiben.

Diese Datei ist eine technische Lizenzübersicht und keine Rechtsberatung.
