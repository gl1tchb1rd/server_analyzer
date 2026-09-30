# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Gl1tchb1rd

from __future__ import annotations

import json
import sys
import traceback
from dataclasses import asdict
from datetime import datetime, timezone
from importlib import metadata as importlib_metadata
from pathlib import Path

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSplitter,
    QStatusBar,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from analyzer_core import analyze_root
from report_export import export_pdf

APP_NAME = "Server Analyzer"
APP_VERSION = "0.5.0"
PROJECT_URL = "https://github.com/gl1tchb1rd/server_analyzer"


class AnalysisWorker(QThread):
    status = Signal(str)
    completed = Signal(dict)
    failed = Signal(str)

    def __init__(self, root: Path):
        super().__init__()
        self.root = root

    def run(self) -> None:
        try:
            result = analyze_root(self.root, self.status.emit)
        except Exception:
            self.failed.emit(traceback.format_exc())
        else:
            self.completed.emit(result)




class DictTable(QTableWidget):
    def __init__(self, columns: list[tuple[str, str]], parent=None):
        super().__init__(parent)
        self.columns = columns
        self.setColumnCount(len(columns))
        self.setHorizontalHeaderLabels([label for _, label in columns])
        self.setSortingEnabled(True)
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.verticalHeader().setVisible(False)

    @staticmethod
    def _format(value):
        if isinstance(value, list):
            return ", ".join(str(x) for x in value)
        if isinstance(value, bool):
            return "ja" if value else "nein"
        if value is None:
            return ""
        return str(value)

    def load(self, rows: list[dict]) -> None:
        self.setSortingEnabled(False)
        self.setRowCount(len(rows))
        for r, row in enumerate(rows):
            for c, (key, _label) in enumerate(self.columns):
                item = QTableWidgetItem(self._format(row.get(key, "")))
                item.setData(Qt.ItemDataRole.UserRole, row)
                self.setItem(r, c, item)
        self.resizeColumnsToContents()
        self.setSortingEnabled(True)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} {APP_VERSION}")
        self.resize(1500, 900)
        self.result: dict | None = None
        self.worker: AnalysisWorker | None = None
        self._build_menu()
        self._build_ui()

    def _build_menu(self) -> None:
        file_menu = self.menuBar().addMenu("Datei")
        open_action = QAction("Linux-Root / extrahiertes Serverimage öffnen …", self)
        open_action.triggered.connect(self.choose_root)
        file_menu.addAction(open_action)
        self.pdf_action = QAction("Ermittlungsbericht als PDF exportieren …", self)
        self.pdf_action.setEnabled(False)
        self.pdf_action.triggered.connect(self.export_pdf_dialog)
        file_menu.addAction(self.pdf_action)
        self.json_action = QAction("Auswertung als JSON exportieren …", self)
        self.json_action.setEnabled(False)
        self.json_action.triggered.connect(self.export_json_dialog)
        file_menu.addAction(self.json_action)
        file_menu.addSeparator()
        quit_action = QAction("Beenden", self)
        quit_action.triggered.connect(self.close)
        file_menu.addAction(quit_action)

        help_menu = self.menuBar().addMenu("Hilfe")
        about_action = QAction("Über & Lizenzen …", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)

    def _build_ui(self) -> None:
        central = QWidget()
        outer = QVBoxLayout(central)
        top = QHBoxLayout()
        self.root_label = QLabel("Noch keine Quelle ausgewählt")
        self.open_button = QPushButton("Server-Root auswählen …")
        self.open_button.clicked.connect(self.choose_root)
        top.addWidget(self.root_label, 1)
        top.addWidget(self.open_button)
        outer.addLayout(top)

        self.tabs = QTabWidget()
        outer.addWidget(self.tabs, 1)
        self.overview = QTextBrowser()
        self.tabs.addTab(self.overview, "Übersicht")

        self.ssh_table = DictTable([("timestamp", "Zeit (UTC)"), ("user", "Benutzer"), ("ip", "Quell-IP"), ("method", "Authentifizierung"), ("source", "Quelle")])
        self.tabs.addTab(self.ssh_table, "Betreiber / SSH")

        admin_page = QWidget(); admin_layout = QVBoxLayout(admin_page)
        self.admin_prioritized = QCheckBox("Nur priorisierte Treffer anzeigen")
        self.admin_prioritized.setChecked(True)
        self.admin_prioritized.toggled.connect(self._reload_admin)
        admin_layout.addWidget(self.admin_prioritized)
        self.admin_table = DictTable([("timestamp", "Zeit"), ("ip", "IP"), ("application", "Anwendung"), ("method", "Methode"), ("path", "Pfad"), ("status", "HTTP"), ("assessment", "Bewertung"), ("ssh_correlated", "SSH-IP"), ("source", "Quelle")])
        admin_layout.addWidget(self.admin_table, 1)
        self.tabs.addTab(admin_page, "Admin-Zugriffe")

        self.website_table = DictTable([("domain", "Domain"), ("aliases", "Aliase"), ("server", "Server"), ("status", "Status"), ("urls", "URLs"), ("document_root", "DocumentRoot"), ("proxy_pass", "Reverse Proxy"), ("application", "Anwendung"), ("source", "Quelle")])
        self.tabs.addTab(self.website_table, "Webseiten")

        mail_tabs = QTabWidget()
        self.mail_accounts = DictTable([("address", "Adresse"), ("assessment", "Bewertung"), ("evidence", "Nachweise"), ("mailbox_path", "Mailbox"), ("forwarding", "Weiterleitung(en)"), ("source", "Quelle")])
        self.mail_access = DictTable([("timestamp", "Zeit"), ("protocol", "Protokoll"), ("user", "Benutzer"), ("ip", "IP"), ("result", "Ergebnis"), ("ssh_correlated", "SSH-IP"), ("source", "Quelle")])
        self.mail_diag = QTextBrowser()
        mail_tabs.addTab(self.mail_accounts, "Konten / Adressen")
        mail_tabs.addTab(self.mail_access, "Authentifizierte Zugriffe")
        mail_tabs.addTab(self.mail_diag, "Diagnose")
        self.tabs.addTab(mail_tabs, "Mail")

        self.services_table = DictTable([("service", "Dienst"), ("state", "Status"), ("evidence", "Bewertung"), ("source", "Quelle/Nachweis"), ("details", "Details")])
        self.tabs.addTab(self.services_table, "Dienste")

        self.tls_table = DictTable([("domains", "Domains / SAN"), ("not_before", "Gültig ab"), ("not_after", "Gültig bis"), ("issuer", "Aussteller"), ("source", "Quelle")])
        self.tabs.addTab(self.tls_table, "TLS / Zertifikate")

        self.artifact_table = DictTable([("kind", "Art"), ("identity", "Identität"), ("value", "Wert"), ("assessment", "Bewertung"), ("source", "Quelle")])
        self.tabs.addTab(self.artifact_table, "Artefakte")

        self.ip_table = DictTable([("ip", "IP"), ("ssh", "SSH"), ("admin", "Admin-Web"), ("imap_pop", "IMAP/POP"), ("smtp_auth", "SMTP AUTH"), ("first", "Erstes Auftreten"), ("last", "Letztes Auftreten")])
        self.tabs.addTab(self.ip_table, "IP-Korrelation")

        journal_page = QWidget(); journal_layout = QVBoxLayout(journal_page)
        self.journal_filter = QLineEdit(); self.journal_filter.setPlaceholderText("Journal-Tabelle filtern …")
        self.journal_filter.textChanged.connect(self._filter_journal)
        journal_layout.addWidget(self.journal_filter)
        splitter = QSplitter(Qt.Orientation.Vertical)
        self.journal_table = DictTable([("__DATETIME_UTC", "Zeit (UTC)"), ("_HOSTNAME", "Host"), ("_SYSTEMD_UNIT", "Unit"), ("_PID", "PID"), ("MESSAGE", "Nachricht"), ("__SOURCE_FILE", "Quelle")])
        self.journal_table.itemSelectionChanged.connect(self._journal_detail)
        self.journal_detail = QTextBrowser()
        splitter.addWidget(self.journal_table); splitter.addWidget(self.journal_detail); splitter.setSizes([600, 250])
        journal_layout.addWidget(splitter, 1)
        self.tabs.addTab(journal_page, "Journal")

        self.diagnostics = QTextBrowser()
        self.tabs.addTab(self.diagnostics, "Diagnose / Hinweise")

        self.progress = QProgressBar(); self.progress.setRange(0, 0); self.progress.hide()
        outer.addWidget(self.progress)
        self.setCentralWidget(central)
        self.setStatusBar(QStatusBar())
        self.overview.setHtml("<h2>Server Analyzer</h2><p>Wähle ein extrahiertes oder von einem Forensiktool bereitgestelltes Linux-Root-Dateisystem aus.</p>")

    def choose_root(self) -> None:
        folder = QFileDialog.getExistingDirectory(self, "Linux-Root auswählen")
        if not folder:
            return
        root = Path(folder)
        self.root_label.setText(str(root))
        self.open_button.setEnabled(False)
        self.pdf_action.setEnabled(False); self.json_action.setEnabled(False)
        self.progress.show(); self.statusBar().showMessage("Auswertung läuft …")
        self.worker = AnalysisWorker(root)
        self.worker.status.connect(self.statusBar().showMessage)
        self.worker.completed.connect(self._analysis_done)
        self.worker.failed.connect(self._analysis_failed)
        self.worker.start()

    def _analysis_done(self, result: dict) -> None:
        self.result = result
        self.progress.hide(); self.open_button.setEnabled(True)
        self.pdf_action.setEnabled(True); self.json_action.setEnabled(True)
        self.statusBar().showMessage("Auswertung abgeschlossen", 6000)
        self._populate()

    def _analysis_failed(self, detail: str) -> None:
        self.progress.hide(); self.open_button.setEnabled(True)
        self.statusBar().showMessage("Auswertung fehlgeschlagen")
        QMessageBox.critical(self, "Auswertung fehlgeschlagen", detail)

    def _populate(self) -> None:
        if not self.result:
            return
        r = self.result; s = r["summary"]
        warnings = "".join(f"<li>{w}</li>" for w in r.get("warnings", []))
        self.overview.setHtml(
            f"<h2>{APP_NAME} – Auswertung</h2><p><b>Quelle:</b> {r['root']}</p>"
            f"<table cellspacing='6'>"
            f"<tr><td>Journal-Dateien</td><td><b>{s['journal_files']}</b></td></tr>"
            f"<tr><td>Journal-Ereignisse</td><td><b>{s['journal_events']}</b></td></tr>"
            f"<tr><td>Erfolgreiche SSH-Anmeldungen</td><td><b>{s['ssh_success']}</b></td></tr>"
            f"<tr><td>Websites/VHosts</td><td><b>{s['websites']}</b></td></tr>"
            f"<tr><td>Admin-Webzugriffe</td><td><b>{s['admin_access']}</b></td></tr>"
            f"<tr><td>Mailkonten/-adressen</td><td><b>{s['mail_accounts']}</b></td></tr>"
            f"<tr><td>Authentifizierte Mailzugriffe</td><td><b>{s['mail_access']}</b></td></tr>"
            f"<tr><td>Dienste</td><td><b>{s['services']}</b></td></tr>"
            f"</table>" + (f"<h3>Hinweise</h3><ul>{warnings}</ul>" if warnings else "")
        )
        self.ssh_table.load(r["ssh"])
        self._reload_admin()
        self.website_table.load(r["websites"])
        self.mail_accounts.load(r["mail"]["accounts"])
        self.mail_access.load(r["mail"]["accesses"])
        self.mail_diag.setPlainText(json.dumps(r["mail"]["diagnostics"], indent=2, ensure_ascii=False))
        self.services_table.load(r["services"])
        self.tls_table.load(r["tls"])
        self.artifact_table.load(r["artifacts"])
        self.ip_table.load(r["ip_summary"])
        self.journal_table.load(r["journal_events"])
        self.diagnostics.setPlainText(json.dumps({"nginx": r["diagnostics"]["nginx"], "journals": r["journal_meta"], "warnings": r["warnings"]}, indent=2, ensure_ascii=False))

    def _reload_admin(self) -> None:
        if not self.result:
            return
        rows = self.result["admin_access"]
        if self.admin_prioritized.isChecked():
            rows = [x for x in rows if x.get("ssh_correlated") or x.get("assessment") in {"Starker Hinweis auf erfolgreiche Anmeldung", "Zugriff auf geschützten/Adminbereich", "Login-POST akzeptiert/weitergeleitet"}]
        self.admin_table.load(rows)

    def _filter_journal(self, text: str) -> None:
        needle = text.casefold().strip()
        for row in range(self.journal_table.rowCount()):
            visible = not needle or any(needle in (self.journal_table.item(row, c).text().casefold() if self.journal_table.item(row, c) else "") for c in range(self.journal_table.columnCount()))
            self.journal_table.setRowHidden(row, not visible)

    def _journal_detail(self) -> None:
        items = self.journal_table.selectedItems()
        if not items:
            self.journal_detail.clear(); return
        row = items[0].data(Qt.ItemDataRole.UserRole) or {}
        self.journal_detail.setPlainText("\n".join(f"{k}={v}" for k, v in sorted(row.items())))

    def export_pdf_dialog(self) -> None:
        if not self.result:
            return
        filename, _ = QFileDialog.getSaveFileName(self, "PDF-Bericht speichern", "Server_Analyzer_Auswertungsbericht.pdf", "PDF (*.pdf)")
        if not filename:
            return
        try:
            export_pdf(Path(filename), self.result)
        except Exception as exc:
            QMessageBox.critical(self, "PDF-Export", f"PDF konnte nicht erstellt werden:\n{exc}")
        else:
            QMessageBox.information(self, "PDF-Export", "Der Auswertungsbericht wurde erstellt.")

    def export_json_dialog(self) -> None:
        if not self.result:
            return
        filename, _ = QFileDialog.getSaveFileName(self, "JSON-Auswertung speichern", "Server_Analyzer_Auswertung.json", "JSON (*.json)")
        if not filename:
            return
        Path(filename).write_text(json.dumps(self.result, indent=2, ensure_ascii=False), encoding="utf-8")

    def show_about(self) -> None:
        def version(name: str) -> str:
            try:
                return importlib_metadata.version(name)
            except Exception:
                return "nicht installiert"

        dialog = QDialog(self); dialog.setWindowTitle(f"Über & Lizenzen – {APP_NAME}"); dialog.resize(900, 700)
        layout = QVBoxLayout(dialog); tabs = QTabWidget(); layout.addWidget(tabs, 1)
        about = QTextBrowser(); about.setOpenExternalLinks(True)
        about.setHtml(
            f"<h2>{APP_NAME}</h2><p><b>Version {APP_VERSION}</b></p>"
            "<p>Windows-basierter, read-only Auswertungsassistent für extrahierte Linux-Server-Beweismittel.</p>"
            f"<p><b>Projektquelle:</b> <a href='{PROJECT_URL}'>{PROJECT_URL}</a></p>"
            "<p><b>Herausgeber / Repository:</b> Gl1tchb1rd</p><p><b>Lizenz:</b> GNU GPL-3.0-or-later</p>"
        ); tabs.addTab(about, "Über")
        disclaimer = QTextBrowser(); disclaimer.setHtml(
            "<h2>Wichtiger Disclaimer / Nutzungshinweis</h2>"
            "<p><b>Server Analyzer dient ausschließlich der Ermittlungs- und Auswertungsunterstützung.</b></p>"
            "<p>Automatisch erkannte, zusammengeführte oder abgeleitete Daten und Bewertungen können aufgrund unvollständiger Beweismittel, fehlender oder rotierter Logs, ungewöhnlicher Serverkonfigurationen, fehlerhafter Zeitstempel oder Parsergrenzen <b>unvollständig, fehlerhaft oder veraltet</b> sein.</p>"
            "<p>Wesentliche Feststellungen sind anhand der ausgewiesenen Quelldateien und Originaldaten unabhängig zu prüfen. Eine technische Korrelation, etwa einer IP-Adresse mit mehreren Diensten, stellt für sich allein keine sichere personenbezogene Zuordnung dar.</p>"
            "<p><b>Die sachliche Bewertung, Verifikation und Dokumentation der Ergebnisse sowie die Prüfung der rechtlichen Zulässigkeit sämtlicher daraus resultierender Ermittlungs-, Sicherungs-, Auskunfts- oder sonstiger Maßnahmen liegen stets beim Nutzer bzw. bei der nutzenden Stelle.</b></p>"
            "<p>Die Software ersetzt weder eine eigenständige forensische Bewertung noch die erforderliche rechtliche Prüfung und begründet keinerlei Eingriffs- oder Ermittlungsbefugnis.</p>"
        ); tabs.addTab(disclaimer, "Disclaimer")
        gpl = QTextBrowser(); gpl.setHtml("<h2>Projektlizenz</h2><p><b>Copyright © 2026 Gl1tchb1rd</b></p><p>Server Analyzer wird unter GNU GPL Version 3 oder jeder späteren Version (GPL-3.0-or-later) veröffentlicht. Der vollständige Text befindet sich in <code>LICENSE</code>.</p>"); tabs.addTab(gpl, "GPL")
        third = QTextBrowser(); third.setOpenExternalLinks(True); third.setHtml(
            "<h2>Nachgeladene Drittanbieter-Software</h2><p>Beim ersten Start installiert der Starter Open-Source-Abhängigkeiten in die lokale <code>_runtime</code>-Umgebung. Diese unterliegen ihren eigenen Lizenzen.</p>"
            "<table border='1' cellspacing='0' cellpadding='5'>"
            f"<tr><th>Komponente</th><th>Version</th><th>Lizenzfamilie</th></tr>"
            f"<tr><td>PySide6</td><td>{version('PySide6')}</td><td>LGPL/GPL (Qt Community)</td></tr>"
            f"<tr><td>Shiboken6</td><td>{version('shiboken6')}</td><td>Qt for Python</td></tr>"
            f"<tr><td>lz4</td><td>{version('lz4')}</td><td>BSD-3-Clause</td></tr>"
            f"<tr><td>zstandard</td><td>{version('zstandard')}</td><td>BSD-3-Clause</td></tr>"
            f"<tr><td>ReportLab</td><td>{version('reportlab')}</td><td>BSD</td></tr>"
            f"<tr><td>cryptography</td><td>{version('cryptography')}</td><td>Apache-2.0 OR BSD-3-Clause</td></tr>"
            "</table><p>Details: <code>THIRD_PARTY_NOTICES.md</code>.</p>"
        ); tabs.addTab(third, "Drittanbieter")
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close); buttons.rejected.connect(dialog.reject); buttons.clicked.connect(dialog.accept); layout.addWidget(buttons)
        dialog.exec()


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME); app.setApplicationVersion(APP_VERSION)
    window = MainWindow(); window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
