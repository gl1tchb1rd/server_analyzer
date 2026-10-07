#!/usr/bin/env python3
from __future__ import annotations

import csv
import hashlib
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from journal_native import JournalParseError, parse_journal_file
from server_forensics import ServerScanResult, detect_linux_root, scan_server_root
from report_export import export_forensic_pdf

from PySide6.QtCore import (
    QAbstractTableModel,
    QModelIndex,
    QObject,
    QSortFilterProxyModel,
    Qt,
    QThread,
    Signal,
)
from PySide6.QtGui import QAction, QFont
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSplitter,
    QStatusBar,
    QTabWidget,
    QTableView,
    QVBoxLayout,
    QWidget,
)

APP_NAME = "Forensic Server Analyzer"
APP_VERSION = "0.6.0"
JOURNAL_SUFFIXES = (".journal", ".journal~")

IP_CANDIDATE_RE = re.compile(
    r"(?<![\w:])(?:"
    r"(?:\d{1,3}\.){3}\d{1,3}"
    r"|"
    r"(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}"
    r")(?![\w:])"
)

SSH_SUCCESS_PATTERNS = (
    re.compile(r"Accepted\s+(?P<method>\S+)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)", re.I),
    re.compile(r"session opened for user\s+(?P<user>\S+)", re.I),
)
SSH_FAIL_PATTERNS = (
    re.compile(r"Failed\s+\S+\s+for(?: invalid user)?\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)", re.I),
    re.compile(r"Invalid user\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)", re.I),
    re.compile(r"authentication failure", re.I),
)
SSH_CLOSE_PATTERNS = (
    re.compile(r"Disconnected from(?: user)?\s*(?P<user>\S+)?\s*(?P<ip>[0-9a-fA-F:.]+)?", re.I),
    re.compile(r"Connection closed by(?: authenticating user)?\s*(?P<user>\S+)?\s*(?P<ip>[0-9a-fA-F:.]+)?", re.I),
    re.compile(r"session closed for user\s+(?P<user>\S+)", re.I),
)


def human_size(num: int) -> str:
    size = float(num)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if size < 1024 or unit == "TiB":
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024
    return f"{num} B"


def safe_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def first_nonempty(record: dict[str, Any], keys: Iterable[str]) -> str:
    for key in keys:
        value = safe_text(record.get(key)).strip()
        if value:
            return value
    return ""


def realtime_to_iso(value: Any) -> str:
    try:
        micros = int(value)
        dt = datetime.fromtimestamp(micros / 1_000_000, tz=timezone.utc)
        return dt.isoformat(timespec="microseconds").replace("+00:00", "Z")
    except (TypeError, ValueError, OverflowError):
        return ""


def valid_ip(candidate: str) -> str | None:
    candidate = candidate.strip("[](),;<>\"'")
    # SSH log lines may contain IPv4:port; do not strip IPv6 colons.
    if candidate.count(":") == 1 and "." in candidate:
        host, maybe_port = candidate.rsplit(":", 1)
        if maybe_port.isdigit():
            candidate = host
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def extract_ips(text: str) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for raw in IP_CANDIDATE_RE.findall(text or ""):
        ip = valid_ip(raw)
        if ip and ip not in seen:
            found.append(ip)
            seen.add(ip)
    return found


def classify_record(raw: dict[str, Any]) -> str:
    message = safe_text(raw.get("MESSAGE"))
    ident = first_nonempty(raw, ("SYSLOG_IDENTIFIER", "_COMM", "_SYSTEMD_UNIT")).lower()
    unit = safe_text(raw.get("_SYSTEMD_UNIT")).lower()
    priority = safe_text(raw.get("PRIORITY"))

    if "sshd" in ident or unit.startswith("ssh") or unit.startswith("sshd"):
        return "SSH"
    if ident == "sudo" or unit.startswith("sudo") or "sudo:" in message.lower():
        return "sudo"
    if any(x in ident for x in ("nginx", "apache", "httpd", "php-fpm")) or any(
        x in unit for x in ("nginx", "apache", "httpd", "php")
    ):
        return "Webserver"
    if "docker" in ident or "containerd" in ident or "docker" in unit or "containerd" in unit:
        return "Container"
    if ident in ("kernel",) or safe_text(raw.get("_TRANSPORT")) == "kernel":
        return "Kernel"
    if priority.isdigit() and int(priority) <= 3:
        return "Fehler"
    if "error" in message.lower() or "failed" in message.lower() or "failure" in message.lower():
        return "Fehler"
    return "Sonstiges"


def normalized_event(raw: dict[str, Any], source_file: str) -> dict[str, Any]:
    message = safe_text(raw.get("MESSAGE"))
    event = {
        "time_utc": realtime_to_iso(raw.get("__REALTIME_TIMESTAMP")),
        "host": safe_text(raw.get("_HOSTNAME")),
        "service": first_nonempty(raw, ("SYSLOG_IDENTIFIER", "_COMM", "_SYSTEMD_UNIT")),
        "pid": first_nonempty(raw, ("_PID", "SYSLOG_PID")),
        "uid": safe_text(raw.get("_UID")),
        "unit": safe_text(raw.get("_SYSTEMD_UNIT")),
        "boot_id": safe_text(raw.get("_BOOT_ID")),
        "priority": safe_text(raw.get("PRIORITY")),
        "category": classify_record(raw),
        "message": message,
        "ips": extract_ips(message),
        "cursor": safe_text(raw.get("__CURSOR")),
        "source_file": source_file,
        "raw": raw,
    }
    return event


def classify_ssh(event: dict[str, Any]) -> dict[str, str] | None:
    if event.get("category") != "SSH":
        return None

    message = event.get("message", "")
    user = ""
    ip = ""
    method = ""
    event_type = "SSH-Ereignis"

    for pattern in SSH_SUCCESS_PATTERNS:
        match = pattern.search(message)
        if match:
            gd = match.groupdict()
            user = gd.get("user") or ""
            ip = valid_ip(gd.get("ip") or "") or ""
            method = gd.get("method") or ""
            event_type = "Anmeldung erfolgreich"
            break

    if event_type == "SSH-Ereignis":
        for pattern in SSH_FAIL_PATTERNS:
            match = pattern.search(message)
            if match:
                gd = match.groupdict()
                user = gd.get("user") or ""
                ip = valid_ip(gd.get("ip") or "") or ""
                event_type = "Anmeldung fehlgeschlagen"
                break

    if event_type == "SSH-Ereignis":
        for pattern in SSH_CLOSE_PATTERNS:
            match = pattern.search(message)
            if match:
                gd = match.groupdict()
                user = gd.get("user") or ""
                ip = valid_ip(gd.get("ip") or "") or ""
                event_type = "Verbindung beendet"
                break

    if not ip and event.get("ips"):
        ip = event["ips"][0]

    return {
        "time_utc": event.get("time_utc", ""),
        "type": event_type,
        "user": user,
        "ip": ip,
        "method": method,
        "host": event.get("host", ""),
        "message": message,
        "source_file": event.get("source_file", ""),
        "cursor": event.get("cursor", ""),
    }


@dataclass
class SourceFileInfo:
    path: str
    size: int
    mtime_utc: str
    sha256: str
    parse_status: str = "Ausstehend"
    parse_error: str = ""
    parser_engine: str = ""


class JournalLoader(QObject):
    progress = Signal(int, int, str)
    finished = Signal(object, object, object, object)
    failed = Signal(str)

    def __init__(self, source: str):
        super().__init__()
        self.source = source

    def run(self) -> None:
        try:
            source_path = Path(self.source)
            files = self.discover_files(source_path)
            linux_root = detect_linux_root(source_path)
            if not files and linux_root is None:
                raise RuntimeError("Keine .journal-Dateien gefunden und kein Linux-Root-Dateisystem erkannt.")

            events: list[dict[str, Any]] = []
            metadata: list[SourceFileInfo] = []
            warnings: list[str] = []
            total = len(files)
            journalctl = shutil.which("journalctl")
            force_native = os.environ.get("K25_NATIVE_PARSER", "").strip() == "1"
            use_native = force_native or os.name == "nt" or not journalctl

            for index, path in enumerate(files, start=1):
                self.progress.emit(index - 1, total, f"Hash: {path.name}")
                stat = path.stat()
                file_info = SourceFileInfo(
                    path=str(path),
                    size=stat.st_size,
                    mtime_utc=datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
                    .isoformat(timespec="seconds")
                    .replace("+00:00", "Z"),
                    sha256=self.sha256_file(path),
                )

                self.progress.emit(index - 1, total, f"Lese: {path.name}")
                parsed_count = 0
                parse_errors: list[str] = []

                if use_native:
                    file_info.parser_engine = "Nativer Parser (plattformunabhängig)"
                    try:
                        parsed = parse_journal_file(path)
                        for raw in parsed.entries:
                            events.append(normalized_event(raw, str(path)))
                            parsed_count += 1
                        if parsed.warnings:
                            parse_errors.extend(parsed.warnings[:20])
                            if len(parsed.warnings) > 20:
                                parse_errors.append(
                                    f"Weitere {len(parsed.warnings) - 20} Parserhinweise wurden zusammengefasst."
                                )
                    except (JournalParseError, OSError, ValueError) as exc:
                        parse_errors.append(str(exc))
                    except Exception as exc:
                        parse_errors.append(f"Unerwarteter Parserfehler: {exc}")
                else:
                    file_info.parser_engine = "systemd journalctl"
                    try:
                        proc = subprocess.Popen(
                            [
                                journalctl,
                                f"--file={path}",
                                "--output=json",
                                "--all",
                                "--no-pager",
                                "--quiet",
                            ],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True,
                            encoding="utf-8",
                            errors="replace",
                        )
                        assert proc.stdout is not None
                        for line_no, line in enumerate(proc.stdout, start=1):
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                raw = json.loads(line)
                                if not isinstance(raw, dict):
                                    continue
                                events.append(normalized_event(raw, str(path)))
                                parsed_count += 1
                            except json.JSONDecodeError as exc:
                                if len(parse_errors) < 5:
                                    parse_errors.append(f"Zeile {line_no}: {exc}")
                        stderr = proc.stderr.read() if proc.stderr else ""
                        returncode = proc.wait()
                        if returncode != 0:
                            parse_errors.append(stderr.strip() or f"journalctl exit code {returncode}")
                    except Exception as exc:
                        parse_errors.append(str(exc))

                if parsed_count and not parse_errors:
                    file_info.parse_status = f"OK ({parsed_count:,} Ereignisse)".replace(",", ".")
                elif parsed_count:
                    file_info.parse_status = f"Teilweise ({parsed_count:,} Ereignisse)".replace(",", ".")
                    file_info.parse_error = " | ".join(parse_errors)
                else:
                    file_info.parse_status = "Fehler / keine Ereignisse"
                    file_info.parse_error = " | ".join(parse_errors) or "Keine Datensätze ausgegeben"

                if file_info.parse_error:
                    warnings.append(f"{path}: {file_info.parse_error}")
                metadata.append(file_info)
                self.progress.emit(index, total, f"Fertig: {path.name}")

            # Exact duplicates can occur in unusual copied/linked journal sets.
            deduped: list[dict[str, Any]] = []
            seen: set[tuple[str, str, str]] = set()
            for event in events:
                key = (
                    event.get("cursor", ""),
                    event.get("time_utc", ""),
                    event.get("message", ""),
                )
                if key[0] and key in seen:
                    continue
                if key[0]:
                    seen.add(key)
                deduped.append(event)

            deduped.sort(key=lambda e: e.get("time_utc", ""))
            ssh_rows = [row for event in deduped if (row := classify_ssh(event)) is not None]
            server_scan = ServerScanResult()
            if linux_root is not None:
                self.progress.emit(total, max(total, 1), "Analysiere Serverstruktur und Web-Access-Logs …")
                server_scan = scan_server_root(
                    linux_root,
                    deduped,
                    ssh_rows,
                    progress=lambda label: self.progress.emit(total, max(total, 1), label),
                )
            else:
                server_scan.scan_notes.append(
                    "Kein Linux-Root erkannt. Webseiten, weitere Dienste und Web-Access-Logs konnten nicht ausgewertet werden."
                )
            self.finished.emit(deduped, metadata, warnings, server_scan)
        except Exception as exc:
            self.failed.emit(str(exc))

    @staticmethod
    def sha256_file(path: Path) -> str:
        h = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    @staticmethod
    def discover_files(source: Path) -> list[Path]:
        if source.is_file():
            if source.name.endswith(JOURNAL_SUFFIXES):
                return [source.resolve()]
            return []

        if not source.is_dir():
            return []

        candidates: list[Path] = []

        # If a mounted root/image root was selected, prefer standard journal paths.
        standard_roots = [source / "var" / "log" / "journal", source / "run" / "log" / "journal"]
        searched_standard = False
        for root in standard_roots:
            if root.is_dir():
                searched_standard = True
                for p in root.rglob("*"):
                    if p.is_file() and p.name.endswith(JOURNAL_SUFFIXES):
                        candidates.append(p.resolve())

        # If a journal directory itself was selected, search it directly.
        if not searched_standard:
            for p in source.rglob("*"):
                if p.is_file() and p.name.endswith(JOURNAL_SUFFIXES):
                    candidates.append(p.resolve())

        return sorted(set(candidates), key=lambda p: str(p))


class DictTableModel(QAbstractTableModel):
    RawRole = Qt.UserRole + 1

    def __init__(self, columns: list[tuple[str, str]], rows: list[dict[str, Any]] | None = None):
        super().__init__()
        self.columns = columns
        self.rows = rows or []

    def set_rows(self, rows: list[dict[str, Any]]) -> None:
        self.beginResetModel()
        self.rows = rows
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.columns)

    def data(self, index: QModelIndex, role=Qt.DisplayRole):
        if not index.isValid() or not (0 <= index.row() < len(self.rows)):
            return None
        row = self.rows[index.row()]
        key = self.columns[index.column()][0]
        if role == Qt.DisplayRole:
            value = row.get(key, "")
            if isinstance(value, list):
                return ", ".join(map(str, value))
            return safe_text(value)
        if role == self.RawRole:
            return row
        if role == Qt.ToolTipRole:
            value = row.get(key, "")
            return safe_text(value)
        return None

    def headerData(self, section: int, orientation: Qt.Orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return self.columns[section][1]
        return super().headerData(section, orientation, role)


class EventFilterProxy(QSortFilterProxyModel):
    def __init__(self):
        super().__init__()
        self.search_text = ""
        self.category = "Alle"
        self.setDynamicSortFilter(True)

    def set_search_text(self, text: str) -> None:
        self.search_text = text.casefold().strip()
        self.invalidateFilter()

    def set_category(self, category: str) -> None:
        self.category = category
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:
        model = self.sourceModel()
        if model is None:
            return True
        idx = model.index(source_row, 0, source_parent)
        row = model.data(idx, DictTableModel.RawRole)
        if not isinstance(row, dict):
            return True

        if self.category != "Alle" and row.get("category") != self.category:
            return False

        if not self.search_text:
            return True

        haystack = " ".join(
            safe_text(row.get(k, ""))
            for k in ("time_utc", "host", "service", "pid", "uid", "unit", "boot_id", "category", "message", "source_file", "ips")
        ).casefold()
        return self.search_text in haystack


class JournalAnalyzerWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} {APP_VERSION}")
        self.resize(1500, 900)

        self.events: list[dict[str, Any]] = []
        self.ssh_rows: list[dict[str, Any]] = []
        self.ip_rows: list[dict[str, Any]] = []
        self.admin_rows: list[dict[str, Any]] = []
        self.website_rows: list[dict[str, Any]] = []
        self.service_rows: list[dict[str, Any]] = []
        self.mail_server_rows: list[dict[str, Any]] = []
        self.mail_account_rows: list[dict[str, Any]] = []
        self.mail_alias_rows: list[dict[str, Any]] = []
        self.mail_access_rows: list[dict[str, Any]] = []
        self.mail_diagnostic_rows: list[dict[str, Any]] = []
        self.tls_rows: list[dict[str, Any]] = []
        self.artifact_rows: list[dict[str, Any]] = []
        self.metadata_rows: list[dict[str, Any]] = []
        self.server_scan = ServerScanResult()
        self.load_warnings: list[str] = []
        self.worker_thread: QThread | None = None

        self._build_ui()
        self._build_menu()
        self._set_ready_state()

    def _build_ui(self) -> None:
        central = QWidget()
        root = QVBoxLayout(central)

        source_row = QHBoxLayout()
        source_row.addWidget(QLabel("Quelle:"))
        self.source_edit = QLineEdit()
        self.source_edit.setPlaceholderText("Journal-Datei, Journal-Verzeichnis oder gemountetes Linux-Dateisystem auswählen …")
        source_row.addWidget(self.source_edit, 1)
        self.open_file_btn = QPushButton("Datei …")
        self.open_dir_btn = QPushButton("Ordner/Image-Root …")
        self.load_btn = QPushButton("Auswerten")
        source_row.addWidget(self.open_file_btn)
        source_row.addWidget(self.open_dir_btn)
        source_row.addWidget(self.load_btn)
        root.addLayout(source_row)

        progress_row = QHBoxLayout()
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        self.progress_label = QLabel("")
        progress_row.addWidget(self.progress, 1)
        progress_row.addWidget(self.progress_label)
        root.addLayout(progress_row)

        self.tabs = QTabWidget()
        root.addWidget(self.tabs, 1)

        self.overview_tab = self._build_overview_tab()
        self.ssh_tab = self._build_ssh_tab()
        self.admin_tab = self._build_admin_tab()
        self.websites_tab = self._build_websites_tab()
        self.mail_tab = self._build_mail_tab()
        self.tls_tab = self._build_tls_tab()
        self.services_tab = self._build_services_tab()
        self.artifacts_tab = self._build_artifacts_tab()
        self.events_tab = self._build_events_tab()
        self.ip_tab = self._build_ip_tab()
        self.meta_tab = self._build_metadata_tab()
        self.report_tab = self._build_report_tab()

        self.tabs.addTab(self.overview_tab, "Übersicht")
        self.tabs.addTab(self.ssh_tab, "Betreiber / SSH")
        self.tabs.addTab(self.admin_tab, "Admin-Zugriffe")
        self.tabs.addTab(self.websites_tab, "Web / Domains")
        self.tabs.addTab(self.mail_tab, "Mail")
        self.tabs.addTab(self.tls_tab, "TLS / Zertifikate")
        self.tabs.addTab(self.services_tab, "Dienste")
        self.tabs.addTab(self.artifacts_tab, "Betreiber-Artefakte")
        self.tabs.addTab(self.events_tab, "Journal")
        self.tabs.addTab(self.ip_tab, "IP-Adressen")
        self.tabs.addTab(self.meta_tab, "Journal-Metadaten")
        self.tabs.addTab(self.report_tab, "Bericht")

        self.setCentralWidget(central)
        self.setStatusBar(QStatusBar())

        self.open_file_btn.clicked.connect(self.choose_file)
        self.open_dir_btn.clicked.connect(self.choose_directory)
        self.load_btn.clicked.connect(self.start_load)

    def _build_menu(self) -> None:
        file_menu = self.menuBar().addMenu("Datei")
        act_file = QAction("Journal-Datei öffnen …", self)
        act_dir = QAction("Ordner / Image-Root öffnen …", self)
        act_export_pdf = QAction("Server-Auswertungsbericht als PDF exportieren …", self)
        act_export_csv = QAction("Gefilterte Ereignisse als CSV exportieren …", self)
        act_export_json = QAction("Gefilterte Ereignisse als JSON exportieren …", self)
        act_exit = QAction("Beenden", self)
        file_menu.addActions([act_file, act_dir])
        file_menu.addSeparator()
        file_menu.addAction(act_export_pdf)
        file_menu.addActions([act_export_csv, act_export_json])
        file_menu.addSeparator()
        file_menu.addAction(act_exit)

        act_file.triggered.connect(self.choose_file)
        act_dir.triggered.connect(self.choose_directory)
        act_export_pdf.triggered.connect(self.export_pdf_report)
        act_export_csv.triggered.connect(self.export_csv)
        act_export_json.triggered.connect(self.export_json)
        act_exit.triggered.connect(self.close)

        help_menu = self.menuBar().addMenu("Hilfe")
        act_about = QAction("Über …", self)
        help_menu.addAction(act_about)
        act_about.triggered.connect(self.show_about)

    def _build_overview_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        self.overview_text = QPlainTextEdit()
        self.overview_text.setReadOnly(True)
        mono = QFont("Monospace")
        mono.setStyleHint(QFont.Monospace)
        self.overview_text.setFont(mono)
        layout.addWidget(self.overview_text)
        return widget

    def _build_events_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)

        filter_row = QHBoxLayout()
        filter_row.addWidget(QLabel("Filter:"))
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Text, Dienst, Benutzer, IP, Boot-ID, Dateipfad …")
        self.category_combo = QComboBox()
        self.category_combo.addItems(["Alle", "SSH", "sudo", "Webserver", "Container", "Kernel", "Fehler", "Sonstiges"])
        filter_row.addWidget(self.search_edit, 1)
        filter_row.addWidget(QLabel("Kategorie:"))
        filter_row.addWidget(self.category_combo)
        layout.addLayout(filter_row)

        splitter = QSplitter(Qt.Vertical)
        self.events_model = DictTableModel(
            [
                ("time_utc", "Zeit (UTC)"),
                ("host", "Host"),
                ("service", "Dienst"),
                ("pid", "PID"),
                ("category", "Kategorie"),
                ("unit", "Unit"),
                ("message", "Nachricht"),
                ("source_file", "Quelle"),
            ]
        )
        self.events_proxy = EventFilterProxy()
        self.events_proxy.setSourceModel(self.events_model)
        self.events_view = QTableView()
        self.events_view.setModel(self.events_proxy)
        self.events_view.setSortingEnabled(True)
        self.events_view.setSelectionBehavior(QTableView.SelectRows)
        self.events_view.setSelectionMode(QTableView.SingleSelection)
        self.events_view.setAlternatingRowColors(True)
        self.events_view.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.events_view.horizontalHeader().setSectionResizeMode(6, QHeaderView.Stretch)
        splitter.addWidget(self.events_view)

        details_widget = QWidget()
        details_layout = QVBoxLayout(details_widget)
        details_layout.setContentsMargins(0, 0, 0, 0)
        details_layout.addWidget(QLabel("Originalfelder / Quellennachweis:"))
        self.details_text = QPlainTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setFont(QFont("Monospace"))
        details_layout.addWidget(self.details_text)
        splitter.addWidget(details_widget)
        splitter.setSizes([600, 250])
        layout.addWidget(splitter, 1)

        self.search_edit.textChanged.connect(self.events_proxy.set_search_text)
        self.category_combo.currentTextChanged.connect(self.events_proxy.set_category)
        self.events_view.selectionModel().selectionChanged.connect(self.show_selected_event)
        return widget

    def _build_ssh_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)

        info_row = QHBoxLayout()
        self.ssh_summary_label = QLabel(
            "Im Regelfall sind für die Betreiberzuordnung erfolgreiche SSH-Anmeldungen besonders relevant. "
            "Fehlversuche können bei öffentlich erreichbaren Servern erhebliches Internetrauschen enthalten."
        )
        self.ssh_summary_label.setWordWrap(True)
        self.ssh_filter_combo = QComboBox()
        self.ssh_filter_combo.addItems(["Nur erfolgreiche Anmeldungen", "Alle SSH-Ereignisse", "Nur fehlgeschlagene Anmeldungen"])
        info_row.addWidget(self.ssh_summary_label, 1)
        info_row.addWidget(self.ssh_filter_combo)
        layout.addLayout(info_row)

        self.ssh_model = DictTableModel(
            [
                ("time_utc", "Zeit (UTC)"),
                ("type", "Ereignis"),
                ("user", "Benutzer"),
                ("ip", "Quell-IP"),
                ("method", "Methode"),
                ("host", "Host"),
                ("message", "Nachricht"),
                ("source_file", "Quelle"),
            ]
        )
        self.ssh_view = QTableView()
        self.ssh_view.setModel(self.ssh_model)
        self.ssh_view.setSortingEnabled(True)
        self.ssh_view.setAlternatingRowColors(True)
        self.ssh_view.setSelectionBehavior(QTableView.SelectRows)
        self.ssh_view.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.ssh_view.horizontalHeader().setSectionResizeMode(6, QHeaderView.Stretch)
        layout.addWidget(self.ssh_view)
        self.ssh_filter_combo.currentTextChanged.connect(self.update_ssh_table)
        return widget

    def update_ssh_table(self) -> None:
        mode = self.ssh_filter_combo.currentText() if hasattr(self, "ssh_filter_combo") else "Nur erfolgreiche Anmeldungen"
        if mode == "Nur erfolgreiche Anmeldungen":
            rows = [r for r in self.ssh_rows if r.get("type") == "Anmeldung erfolgreich"]
        elif mode == "Nur fehlgeschlagene Anmeldungen":
            rows = [r for r in self.ssh_rows if r.get("type") == "Anmeldung fehlgeschlagen"]
        else:
            rows = self.ssh_rows
        self.ssh_model.set_rows(rows)

    def _build_admin_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        note = QLabel(
            "Webzugriffe werden bewusst vorsichtig bewertet: Der bloße Abruf einer Login-Seite ist kein erfolgreicher Login. "
            "Als stärkeres Indiz gilt z. B. ein Login-POST mit Redirect und ein zeitnaher Zugriff derselben IP auf einen geschützten Bereich."
        )
        note.setWordWrap(True)
        layout.addWidget(note)
        admin_filter_row = QHBoxLayout()
        admin_filter_row.addStretch(1)
        admin_filter_row.addWidget(QLabel("Ansicht:"))
        self.admin_filter_combo = QComboBox()
        self.admin_filter_combo.addItems([
            "Priorisierte Zugriffe",
            "Alle Admin-Zugriffe",
            "Starke Login-Hinweise",
            "Mit erfolgreichem SSH korreliert",
            "Abgewiesen / nicht vorhanden",
        ])
        admin_filter_row.addWidget(self.admin_filter_combo)
        layout.addLayout(admin_filter_row)
        self.admin_model = DictTableModel(
            [
                ("time_utc", "Zeit (UTC)"),
                ("tool", "Administrationstool"),
                ("assessment", "Bewertung"),
                ("ip", "Quell-IP"),
                ("ssh_correlation", "Korrelation mit SSH"),
                ("method", "Methode"),
                ("path", "Pfad"),
                ("status", "HTTP"),
                ("site", "Site/VHost"),
                ("source_file", "Quelle"),
                ("line", "Zeile"),
            ]
        )
        self.admin_view = QTableView()
        self.admin_view.setModel(self.admin_model)
        self.admin_view.setSortingEnabled(True)
        self.admin_view.setAlternatingRowColors(True)
        self.admin_view.setSelectionBehavior(QTableView.SelectRows)
        self.admin_view.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.admin_view.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.admin_view.horizontalHeader().setSectionResizeMode(6, QHeaderView.Stretch)
        layout.addWidget(self.admin_view)
        self.admin_filter_combo.currentTextChanged.connect(self.update_admin_table)
        return widget

    def update_admin_table(self) -> None:
        mode = self.admin_filter_combo.currentText() if hasattr(self, "admin_filter_combo") else "Priorisierte Zugriffe"
        if mode == "Priorisierte Zugriffe":
            rows = [
                r for r in self.admin_rows
                if r.get("ssh_correlation")
                or str(r.get("assessment", "")).startswith("Starker Hinweis")
                or str(r.get("assessment", "")).startswith("Geschützter Bereich")
            ]
        elif mode == "Starke Login-Hinweise":
            rows = [r for r in self.admin_rows if str(r.get("assessment", "")).startswith("Starker Hinweis")]
        elif mode == "Mit erfolgreichem SSH korreliert":
            rows = [r for r in self.admin_rows if r.get("ssh_correlation")]
        elif mode == "Abgewiesen / nicht vorhanden":
            rows = [
                r for r in self.admin_rows
                if "abgewiesen" in str(r.get("assessment", "")).casefold()
                or "404" in str(r.get("assessment", ""))
            ]
        else:
            rows = self.admin_rows
        self.admin_model.set_rows(rows)

    def _build_websites_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        note = QLabel(
            "Bei Nginx wird sowohl die aktive Include-Kette ab nginx.conf als auch das vollständige Konfigurationsinventar unter /etc/nginx (einschließlich sites-available/sites-enabled) und relevanten Plesk-VHost-Pfaden ausgewertet. "
            "Dateinamen müssen keine .conf-Endung besitzen; auch domainartige Namen wie shop-beispiel.de werden berücksichtigt. Include-Snippets innerhalb von server-Blöcken werden bestmöglich rekonstruiert. "
            "Dadurch kann eine aktiv eingebundene VHost-Konfiguration von einem bloßen Konfigurationsfund unterschieden werden. Ein aktiver Config-Fund belegt dennoch nicht zwingend die Erreichbarkeit im gesamten Auswertungszeitraum."
        )
        note.setWordWrap(True)
        layout.addWidget(note)
        self.websites_model = DictTableModel(
            [
                ("active", "Aktiv eingebunden"),
                ("webserver", "Webserver"),
                ("domains", "Domain(s) / URL-Host"),
                ("urls", "abgeleitete URL(s)"),
                ("listen", "Listen"),
                ("document_root", "DocumentRoot"),
                ("application", "Anwendung"),
                ("proxy_pass", "Reverse Proxy"),
                ("fastcgi_pass", "FastCGI/PHP"),
                ("ssl_certificate", "TLS-Zertifikat"),
                ("access_log", "Access-Log"),
                ("error_log", "Error-Log"),
                ("status_hint", "Statushinweis"),
                ("source_file", "Quelle"),
            ]
        )
        self.websites_view = QTableView()
        self.websites_view.setModel(self.websites_model)
        self.websites_view.setSortingEnabled(True)
        self.websites_view.setAlternatingRowColors(True)
        self.websites_view.setSelectionBehavior(QTableView.SelectRows)
        self.websites_view.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.websites_view.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.websites_view.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.websites_view.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        self.websites_view.horizontalHeader().setSectionResizeMode(7, QHeaderView.Stretch)
        layout.addWidget(self.websites_view)
        return widget

    def _build_mail_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        note = QLabel(
            "Mailauswertung aus Postfix-/Dovecot-/Exim-Konfigurationen, Maildir-/Plesk-Strukturen und Mail-Logs. "
            "Kennwörter, Passwort-Hashes und vergleichbare Secrets werden nicht in Tabellen oder PDF-Bericht ausgegeben."
        )
        note.setWordWrap(True)
        layout.addWidget(note)

        sub = QTabWidget()
        layout.addWidget(sub, 1)

        server_page = QWidget()
        server_layout = QVBoxLayout(server_page)
        self.mail_servers_model = DictTableModel([
            ("component", "Komponente"), ("hostname", "Hostname"), ("domains", "Maildomain(s)"),
            ("relay", "Relay/Smarthost"), ("interfaces", "Interfaces"), ("protocols", "Protokolle"),
            ("source_file", "Quelle"), ("notes", "Hinweis"),
        ])
        self.mail_servers_view = QTableView()
        self.mail_servers_view.setModel(self.mail_servers_model)
        self.mail_servers_view.setSortingEnabled(True)
        self.mail_servers_view.setAlternatingRowColors(True)
        self.mail_servers_view.setSelectionBehavior(QTableView.SelectRows)
        self.mail_servers_view.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.mail_servers_view.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.mail_servers_view.horizontalHeader().setSectionResizeMode(7, QHeaderView.Stretch)
        server_layout.addWidget(self.mail_servers_view)
        sub.addTab(server_page, "Server / Domains")

        accounts_page = QWidget()
        accounts_layout = QVBoxLayout(accounts_page)
        self.mail_accounts_model = DictTableModel([
            ("address", "Mail-Adresse"), ("domain", "Domain"), ("assessment", "Bewertung"),
            ("evidence", "Nachweis"), ("source_file", "Quelle"), ("detail", "Detail"),
        ])
        self.mail_accounts_view = QTableView()
        self.mail_accounts_view.setModel(self.mail_accounts_model)
        self.mail_accounts_view.setSortingEnabled(True)
        self.mail_accounts_view.setAlternatingRowColors(True)
        self.mail_accounts_view.setSelectionBehavior(QTableView.SelectRows)
        self.mail_accounts_view.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.mail_accounts_view.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.mail_accounts_view.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        accounts_layout.addWidget(self.mail_accounts_view)
        sub.addTab(accounts_page, "Mail-Adressen")

        alias_page = QWidget()
        alias_layout = QVBoxLayout(alias_page)
        self.mail_aliases_model = DictTableModel([
            ("alias", "Alias/Adresse"), ("target", "Ziel/Weiterleitung"),
            ("external_forward", "Externe Weiterleitung"), ("evidence", "Nachweis"), ("source_file", "Quelle"),
        ])
        self.mail_aliases_view = QTableView()
        self.mail_aliases_view.setModel(self.mail_aliases_model)
        self.mail_aliases_view.setSortingEnabled(True)
        self.mail_aliases_view.setAlternatingRowColors(True)
        self.mail_aliases_view.setSelectionBehavior(QTableView.SelectRows)
        self.mail_aliases_view.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.mail_aliases_view.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        alias_layout.addWidget(self.mail_aliases_view)
        sub.addTab(alias_page, "Aliase / Weiterleitungen")

        access_page = QWidget()
        access_layout = QVBoxLayout(access_page)
        access_note = QLabel(
            "Hier stehen nur erkannte Authentifizierungs-/Login-Hinweise. Eine gleiche Quell-IP bei erfolgreichem SSH und Mail-Login wird hervorgehoben."
        )
        access_note.setWordWrap(True)
        access_layout.addWidget(access_note)
        self.mail_access_model = DictTableModel([
            ("time", "Zeit/Logzeit"), ("service", "Dienst"), ("result", "Ergebnis"), ("user", "Benutzer"),
            ("ip", "Quell-IP"), ("ssh_correlation", "Korrelation mit SSH"), ("source_file", "Quelle"),
            ("line", "Zeile"), ("message", "Originalmeldung"),
        ])
        self.mail_access_view = QTableView()
        self.mail_access_view.setModel(self.mail_access_model)
        self.mail_access_view.setSortingEnabled(True)
        self.mail_access_view.setAlternatingRowColors(True)
        self.mail_access_view.setSelectionBehavior(QTableView.SelectRows)
        self.mail_access_view.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.mail_access_view.horizontalHeader().setSectionResizeMode(8, QHeaderView.Stretch)
        access_layout.addWidget(self.mail_access_view)
        sub.addTab(access_page, "Authentifizierte Zugriffe")

        diag_page = QWidget()
        diag_layout = QVBoxLayout(diag_page)
        diag_note = QLabel(
            "Diagnose der Mailerkennung: zeigt erkannte Storage-Pfade, Dovecot-/Postfix-Quellen sowie nicht lesbare Einträge. "
            "Warnungen können auf Besonderheiten eines Windows-Forensik-Mounts oder Linux-Symlinks hinweisen."
        )
        diag_note.setWordWrap(True)
        diag_layout.addWidget(diag_note)
        self.mail_diagnostics_model = DictTableModel([
            ("area", "Bereich"), ("item", "Prüfung"), ("value", "Wert"),
            ("status", "Status"), ("source_file", "Quelle / Detail"),
        ])
        self.mail_diagnostics_view = QTableView()
        self.mail_diagnostics_view.setModel(self.mail_diagnostics_model)
        self.mail_diagnostics_view.setSortingEnabled(True)
        self.mail_diagnostics_view.setAlternatingRowColors(True)
        self.mail_diagnostics_view.setSelectionBehavior(QTableView.SelectRows)
        self.mail_diagnostics_view.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.mail_diagnostics_view.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.mail_diagnostics_view.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        diag_layout.addWidget(self.mail_diagnostics_view)
        sub.addTab(diag_page, "Diagnose")
        return widget

    def _build_tls_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        note = QLabel(
            "Zertifikate werden insbesondere aus Nginx-/Mailserver-Referenzen und Let's-Encrypt-Beständen ermittelt. "
            "SAN-Domains können Hinweise auf weitere oder frühere Dienste/Hosts liefern."
        )
        note.setWordWrap(True)
        layout.addWidget(note)
        self.tls_model = DictTableModel([
            ("subject", "Subject/CN"), ("sans", "Subject Alternative Names"), ("issuer", "Aussteller"),
            ("not_before", "Gültig ab"), ("not_after", "Gültig bis"), ("serial", "Seriennummer"),
            ("referenced_by", "Referenziert durch"), ("certificate_path", "Zertifikatspfad"),
            ("source_file", "Quelle"), ("status", "Status"),
        ])
        self.tls_view = QTableView()
        self.tls_view.setModel(self.tls_model)
        self.tls_view.setSortingEnabled(True)
        self.tls_view.setAlternatingRowColors(True)
        self.tls_view.setSelectionBehavior(QTableView.SelectRows)
        self.tls_view.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.tls_view.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.tls_view.horizontalHeader().setSectionResizeMode(6, QHeaderView.Stretch)
        layout.addWidget(self.tls_view)
        return widget

    def _build_artifacts_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        filter_row = QHBoxLayout()
        note = QLabel(
            "Ermittlungsnahe Artefakte aus Benutzerprofilen und Systemkonfiguration: SSH-Schlüssel/-Ziele, Git-Identität, Shell-History und Cron. "
            "Offensichtliche Kennwörter/Tokens in Befehlszeilen werden in der Anzeige maskiert."
        )
        note.setWordWrap(True)
        filter_row.addWidget(note, 1)
        filter_row.addWidget(QLabel("Kategorie:"))
        self.artifact_filter_combo = QComboBox()
        self.artifact_filter_combo.addItems([
            "Alle", "Lokales Benutzerkonto", "SSH-Schlüssel", "SSH-Zielsystem", "Git-Identität", "Git-Repository", "Shell-History", "Zeitgesteuerter Auftrag"
        ])
        filter_row.addWidget(self.artifact_filter_combo)
        layout.addLayout(filter_row)
        self.artifacts_model = DictTableModel([
            ("category", "Kategorie"), ("owner", "Benutzer"), ("artifact", "Artefakt"),
            ("value", "Wert/Befehl/Kommentar"), ("detail", "Detail"), ("source_file", "Quelle"), ("line", "Zeile"),
        ])
        self.artifacts_view = QTableView()
        self.artifacts_view.setModel(self.artifacts_model)
        self.artifacts_view.setSortingEnabled(True)
        self.artifacts_view.setAlternatingRowColors(True)
        self.artifacts_view.setSelectionBehavior(QTableView.SelectRows)
        self.artifacts_view.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.artifacts_view.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.artifacts_view.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        layout.addWidget(self.artifacts_view)
        self.artifact_filter_combo.currentTextChanged.connect(self.update_artifact_table)
        return widget

    def update_artifact_table(self) -> None:
        mode = self.artifact_filter_combo.currentText() if hasattr(self, "artifact_filter_combo") else "Alle"
        rows = self.artifact_rows if mode == "Alle" else [r for r in self.artifact_rows if r.get("category") == mode]
        self.artifacts_model.set_rows(rows)

    def _build_report_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        title = QLabel("PDF-Auswertungsbericht")
        font = title.font()
        font.setBold(True)
        font.setPointSize(font.pointSize() + 2)
        title.setFont(font)
        layout.addWidget(title)
        self.report_text = QPlainTextEdit()
        self.report_text.setReadOnly(True)
        self.report_text.setPlainText(
            "Nach einer Auswertung kann hier ein zusammenfassender PDF-Bericht erzeugt werden.\n\n"
            "Enthalten sind - soweit festgestellt - erfolgreiche SSH-Zugriffe, Web-Adminzugriffe, aktive/konfigurierte Domains und VHosts, "
            "Mailserver/-konten/-weiterleitungen, authentifizierte Mailzugriffe, TLS-Zertifikate, Dienste, Betreiber-Artefakte und die Journal-Quelldokumentation.\n\n"
            "Passwörter, Passwort-Hashes und erkannte Secrets werden nicht in den PDF-Bericht übernommen."
        )
        layout.addWidget(self.report_text, 1)
        self.report_export_btn = QPushButton("PDF-Bericht erstellen …")
        self.report_export_btn.clicked.connect(self.export_pdf_report)
        layout.addWidget(self.report_export_btn)
        return widget

    def _build_services_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        note = QLabel(
            "Die Spalte 'Nachweis' unterscheidet zwischen bloß vorhandener Installation/Konfiguration und tatsächlich im Journal festgestellter Aktivität."
        )
        note.setWordWrap(True)
        layout.addWidget(note)
        self.services_model = DictTableModel(
            [
                ("category", "Kategorie"),
                ("service", "Dienst"),
                ("assessment", "Nachweis"),
                ("journal_count", "Journal-Ereignisse"),
                ("first_seen", "Erstmals (UTC)"),
                ("last_seen", "Letztmals (UTC)"),
                ("evidence", "Beleg/Dateipfad"),
            ]
        )
        self.services_view = QTableView()
        self.services_view.setModel(self.services_model)
        self.services_view.setSortingEnabled(True)
        self.services_view.setAlternatingRowColors(True)
        self.services_view.setSelectionBehavior(QTableView.SelectRows)
        self.services_view.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.services_view.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.services_view.horizontalHeader().setSectionResizeMode(6, QHeaderView.Stretch)
        layout.addWidget(self.services_view)
        return widget

    def _build_ip_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        self.ip_model = DictTableModel(
            [
                ("ip", "IP-Adresse"),
                ("version", "Typ"),
                ("scope", "Bereich"),
                ("first_seen", "Erstmals (UTC)"),
                ("last_seen", "Letztmals (UTC)"),
                ("count", "Ereignisse"),
                ("categories", "Kategorien"),
            ]
        )
        self.ip_view = QTableView()
        self.ip_view.setModel(self.ip_model)
        self.ip_view.setSortingEnabled(True)
        self.ip_view.setAlternatingRowColors(True)
        self.ip_view.setSelectionBehavior(QTableView.SelectRows)
        self.ip_view.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.ip_view)
        return widget

    def _build_metadata_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        self.meta_model = DictTableModel(
            [
                ("path", "Datei"),
                ("size_human", "Größe"),
                ("mtime_utc", "Dateizeit (UTC)"),
                ("sha256", "SHA-256"),
                ("parser_engine", "Parser"),
                ("parse_status", "Parserstatus"),
                ("parse_error", "Hinweis"),
            ]
        )
        self.meta_view = QTableView()
        self.meta_view.setModel(self.meta_model)
        self.meta_view.setSortingEnabled(True)
        self.meta_view.setAlternatingRowColors(True)
        self.meta_view.setSelectionBehavior(QTableView.SelectRows)
        self.meta_view.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.meta_view.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.meta_view.horizontalHeader().setSectionResizeMode(6, QHeaderView.Stretch)
        layout.addWidget(self.meta_view)
        return widget

    def _set_ready_state(self) -> None:
        self.overview_text.setPlainText(
            f"{APP_NAME} {APP_VERSION}\n\n"
            "Windows-basierter Auswertungsassistent für vollständige Linux-Server-Beweismittel.\n\n"
            "Für die vollständige Auswertung idealerweise den Root-Ordner des zuvor mit einem Forensikwerkzeug zugänglich gemachten "
            "Linux-Dateisystems auswählen (Ordner mit etc, var, home usw.). Die Quelldateien werden ausschließlich lesend verarbeitet.\n\n"
            "Schwerpunkte:\n"
            "- erfolgreiche SSH-Anmeldungen und Korrelation administrativer Quell-IP-Adressen\n"
            "- Zugriffe auf Plesk, WordPress, Nextcloud, phpMyAdmin und typische Adminpfade\n"
            "- aktive/eingebundene Nginx-Konfiguration, Domains, Reverse-Proxies, Logs und TLS-Pfade\n"
            "- Postfix/Dovecot/Exim: Maildomains, Mail-Adressen, Aliase/Weiterleitungen und authentifizierte Zugriffe\n"
            "- TLS-/Let's-Encrypt-Zertifikate und zusätzliche SAN-Domains\n"
            "- SSH-Schlüssel, Git-Identitäten, Shell-History und Cron als Betreiber-Artefakte\n"
            "- weitere Serverdienste und systemd-Journal\n"
            "- zusammenfassender PDF-Auswertungsbericht mit Quellennachweis\n\n"
            "Ereigniszeiten aus systemd-Journal werden in UTC dargestellt. Linux/WSL ist unter Windows nicht erforderlich.\n"
        )

    def choose_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Journal-Datei auswählen",
            "",
            "systemd Journal (*.journal *.journal~);;Alle Dateien (*)",
        )
        if path:
            self.source_edit.setText(path)

    def choose_directory(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Journal-Verzeichnis oder gemountetes Image-Root auswählen")
        if path:
            self.source_edit.setText(path)

    def start_load(self) -> None:
        source = self.source_edit.text().strip()
        if not source:
            QMessageBox.warning(self, APP_NAME, "Bitte zuerst eine Quelle auswählen.")
            return
        if not Path(source).exists():
            QMessageBox.warning(self, APP_NAME, "Die angegebene Quelle existiert nicht.")
            return
        if self.worker_thread and self.worker_thread.isRunning():
            return

        self.events = []
        self.ssh_rows = []
        self.ip_rows = []
        self.admin_rows = []
        self.website_rows = []
        self.service_rows = []
        self.mail_server_rows = []
        self.mail_account_rows = []
        self.mail_alias_rows = []
        self.mail_access_rows = []
        self.mail_diagnostic_rows = []
        self.tls_rows = []
        self.artifact_rows = []
        self.metadata_rows = []
        self.server_scan = ServerScanResult()
        self.details_text.clear()
        self.events_model.set_rows([])
        self.ssh_model.set_rows([])
        self.admin_model.set_rows([])
        self.websites_model.set_rows([])
        self.services_model.set_rows([])
        self.mail_servers_model.set_rows([])
        self.mail_accounts_model.set_rows([])
        self.mail_aliases_model.set_rows([])
        self.mail_access_model.set_rows([])
        self.mail_diagnostics_model.set_rows([])
        self.tls_model.set_rows([])
        self.artifacts_model.set_rows([])
        self.ip_model.set_rows([])
        self.meta_model.set_rows([])

        self.progress.setVisible(True)
        self.progress.setRange(0, 0)
        self.progress_label.setText("Vorbereitung …")
        self.load_btn.setEnabled(False)
        self.statusBar().showMessage("Serverauswertung läuft …")

        self.worker_thread = QThread(self)
        self.worker = JournalLoader(source)
        self.worker.moveToThread(self.worker_thread)
        self.worker_thread.started.connect(self.worker.run)
        self.worker.progress.connect(self.on_progress)
        self.worker.finished.connect(self.on_loaded)
        self.worker.failed.connect(self.on_load_failed)
        self.worker.finished.connect(self.worker_thread.quit)
        self.worker.failed.connect(self.worker_thread.quit)
        self.worker_thread.finished.connect(self.worker.deleteLater)
        self.worker_thread.finished.connect(self._cleanup_worker_thread)
        self.worker_thread.start()

    def _cleanup_worker_thread(self) -> None:
        thread = self.worker_thread
        self.worker_thread = None
        self.worker = None
        if thread is not None:
            thread.deleteLater()

    def on_progress(self, current: int, total: int, label: str) -> None:
        self.progress.setRange(0, max(total, 1))
        self.progress.setValue(current)
        self.progress_label.setText(label)

    def on_loaded(
        self,
        events: list[dict[str, Any]],
        metadata: list[SourceFileInfo],
        warnings: list[str],
        server_scan: ServerScanResult,
    ) -> None:
        self.events = events
        self.load_warnings = warnings
        self.server_scan = server_scan
        self.metadata_rows = [
            {
                "path": m.path,
                "size": m.size,
                "size_human": human_size(m.size),
                "mtime_utc": m.mtime_utc,
                "sha256": m.sha256,
                "parser_engine": m.parser_engine,
                "parse_status": m.parse_status,
                "parse_error": m.parse_error,
            }
            for m in metadata
        ]
        self.ssh_rows = [row for event in events if (row := classify_ssh(event)) is not None]
        self.admin_rows = list(server_scan.admin_accesses)
        self.website_rows = list(server_scan.websites)
        self.service_rows = list(server_scan.services)
        self.mail_server_rows = list(server_scan.mail_servers)
        self.mail_account_rows = list(server_scan.mail_accounts)
        self.mail_alias_rows = list(server_scan.mail_aliases)
        self.mail_diagnostic_rows = list(server_scan.mail_diagnostics)
        success_ssh_ips = {r.get("ip", "") for r in self.ssh_rows if r.get("type") == "Anmeldung erfolgreich" and r.get("ip")}
        self.mail_access_rows = []
        for source_row in server_scan.mail_accesses:
            row = dict(source_row)
            row["ssh_correlation"] = "Ja - gleiche IP mit erfolgreicher SSH-Anmeldung" if row.get("ip") in success_ssh_ips else ""
            self.mail_access_rows.append(row)
        self.tls_rows = list(server_scan.tls_certificates)
        self.artifact_rows = list(server_scan.operator_artifacts)
        self.ip_rows = self.build_ip_rows(events, self.admin_rows, self.mail_access_rows)

        self.events_model.set_rows(self.events)
        self.update_ssh_table()
        self.update_admin_table()
        self.websites_model.set_rows(self.website_rows)
        self.services_model.set_rows(self.service_rows)
        self.mail_servers_model.set_rows(self.mail_server_rows)
        self.mail_accounts_model.set_rows(self.mail_account_rows)
        self.mail_aliases_model.set_rows(self.mail_alias_rows)
        self.mail_access_model.set_rows(self.mail_access_rows)
        self.mail_diagnostics_model.set_rows(self.mail_diagnostic_rows)
        self.tls_model.set_rows(self.tls_rows)
        self.update_artifact_table()
        self.ip_model.set_rows(self.ip_rows)
        self.meta_model.set_rows(self.metadata_rows)
        self.update_overview()
        self.update_report_summary()

        self.progress.setVisible(False)
        self.progress_label.setText("")
        self.load_btn.setEnabled(True)
        self.statusBar().showMessage(
            (
                f"Auswertung abgeschlossen: {len(events):,} Journal-Ereignisse, "
                f"{len(self.website_rows)} Website-Feststellungen, {len(self.admin_rows)} Adminzugriffe, "
                f"{len(self.mail_account_rows)} Mail-Adressen."
            ).replace(",", "."),
            15000,
        )
        if warnings:
            QMessageBox.warning(
                self,
                APP_NAME,
                f"Die Auswertung wurde abgeschlossen, bei {len(warnings)} Datei(en) gab es Hinweise. "
                "Details stehen im Reiter 'Journal-Metadaten'.",
            )

    def on_load_failed(self, message: str) -> None:
        self.progress.setVisible(False)
        self.progress_label.setText("")
        self.load_btn.setEnabled(True)
        self.statusBar().clearMessage()
        QMessageBox.critical(self, APP_NAME, message)

    @staticmethod
    def build_ip_rows(
        events: list[dict[str, Any]],
        admin_rows: list[dict[str, Any]] | None = None,
        mail_access_rows: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        agg: dict[str, dict[str, Any]] = {}
        for event in events:
            for ip in event.get("ips", []):
                try:
                    ip_obj = ipaddress.ip_address(ip)
                except ValueError:
                    continue
                item = agg.setdefault(
                    ip,
                    {
                        "ip": ip,
                        "version": f"IPv{ip_obj.version}",
                        "scope": (
                            "Loopback" if ip_obj.is_loopback else
                            "Link-local" if ip_obj.is_link_local else
                            "Privat" if ip_obj.is_private else
                            "Multicast" if ip_obj.is_multicast else
                            "Global/öffentlich" if ip_obj.is_global else
                            "Sonstiger Bereich"
                        ),
                        "first_seen": event.get("time_utc", ""),
                        "last_seen": event.get("time_utc", ""),
                        "count": 0,
                        "category_counter": Counter(),
                    },
                )
                ts = event.get("time_utc", "")
                if ts and (not item["first_seen"] or ts < item["first_seen"]):
                    item["first_seen"] = ts
                if ts and (not item["last_seen"] or ts > item["last_seen"]):
                    item["last_seen"] = ts
                item["count"] += 1
                item["category_counter"][event.get("category", "Sonstiges")] += 1

        def add_external(ip: str, ts: str, category: str) -> None:
            try:
                ip_obj = ipaddress.ip_address(ip)
            except ValueError:
                return
            item = agg.setdefault(
                ip,
                {
                    "ip": ip,
                    "version": f"IPv{ip_obj.version}",
                    "scope": (
                        "Loopback" if ip_obj.is_loopback else
                        "Link-local" if ip_obj.is_link_local else
                        "Privat" if ip_obj.is_private else
                        "Multicast" if ip_obj.is_multicast else
                        "Global/öffentlich" if ip_obj.is_global else
                        "Sonstiger Bereich"
                    ),
                    "first_seen": ts,
                    "last_seen": ts,
                    "count": 0,
                    "category_counter": Counter(),
                },
            )
            if ts and (not item["first_seen"] or ts < item["first_seen"]):
                item["first_seen"] = ts
            if ts and (not item["last_seen"] or ts > item["last_seen"]):
                item["last_seen"] = ts
            item["count"] += 1
            item["category_counter"][category] += 1

        for row in admin_rows or []:
            add_external(str(row.get("ip", "")), str(row.get("time_utc", "")), "Web-Administration")
        for row in mail_access_rows or []:
            mail_time = str(row.get("time", ""))
            if not re.match(r"^\d{4}-\d{2}-\d{2}T", mail_time):
                mail_time = ""
            add_external(str(row.get("ip", "")), mail_time, "Mail-Authentifizierung")

        rows = []
        for item in agg.values():
            item["categories"] = ", ".join(
                f"{name}: {count}" for name, count in item.pop("category_counter").most_common()
            )
            rows.append(item)
        rows.sort(key=lambda r: (-int(r["count"]), r["ip"]))
        return rows

    def update_overview(self) -> None:
        if not (self.events or self.website_rows or self.service_rows or self.admin_rows or self.mail_server_rows or self.tls_rows or self.artifact_rows):
            self._set_ready_state()
            return

        times = [e["time_utc"] for e in self.events if e.get("time_utc")]
        hosts = sorted({e.get("host", "") for e in self.events if e.get("host")})
        boots = {e.get("boot_id", "") for e in self.events if e.get("boot_id")}
        cats = Counter(e.get("category", "Sonstiges") for e in self.events)
        ssh_types = Counter(r.get("type", "") for r in self.ssh_rows)
        success_ssh = [r for r in self.ssh_rows if r.get("type") == "Anmeldung erfolgreich"]
        success_ips = Counter(r.get("ip", "") for r in success_ssh if r.get("ip"))
        success_users = Counter(r.get("user", "") for r in success_ssh if r.get("user"))

        strong_admin = [r for r in self.admin_rows if str(r.get("assessment", "")).startswith("Starker Hinweis")]
        rejected_admin = [r for r in self.admin_rows if "abgewiesen" in str(r.get("assessment", "")).casefold()]
        correlated_admin = [r for r in self.admin_rows if r.get("ssh_correlation")]

        lines = [
            f"{APP_NAME} {APP_VERSION}",
            "=" * 86,
            "",
            f"Quelle:                       {self.source_edit.text().strip()}",
            f"Erkanntes Linux-Root:         {self.server_scan.linux_root or '-'}",
            f"Journal-Dateien:              {len(self.metadata_rows)}",
            f"Journal-Ereignisse:           {len(self.events):,}".replace(",", "."),
            f"Zeitraum Journal (UTC):       {min(times) if times else '-'}",
            f"                              bis {max(times) if times else '-'}",
            f"Hosts:                         {', '.join(hosts) if hosts else '-'}",
            f"Boot-IDs:                      {len(boots)}",
            "",
            "ERFOLGREICHE SSH-ANMELDUNGEN / MÖGLICHE BETREIBERZUGRIFFE",
            "-" * 86,
            f"Erfolgreiche Anmeldungen:      {len(success_ssh):,}".replace(",", "."),
            f"Unterschiedliche Quell-IP:     {len(success_ips)}",
            f"Verwendete Benutzerkonten:     {len(success_users)}",
        ]
        for ip, count in success_ips.most_common(15):
            lines.append(f"  {ip:<42}{count:>8} erfolgreiche Anmeldung(en)")
        if not success_ssh:
            lines.append("  Keine erfolgreichen SSH-Anmeldungen erkannt.")

        lines.extend(["", "ADMINISTRATIONSOBERFLÄCHEN / WEBZUGRIFFE", "-" * 86])
        lines.append(f"Relevante Adminzugriffe:       {len(self.admin_rows):,}".replace(",", "."))
        lines.append(f"Starker Login-Hinweis:         {len(strong_admin):,}".replace(",", "."))
        lines.append(f"Abgewiesene Zugriffe:          {len(rejected_admin):,}".replace(",", "."))
        lines.append(f"IP auch bei erfolgreichem SSH: {len(correlated_admin):,}".replace(",", "."))
        tool_counts = Counter(r.get("tool", "") for r in self.admin_rows if r.get("tool"))
        for tool, count in tool_counts.most_common():
            lines.append(f"  {tool:<42}{count:>8} Ereignis(se)")

        lines.extend(["", "ERKANNTE WEBSEITEN / WEBANWENDUNGEN", "-" * 86])
        lines.append(f"Website-/VHost-Feststellungen: {len(self.website_rows)}")
        for row in self.website_rows[:30]:
            app = f" [{row.get('application')}]" if row.get("application") else ""
            lines.append(
                f"  {row.get('domains', '-')[:48]:<50} {row.get('webserver', '')}{app}  {row.get('document_root', '')}"
            )
        if len(self.website_rows) > 30:
            lines.append(f"  ... weitere {len(self.website_rows) - 30} Einträge im Reiter 'Web / Domains'.")

        lines.extend(["", "MAILSYSTEM / MAIL-ADRESSEN / AUTHENTIFIZIERTE ZUGRIFFE", "-" * 86])
        mail_domains: set[str] = set()
        for row in self.mail_server_rows:
            for value in str(row.get("domains", "")).replace(";", ",").split(","):
                value = value.strip()
                if value:
                    mail_domains.add(value)
        external_aliases = [r for r in self.mail_alias_rows if r.get("external_forward")]
        correlated_mail = [r for r in self.mail_access_rows if r.get("ssh_correlation")]
        lines.append(f"Mailserver-Komponenten:         {len(self.mail_server_rows)}")
        lines.append(f"Erkannte Maildomains:          {len(mail_domains)}")
        lines.append(f"Erkannte Mail-Adressen:        {len(self.mail_account_rows)}")
        lines.append(f"Aliase/Weiterleitungen:        {len(self.mail_alias_rows)}")
        lines.append(f"Davon externe Weiterleitungen: {len(external_aliases)}")
        lines.append(f"Authentifizierte Mailzugriffe: {len(self.mail_access_rows)}")
        lines.append(f"Mail-IP auch bei SSH erkannt:  {len(correlated_mail)}")
        for domain in sorted(mail_domains)[:20]:
            lines.append(f"  Maildomain: {domain}")
        for row in external_aliases[:10]:
            lines.append(f"  Externe Weiterleitung: {row.get('alias', '')} -> {row.get('target', '')}")

        lines.extend(["", "TLS / ZERTIFIKATE", "-" * 86])
        lines.append(f"Zertifikats-/Renewal-Feststellungen: {len(self.tls_rows)}")
        for row in self.tls_rows[:20]:
            names = row.get("sans", "") or row.get("subject", "") or row.get("certificate_path", "")
            lines.append(f"  {str(names)[:78]}")

        lines.extend(["", "BETREIBER-ARTEFAKTE", "-" * 86])
        artifact_counts = Counter(r.get("category", "") for r in self.artifact_rows if r.get("category"))
        for name, count in artifact_counts.most_common():
            lines.append(f"  {name:<42}{count:>8}")
        if not artifact_counts:
            lines.append("  Keine unterstützten Betreiber-Artefakte erkannt.")

        lines.extend(["", "ERKANNTE DIENSTE", "-" * 86])
        for row in self.service_rows[:40]:
            lines.append(
                f"  {row.get('category', '')[:18]:<20}{row.get('service', '')[:28]:<30}{row.get('assessment', '')}"
            )
        if len(self.service_rows) > 40:
            lines.append(f"  ... weitere {len(self.service_rows) - 40} Einträge im Reiter 'Dienste'.")

        lines.extend(["", "JOURNAL-KATEGORIEN", "-" * 86])
        for name, count in cats.most_common():
            lines.append(f"{name:<34}{count:>12,}".replace(",", "."))
        for name, count in ssh_types.most_common():
            lines.append(f"SSH: {name:<29}{count:>12,}".replace(",", "."))

        lines.extend(["", "BEWERTUNGSHINWEIS", "-" * 86])
        lines.append(
            "Eine erfolgreiche SSH-Anmeldung belegt eine erfolgreiche Authentifizierung des protokollierten "
            "Benutzerkontos von der angegebenen Quell-IP. Die personenbezogene Zuordnung dieser IP zum Betreiber "
            "ist eine davon getrennte Ermittlungsfrage."
        )
        lines.append(
            "Bei Web-Adminzugriffen wird der bloße Seitenaufruf nicht als erfolgreicher Login behandelt. "
            "Stärkere Hinweise werden nur bei passenden Ereignisfolgen (z. B. Login-POST/Redirect + geschützter Bereich) ausgewiesen."
        )

        lines.extend(["", "BEWEISMITTEL / QUELLENNACHWEIS", "-" * 86])
        lines.append("SHA-256-Werte und Parserstatus der Journal-Dateien stehen im Reiter 'Journal-Metadaten'.")
        lines.append("Die ausgewerteten Dateien werden ausschließlich lesend geöffnet.")
        if self.server_scan.access_log_files:
            lines.append(f"Ausgewertete typische Web-/Panel-Access-Logs: {len(self.server_scan.access_log_files)}")
        if self.server_scan.mail_log_files:
            lines.append(f"Ausgewertete typische Mail-Logs: {len(self.server_scan.mail_log_files)}")
        for note in self.server_scan.scan_notes:
            lines.append(f"Hinweis: {note}")
        parsers = sorted({m.get("parser_engine", "") for m in self.metadata_rows if m.get("parser_engine")})
        if parsers:
            lines.append(f"Journal-Parser: {', '.join(parsers)}")
        if self.load_warnings:
            lines.append(f"Parserhinweise: {len(self.load_warnings)} Datei(en) - siehe Journal-Metadaten.")

        self.overview_text.setPlainText("\n".join(lines))

    def update_report_summary(self) -> None:
        if not hasattr(self, "report_text"):
            return
        success_ssh = sum(1 for r in self.ssh_rows if r.get("type") == "Anmeldung erfolgreich")
        external_aliases = sum(1 for r in self.mail_alias_rows if r.get("external_forward"))
        correlated_mail = sum(1 for r in self.mail_access_rows if r.get("ssh_correlation"))
        text = [
            "PDF-Auswertungsbericht",
            "=" * 72,
            "",
            f"Quelle: {self.source_edit.text().strip()}",
            f"Erfolgreiche SSH-Anmeldungen: {success_ssh}",
            f"Web-/VHost-Feststellungen: {len(self.website_rows)}",
            f"Admin-Webzugriffe: {len(self.admin_rows)}",
            f"Mail-Adressen: {len(self.mail_account_rows)}",
            f"Mail-Aliase/Weiterleitungen: {len(self.mail_alias_rows)} (extern: {external_aliases})",
            f"Authentifizierte Mailzugriffe: {len(self.mail_access_rows)} (mit SSH-IP-Korrelation: {correlated_mail})",
            f"TLS-/Zertifikatsfeststellungen: {len(self.tls_rows)}",
            f"Dienste: {len(self.service_rows)}",
            f"Betreiber-Artefakte: {len(self.artifact_rows)}",
            "",
            "Der PDF-Bericht übernimmt die zusammengefassten Erkenntnisse und deren Quellenbezug. "
            "Kennwörter, Passwort-Hashes und erkannte Secrets werden nicht exportiert.",
        ]
        self.report_text.setPlainText("\n".join(text))

    def show_selected_event(self) -> None:
        selected = self.events_view.selectionModel().selectedRows()
        if not selected:
            self.details_text.clear()
            return
        proxy_index = selected[0]
        source_index = self.events_proxy.mapToSource(proxy_index)
        event = self.events_model.rows[source_index.row()]
        raw = event.get("raw", {})
        detail = {
            "normalized": {k: v for k, v in event.items() if k != "raw"},
            "original_fields": raw,
        }
        self.details_text.setPlainText(json.dumps(detail, ensure_ascii=False, indent=2, sort_keys=True))

    def filtered_events(self) -> list[dict[str, Any]]:
        rows = []
        for proxy_row in range(self.events_proxy.rowCount()):
            proxy_index = self.events_proxy.index(proxy_row, 0)
            source_index = self.events_proxy.mapToSource(proxy_index)
            rows.append(self.events_model.rows[source_index.row()])
        return rows

    def export_pdf_report(self) -> None:
        if not (self.events or self.website_rows or self.service_rows or self.admin_rows or self.mail_server_rows or self.tls_rows or self.artifact_rows):
            QMessageBox.information(self, APP_NAME, "Noch keine Auswertung vorhanden.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Server-Auswertungsbericht als PDF exportieren",
            "Forensic_Server_Analyzer_Auswertungsbericht.pdf",
            "PDF (*.pdf)",
        )
        if not path:
            return
        if not path.lower().endswith(".pdf"):
            path += ".pdf"
        try:
            export_forensic_pdf(
                path=path,
                app_name=APP_NAME,
                app_version=APP_VERSION,
                source=self.source_edit.text().strip(),
                events=self.events,
                ssh_rows=self.ssh_rows,
                admin_rows=self.admin_rows,
                websites=self.website_rows,
                services=self.service_rows,
                mail_servers=self.mail_server_rows,
                mail_accounts=self.mail_account_rows,
                mail_aliases=self.mail_alias_rows,
                mail_accesses=self.mail_access_rows,
                mail_diagnostics=self.mail_diagnostic_rows,
                tls_certificates=self.tls_rows,
                operator_artifacts=self.artifact_rows,
                metadata=self.metadata_rows,
                scan_notes=self.server_scan.scan_notes,
            )
        except Exception as exc:
            QMessageBox.critical(self, APP_NAME, f"PDF-Export fehlgeschlagen:\n{exc}")
            return
        self.statusBar().showMessage(f"PDF-Bericht exportiert: {path}", 15000)
        QMessageBox.information(self, APP_NAME, f"PDF-Bericht wurde erstellt:\n{path}")

    def export_csv(self) -> None:
        rows = self.filtered_events()
        if not rows:
            QMessageBox.information(self, APP_NAME, "Keine Ereignisse zum Exportieren vorhanden.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "CSV exportieren", "journal_events.csv", "CSV (*.csv)")
        if not path:
            return
        fields = [
            "time_utc", "host", "service", "pid", "uid", "unit", "boot_id", "priority",
            "category", "message", "ips", "cursor", "source_file"
        ]
        with open(path, "w", newline="", encoding="utf-8-sig") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields, delimiter=";")
            writer.writeheader()
            for event in rows:
                out = {key: event.get(key, "") for key in fields}
                out["ips"] = ", ".join(event.get("ips", []))
                writer.writerow(out)
        self.statusBar().showMessage(f"CSV exportiert: {path}", 10000)

    def export_json(self) -> None:
        rows = self.filtered_events()
        if not rows:
            QMessageBox.information(self, APP_NAME, "Keine Ereignisse zum Exportieren vorhanden.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "JSON exportieren", "journal_events.json", "JSON (*.json)")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(rows, handle, ensure_ascii=False, indent=2)
        self.statusBar().showMessage(f"JSON exportiert: {path}", 10000)

    def show_about(self) -> None:
        QMessageBox.about(
            self,
            APP_NAME,
            f"{APP_NAME} {APP_VERSION}\n\n"
            "Forensisches Analysewerkzeug zur strukturierten Auswertung von Linux-Serverabbildern unter Windows.\n"
            "Die Quelldateien werden ausschließlich lesend verarbeitet.\n\n"
            "Projektquelle:\n"
            "https://github.com/gl1tchb1rd/server_analyzer\n\n"
            "Lizenz:\n"
            "GNU General Public License v3 oder später (GPL-3.0-or-later).\n\n"
            "Drittanbieter-Komponenten (werden bei Bedarf lokal nachgeladen):\n"
            "PySide6 / Qt for Python – LGPL-3.0 / GPL-3.0 / kommerzielle Qt-Lizenz\n"
            "lz4 – BSD-3-Clause\n"
            "zstandard – BSD-3-Clause\n"
            "ReportLab – BSD-Lizenz\n"
            "PyInstaller (optional für Builds) – GPL-2.0-or-later mit spezieller Ausnahme\n\n"
            "DISCLAIMER / WICHTIGER HINWEIS:\n"
            "Die Software dient ausschließlich der technischen Ermittlungs- und Auswertungsunterstützung. "
            "Automatisch erzeugte Ergebnisse können unvollständig, fehlerhaft oder missverständlich sein und müssen "
            "durch die bearbeitende Person anhand der Originalquellen verifiziert und sachlich bewertet werden. "
            "Insbesondere stellt die Korrelation einer IP-Adresse für sich allein keine sichere personenbezogene Zuordnung dar. "
            "Die Prüfung der rechtlichen Zulässigkeit sämtlicher daraus resultierender Ermittlungs-, Sicherungs-, "
            "Auskunfts- oder sonstiger Maßnahmen liegt beim Nutzer bzw. bei der nutzenden Stelle.\n\n"
            "Passwörter/Secrets werden nicht in den PDF-Bericht übernommen. "
            "Weitere Lizenz- und Haftungshinweise befinden sich in LICENSE, THIRD_PARTY_NOTICES.md und DISCLAIMER.md.",
        )


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(APP_VERSION)
    window = JournalAnalyzerWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
