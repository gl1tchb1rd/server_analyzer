# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Gl1tchb1rd

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    KeepTogether,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

APP_NAME = "Server Analyzer"
APP_VERSION = "0.5.0"
PROJECT_SOURCE_URL = "https://github.com/gl1tchb1rd/server_analyzer"

DISCLAIMER_SHORT = (
    "Der Bericht wurde automatisiert zur Ermittlungs- und Auswertungsunterstützung erzeugt. "
    "Automatische Erkennungen und Korrelationen können unvollständig oder fehlerhaft sein und sind anhand der "
    "ausgewiesenen Quelldateien und Originaldaten zu verifizieren. Eine technische IP-Korrelation stellt für sich "
    "allein keine sichere personenbezogene Zuordnung dar. Sachliche Bewertung und rechtliche Prüfung verbleiben "
    "beim Nutzer bzw. bei der nutzenden Stelle."
)


def _p(value: Any, style: ParagraphStyle) -> Paragraph:
    text = "" if value is None else str(value)
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    text = text.replace("\n", "<br/>")
    return Paragraph(text, style)


def _join(value: Any) -> str:
    if isinstance(value, (list, tuple, set)):
        return ", ".join(str(x) for x in value)
    return "" if value is None else str(value)


def _make_table(headers: list[str], rows: Iterable[Iterable[Any]], widths: list[float] | None, styles) -> Table:
    body = [[_p(h, styles["table_header"]) for h in headers]]
    for row in rows:
        body.append([_p(_join(v), styles["table"]) for v in row])
    table = Table(body, colWidths=widths, repeatRows=1, hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E9EDF2")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#20252B")),
                ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#BFC5CC")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return table


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("ServerAnalyzerTitle", parent=base["Title"], fontName="Helvetica-Bold", fontSize=20, leading=24, alignment=TA_LEFT, spaceAfter=8),
        "h1": ParagraphStyle("ServerAnalyzerH1", parent=base["Heading1"], fontName="Helvetica-Bold", fontSize=14, leading=17, spaceBefore=8, spaceAfter=6),
        "h2": ParagraphStyle("ServerAnalyzerH2", parent=base["Heading2"], fontName="Helvetica-Bold", fontSize=11, leading=14, spaceBefore=6, spaceAfter=4),
        "normal": ParagraphStyle("ServerAnalyzerNormal", parent=base["BodyText"], fontName="Helvetica", fontSize=8.5, leading=11),
        "small": ParagraphStyle("ServerAnalyzerSmall", parent=base["BodyText"], fontName="Helvetica", fontSize=7.2, leading=9),
        "table": ParagraphStyle("ServerAnalyzerTable", parent=base["BodyText"], fontName="Helvetica", fontSize=6.8, leading=8.4),
        "table_header": ParagraphStyle("ServerAnalyzerTableHeader", parent=base["BodyText"], fontName="Helvetica-Bold", fontSize=6.8, leading=8.4),
        "warning": ParagraphStyle("ServerAnalyzerWarning", parent=base["BodyText"], fontName="Helvetica-Bold", fontSize=8.2, leading=10.5, borderWidth=0.5, borderColor=colors.HexColor("#888888"), borderPadding=6, backColor=colors.HexColor("#F6F6F6")),
    }


def export_pdf(path: Path, result: dict[str, Any]) -> None:
    path = Path(path)
    styles = _styles()
    pagesize = landscape(A4)
    width, height = pagesize

    doc = BaseDocTemplate(
        str(path),
        pagesize=pagesize,
        leftMargin=14 * mm,
        rightMargin=14 * mm,
        topMargin=14 * mm,
        bottomMargin=14 * mm,
        title=f"{APP_NAME} – Auswertungsbericht",
        author="Gl1tchb1rd",
        creator=f"{APP_NAME} {APP_VERSION}",
    )

    frame = Frame(doc.leftMargin, doc.bottomMargin + 7 * mm, doc.width, doc.height - 7 * mm, id="normal")

    def footer(canvas, _doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.HexColor("#666666"))
        canvas.drawString(doc.leftMargin, 7 * mm, f"{APP_NAME} – maschinell erzeugter Auswertungsbericht")
        canvas.drawRightString(width - doc.rightMargin, 7 * mm, f"Seite {_doc.page}")
        canvas.restoreState()

    doc.addPageTemplates([PageTemplate(id="main", frames=frame, onPage=footer)])
    story: list[Any] = []
    story += [
        Paragraph("Server-Auswertungsbericht", styles["title"]),
        _make_table(
            ["Feld", "Angabe"],
            [
                ("Werkzeug", f"{APP_NAME} {APP_VERSION}"),
                ("Projektquelle", PROJECT_SOURCE_URL),
                ("Ausgewertete Quelle", result.get("root", "")),
                ("Auswertung erzeugt", result.get("generated_at", datetime.now(timezone.utc).isoformat())),
                ("Modus", "Read-only / Offline-Auswertung"),
            ],
            [42 * mm, 210 * mm],
            styles,
        ),
        Spacer(1, 5 * mm),
        Paragraph("Wichtiger Bewertungshinweis", styles["h2"]),
        Paragraph(DISCLAIMER_SHORT, styles["warning"]),
        Spacer(1, 4 * mm),
    ]

    summary = result.get("summary", {})
    story += [Paragraph("1. Übersicht", styles["h1"])]
    story.append(
        _make_table(
            ["Kennzahl", "Wert"],
            [
                ("Journal-Dateien", summary.get("journal_files", 0)),
                ("Journal-Ereignisse", summary.get("journal_events", 0)),
                ("Erfolgreiche SSH-Anmeldungen", summary.get("ssh_success", 0)),
                ("Websites/VHosts", summary.get("websites", 0)),
                ("Admin-Webzugriffe", summary.get("admin_access", 0)),
                ("Mailkonten/-adressen", summary.get("mail_accounts", 0)),
                ("Authentifizierte Mailzugriffe", summary.get("mail_access", 0)),
                ("Dienste", summary.get("services", 0)),
                ("TLS-Zertifikate", summary.get("tls", 0)),
                ("Betreiber-Artefakte", summary.get("artifacts", 0)),
            ],
            [75 * mm, 60 * mm],
            styles,
        )
    )

    ssh = result.get("ssh", [])
    story += [Paragraph("2. Erfolgreiche SSH-Anmeldungen", styles["h1"])]
    if ssh:
        story.append(_make_table(["Zeit (UTC)", "Benutzer", "Quell-IP", "Auth.", "Quelle"], ((x.get("timestamp"), x.get("user"), x.get("ip"), x.get("method"), x.get("source")) for x in ssh), [48*mm, 32*mm, 38*mm, 32*mm, 105*mm], styles))
    else:
        story.append(Paragraph("Keine erfolgreichen SSH-Anmeldungen erkannt.", styles["normal"]))

    admin = result.get("admin_access", [])
    story += [Paragraph("3. Web-/Administrationszugriffe", styles["h1"])]
    if admin:
        story.append(_make_table(["Zeit", "IP", "Anwendung", "Request", "Status", "Bewertung", "SSH-Korrelation"], ((x.get("timestamp"), x.get("ip"), x.get("application"), f"{x.get('method')} {x.get('path')}", x.get("status"), x.get("assessment"), "ja" if x.get("ssh_correlated") else "nein") for x in admin), [40*mm, 30*mm, 28*mm, 70*mm, 18*mm, 58*mm, 24*mm], styles))
    else:
        story.append(Paragraph("Keine priorisierten Web-/Administrationszugriffe erkannt.", styles["normal"]))

    websites = result.get("websites", [])
    story += [Paragraph("4. Websites / Domains", styles["h1"])]
    if websites:
        story.append(_make_table(["Domain", "Server", "Status", "URLs", "DocumentRoot / Proxy", "Anwendung", "Quelle"], ((x.get("domain"), x.get("server"), x.get("status"), x.get("urls"), x.get("document_root") or x.get("proxy_pass"), x.get("application"), x.get("source")) for x in websites), [43*mm, 20*mm, 38*mm, 48*mm, 55*mm, 26*mm, 52*mm], styles))
    else:
        story.append(Paragraph("Keine Web-VHosts erkannt.", styles["normal"]))

    nginx_diag = result.get("diagnostics", {}).get("nginx", {})
    if nginx_diag:
        story += [Paragraph("NGINX-Verzeichnisdiagnose", styles["h2"])]
        story.append(_make_table(["Parameter", "Wert"], ((k, v) for k, v in nginx_diag.items()), [80*mm, 120*mm], styles))

    mail = result.get("mail", {})
    story += [Paragraph("5. Mail-Infrastruktur", styles["h1"])]
    accounts = mail.get("accounts", [])
    if accounts:
        story.append(_make_table(["Adresse", "Bewertung", "Nachweise", "Mailbox", "Weiterleitung(en)"], ((x.get("address"), x.get("assessment"), x.get("evidence"), x.get("mailbox_path"), x.get("forwarding")) for x in accounts), [48*mm, 28*mm, 80*mm, 65*mm, 65*mm], styles))
    else:
        story.append(Paragraph("Keine Mailkonten/-adressen erkannt.", styles["normal"]))

    accesses = mail.get("accesses", [])
    if accesses:
        story += [Paragraph("Authentifizierte Mailzugriffe", styles["h2"])]
        story.append(_make_table(["Zeit", "Protokoll", "Benutzer", "Quell-IP", "SSH-Korrelation", "Quelle"], ((x.get("timestamp"), x.get("protocol"), x.get("user"), x.get("ip"), "ja" if x.get("ssh_correlated") else "nein", x.get("source")) for x in accesses), [38*mm, 28*mm, 55*mm, 36*mm, 32*mm, 85*mm], styles))

    if mail.get("diagnostics"):
        story += [Paragraph("Mail-Diagnose", styles["h2"])]
        story.append(_make_table(["Parameter", "Wert"], ((k, _join(v)) for k, v in mail["diagnostics"].items()), [80*mm, 150*mm], styles))

    services = result.get("services", [])
    story += [Paragraph("6. Dienste", styles["h1"])]
    if services:
        story.append(_make_table(["Dienst", "Status", "Bewertung", "Quelle/Nachweis", "Details"], ((x.get("service"), x.get("state"), x.get("evidence"), x.get("source"), x.get("details")) for x in services), [42*mm, 52*mm, 28*mm, 85*mm, 70*mm], styles))

    tls = result.get("tls", [])
    story += [Paragraph("7. TLS-Zertifikate / Domains", styles["h1"])]
    if tls:
        story.append(_make_table(["Domains/SAN", "Gültig ab", "Gültig bis", "Aussteller", "Quelle"], ((x.get("domains"), x.get("not_before"), x.get("not_after"), x.get("issuer"), x.get("source")) for x in tls), [70*mm, 40*mm, 40*mm, 75*mm, 70*mm], styles))

    artifacts = result.get("artifacts", [])
    story += [Paragraph("8. Betreiber-/Administrationsartefakte", styles["h1"])]
    if artifacts:
        story.append(_make_table(["Art", "Identität", "Wert", "Bewertung", "Quelle"], ((x.get("kind"), x.get("identity"), x.get("value"), x.get("assessment"), x.get("source")) for x in artifacts), [42*mm, 42*mm, 105*mm, 30*mm, 70*mm], styles))

    ips = result.get("ip_summary", [])
    story += [Paragraph("9. IP-Korrelation", styles["h1"])]
    if ips:
        story.append(_make_table(["IP", "SSH", "Admin-Web", "IMAP/POP", "SMTP AUTH", "Erstes Auftreten", "Letztes Auftreten"], ((x.get("ip"), x.get("ssh"), x.get("admin"), x.get("imap_pop"), x.get("smtp_auth"), x.get("first"), x.get("last")) for x in ips), [38*mm, 18*mm, 25*mm, 25*mm, 25*mm, 58*mm, 58*mm], styles))

    journals = result.get("journal_meta", [])
    story += [Paragraph("10. Journal-Quelldokumentation", styles["h1"])]
    if journals:
        story.append(_make_table(["Datei", "SHA-256", "Größe", "Einträge", "Parserfehler"], ((x.get("path"), x.get("sha256"), x.get("size"), f"{x.get('parsed_entries')}/{x.get('declared_entries')}", x.get("errors")) for x in journals), [92*mm, 92*mm, 27*mm, 30*mm, 27*mm], styles))

    story += [Spacer(1, 5 * mm), Paragraph("Projekt- und Quellenhinweis", styles["h2"]), Paragraph(f"Server Analyzer wird unter GPL-3.0-or-later veröffentlicht. Projektquelle: {PROJECT_SOURCE_URL}", styles["small"])]
    doc.build(story)
