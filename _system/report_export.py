from __future__ import annotations

from collections import Counter
from html import escape
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

MAX_DETAIL_ROWS = 1000
MAX_ARTIFACT_ROWS = 600


def _txt(value: Any) -> str:
    return escape("" if value is None else str(value)).replace("\n", "<br/>")


def _styles():
    styles = getSampleStyleSheet()
    normal = ParagraphStyle(
        "K25Normal", parent=styles["BodyText"], fontName="Helvetica", fontSize=8, leading=10,
        spaceAfter=2 * mm, alignment=TA_LEFT,
    )
    small = ParagraphStyle(
        "K25Small", parent=normal, fontSize=6.2, leading=7.5, wordWrap="CJK",
    )
    heading1 = ParagraphStyle(
        "K25H1", parent=styles["Heading1"], fontName="Helvetica-Bold", fontSize=17,
        leading=20, spaceAfter=5 * mm,
    )
    heading2 = ParagraphStyle(
        "K25H2", parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=12,
        leading=14, spaceBefore=5 * mm, spaceAfter=2 * mm,
    )
    heading3 = ParagraphStyle(
        "K25H3", parent=styles["Heading3"], fontName="Helvetica-Bold", fontSize=9,
        leading=11, spaceBefore=2 * mm, spaceAfter=1 * mm,
    )
    return normal, small, heading1, heading2, heading3


def _p(value: Any, style) -> Paragraph:
    return Paragraph(_txt(value), style)


def _table(headers: list[str], rows: list[list[Any]], widths: list[float], small_style, empty: str):
    if not rows:
        return Paragraph(f"<i>{_txt(empty)}</i>", small_style)
    data = [[_p(h, small_style) for h in headers]]
    data.extend([[_p(v, small_style) for v in row] for row in rows])
    table = Table(data, colWidths=widths, repeatRows=1, hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e6e6e6")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#999999")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 2.2),
                ("RIGHTPADDING", (0, 0), (-1, -1), 2.2),
                ("TOPPADDING", (0, 0), (-1, -1), 2.2),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2.2),
            ]
        )
    )
    return table


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.drawString(12 * mm, 7 * mm, "Forensic Server Analyzer - maschinell erzeugter Auswertungsbericht")
    canvas.drawRightString(landscape(A4)[0] - 12 * mm, 7 * mm, f"Seite {doc.page}")
    canvas.restoreState()


def export_forensic_pdf(
    path: str,
    app_name: str,
    app_version: str,
    source: str,
    events: list[dict[str, Any]],
    ssh_rows: list[dict[str, Any]],
    admin_rows: list[dict[str, Any]],
    websites: list[dict[str, Any]],
    services: list[dict[str, Any]],
    mail_servers: list[dict[str, Any]],
    mail_accounts: list[dict[str, Any]],
    mail_aliases: list[dict[str, Any]],
    mail_accesses: list[dict[str, Any]],
    mail_diagnostics: list[dict[str, Any]],
    tls_certificates: list[dict[str, Any]],
    operator_artifacts: list[dict[str, Any]],
    metadata: list[dict[str, Any]],
    scan_notes: list[str],
) -> None:
    normal, small, h1, h2, h3 = _styles()
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    doc = SimpleDocTemplate(
        str(target), pagesize=landscape(A4), rightMargin=12 * mm, leftMargin=12 * mm,
        topMargin=12 * mm, bottomMargin=12 * mm, title="Auswertungsbericht Linux-Server",
        author=f"{app_name} {app_version}",
    )

    success_ssh = [r for r in ssh_rows if r.get("type") == "Anmeldung erfolgreich"]
    success_ip_counts = Counter(str(r.get("ip", "")) for r in success_ssh if r.get("ip"))
    times = [str(e.get("time_utc", "")) for e in events if e.get("time_utc")]
    period = f"{min(times)} bis {max(times)}" if times else "keine Journal-Zeitstempel verfügbar"
    external_aliases = [r for r in mail_aliases if r.get("external_forward")]
    correlated_mail = [r for r in mail_accesses if r.get("ssh_correlation")]
    strong_admin = [r for r in admin_rows if str(r.get("assessment", "")).startswith("Starker Hinweis")]

    story = [
        Paragraph("Auswertungsbericht - Linux-Server", h1),
        _table(
            ["Angabe", "Wert"],
            [
                ["Werkzeug", f"{app_name} {app_version}"],
                ["Projektquelle", "https://github.com/gl1tchb1rd/server_analyzer"],
                ["Ausgewertete Quelle", source],
                ["Journal-Zeitraum (UTC)", period],
                ["Journal-Ereignisse", len(events)],
                ["Erfolgreiche SSH-Anmeldungen", len(success_ssh)],
                ["Website-/VHost-Feststellungen", len(websites)],
                ["Admin-Webzugriffe", len(admin_rows)],
                ["Mail-Adressen", len(mail_accounts)],
                ["Authentifizierte Mailzugriffe", len(mail_accesses)],
                ["TLS-/Zertifikatsfeststellungen", len(tls_certificates)],
            ],
            [58 * mm, 207 * mm], small, "",
        ),
        Spacer(1, 4 * mm),
        Paragraph(
            "<b>Bewertungshinweis:</b> Eine erfolgreiche technische Authentifizierung belegt den Zugriff des protokollierten "
            "Kontos von der protokollierten Quell-IP, nicht automatisch die personenbezogene Identität des Nutzers. "
            "Bei Web-Administrationsoberflächen wird zwischen Seitenaufruf, abgewiesenem Zugriff und stärkeren Login-Indizien unterschieden. "
            "Konfigurationsfunde belegen eine vorhandene Konfiguration; die tatsächliche Erreichbarkeit im gesamten Tatzeitraum ist gesondert zu bewerten.",
            normal,
        ),
        Paragraph(
            "<b>Schutz von Zugangsdaten:</b> Kennwörter, Passwort-Hashes und erkannte Secrets werden durch den Bericht nicht ausgegeben.",
            normal,
        ),
        Paragraph("1. Erfolgreiche SSH-Anmeldungen", h2),
        Paragraph(f"Erkannte erfolgreiche SSH-Anmeldungen: <b>{len(success_ssh)}</b>", normal),
        Paragraph("Quell-IP-Adressen", h3),
        _table(
            ["Quell-IP", "Erfolgreiche SSH-Anmeldungen"],
            [[ip, count] for ip, count in success_ip_counts.most_common()],
            [90 * mm, 70 * mm], small, "Keine erfolgreichen SSH-Anmeldungen erkannt.",
        ),
        Paragraph("Einzelereignisse", h3),
        _table(
            ["Zeit UTC", "Benutzer", "Quell-IP", "Methode", "Quelle"],
            [[r.get("time_utc", ""), r.get("user", ""), r.get("ip", ""), r.get("method", ""), r.get("source_file", "")] for r in success_ssh[:MAX_DETAIL_ROWS]],
            [42 * mm, 35 * mm, 38 * mm, 30 * mm, 120 * mm], small,
            "Keine erfolgreichen SSH-Anmeldungen erkannt.",
        ),
        PageBreak(),
        Paragraph("2. Zugriffe auf Administrationsoberflächen", h2),
        Paragraph(f"Erkannte Admin-Webzugriffe: <b>{len(admin_rows)}</b>; davon starke Login-Hinweise: <b>{len(strong_admin)}</b>.", normal),
        _table(
            ["Zeit UTC", "Tool", "Bewertung", "Quell-IP", "SSH-Korrelation", "Methode", "Pfad", "HTTP", "Site/VHost", "Quelle"],
            [[r.get("time_utc", ""), r.get("tool", ""), r.get("assessment", ""), r.get("ip", ""), r.get("ssh_correlation", ""), r.get("method", ""), r.get("path", ""), r.get("status", ""), r.get("site", ""), r.get("source_file", "")] for r in admin_rows[:MAX_DETAIL_ROWS]],
            [24 * mm, 18 * mm, 45 * mm, 25 * mm, 32 * mm, 14 * mm, 45 * mm, 10 * mm, 22 * mm, 35 * mm], small,
            "Keine typischen Adminzugriffe in den ausgewerteten Access-Logs erkannt.",
        ),
        Paragraph("3. Webserver, Domains und Anwendungen", h2),
        _table(
            ["Aktiv", "Webserver", "Domain(s) / URL(s)", "Listen", "DocumentRoot", "Anwendung", "Reverse Proxy", "TLS", "Access-Log", "Quelle"],
            [[r.get("active", ""), r.get("webserver", ""), (str(r.get("domains", "")) + ("\n" + str(r.get("urls", "")) if r.get("urls") else "")), r.get("listen", ""), r.get("document_root", ""), r.get("application", ""), r.get("proxy_pass", ""), r.get("ssl_certificate", ""), r.get("access_log", ""), r.get("source_file", "")] for r in websites],
            [14 * mm, 16 * mm, 36 * mm, 18 * mm, 36 * mm, 18 * mm, 30 * mm, 28 * mm, 25 * mm, 50 * mm], small,
            "Keine VHost-/Website-Konfiguration erkannt.",
        ),
        PageBreak(),
        Paragraph("4. Mailsystem", h2),
        Paragraph("Mailserver / Domains", h3),
        _table(
            ["Komponente", "Hostname", "Maildomain(s)", "Relay", "Interfaces", "Protokolle", "Quelle", "Hinweis"],
            [[r.get("component", ""), r.get("hostname", ""), r.get("domains", ""), r.get("relay", ""), r.get("interfaces", ""), r.get("protocols", ""), r.get("source_file", ""), r.get("notes", "")] for r in mail_servers],
            [20 * mm, 30 * mm, 45 * mm, 34 * mm, 26 * mm, 22 * mm, 48 * mm, 45 * mm], small,
            "Keine unterstützte Mailserver-Konfiguration erkannt.",
        ),
        Paragraph("Erkannte Mail-Adressen", h3),
        _table(
            ["Mail-Adresse", "Domain", "Bewertung", "Nachweis", "Quelle", "Detail"],
            [[r.get("address", ""), r.get("domain", ""), r.get("assessment", ""), r.get("evidence", ""), r.get("source_file", ""), r.get("detail", "")] for r in mail_accounts[:MAX_DETAIL_ROWS]],
            [45 * mm, 30 * mm, 24 * mm, 46 * mm, 58 * mm, 68 * mm], small,
            "Keine Mail-Adressen aus unterstützten Quellen abgeleitet.",
        ),
        Paragraph("Aliase / Weiterleitungen", h3),
        Paragraph(f"Aliase/Weiterleitungen: <b>{len(mail_aliases)}</b>; davon als externe Weiterleitung markiert: <b>{len(external_aliases)}</b>.", normal),
        _table(
            ["Alias/Adresse", "Ziel", "Extern", "Nachweis", "Quelle"],
            [[r.get("alias", ""), r.get("target", ""), r.get("external_forward", ""), r.get("evidence", ""), r.get("source_file", "")] for r in mail_aliases[:MAX_DETAIL_ROWS]],
            [50 * mm, 58 * mm, 18 * mm, 60 * mm, 84 * mm], small,
            "Keine Aliase/Weiterleitungen erkannt.",
        ),
        Paragraph("Authentifizierte Mailzugriffe", h3),
        Paragraph(f"Erkannte Mail-Authentifizierungen: <b>{len(mail_accesses)}</b>; davon mit erfolgreicher SSH-IP korreliert: <b>{len(correlated_mail)}</b>.", normal),
        _table(
            ["Zeit/Logzeit", "Dienst", "Ergebnis", "Benutzer", "Quell-IP", "SSH-Korrelation", "Quelle"],
            [[r.get("time", ""), r.get("service", ""), r.get("result", ""), r.get("user", ""), r.get("ip", ""), r.get("ssh_correlation", ""), r.get("source_file", "")] for r in mail_accesses[:MAX_DETAIL_ROWS]],
            [34 * mm, 28 * mm, 34 * mm, 42 * mm, 26 * mm, 48 * mm, 58 * mm], small,
            "Keine unterstützten Mail-Login-/Authentifizierungsereignisse erkannt.",
        ),
        Paragraph("Mail-Diagnose", h3),
        _table(
            ["Bereich", "Prüfung", "Wert", "Status", "Quelle / Detail"],
            [[r.get("area", ""), r.get("item", ""), r.get("value", ""), r.get("status", ""), r.get("source_file", "")] for r in mail_diagnostics[:MAX_DETAIL_ROWS]],
            [28 * mm, 62 * mm, 38 * mm, 22 * mm, 121 * mm], small,
            "Keine Mail-Diagnosedaten vorhanden.",
        ),
        PageBreak(),
        Paragraph("5. TLS-/Zertifikatsfeststellungen", h2),
        _table(
            ["Subject/CN", "SAN-Domains", "Aussteller", "Gültig ab", "Gültig bis", "Referenziert durch", "Zertifikat/Quelle", "Status"],
            [[r.get("subject", ""), r.get("sans", ""), r.get("issuer", ""), r.get("not_before", ""), r.get("not_after", ""), r.get("referenced_by", ""), r.get("certificate_path", "") or r.get("source_file", ""), r.get("status", "")] for r in tls_certificates],
            [32 * mm, 46 * mm, 34 * mm, 24 * mm, 24 * mm, 45 * mm, 42 * mm, 24 * mm], small,
            "Keine unterstützten TLS-/Let's-Encrypt-Zertifikate erkannt.",
        ),
        Paragraph("6. Erkannte Dienste", h2),
        _table(
            ["Kategorie", "Dienst", "Nachweis", "Journal-Anzahl", "Erstmals UTC", "Letztmals UTC", "Beleg"],
            [[r.get("category", ""), r.get("service", ""), r.get("assessment", ""), r.get("journal_count", ""), r.get("first_seen", ""), r.get("last_seen", ""), r.get("evidence", "")] for r in services],
            [24 * mm, 34 * mm, 58 * mm, 22 * mm, 32 * mm, 32 * mm, 65 * mm], small,
            "Keine typischen Dienste erkannt.",
        ),
        PageBreak(),
        Paragraph("7. Betreiber-Artefakte", h2),
        Paragraph(
            "Die Tabelle enthält insbesondere SSH-Schlüssel/-Ziele, Git-Identitäten, Shell-History und Cron-Funde. "
            "Offensichtliche Kennwort-/Tokenwerte in Befehlszeilen werden maskiert.", normal,
        ),
        _table(
            ["Kategorie", "Benutzer", "Artefakt", "Wert/Befehl/Kommentar", "Detail", "Quelle", "Zeile"],
            [[r.get("category", ""), r.get("owner", ""), r.get("artifact", ""), r.get("value", ""), r.get("detail", ""), r.get("source_file", ""), r.get("line", "")] for r in operator_artifacts[:MAX_ARTIFACT_ROWS]],
            [28 * mm, 20 * mm, 24 * mm, 70 * mm, 48 * mm, 68 * mm, 12 * mm], small,
            "Keine unterstützten Betreiber-Artefakte erkannt.",
        ),
        Paragraph("8. Beweismittel-/Quelldokumentation", h2),
        _table(
            ["Journal-Datei", "Größe", "SHA-256", "Parserstatus"],
            [[r.get("path", ""), r.get("size_human", ""), r.get("sha256", ""), r.get("parse_status", "")] for r in metadata],
            [100 * mm, 20 * mm, 105 * mm, 42 * mm], small,
            "Keine Journal-Dateien ausgewertet. Dateisystembasierte Auswertungen können dennoch erfolgt sein.",
        ),
        Paragraph("9. Hinweise und Auswertungsgrenzen", h2),
    ]

    notes = list(scan_notes)
    if len(success_ssh) > MAX_DETAIL_ROWS:
        notes.append(f"SSH-Detailtabelle im PDF auf {MAX_DETAIL_ROWS} Einträge begrenzt; insgesamt {len(success_ssh)} erfolgreiche Anmeldungen erkannt.")
    if len(admin_rows) > MAX_DETAIL_ROWS:
        notes.append(f"Adminzugriffs-Tabelle im PDF auf {MAX_DETAIL_ROWS} Einträge begrenzt; insgesamt {len(admin_rows)} relevante Webzugriffe erkannt.")
    if len(mail_accounts) > MAX_DETAIL_ROWS:
        notes.append(f"Mail-Adressen im PDF auf {MAX_DETAIL_ROWS} Einträge begrenzt; insgesamt {len(mail_accounts)} erkannt.")
    if len(mail_aliases) > MAX_DETAIL_ROWS:
        notes.append(f"Mail-Aliase im PDF auf {MAX_DETAIL_ROWS} Einträge begrenzt; insgesamt {len(mail_aliases)} erkannt.")
    if len(mail_accesses) > MAX_DETAIL_ROWS:
        notes.append(f"Mail-Authentifizierungen im PDF auf {MAX_DETAIL_ROWS} Einträge begrenzt; insgesamt {len(mail_accesses)} erkannt.")
    if len(mail_diagnostics) > MAX_DETAIL_ROWS:
        notes.append(f"Mail-Diagnose im PDF auf {MAX_DETAIL_ROWS} Einträge begrenzt; insgesamt {len(mail_diagnostics)} vorhanden.")
    if len(operator_artifacts) > MAX_ARTIFACT_ROWS:
        notes.append(f"Betreiber-Artefakte im PDF auf {MAX_ARTIFACT_ROWS} Einträge begrenzt; insgesamt {len(operator_artifacts)} erkannt.")
    if not notes:
        notes.append("Keine zusätzlichen Hinweise.")
    for note in notes:
        story.append(Paragraph(f"- {_txt(note)}", normal))
    story.append(Spacer(1, 3 * mm))
    story.append(
        Paragraph(
            "Die Quelldateien werden durch den Analyzer ausschließlich lesend verarbeitet. Der PDF-Bericht fasst maschinell erkannte "
            "Befunde zusammen; wesentliche Feststellungen sollten anhand der ausgewiesenen Quelldatei und Originaldaten nachvollzogen werden. "
            "Traditionelle Syslog-Zeitstempel in Mail-Logs können Jahr und Zeitzone nicht enthalten und werden deshalb in ihrer Quellform wiedergegeben.",
            normal,
        )
    )

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
