# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Gl1tchb1rd

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from journal_native import JournalReader, JournalMeta, discover_journals, sha256_file
from mail_forensics import analyze_mail
from server_forensics import (
    analyze_admin_access, analyze_apache, analyze_nginx, analyze_operator_artifacts,
    analyze_services, analyze_tls, collect_ip_summary, extract_successful_ssh,
)

MAX_DISPLAY_JOURNAL = 100_000

def analyze_root(root: Path, status=lambda _x: None) -> dict:
    root = Path(root)
    generated_at = datetime.now(timezone.utc).isoformat()
    status("Suche systemd-Journaldateien …")
    journal_files = discover_journals(root)
    journal_meta: list[dict] = []
    display_events: list[dict[str, str]] = []
    analysis_events: list[dict[str, str]] = []
    warnings: list[str] = []
    unique_units: set[str] = set()
    total_events = 0

    for idx, path in enumerate(journal_files, start=1):
        status(f"Journal {idx}/{len(journal_files)}: {path.name}")
        digest = sha256_file(path)
        parsed = 0
        errors = 0
        try:
            with JournalReader(path) as reader:
                for event in reader.entries():
                    parsed += 1
                    total_events += 1
                    if len(display_events) < MAX_DISPLAY_JOURNAL:
                        display_events.append(event)
                    msg = event.get("MESSAGE", "")
                    lower = msg.lower()
                    keep = (
                        "accepted " in lower
                        or "dovecot" in lower
                        or "-login:" in lower
                        or "sasl_username=" in lower
                        or "authentication" in lower
                    )
                    unit = event.get("_SYSTEMD_UNIT", "")
                    if unit and unit not in unique_units:
                        unique_units.add(unit)
                        keep = True
                    if keep:
                        analysis_events.append(event)
                meta = JournalMeta(
                    path=str(path),
                    sha256=digest,
                    size=path.stat().st_size,
                    compact=reader.compact,
                    compatible_flags=reader.compatible_flags,
                    incompatible_flags=reader.incompatible_flags,
                    header_size=reader.header_size,
                    declared_entries=reader.declared_entries,
                    parsed_entries=parsed,
                    errors=errors,
                )
        except Exception as exc:
            warnings.append(f"Journal konnte nicht vollständig gelesen werden: {path}: {exc}")
            meta = JournalMeta(str(path), digest, path.stat().st_size, False, 0, 0, 0, 0, parsed, errors + 1)
        journal_meta.append(asdict(meta))

    if total_events > MAX_DISPLAY_JOURNAL:
        warnings.append(
            f"Die Journal-Tabelle zeigt aus Speichergründen nur die ersten {MAX_DISPLAY_JOURNAL:,} von {total_events:,} Ereignissen. "
            "Die spezialisierten SSH-/Mail-/Service-Auswertungen werden davon nicht auf diese Anzeigegrenze beschränkt."
        )

    status("Werte erfolgreiche SSH-Anmeldungen aus …")
    ssh = extract_successful_ssh(analysis_events)

    status("Rekonstruiere NGINX-/Apache-Websites …")
    nginx_websites, nginx_diag = analyze_nginx(root)
    apache_websites = analyze_apache(root)
    websites = nginx_websites + [w for w in apache_websites if not any(x["domain"] == w["domain"] and x["server"] == w["server"] for x in nginx_websites)]

    status("Werte Web-/Administrationszugriffe aus …")
    admin = analyze_admin_access(root, ssh)

    status("Analysiere Mail-Infrastruktur …")
    mail = analyze_mail(root, analysis_events, ssh)

    status("Inventarisiere Dienste …")
    services = analyze_services(root, analysis_events)

    status("Analysiere TLS-Zertifikate …")
    tls = analyze_tls(root)

    status("Suche Betreiber-/Administrationsartefakte …")
    artifacts = analyze_operator_artifacts(root)

    ip_summary = collect_ip_summary(ssh, admin, mail.get("accesses", []))
    summary = {
        "journal_files": len(journal_files),
        "journal_events": total_events,
        "ssh_success": len(ssh),
        "websites": len(websites),
        "admin_access": len(admin),
        "mail_accounts": len(mail.get("accounts", [])),
        "mail_access": len(mail.get("accesses", [])),
        "services": len(services),
        "tls": len(tls),
        "artifacts": len(artifacts),
    }
    status("Auswertung abgeschlossen")
    return {
        "root": str(root),
        "generated_at": generated_at,
        "summary": summary,
        "ssh": ssh,
        "websites": websites,
        "admin_access": admin,
        "mail": mail,
        "services": services,
        "tls": tls,
        "artifacts": artifacts,
        "ip_summary": ip_summary,
        "journal_meta": journal_meta,
        "journal_events": display_events,
        "diagnostics": {"nginx": nginx_diag},
        "warnings": warnings,
    }

