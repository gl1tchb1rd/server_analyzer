# Server Analyzer

**Server Analyzer** ist ein read-only Analysewerkzeug für extrahierte oder von Forensiksoftware bereitgestellte Linux-Server-Dateisysteme. Schwerpunkt ist die schnelle Ermittlungs- und Auswertungsunterstützung: Welche Websites, Mailkonten und Dienste wurden betrieben, und von welchen IP-Adressen erfolgten erfolgreiche administrative Zugriffe?

> **Aktueller Stand: v0.5.0 – Windows 10/11.** Linux und macOS sind derzeit nicht freigegeben oder getestet. Cross-Platform-Unterstützung ist für eine spätere Hauptversion vorgesehen.

## Schwerpunkte

- native Auswertung binärer `systemd-journald`-Dateien unter Windows, ohne WSL oder `journalctl`
- erfolgreiche SSH-Anmeldungen mit Benutzer, Authentifizierungsmethode, Quell-IP und Quelle
- NGINX-VHost-Rekonstruktion aus `nginx.conf`, Includes, `sites-enabled`, `sites-available` und Plesk-VHost-Strukturen
- Apache-VHost-Erkennung
- Web-/Administrationszugriffe auf WordPress, Plesk, phpMyAdmin und Nextcloud mit vorsichtiger Erfolgsbewertung
- Postfix-, Dovecot- und Plesk-Mailanalyse einschließlich Mailkonten, Maildir-/Mailbox-Nachweisen und Weiterleitungen
- erfolgreiche IMAP-/POP3-/SMTP-AUTH-Zugriffe und IP-Korrelation mit SSH
- TLS-/Let's-Encrypt-Zertifikate einschließlich SAN-Domains
- Dienste wie Mail, Webserver, Datenbanken, Docker/Podman, TeamSpeak, Nextcloud, VPN usw.
- Betreiberartefakte wie `authorized_keys`, SSH-Key-Fingerprints, Git-Identitäten/Remotes, Shell-History, Cron und systemd-Units
- PDF-Auswertungsbericht mit Quellenbezug und SHA-256 der ausgewerteten Journaldateien
- JSON-Export der Gesamtauswertung

## Forensische Einordnung

Server Analyzer arbeitet ausschließlich **lesend** auf der ausgewählten Quelle. Die Anwendung mountet oder verändert Datenträgerimages nicht selbst. RAW-/E01-/ext4-Images müssen zuvor mit geeigneter Forensiksoftware read-only bereitgestellt oder extrahiert werden.

Ergebnisse werden bewusst abgestuft dargestellt. Ein vorhandener Konfigurationseintrag ist nicht automatisch gleichbedeutend mit nachgewiesener Nutzung; ein HTTP-200 auf einer Loginseite ist nicht automatisch ein erfolgreicher Login. Wo möglich, werden mehrere unabhängige Quellen korreliert.

Siehe unbedingt [DISCLAIMER.md](DISCLAIMER.md).

## Installation unter Windows

Voraussetzung: **Python 3.11 oder neuer**.

1. Repository herunterladen oder klonen.
2. `Server_Analyzer.py` starten.
3. Beim ersten Lauf erzeugt der Starter lokal `_runtime/venv` und installiert die Abhängigkeiten aus `_system/requirements.txt`.
4. In der GUI das Root-Verzeichnis des extrahierten/gemounteten Linux-Servers auswählen.

```powershell
git clone https://github.com/gl1tchb1rd/server_analyzer.git
cd server_analyzer
py Server_Analyzer.py
```

Die eigentliche Analyse benötigt keine Internetverbindung. Eine Internetverbindung kann beim **ersten** Start für die Installation der Python-Abhängigkeiten erforderlich sein.

## Wichtige Fundstellen

Die Auswertung berücksichtigt unter anderem:

```text
/var/log/journal/
/run/log/journal/
/etc/nginx/
/etc/apache2/
/var/www/vhosts/system/
/var/log/nginx/
/var/log/apache2/
/var/log/plesk/
/etc/postfix/
/etc/dovecot/
/etc/psa/psa.conf
/var/qmail/mailnames/   (oder PLESK_MAILNAMES_D)
/etc/letsencrypt/
/etc/passwd
/root/.ssh/
/home/*/.ssh/
/root/.gitconfig
/home/*/.gitconfig
/etc/systemd/system/
/etc/cron.d/
```

Die tatsächlichen Pfade können distributions- und konfigurationsabhängig abweichen. Der Analyzer versucht deshalb, Includes, konfigurierte Pfade und typische Windows-/Forensik-Mount-Probleme wie nicht direkt auflösbare Linux-Symlinks zu berücksichtigen.

## Verzeichnisstruktur

```text
server_analyzer/
├── Server_Analyzer.py
├── README.md
├── LICENSE
├── DISCLAIMER.md
├── THIRD_PARTY_NOTICES.md
├── CHANGELOG.md
└── _system/
    ├── app.py
    ├── journal_native.py
    ├── server_forensics.py
    ├── mail_forensics.py
    ├── report_export.py
    ├── requirements.txt
    └── licenses/
```

`_runtime/` wird erst lokal erzeugt und gehört nicht ins Repository.

## Datenschutz / Netzwerk

Die Beweismittelauswertung erfolgt lokal. Server Analyzer überträgt während der Analyse keine Inhalte an externe Dienste. Der Starter kann beim ersten Lauf `pip` verwenden, um die in `_system/requirements.txt` genannten Open-Source-Abhängigkeiten nachzuladen.

## Lizenz

Copyright © 2026 Gl1tchb1rd.

Server Analyzer wird unter **GNU GPL-3.0-or-later** veröffentlicht. Siehe [LICENSE](LICENSE) und [LICENSE-NOTICE.md](LICENSE-NOTICE.md). Drittanbieterkomponenten unterliegen ihren jeweiligen Lizenzen; siehe [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

Projektquelle: https://github.com/gl1tchb1rd/server_analyzer
