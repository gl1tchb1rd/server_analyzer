# Changelog

## 0.6.0

- Technischer Rollback auf den bewährten Funktionsstand 0.4.3.
- Sichtbarer Produktname auf **Forensic Server Analyzer** geändert.
- GPL-3.0-or-later, Drittanbieter-Lizenzhinweise und Disclaimer ergänzt.
- Projektquelle im Über-Bereich und im PDF-Auswertungsbericht ergänzt.
- Journal-, NGINX-, Mail-, TLS- und Betreiber-Analysemodule aus 0.4.3 unverändert übernommen.

## 0.4.3

- Mailauswertung für Windows-Forensik-Mounts gehärtet.
- Plesk-Mailstorage wird dynamisch über `PLESK_MAILNAMES_D` aus `/etc/psa/psa.conf` ermittelt; `/var/qmail/mailnames` bleibt als Fallback erhalten.
- Linux-Symlinks und als Textdatei exportierte Symlink-Ziele werden auch im Mailbereich bestmöglich rekonstruiert.
- Plesk/Qmail-Mailkonten, Maildir-/mdbox-/sdbox-Hinweise und `.qmail`-Weiterleitungen werden gemeinsam ausgewertet.
- Dovecot-Include-Dateien werden unabhängig von der Dateiendung inventarisiert; dynamische passwd-file-Pfade mit Benutzer-/Domainvariablen werden offline auf vorhandene Dateien abgebildet.
- System-Maildir- und klassische mbox-Strukturen werden ergänzend geprüft.
- Mailkonten erhalten eine Bewertung `Belegt`, `Konfiguriert` oder `Hinweis` auf Basis mehrerer unabhängiger Quellen.
- Erfolgreiche IMAP/POP3-/SMTP-Authentifizierungen werden als zusätzlicher Account-Nachweis übernommen.
- Neuer GUI-Unterreiter `Mail -> Diagnose` zeigt Storage-Pfade, Auswertungsquellen und nicht lesbare Einträge.
- PDF-Bericht um Mailkonto-Bewertung und Mail-Diagnose erweitert.


## 0.4.2

- NGINX-Auswertung für Windows-Forensik-Mounts gehärtet.
- `sites-enabled` und `sites-available` werden explizit per Verzeichniseinträgen inventarisiert, auch wenn Linux-Symlinks nicht als normale Windows-Dateien erscheinen.
- Symlink-Ziele, die ein Export als kleine Textdatei (`../sites-available/...`) ablegt, werden rekonstruiert.
- Wenn ein Eintrag in `sites-enabled` nicht auflösbar ist, wird die gleichnamige Datei in `sites-available` als Ziel herangezogen.
- Domainartige Dateinamen in `sites-enabled` bleiben als aktiver Konfigurationshinweis erhalten, auch wenn der Mount den Symlink-Inhalt nicht lesbar macht.
- Neue NGINX-Verzeichnisdiagnose meldet Anzahl und Auflösungsart der Einträge in `sites-enabled`/`sites-available`.

## 0.4.1

- NGINX-Inventarisierung deutlich erweitert.
- `sites-available` und `sites-enabled` werden unabhängig von Dateiendungen ausgewertet; Domain-Dateinamen wie `shop.example.de` werden nicht mehr fälschlich verworfen.
- Gesamter `/etc/nginx`-Baum wird als Konfigurationsinventar berücksichtigt; aktive Include-Kette bleibt separat erkennbar.
- NGINX-`include`-Direktiven in VHosts werden rekursiv rekonstruiert, damit `server_name`, `root`, Logging- und Proxy-Direktiven aus Snippets dem VHost zugeordnet werden können.
- Relevante Plesk-VHost-Konfigurationen werden breiter erfasst; Domainname kann zusätzlich aus `/var/www/vhosts/system/<domain>/conf/` abgeleitet werden.
- Fallback-Erkennung für `server_name`-Direktiven bei unvollständig/ungewöhnlich strukturierten Konfigurationsdateien.
- Regressionstests mit 16 domainbenannten VHosts, nur-`sites-available`-Konfiguration und eingebundenem `server_name`-Snippet.

## 0.4.0

- Projekt auf `K25 Server Analyzer` erweitert und Windows als primäre Zielplattform beibehalten.
- neue, vereinfachte Ordnerstruktur: im Hauptordner nur Starter und README; technische Dateien unter `_system`, lokale Laufzeitumgebung unter `_runtime`.
- Python-Starter prüft beim ersten Start automatisch die Abhängigkeiten, erstellt bei Bedarf eine lokale venv und installiert fehlende Pakete.
- optionaler Offline-Wheel-Bestand unter `_system/wheels` wird unterstützt.
- Nginx-Auswertung erweitert: Include-Kette ab `nginx.conf`, aktive Konfiguration, `server_name`, `listen`, `root`, `proxy_pass`, `fastcgi_pass`, Access-/Error-Logs und TLS-Zertifikatspfade.
- Zuordnung von bekannten Nginx-Access-Logs zu den konfigurierten Domains verbessert.
- Mailanalyse ergänzt:
  - Postfix (`main.cf`, Text-Maps, virtuelle Mailboxen/Aliase, Relay)
  - Dovecot (Protokolle, Mailablage, Benutzerdateien)
  - Exim-Grundkonfiguration
  - Plesk/Qmail- und typische Maildir/Vmail-Verzeichnisstrukturen
  - Nextcloud-Mailkonfiguration und sichere `.env`-Mailparameter gängiger Webanwendungen
  - Mail-Adressen, Aliase und externe Weiterleitungen
  - erfolgreiche Dovecot-Logins und Postfix SMTP AUTH aus Mail-Logs/Journal
  - Korrelation von Mail-Quell-IP-Adressen mit erfolgreichen SSH-Anmeldungen
- TLS-/Let's-Encrypt-Auswertung mit Subject, SAN-Domains, Aussteller, Gültigkeit, Seriennummer und Referenzquelle.
- Betreiber-Artefakte ergänzt:
  - lokale Benutzerkonten aus `/etc/passwd`
  - `authorized_keys` inkl. SHA-256-Fingerprint
  - `known_hosts`
  - Git-Identitäten und Git-Repositories/Remote-URLs
  - Bash-/Zsh-History
  - Cron-Aufträge
- offensichtliche Kennwort-/Tokenwerte in Shell-/Cron-Befehlen werden in der Anzeige maskiert.
- PDF-Auswertungsbericht um Web-, Mail-, TLS-, Dienste- und Betreiber-Artefakte erweitert.
- eigener GUI-Reiter `Bericht` für den PDF-Export.

## 0.3.0

- Windows-zentrierte Ermittlungsansicht für erfolgreiche SSH-Zugriffe, Admin-Webzugriffe, Websites/VHosts, Dienste und PDF-Bericht.
- Web-Admin-Korrelation für WordPress, Plesk, Nextcloud und phpMyAdmin.
- Nginx-/Apache-/Plesk-VHost-Erkennung und Service-Signaturen.

## 0.2.0

- nativer systemd-Journal-Parser für Windows; Linux/WSL nicht erforderlich.

## 0.1.0

- erste Journal-GUI mit Timeline, SSH-/IP-Auswertung, SHA-256 und CSV/JSON-Export.
