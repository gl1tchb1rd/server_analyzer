FORENSIC SERVER ANALYZER 0.6.0 - WINDOWS
==================================

START
-----
1. ZIP vollständig in einen Arbeitsordner entpacken.
2. Forensic_Server_Analyzer.py doppelklicken bzw. mit Python 3.11 oder neuer starten.
3. Beim ersten Start wird automatisch eine lokale Programmumgebung eingerichtet
   und die benötigten Abhängigkeiten werden geprüft/installiert.
4. Danach startet die grafische Oberfläche.

Im Hauptordner befinden sich bewusst nur diese Startdatei und die README.
Technische Programmdateien liegen unter _system, die lokale Python-Umgebung wird
unter _runtime angelegt. Unter Windows setzt der Starter beide Ordner zusätzlich
auf "hidden". Falls eine technische Fehlersuche erforderlich ist, können in
Explorer "Ausgeblendete Elemente" eingeblendet werden.

ERSTER START / NETZWERK
-----------------------
Die Auswertung selbst arbeitet lokal und benötigt keine Internetverbindung.
Die erstmalige Standardinstallation der Python-Abhängigkeiten benötigt jedoch
Zugriff auf eine von der Dienststelle freigegebene pip-Paketquelle.

Für vollständig abgeschottete Systeme kann die IT die benötigten Wheels unter
_system\wheels ablegen. Der Starter versucht einen vorhandenen vollständigen
Wheel-Bestand zuerst offline zu verwenden.

VORAUSSETZUNG
-------------
- Windows
- Python 3.11 oder neuer
- keine Linux-/WSL-Umgebung erforderlich

AUSWERTUNGSQUELLE
-----------------
Für die vollständige Auswertung möglichst den Root-Ordner eines bereits mit dem
Forensikwerkzeug zugänglich gemachten Linux-Dateisystems auswählen, z. B.:

X:\Serverimage\
  etc\
  var\
  home\
  usr\
  ...

RAW-/E01-/Ext4-Images werden derzeit nicht selbst gemountet. Das Dateisystem
muss vorher read-only sichtbar gemacht oder in einen Arbeitsordner extrahiert
werden.

SCHWERPUNKTE 0.6.0

NGINX:
- vollständige Inventarisierung von /etc/nginx einschließlich sites-available und sites-enabled
- keine Beschränkung auf .conf-Dateien; Domain-Dateinamen werden berücksichtigt
- rekursive Include-Rekonstruktion innerhalb von VHosts
- aktive Konfiguration und bloße Konfigurationsfunde bleiben getrennt gekennzeichnet

MAIL 0.6.0:
- Plesk-Mailstorage dynamisch über PLESK_MAILNAMES_D aus /etc/psa/psa.conf
- Windows-/Forensik-Symlink-Fallbacks auch für Mailpfade
- Plesk/Qmail-Mailkonten, Maildir-/mdbox-/sdbox-Hinweise und .qmail-Weiterleitungen
- Dovecot-Includes ohne Beschränkung auf .conf-Dateien und dynamische passwd-file-Pfade
- ergänzende Prüfung typischer Vmail-, System-Maildir- und mbox-Strukturen
- Accountbewertung als Belegt / Konfiguriert / Hinweis
- eigener Mail-Diagnose-Reiter und Mail-Diagnose im PDF-Bericht

------------------
- systemd-Journal direkt unter Windows auswerten
- erfolgreiche SSH-Anmeldungen priorisieren
- Web-Adminzugriffe (u. a. WordPress, Plesk, Nextcloud, phpMyAdmin) bewerten
- Nginx-Include-Kette, Domains/VHosts, Listen-Ports, DocumentRoots,
  Reverse-Proxies, FastCGI/PHP, Access-/Error-Logs und TLS-Pfade ermitteln
- Apache-/Plesk-VHosts und Webanwendungsmarker erfassen
- Postfix/Dovecot/Exim-Konfigurationen auswerten
- Maildomains, Mail-Adressen, Aliase und externe Weiterleitungen ermitteln
- authentifizierte IMAP/POP3/SMTP-Zugriffe erkennen und mit erfolgreichen
  SSH-Quell-IP-Adressen korrelieren
- TLS-/Let's-Encrypt-Zertifikate und SAN-Domains auswerten
- SSH authorized_keys/known_hosts, Git-Identitäten, Shell-History und Cron als
  Betreiber-Artefakte erfassen
- weitere Dienste erkennen
- zusammenfassenden PDF-Auswertungsbericht erzeugen

SICHERHEIT / FORENSIK
---------------------
Die analysierten Quelldateien werden ausschließlich lesend geöffnet.
Originalimage und originäre Beweismittel sind unabhängig hiervon unverändert und
beweissicher aufzubewahren.

Eine erfolgreiche technische Anmeldung belegt die erfolgreiche Authentifizierung
des protokollierten Kontos von der protokollierten Quell-IP. Sie stellt für sich
allein keine sichere personenbezogene Zuordnung zum Betreiber dar.

Kennwörter, Passwort-Hashes und erkannte Secrets werden nicht in den PDF-Bericht
übernommen. Offensichtliche Secrets in Shell-/Cron-Befehlen werden in der Anzeige
maskiert.

PDF-BERICHT
-----------
Im Reiter "Bericht" oder über Datei -> Server-Auswertungsbericht als PDF
exportieren kann nach der Auswertung ein zusammenfassender Bericht erstellt
werden. Er enthält die erkannten Befunde sowie Quellenbezüge und Hinweise zu
Auswertungsgrenzen.

VERSION
-------
0.6.0 - technisch auf dem bewährten Funktionsstand 0.4.3 basierender Windows-zentrierter Linux Server Evidence Analyzer mit Web-, Mail-,
TLS-, Betreiber-Artefakt- und PDF-Auswertung.


LIZENZ / PROJEKTQUELLE
----------------------
Forensic Server Analyzer wird unter GNU GPL-3.0-or-later veröffentlicht.
Projektquelle: https://github.com/gl1tchb1rd/server_analyzer

Die beim ersten Start nachgeladenen Drittanbieterpakete bleiben unter ihren
jeweiligen eigenen Lizenzen. Einzelheiten: THIRD_PARTY_NOTICES.md.

WICHTIGER HINWEIS / DISCLAIMER
------------------------------
Die Software dient ausschließlich der technischen Ermittlungs- und
Auswertungsunterstützung. Automatisch erzeugte Ergebnisse sind anhand der
Originalquellen zu verifizieren und fachlich zu bewerten. Eine technische
Korrelation, insbesondere anhand einer IP-Adresse, stellt für sich allein keine
sichere personenbezogene Zuordnung dar. Die rechtliche Bewertung und die
Zulässigkeit daraus resultierender Maßnahmen obliegen dem Nutzer bzw. der
nutzenden Stelle. Vollständiger Text: DISCLAIMER.md.
