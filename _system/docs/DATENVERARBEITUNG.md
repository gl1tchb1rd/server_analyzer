# Datenverarbeitung / externe Verbindungen

## Laufzeit des Forensic Server Analyzer

Der Forensic Server Analyzer 0.6.0 führt während der eigentlichen Beweismittelauswertung selbst **keine Netzwerkabfragen** durch. Journal-Inhalte, Serverkonfigurationen, Access-/Mail-Logs, IP-Adressen, Hostnamen, Benutzernamen, Mail-Adressen, Zertifikatsdaten und sonstige ausgelesene Ermittlungsdaten werden nicht an externe Dienste übertragen.

Die Analyse erfolgt auf den lokal bzw. über das Forensikwerkzeug bereitgestellten Dateien.

## Erster Start / Python-Abhängigkeiten

`Forensic_Server_Analyzer.py` richtet bei Bedarf unter `_runtime` eine lokale Python-Umgebung ein und verwendet `pip`, um die in `_system/requirements.txt` genannten Pakete zu installieren. Sofern keine interne Paketquelle konfiguriert ist, kann `pip` hierbei eine externe Python-Paketquelle kontaktieren.

Dieser Installationsvorgang findet **vor und unabhängig von der späteren Auswertung** statt. Dabei werden keine Inhalte der auszuwertenden Serverdaten übertragen.

Für abgeschottete Umgebungen kann ein vollständiger, dienstlich freigegebener Wheel-Bestand unter `_system/wheels` bereitgestellt werden. Der Starter versucht einen vorhandenen Wheel-Bestand zunächst ohne Paketindex zu verwenden.

## Read-only-Prinzip

Die auszuwertenden Quelldateien werden vom Analyzer nur lesend geöffnet. Dies betrifft insbesondere:

- systemd-Journal-Dateien
- Nginx-/Apache-/Plesk-Konfigurationen und Access-Logs
- Postfix-/Dovecot-/Exim-Konfigurationen und Mail-Logs
- TLS-/Let's-Encrypt-Zertifikate
- SSH-, Git-, Shell-History- und Cron-Artefakte

Exportdateien (PDF/CSV/JSON) werden ausschließlich an einem vom Benutzer gewählten Zielpfad neu erzeugt.

## Zugangsdaten / Secrets

Der Analyzer sucht nicht nach Kennwörtern als Selbstzweck. Konfigurationsquellen können jedoch Zugangsdaten enthalten. Passwortfelder, Passwort-Hashes und erkannte Secrets werden nicht in den PDF-Bericht übernommen. Offensichtliche Passwort-/Tokenwerte in Shell-/Cron-Befehlen werden in der GUI-Ausgabe maskiert.

Die Originaldatei bleibt als Beweismittel unverändert und kann bei Bedarf mit einem geeigneten Forensikwerkzeug gezielt geprüft werden.
