from __future__ import annotations

import os
import re
import ssl
from pathlib import Path
from typing import Any

MAX_CONFIG_FILE = 8 * 1024 * 1024
CERT_DIRECTIVE_RE = re.compile(r"(?mi)^\s*ssl_certificate\s+([^;\s]+)\s*;")
POSTFIX_CERT_RE = re.compile(r"(?mi)^\s*(?:smtpd_tls_cert_file|smtp_tls_cert_file)\s*=\s*([^\s#]+)")
DOVECOT_CERT_RE = re.compile(r"(?mi)^\s*ssl_cert\s*=\s*<?([^\s#]+)")


def _safe_rel(root: Path, path: Path) -> str:
    try:
        return "/" + path.relative_to(root).as_posix()
    except (ValueError, OSError):
        return str(path)


def _read_text(path: Path, limit: int = MAX_CONFIG_FILE) -> str:
    try:
        if not path.is_file() or path.stat().st_size > limit:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _host_from_linux(root: Path, linux_path: str) -> Path:
    value = linux_path.strip().strip('"\'').replace("$ssl_server_name", "")
    if value.startswith("/"):
        value = value[1:]
    return root / value


def _rooted_symlink_target(root: Path, path: Path, max_depth: int = 8) -> Path:
    current = path
    for _ in range(max_depth):
        try:
            if not current.is_symlink():
                return current
            target = os.readlink(current)
        except OSError:
            return current
        if os.path.isabs(target):
            current = root / target.lstrip("/\\")
        else:
            current = current.parent / target
        current = Path(os.path.normpath(str(current)))
    return current


def _name_from_x509(value: Any) -> str:
    parts: list[str] = []
    try:
        for rdn in value or ():
            for key, val in rdn:
                if key == "commonName":
                    parts.insert(0, str(val))
                else:
                    parts.append(f"{key}={val}")
    except Exception:
        return str(value or "")
    return ", ".join(parts)


def _decode_cert(path: Path) -> dict[str, Any] | None:
    try:
        decoder = getattr(ssl._ssl, "_test_decode_cert", None)
        if decoder is None:
            return None
        data = decoder(str(path))
        if not isinstance(data, dict):
            return None
        return data
    except (OSError, ValueError, ssl.SSLError):
        return None


def _collect_config_refs(root: Path) -> dict[str, set[str]]:
    refs: dict[str, set[str]] = {}

    nginx_base = root / "etc/nginx"
    if nginx_base.is_dir():
        try:
            for path in nginx_base.rglob("*"):
                if not path.is_file() or path.stat().st_size > MAX_CONFIG_FILE:
                    continue
                text = _read_text(path)
                for match in CERT_DIRECTIVE_RE.finditer(text):
                    linux_path = match.group(1).strip().strip('"\'')
                    if linux_path.startswith("/"):
                        refs.setdefault(linux_path, set()).add(f"Nginx: {_safe_rel(root, path)}")
        except OSError:
            pass

    postfix = root / "etc/postfix/main.cf"
    text = _read_text(postfix)
    for match in POSTFIX_CERT_RE.finditer(text):
        linux_path = match.group(1).strip().strip('"\'')
        if linux_path.startswith("/"):
            refs.setdefault(linux_path, set()).add("Postfix")

    dovecot = root / "etc/dovecot"
    if dovecot.is_dir():
        try:
            for path in dovecot.rglob("*.conf"):
                text = _read_text(path)
                for match in DOVECOT_CERT_RE.finditer(text):
                    linux_path = match.group(1).strip().strip('"\'')
                    if linux_path.startswith("/"):
                        refs.setdefault(linux_path, set()).add(f"Dovecot: {_safe_rel(root, path)}")
        except OSError:
            pass

    # Let's Encrypt live certificates are operationally interesting even if the vhost config is missing.
    live = root / "etc/letsencrypt/live"
    if live.is_dir():
        try:
            for domain_dir in live.iterdir():
                if not domain_dir.is_dir():
                    continue
                for name in ("fullchain.pem", "cert.pem"):
                    path = domain_dir / name
                    try:
                        path.lstat()
                    except OSError:
                        continue
                    linux_path = _safe_rel(root, path)
                    refs.setdefault(linux_path, set()).add(f"Let's Encrypt live: {domain_dir.name}")
        except OSError:
            pass

    return refs


def _scan_renewal_configs(root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    renewal = root / "etc/letsencrypt/renewal"
    if not renewal.is_dir():
        return rows
    try:
        files = sorted(renewal.glob("*.conf"))
    except OSError:
        return rows
    for path in files:
        text = _read_text(path)
        if not text:
            continue
        values: dict[str, str] = {}
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            values[key.strip().casefold()] = value.strip()
        domains = values.get("domains", "")
        cert_path = values.get("cert", "") or values.get("fullchain", "")
        rows.append(
            {
                "subject": path.stem,
                "sans": domains,
                "issuer": "",
                "serial": "",
                "not_before": "",
                "not_after": "",
                "source_file": _safe_rel(root, path),
                "referenced_by": "Let's Encrypt Renewal-Konfiguration",
                "status": "Renewal-Konfiguration; Zertifikat separat zu prüfen",
                "certificate_path": cert_path,
            }
        )
    return rows


def scan_tls_certificates(root: Path) -> list[dict[str, Any]]:
    refs = _collect_config_refs(root)
    rows: list[dict[str, Any]] = []
    seen_real: set[str] = set()

    for linux_path, referenced_by in sorted(refs.items()):
        host = _host_from_linux(root, linux_path)
        real_host = _rooted_symlink_target(root, host)
        try:
            real_key = str(real_host.resolve(strict=False))
        except OSError:
            real_key = str(real_host)
        if real_key in seen_real:
            continue
        seen_real.add(real_key)
        decoded = _decode_cert(real_host)
        if decoded:
            sans = [str(v) for key, v in decoded.get("subjectAltName", ()) if str(key).casefold() == "dns"]
            rows.append(
                {
                    "subject": _name_from_x509(decoded.get("subject")),
                    "sans": ", ".join(sans),
                    "issuer": _name_from_x509(decoded.get("issuer")),
                    "serial": decoded.get("serialNumber", ""),
                    "not_before": decoded.get("notBefore", ""),
                    "not_after": decoded.get("notAfter", ""),
                    "source_file": _safe_rel(root, host),
                    "referenced_by": " | ".join(sorted(referenced_by)),
                    "status": "Zertifikat dekodiert",
                    "certificate_path": linux_path,
                }
            )
        else:
            rows.append(
                {
                    "subject": "",
                    "sans": "",
                    "issuer": "",
                    "serial": "",
                    "not_before": "",
                    "not_after": "",
                    "source_file": _safe_rel(root, host),
                    "referenced_by": " | ".join(sorted(referenced_by)),
                    "status": "Zertifikat referenziert, aber nicht dekodierbar/nicht vorhanden",
                    "certificate_path": linux_path,
                }
            )

    # Add renewal configs only when they contribute domains not already visible.
    visible = " ".join((str(r.get("subject", "")) + " " + str(r.get("sans", ""))).casefold() for r in rows)
    for renewal_row in _scan_renewal_configs(root):
        domains = [x.strip() for x in str(renewal_row.get("sans", "")).split(",") if x.strip()]
        if domains and all(domain.casefold() in visible for domain in domains):
            continue
        rows.append(renewal_row)

    rows.sort(key=lambda r: (str(r.get("sans", "")), str(r.get("subject", "")), str(r.get("source_file", ""))))
    return rows
