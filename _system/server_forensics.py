# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Gl1tchb1rd

from __future__ import annotations

import base64
import fnmatch
import hashlib
import ipaddress
import os
import re
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, Iterator

DOMAIN_RE = re.compile(r"(?i)(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?![\w.-])")
IP_RE = re.compile(r"(?<![\w:])(?:\d{1,3}\.){3}\d{1,3}(?![\w:])")
NGINX_DIRECTIVE_RE = re.compile(r"(?ms)^\s*([a-zA-Z_][\w-]*)\s+([^;{}]+);")
LOG_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<path>\S+)(?:\s+HTTP/[^\"]+)?"\s+(?P<status>\d{3})\s+(?P<size>\S+)(?:\s+"(?P<ref>[^\"]*)"\s+"(?P<ua>[^\"]*)")?'
)

SECRET_KEYWORDS = ("password", "passwd", "secret", "token", "apikey", "api_key", "authorization", "cookie", "session")


@dataclass(slots=True)
class Website:
    domain: str
    aliases: list[str]
    status: str
    server: str
    source: str
    listen: list[str]
    urls: list[str]
    document_root: str = ""
    application: str = ""
    proxy_pass: list[str] | None = None
    fastcgi_pass: list[str] | None = None
    access_log: str = ""
    error_log: str = ""
    tls_certificate: str = ""
    evidence: str = "Konfiguriert"


@dataclass(slots=True)
class ServiceFinding:
    service: str
    state: str
    evidence: str
    source: str
    details: str = ""


@dataclass(slots=True)
class AdminAccess:
    timestamp: str
    ip: str
    application: str
    method: str
    path: str
    status: int
    assessment: str
    source: str
    ssh_correlated: bool = False
    user_agent: str = ""


@dataclass(slots=True)
class TLSFinding:
    source: str
    subject: str
    issuer: str
    serial: str
    not_before: str
    not_after: str
    domains: list[str]


@dataclass(slots=True)
class OperatorArtifact:
    kind: str
    identity: str
    value: str
    source: str
    assessment: str = "Hinweis"


def safe_read_text(path: Path, max_bytes: int = 8 * 1024 * 1024) -> str:
    try:
        with path.open("rb") as fh:
            data = fh.read(max_bytes + 1)
        if len(data) > max_bytes:
            data = data[:max_bytes]
        return data.decode("utf-8", errors="replace")
    except (OSError, ValueError):
        return ""


def _is_probable_symlink_text(text: str) -> str | None:
    stripped = text.strip().replace("\\", "/")
    if not stripped or "\n" in stripped or "\r" in stripped or len(stripped) > 4096:
        return None
    if stripped.startswith(("../", "./", "/")) or "/sites-available/" in stripped or "/archive/" in stripped:
        return stripped
    return None


def linux_to_host(root: Path, linux_path: str, base: Path | None = None) -> Path:
    p = linux_path.strip().strip('"\'')
    if p.startswith("/"):
        return root / p.lstrip("/")
    return (base or root) / p


def resolve_evidence_path(root: Path, path: Path, max_hops: int = 8) -> tuple[Path, str]:
    """Resolve real symlinks and common forensic-export symlink representations."""
    current = path
    method = "direkt"
    seen: set[str] = set()
    for _ in range(max_hops):
        key = str(current)
        if key in seen:
            break
        seen.add(key)
        try:
            if current.is_symlink():
                target = os.readlink(current)
                current = linux_to_host(root, target, current.parent)
                method = "Symlink"
                continue
        except OSError:
            pass
        if current.is_file():
            text = safe_read_text(current, 4096)
            target = _is_probable_symlink_text(text)
            if target:
                candidate = linux_to_host(root, target, current.parent)
                if candidate.exists():
                    current = candidate
                    method = "Symlink-Text"
                    continue
        break
    return current, method


def rel_source(root: Path, path: Path) -> str:
    try:
        return "/" + str(path.resolve(strict=False).relative_to(root.resolve(strict=False))).replace("\\", "/")
    except Exception:
        try:
            return "/" + str(path.relative_to(root)).replace("\\", "/")
        except Exception:
            return str(path)


def redact(text: str) -> str:
    out = text
    for key in SECRET_KEYWORDS:
        out = re.sub(rf"(?i)({re.escape(key)}\s*[:=]\s*)([^\s;]+)", r"\1[REDACTED]", out)
    out = re.sub(r"(?i)(https?://[^:/\s]+:)([^@/\s]+)(@)", r"\1[REDACTED]\3", out)
    return out


def _balanced_blocks(text: str, keyword: str) -> list[tuple[int, int, str]]:
    blocks: list[tuple[int, int, str]] = []
    rx = re.compile(rf"\b{re.escape(keyword)}\s*\{{")
    for match in rx.finditer(text):
        brace = text.find("{", match.start())
        depth = 0
        quote: str | None = None
        escape = False
        for i in range(brace, len(text)):
            ch = text[i]
            if quote:
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == quote:
                    quote = None
                continue
            if ch in ("'", '"'):
                quote = ch
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    blocks.append((match.start(), i + 1, text[brace + 1:i]))
                    break
    return blocks


def _strip_comments(text: str) -> str:
    lines = []
    for line in text.splitlines():
        out = []
        quote: str | None = None
        escaped = False
        for ch in line:
            if quote:
                out.append(ch)
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == quote:
                    quote = None
            else:
                if ch in ("'", '"'):
                    quote = ch
                    out.append(ch)
                elif ch == "#":
                    break
                else:
                    out.append(ch)
        lines.append("".join(out))
    return "\n".join(lines)


def _directive_values(text: str, name: str) -> list[str]:
    vals: list[str] = []
    for m in re.finditer(rf"(?is)(?<![\w-]){re.escape(name)}\s+([^;{{}}]+);", text):
        vals.extend(x for x in re.split(r"\s+", m.group(1).strip()) if x)
    return vals


def _expand_glob(root: Path, base: Path, token: str) -> list[Path]:
    token = token.strip().strip('"\'')
    host = linux_to_host(root, token, base)
    if any(c in str(host) for c in "*?["):
        parent = Path(str(host).split("*")[0]).parent
        # pathlib glob with absolute patterns is awkward; use fnmatch over nearby tree.
        anchor = root if str(host).startswith(str(root)) else base
        pattern = str(host).replace("\\", "/")
        found: list[Path] = []
        try:
            for p in anchor.rglob("*"):
                if p.is_file() and fnmatch.fnmatch(str(p).replace("\\", "/"), pattern):
                    found.append(p)
        except OSError:
            pass
        return sorted(found)
    return [host]


def _nginx_include_chain(root: Path) -> tuple[set[Path], dict[str, int]]:
    nginx = root / "etc/nginx"
    queue: list[Path] = [nginx / "nginx.conf"]
    seen: set[Path] = set()
    diag = {
        "sites_enabled_entries": 0,
        "sites_enabled_direct": 0,
        "sites_enabled_symlink": 0,
        "sites_enabled_textlink": 0,
        "sites_enabled_available_fallback": 0,
        "sites_enabled_unreadable": 0,
        "active_config_files": 0,
        "all_nginx_files": 0,
    }

    enabled = nginx / "sites-enabled"
    available = nginx / "sites-available"
    if enabled.is_dir():
        try:
            entries = list(enabled.iterdir())
        except OSError:
            entries = []
        diag["sites_enabled_entries"] = len(entries)
        for entry in entries:
            resolved, method = resolve_evidence_path(root, entry)
            if resolved.is_file():
                queue.append(resolved)
                if method == "Symlink":
                    diag["sites_enabled_symlink"] += 1
                elif method == "Symlink-Text":
                    diag["sites_enabled_textlink"] += 1
                else:
                    diag["sites_enabled_direct"] += 1
            else:
                fallback = available / entry.name
                if fallback.is_file():
                    queue.append(fallback)
                    diag["sites_enabled_available_fallback"] += 1
                else:
                    diag["sites_enabled_unreadable"] += 1

    while queue:
        raw = queue.pop(0)
        resolved, _ = resolve_evidence_path(root, raw)
        try:
            key = resolved.resolve(strict=False)
        except OSError:
            key = resolved
        if key in seen or not resolved.is_file():
            continue
        seen.add(key)
        text = _strip_comments(safe_read_text(resolved))
        for m in re.finditer(r"(?is)(?<![\w-])include\s+([^;{}]+);", text):
            for inc in _expand_glob(root, resolved.parent, m.group(1)):
                r, _ = resolve_evidence_path(root, inc)
                if r.is_file():
                    queue.append(r)
    diag["active_config_files"] = len(seen)
    try:
        diag["all_nginx_files"] = sum(1 for p in nginx.rglob("*") if p.is_file() or p.is_symlink()) if nginx.exists() else 0
    except OSError:
        pass
    return seen, diag


def _all_nginx_candidates(root: Path) -> list[tuple[Path, str]]:
    nginx = root / "etc/nginx"
    found: dict[str, tuple[Path, str]] = {}
    if nginx.exists():
        try:
            for p in nginx.rglob("*"):
                if p.is_file() or p.is_symlink():
                    resolved, method = resolve_evidence_path(root, p)
                    source = p
                    if resolved.is_file():
                        found[str(resolved.resolve(strict=False))] = (resolved, method)
                    elif p.parent.name in {"sites-enabled", "sites-available"}:
                        found[str(p)] = (p, "unlesbar")
        except OSError:
            pass
    plesk = root / "var/www/vhosts/system"
    if plesk.exists():
        try:
            for p in plesk.rglob("conf/*"):
                if p.is_file():
                    found[str(p.resolve(strict=False))] = (p, "Plesk")
        except OSError:
            pass
    return sorted(found.values(), key=lambda x: str(x[0]).casefold())


def _application_from_root(root: Path, docroot: str) -> str:
    if not docroot:
        return ""
    p = linux_to_host(root, docroot)
    if (p / "wp-config.php").is_file() or (p / "wp-admin").is_dir():
        return "WordPress"
    if (p / "config/config.php").is_file() and (p / "occ").exists():
        return "Nextcloud"
    if (p / "configuration.php").is_file() and (p / "administrator").is_dir():
        return "Joomla"
    return ""


def analyze_nginx(root: Path) -> tuple[list[dict], dict[str, int]]:
    active_files, diag = _nginx_include_chain(root)
    active_str = {str(p.resolve(strict=False)).casefold() for p in active_files}
    websites: list[Website] = []
    seen_key: set[tuple[str, str, str]] = set()

    for file_path, method in _all_nginx_candidates(root):
        text = _strip_comments(safe_read_text(file_path)) if file_path.is_file() else ""
        path_norm = str(file_path.resolve(strict=False)).casefold() if file_path.exists() else str(file_path).casefold()
        active = path_norm in active_str or "sites-enabled" in str(file_path).replace("\\", "/")
        status = "aktiv eingebunden" if active else "Konfiguration vorhanden"
        source = rel_source(root, file_path)
        blocks = _balanced_blocks(text, "server") if text else []
        if not blocks and text:
            # Recovery path for malformed/truncated configurations.
            blocks = [(0, len(text), text)] if re.search(r"\bserver_name\b", text) else []

        for _start, _end, block in blocks:
            # Resolve includes located inside the server block (common for Plesk/snippets).
            expanded = block
            for inc in re.findall(r"(?is)(?<![\w-])include\s+([^;{}]+);", block):
                for p in _expand_glob(root, file_path.parent, inc):
                    rp, _ = resolve_evidence_path(root, p)
                    if rp.is_file():
                        expanded += "\n" + _strip_comments(safe_read_text(rp))

            names = [n for n in _directive_values(expanded, "server_name") if n not in {"_", "localhost"} and "$" not in n]
            domains: list[str] = []
            for name in names:
                domains.extend(DOMAIN_RE.findall(name))
            domains = list(dict.fromkeys(d.lower().rstrip(".") for d in domains))
            if not domains:
                # Plesk path can be authoritative enough to preserve a configured vhost.
                parts = str(file_path).replace("\\", "/").split("/var/www/vhosts/system/")
                if len(parts) > 1:
                    d = parts[1].split("/", 1)[0]
                    if DOMAIN_RE.fullmatch(d):
                        domains = [d.lower()]
            if not domains:
                name = file_path.name.lower()
                if DOMAIN_RE.fullmatch(name) and file_path.parent.name in {"sites-enabled", "sites-available"}:
                    domains = [name]
                    status = "aktiver Dateinamen-Hinweis" if file_path.parent.name == "sites-enabled" else "Dateinamen-Hinweis"
            if not domains:
                continue

            listens = _directive_values(expanded, "listen")
            roots = _directive_values(expanded, "root")
            proxies = _directive_values(expanded, "proxy_pass")
            fastcgi = _directive_values(expanded, "fastcgi_pass")
            access = _directive_values(expanded, "access_log")
            error = _directive_values(expanded, "error_log")
            certs = _directive_values(expanded, "ssl_certificate")
            primary = domains[0]
            aliases = [x for x in domains[1:] if x != primary]
            scheme_https = any("443" in x or "ssl" in x for x in listens) or bool(certs)
            scheme_http = any("80" in x and "808" not in x for x in listens) or not scheme_https
            urls = []
            if scheme_http:
                urls.append(f"http://{primary}/")
            if scheme_https:
                urls.append(f"https://{primary}/")
            docroot = roots[0] if roots else ""
            app = _application_from_root(root, docroot)
            key = (primary, source, "|".join(listens))
            if key in seen_key:
                continue
            seen_key.add(key)
            websites.append(
                Website(
                    domain=primary,
                    aliases=aliases,
                    status=status,
                    server="NGINX",
                    source=source,
                    listen=listens,
                    urls=urls,
                    document_root=docroot,
                    application=app,
                    proxy_pass=proxies,
                    fastcgi_pass=fastcgi,
                    access_log=access[0] if access else "",
                    error_log=error[0] if error else "",
                    tls_certificate=certs[0] if certs else "",
                    evidence="Belegt" if active else "Konfiguriert",
                )
            )

    # Last-resort preservation of visible sites-enabled names even when the mount cannot read them.
    enabled = root / "etc/nginx/sites-enabled"
    if enabled.is_dir():
        try:
            for p in enabled.iterdir():
                name = p.name.lower()
                if DOMAIN_RE.fullmatch(name) and not any(w.domain == name for w in websites):
                    websites.append(
                        Website(
                            domain=name,
                            aliases=[],
                            status="sites-enabled: Inhalt nicht lesbar",
                            server="NGINX",
                            source=rel_source(root, p),
                            listen=[],
                            urls=[f"http://{name}/", f"https://{name}/"],
                            evidence="Hinweis",
                        )
                    )
        except OSError:
            pass

    websites.sort(key=lambda w: (w.domain, w.source))
    return [asdict(w) for w in websites], diag


def analyze_apache(root: Path) -> list[dict]:
    candidates: list[tuple[Path, bool]] = []
    for rel, active in (("etc/apache2/sites-enabled", True), ("etc/apache2/sites-available", False), ("etc/httpd/conf.d", True)):
        base = root / rel
        if not base.exists():
            continue
        try:
            for p in base.iterdir():
                rp, _ = resolve_evidence_path(root, p)
                if rp.is_file():
                    candidates.append((rp, active))
        except OSError:
            pass
    out: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for path, active in candidates:
        text = _strip_comments(safe_read_text(path))
        blocks = _balanced_blocks(text.replace("<VirtualHost", "server {").replace("</VirtualHost>", "}"), "server")
        if not blocks:
            blocks = [(0, len(text), text)]
        for _, _, block in blocks:
            m = re.search(r"(?im)^\s*ServerName\s+(\S+)", block)
            if not m:
                continue
            domain_match = DOMAIN_RE.search(m.group(1))
            if not domain_match:
                continue
            domain = domain_match.group(0).lower()
            aliases = []
            for am in re.finditer(r"(?im)^\s*ServerAlias\s+(.+)$", block):
                aliases.extend(DOMAIN_RE.findall(am.group(1)))
            root_m = re.search(r"(?im)^\s*DocumentRoot\s+\"?([^\"\s]+)", block)
            key = (domain, rel_source(root, path))
            if key in seen:
                continue
            seen.add(key)
            docroot = root_m.group(1) if root_m else ""
            out.append(
                asdict(
                    Website(
                        domain=domain,
                        aliases=list(dict.fromkeys(a.lower() for a in aliases)),
                        status="aktiv eingebunden" if active else "Konfiguration vorhanden",
                        server="Apache",
                        source=rel_source(root, path),
                        listen=[],
                        urls=[f"http://{domain}/", f"https://{domain}/"],
                        document_root=docroot,
                        application=_application_from_root(root, docroot),
                        evidence="Belegt" if active else "Konfiguriert",
                    )
                )
            )
    return out


def extract_successful_ssh(journal_events: Iterable[dict[str, str]]) -> list[dict]:
    rx = re.compile(
        r"Accepted\s+(?P<method>publickey|password|keyboard-interactive/pam|keyboard-interactive)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>[0-9a-fA-F:.]+)\s+port\s+(?P<port>\d+)",
        re.I,
    )
    out: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    for e in journal_events:
        msg = e.get("MESSAGE", "")
        m = rx.search(msg)
        if not m:
            continue
        ts = e.get("__DATETIME_UTC") or _timestamp_from_micro(e.get("__REALTIME_TIMESTAMP", ""))
        item = {
            "timestamp": ts,
            "user": m.group("user"),
            "ip": m.group("ip"),
            "port": m.group("port"),
            "method": m.group("method"),
            "source": e.get("__SOURCE_FILE", ""),
            "cursor": e.get("__CURSOR", ""),
            "message": msg,
        }
        key = (ts, item["user"], item["ip"])
        if key not in seen:
            seen.add(key)
            out.append(item)
    out.sort(key=lambda x: x["timestamp"])
    return out


def _timestamp_from_micro(value: str) -> str:
    try:
        return datetime.fromtimestamp(int(value) / 1_000_000, tz=timezone.utc).isoformat()
    except Exception:
        return ""


def _parse_access_time(value: str) -> datetime | None:
    for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%d/%b/%Y:%H:%M:%S"):
        try:
            dt = datetime.strptime(value, fmt)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return None


def discover_access_logs(root: Path) -> list[Path]:
    patterns = [
        "var/log/nginx/*access*.log*",
        "var/log/apache2/*access*.log*",
        "var/log/httpd/*access*",
        "var/log/plesk/httpsd_access_log*",
        "var/log/sw-cp-server/access.log*",
        "var/www/vhosts/system/*/logs/access_log*",
        "var/www/vhosts/system/*/logs/proxy_access_log*",
    ]
    out: set[Path] = set()
    for pattern in patterns:
        parts = pattern.split("/")
        base = root
        # pathlib glob relative to root works with globs.
        try:
            for p in root.glob(pattern):
                if p.is_file():
                    out.add(p)
        except OSError:
            continue
    return sorted(out, key=lambda p: str(p).casefold())


ADMIN_RULES = [
    ("WordPress", re.compile(r"(?i)^/wp-login\.php(?:[/?]|$)"), re.compile(r"(?i)^/wp-admin(?:[/?]|$)")),
    ("Plesk", re.compile(r"(?i)(?:^|/)login_up\.php|^/login(?:[/?]|$)"), re.compile(r"(?i)^/(?:smb|admin|modules|plesk|webmail)(?:[/?]|$)")),
    ("phpMyAdmin", re.compile(r"(?i)/(?:phpmyadmin|pma)(?:/|$)"), re.compile(r"(?i)/(?:phpmyadmin|pma)(?:/|$)")),
    ("Nextcloud", re.compile(r"(?i)^/(?:index\.php/)?login(?:[/?]|$)"), re.compile(r"(?i)^/(?:index\.php/)?(?:apps|settings|ocs|remote)(?:[/?]|$)")),
]


def analyze_admin_access(root: Path, ssh_logins: list[dict]) -> list[dict]:
    ssh_ips = {x.get("ip", "") for x in ssh_logins}
    records: list[tuple[datetime | None, dict]] = []
    raw_hits: list[dict] = []
    for path in discover_access_logs(root):
        text = safe_read_text(path, 64 * 1024 * 1024)
        for line in text.splitlines():
            m = LOG_RE.match(line)
            if not m:
                continue
            req_path = m.group("path")
            app = ""
            login = False
            protected = False
            for name, login_rx, protected_rx in ADMIN_RULES:
                if login_rx.search(req_path):
                    app, login = name, True
                    break
                if protected_rx.search(req_path):
                    app, protected = name, True
                    break
            if not app:
                continue
            dt = _parse_access_time(m.group("time"))
            raw_hits.append(
                {
                    "dt": dt,
                    "timestamp": dt.isoformat() if dt else m.group("time"),
                    "ip": m.group("ip"),
                    "application": app,
                    "method": m.group("method"),
                    "path": req_path,
                    "status": int(m.group("status")),
                    "login": login,
                    "protected": protected,
                    "source": rel_source(root, path),
                    "ua": m.group("ua") or "",
                }
            )

    by_ip_app: dict[tuple[str, str], list[dict]] = {}
    for hit in raw_hits:
        by_ip_app.setdefault((hit["ip"], hit["application"]), []).append(hit)
    for group in by_ip_app.values():
        group.sort(key=lambda h: h["dt"] or datetime.min.replace(tzinfo=timezone.utc))

    out: list[dict] = []
    for hit in raw_hits:
        status = hit["status"]
        assessment = "Zugriffsversuch"
        if hit["login"] and hit["method"] == "POST" and 200 <= status < 400:
            strong = False
            if hit["dt"]:
                for other in by_ip_app[(hit["ip"], hit["application"])]:
                    if not other["protected"] or not other["dt"]:
                        continue
                    delta = other["dt"] - hit["dt"]
                    if timedelta(seconds=0) <= delta <= timedelta(minutes=10) and 200 <= other["status"] < 400:
                        strong = True
                        break
            assessment = "Starker Hinweis auf erfolgreiche Anmeldung" if strong else "Login-POST akzeptiert/weitergeleitet"
        elif hit["protected"] and 200 <= status < 400:
            assessment = "Zugriff auf geschützten/Adminbereich"
        elif status in (401, 403):
            assessment = "Abgewiesener Zugriff"
        elif status >= 400:
            assessment = "Fehlgeschlagener/technischer Zugriff"
        out.append(
            asdict(
                AdminAccess(
                    timestamp=hit["timestamp"],
                    ip=hit["ip"],
                    application=hit["application"],
                    method=hit["method"],
                    path=hit["path"],
                    status=status,
                    assessment=assessment,
                    source=hit["source"],
                    ssh_correlated=hit["ip"] in ssh_ips,
                    user_agent=hit["ua"],
                )
            )
        )
    out.sort(key=lambda x: x["timestamp"])
    return out


def analyze_tls(root: Path) -> list[dict]:
    try:
        from cryptography import x509
    except ImportError:
        return []
    candidates: set[Path] = set()
    for rel in ("etc/letsencrypt/live", "etc/letsencrypt/archive", "etc/ssl", "var/www/vhosts/system"):
        base = root / rel
        if not base.exists():
            continue
        try:
            for p in base.rglob("*"):
                if p.suffix.lower() in {".pem", ".crt", ".cer"} and (p.is_file() or p.is_symlink()):
                    rp, _ = resolve_evidence_path(root, p)
                    if rp.is_file():
                        candidates.add(rp)
        except OSError:
            pass
    out: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for p in sorted(candidates, key=lambda x: str(x).casefold()):
        try:
            data = p.read_bytes()
            cert = x509.load_pem_x509_certificate(data) if b"BEGIN CERTIFICATE" in data else x509.load_der_x509_certificate(data)
        except Exception:
            continue
        domains: list[str] = []
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            domains.extend(san.value.get_values_for_type(x509.DNSName))
        except Exception:
            pass
        try:
            from cryptography.x509.oid import NameOID
            cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            domains.extend(a.value for a in cn if DOMAIN_RE.fullmatch(a.value))
        except Exception:
            pass
        domains = list(dict.fromkeys(d.lower() for d in domains))
        key = (str(cert.serial_number), ",".join(domains))
        if key in seen:
            continue
        seen.add(key)
        not_before = getattr(cert, "not_valid_before_utc", cert.not_valid_before.replace(tzinfo=timezone.utc)).isoformat()
        not_after = getattr(cert, "not_valid_after_utc", cert.not_valid_after.replace(tzinfo=timezone.utc)).isoformat()
        out.append(
            asdict(
                TLSFinding(
                    source=rel_source(root, p),
                    subject=cert.subject.rfc4514_string(),
                    issuer=cert.issuer.rfc4514_string(),
                    serial=f"{cert.serial_number:x}",
                    not_before=not_before,
                    not_after=not_after,
                    domains=domains,
                )
            )
        )
    return out


def analyze_services(root: Path, journal_events: Iterable[dict[str, str]]) -> list[dict]:
    checks = [
        ("OpenSSH", ["etc/ssh/sshd_config", "usr/sbin/sshd"], ["sshd.service", "ssh.service"]),
        ("NGINX", ["etc/nginx/nginx.conf"], ["nginx.service"]),
        ("Apache", ["etc/apache2/apache2.conf", "etc/httpd/conf/httpd.conf"], ["apache2.service", "httpd.service"]),
        ("PHP-FPM", ["etc/php", "etc/php-fpm.conf"], ["php", "php-fpm"]),
        ("Plesk", ["etc/psa/psa.conf", "usr/local/psa"], ["psa.service", "sw-cp-server.service"]),
        ("Postfix", ["etc/postfix/main.cf"], ["postfix.service"]),
        ("Exim", ["etc/exim4", "etc/exim"], ["exim4.service", "exim.service"]),
        ("Dovecot", ["etc/dovecot/dovecot.conf"], ["dovecot.service"]),
        ("Rspamd", ["etc/rspamd"], ["rspamd.service"]),
        ("SpamAssassin", ["etc/spamassassin"], ["spamassassin.service", "spamd.service"]),
        ("TeamSpeak", ["opt/teamspeak", "var/lib/teamspeak"], ["teamspeak.service", "ts3server.service"]),
        ("Nextcloud", ["var/www/nextcloud", "opt/nextcloud"], []),
        ("Docker", ["var/lib/docker", "etc/docker"], ["docker.service"]),
        ("Podman", ["var/lib/containers", "etc/containers"], ["podman.service"]),
        ("MariaDB/MySQL", ["var/lib/mysql", "etc/mysql"], ["mariadb.service", "mysql.service"]),
        ("PostgreSQL", ["var/lib/postgresql", "etc/postgresql"], ["postgresql.service"]),
        ("Redis", ["etc/redis", "var/lib/redis"], ["redis.service", "redis-server.service"]),
        ("Fail2ban", ["etc/fail2ban"], ["fail2ban.service"]),
        ("WireGuard", ["etc/wireguard"], ["wg-quick@"]),
        ("OpenVPN", ["etc/openvpn"], ["openvpn.service", "openvpn-server@"]),
        ("vsftpd", ["etc/vsftpd.conf"], ["vsftpd.service"]),
        ("ProFTPD", ["etc/proftpd"], ["proftpd.service"]),
    ]
    units = set()
    for e in journal_events:
        for key in ("_SYSTEMD_UNIT", "UNIT"):
            if e.get(key):
                units.add(e[key])
    out: list[ServiceFinding] = []
    for name, paths, unit_tokens in checks:
        fs_sources = [p for p in paths if (root / p).exists()]
        unit_hits = [u for u in units if any(t in u for t in unit_tokens)] if unit_tokens else []
        if unit_hits:
            out.append(ServiceFinding(name, "Aktivität im Journal", "Belegt", ", ".join(unit_hits[:6]), ", ".join(fs_sources)))
        elif fs_sources:
            out.append(ServiceFinding(name, "Installation/Konfiguration festgestellt", "Konfiguriert", ", ".join("/" + p for p in fs_sources)))
    # Preserve additional services seen in journal.
    known_units = {u for f in out for u in f.source.split(", ") if u.endswith(".service")}
    for u in sorted(x for x in units if x.endswith(".service") and x not in known_units):
        out.append(ServiceFinding(u, "Aktivität im Journal", "Belegt", "systemd journal"))
    return [asdict(x) for x in out]


def _ssh_fingerprint(line: str) -> tuple[str, str, str] | None:
    parts = line.strip().split()
    if len(parts) < 2 or not parts[0].startswith(("ssh-", "ecdsa-")):
        return None
    try:
        raw = base64.b64decode(parts[1].encode("ascii"), validate=True)
    except Exception:
        return None
    fp = base64.b64encode(hashlib.sha256(raw).digest()).decode("ascii").rstrip("=")
    comment = " ".join(parts[2:]) if len(parts) > 2 else ""
    return parts[0], f"SHA256:{fp}", comment


def _linux_users(root: Path) -> list[tuple[str, str]]:
    passwd = root / "etc/passwd"
    text = safe_read_text(passwd)
    out: list[tuple[str, str]] = []
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) >= 7:
            out.append((parts[0], parts[5]))
    return out


def analyze_operator_artifacts(root: Path) -> list[dict]:
    out: list[OperatorArtifact] = []
    for user, home in _linux_users(root):
        out.append(OperatorArtifact("Linux-Benutzer", user, home, "/etc/passwd", "Konfiguriert"))
        home_path = linux_to_host(root, home)
        auth = home_path / ".ssh/authorized_keys"
        if auth.is_file():
            for line in safe_read_text(auth).splitlines():
                fp = _ssh_fingerprint(line)
                if fp:
                    keytype, fingerprint, comment = fp
                    out.append(OperatorArtifact("SSH-Key", user, f"{keytype} {fingerprint}" + (f" ({comment})" if comment else ""), rel_source(root, auth), "Belegt"))
        known = home_path / ".ssh/known_hosts"
        if known.is_file():
            count = sum(1 for line in safe_read_text(known).splitlines() if line.strip() and not line.startswith("#"))
            out.append(OperatorArtifact("SSH known_hosts", user, f"{count} Einträge", rel_source(root, known)))
        gitconfig = home_path / ".gitconfig"
        if gitconfig.is_file():
            text = safe_read_text(gitconfig)
            name = re.search(r"(?im)^\s*name\s*=\s*(.+)$", text)
            email = re.search(r"(?im)^\s*email\s*=\s*(.+)$", text)
            if name or email:
                out.append(OperatorArtifact("Git-Identität", user, redact(f"{name.group(1).strip() if name else ''} <{email.group(1).strip() if email else ''}>").strip(), rel_source(root, gitconfig), "Hinweis"))
        for history_name in (".bash_history", ".zsh_history"):
            hist = home_path / history_name
            if hist.is_file():
                lines = [redact(x.strip()) for x in safe_read_text(hist, 4 * 1024 * 1024).splitlines() if x.strip()]
                preview = " | ".join(lines[-8:])[:2000]
                out.append(OperatorArtifact("Shell-History", user, f"{len(lines)} Einträge; letzte Befehle: {preview}", rel_source(root, hist), "Hinweis"))

    # Git repositories and remotes in common web/service locations.
    for base_rel in ("var/www", "srv", "opt", "home", "root"):
        base = root / base_rel
        if not base.exists():
            continue
        try:
            for config in base.rglob(".git/config"):
                text = safe_read_text(config)
                remotes = re.findall(r"(?im)^\s*url\s*=\s*(.+)$", text)
                repo = config.parent.parent
                for remote in remotes[:8]:
                    out.append(OperatorArtifact("Git-Remote", rel_source(root, repo), redact(remote.strip()), rel_source(root, config), "Hinweis"))
        except OSError:
            pass

    # Cron and custom systemd services.
    cron_paths = [root / "etc/crontab"]
    for rel in ("etc/cron.d", "var/spool/cron", "var/spool/cron/crontabs"):
        base = root / rel
        if base.exists():
            try:
                cron_paths.extend(p for p in base.rglob("*") if p.is_file())
            except OSError:
                pass
    for p in cron_paths:
        if not p.is_file():
            continue
        lines = [redact(x.strip()) for x in safe_read_text(p).splitlines() if x.strip() and not x.lstrip().startswith("#")]
        if lines:
            out.append(OperatorArtifact("Cron", p.name, " | ".join(lines[:12])[:2500], rel_source(root, p), "Konfiguriert"))

    for rel in ("etc/systemd/system", "usr/lib/systemd/system", "lib/systemd/system"):
        base = root / rel
        if not base.exists():
            continue
        try:
            for unit in base.glob("*.service"):
                text = safe_read_text(unit)
                if not text:
                    continue
                execs = re.findall(r"(?im)^\s*ExecStart\s*=\s*(.+)$", text)
                envs = re.findall(r"(?im)^\s*EnvironmentFile\s*=\s*-?(.+)$", text)
                if execs or envs:
                    details = "; ".join([*("ExecStart=" + redact(x) for x in execs[:3]), *("EnvironmentFile=" + x for x in envs[:3])])
                    out.append(OperatorArtifact("systemd Service", unit.name, details, rel_source(root, unit), "Konfiguriert"))
        except OSError:
            pass

    return [asdict(x) for x in out]


def collect_ip_summary(ssh: list[dict], admins: list[dict], mail_access: list[dict]) -> list[dict]:
    rows: dict[str, dict] = {}
    def get(ip: str) -> dict:
        return rows.setdefault(ip, {"ip": ip, "ssh": 0, "admin": 0, "imap_pop": 0, "smtp_auth": 0, "first": "", "last": ""})
    def touch(row: dict, ts: str) -> None:
        if not ts:
            return
        if not row["first"] or ts < row["first"]:
            row["first"] = ts
        if not row["last"] or ts > row["last"]:
            row["last"] = ts
    for x in ssh:
        row = get(x.get("ip", "")); row["ssh"] += 1; touch(row, x.get("timestamp", ""))
    for x in admins:
        row = get(x.get("ip", "")); row["admin"] += 1; touch(row, x.get("timestamp", ""))
    for x in mail_access:
        row = get(x.get("ip", ""));
        if x.get("protocol") in {"IMAP", "POP3"}: row["imap_pop"] += 1
        if x.get("protocol") == "SMTP AUTH": row["smtp_auth"] += 1
        touch(row, x.get("timestamp", ""))
    return sorted((v for k, v in rows.items() if k), key=lambda x: (-(x["ssh"] + x["admin"] + x["imap_pop"] + x["smtp_auth"]), x["ip"]))
