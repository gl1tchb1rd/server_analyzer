from __future__ import annotations

import gzip
import glob
import ipaddress
import os
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

from mail_forensics import scan_mail
from operator_artifacts import scan_operator_artifacts
from tls_forensics import scan_tls_certificates

MAX_TEXT_FILE = 32 * 1024 * 1024
MAX_CONFIG_FILE = 8 * 1024 * 1024
MAX_ACCESS_LOGS = 500
MAX_APP_MARKERS = 250
MAX_ADMIN_FINDINGS = 200_000
MAX_ACCESS_LINES_PER_FILE = 2_000_000
MAX_ACCESS_LINE_LENGTH = 1_000_000

ACCESS_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)(?:\s+HTTP/[^"]+)?"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)

NGINX_SERVER_NAME_RE = re.compile(r"\bserver_name\s+([^;]+);", re.I)
NGINX_ROOT_RE = re.compile(r"\broot\s+([^;]+);", re.I)
NGINX_LISTEN_RE = re.compile(r"\blisten\s+([^;]+);", re.I)
NGINX_PROXY_PASS_RE = re.compile(r"\bproxy_pass\s+([^;]+);", re.I)
NGINX_ACCESS_LOG_RE = re.compile(r"\baccess_log\s+([^;]+);", re.I)
NGINX_ERROR_LOG_RE = re.compile(r"\berror_log\s+([^;]+);", re.I)
NGINX_SSL_CERT_RE = re.compile(r"\bssl_certificate\s+([^;]+);", re.I)
NGINX_FASTCGI_RE = re.compile(r"\bfastcgi_pass\s+([^;]+);", re.I)
NGINX_INCLUDE_RE = re.compile(r"\binclude\s+([^;]+);", re.I)
NGINX_DOMAIN_FILENAME_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$", re.I)
APACHE_VHOST_RE = re.compile(r"<VirtualHost\b([^>]*)>(.*?)</VirtualHost>", re.I | re.S)
APACHE_NAME_RE = re.compile(r"(?mi)^\s*ServerName\s+(.+?)\s*$")
APACHE_ALIAS_RE = re.compile(r"(?mi)^\s*ServerAlias\s+(.+?)\s*$")
APACHE_ROOT_RE = re.compile(r"(?mi)^\s*DocumentRoot\s+\"?([^\"\r\n]+)\"?\s*$")

WORDPRESS_PATH_RE = re.compile(r"/(?:wp-login\.php|wp-admin(?:/|$))", re.I)
NEXTCLOUD_PATH_RE = re.compile(r"/(?:index\.php/)?(?:login|settings/admin)(?:/|\?|$)", re.I)
PHPMYADMIN_PATH_RE = re.compile(r"/(?:phpmyadmin|pma)(?:/|$)", re.I)
GENERIC_ADMIN_PATH_RE = re.compile(r"/(?:administrator|admin)(?:/|$)", re.I)

SSH_SUCCESS_TEXT = "Anmeldung erfolgreich"


@dataclass
class ServerScanResult:
    linux_root: str = ""
    websites: list[dict[str, Any]] = field(default_factory=list)
    services: list[dict[str, Any]] = field(default_factory=list)
    admin_accesses: list[dict[str, Any]] = field(default_factory=list)
    mail_servers: list[dict[str, Any]] = field(default_factory=list)
    mail_accounts: list[dict[str, Any]] = field(default_factory=list)
    mail_aliases: list[dict[str, Any]] = field(default_factory=list)
    mail_accesses: list[dict[str, Any]] = field(default_factory=list)
    mail_diagnostics: list[dict[str, Any]] = field(default_factory=list)
    tls_certificates: list[dict[str, Any]] = field(default_factory=list)
    operator_artifacts: list[dict[str, Any]] = field(default_factory=list)
    scan_notes: list[str] = field(default_factory=list)
    access_log_files: list[str] = field(default_factory=list)
    mail_log_files: list[str] = field(default_factory=list)


def detect_linux_root(source: Path) -> Path | None:
    """Best-effort detection of an extracted/mounted Linux root directory."""
    try:
        source = source.resolve()
    except OSError:
        pass
    start = source.parent if source.is_file() else source
    candidates = [start] + list(start.parents[:8])
    for candidate in candidates:
        if (candidate / "etc").is_dir() and (candidate / "var").is_dir():
            return candidate
    return None


def _read_text(path: Path, limit: int = MAX_CONFIG_FILE) -> str:
    try:
        if path.stat().st_size > limit:
            return path.read_bytes()[:limit].decode("utf-8", errors="replace")
        return path.read_text(encoding="utf-8", errors="replace")
    except (OSError, PermissionError):
        return ""


def _safe_rel(root: Path, path: Path) -> str:
    try:
        return "/" + path.relative_to(root).as_posix()
    except Exception:
        return str(path)


def _linux_to_host_path(root: Path, linux_path: str) -> Path:
    cleaned = linux_path.strip().strip('"\'').split()[0]
    if cleaned.startswith("/"):
        cleaned = cleaned[1:]
    return root / cleaned


def _strip_nginx_comments(text: str) -> str:
    lines = []
    for line in text.splitlines():
        # Good enough for nginx config: '#' starts comments outside quoted URLs in normal configs.
        if "#" in line:
            line = line.split("#", 1)[0]
        lines.append(line)
    return "\n".join(lines)


def _brace_blocks(text: str, keyword: str) -> list[str]:
    blocks: list[str] = []
    token = re.compile(rf"\b{re.escape(keyword)}\s*\{{", re.I)
    for match in token.finditer(text):
        open_pos = text.find("{", match.start())
        if open_pos < 0:
            continue
        depth = 0
        in_quote: str | None = None
        escaped = False
        for i in range(open_pos, len(text)):
            ch = text[i]
            if escaped:
                escaped = False
                continue
            if ch == "\\":
                escaped = True
                continue
            if in_quote:
                if ch == in_quote:
                    in_quote = None
                continue
            if ch in ("'", '"'):
                in_quote = ch
                continue
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    blocks.append(text[match.start():i + 1])
                    break
    return blocks


def _app_for_root(root: Path, linux_docroot: str) -> str:
    if not linux_docroot:
        return ""
    host = _linux_to_host_path(root, linux_docroot)
    if (host / "wp-config.php").is_file() or (host / "wp-includes" / "version.php").is_file():
        return "WordPress"
    if (host / "occ").is_file() and (host / "config" / "config.php").is_file():
        return "Nextcloud"
    return ""




def _website_status(path: Path) -> str:
    p = path.as_posix().casefold()
    if "/sites-enabled/" in p:
        return "aktiv konfiguriert (sites-enabled)"
    if "/sites-available/" in p:
        return "Konfiguration vorhanden (sites-available)"
    if "/var/www/vhosts/system/" in p:
        return "Plesk-VHost-Konfiguration"
    if "/conf.d/" in p:
        return "Konfiguration in conf.d"
    return "Webserver-Konfiguration"


def _config_priority(path: Path) -> tuple[int, str]:
    p = path.as_posix().casefold()
    if "/sites-enabled/" in p:
        rank = 0
    elif "/var/www/vhosts/system/" in p or "/conf.d/" in p:
        rank = 1
    elif "/sites-available/" in p:
        rank = 3
    else:
        rank = 2
    return rank, str(path)


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


def _nginx_include_candidates(root: Path, current_file: Path, pattern: str) -> list[Path]:
    """Resolve nginx include directives against an extracted Linux root."""
    pattern = pattern.strip().strip('"\'')
    if not pattern or "$" in pattern:
        return []
    host_patterns: list[Path] = []
    if pattern.startswith("/"):
        host_patterns.append(root / pattern.lstrip("/"))
    else:
        # Be liberal: packaged nginx configs are often easiest to reconstruct
        # relative to /etc/nginx, while custom setups may use file-relative paths.
        host_patterns.append(current_file.parent / pattern)
        host_patterns.append(root / "etc/nginx" / pattern)
    found: list[Path] = []
    for host_pattern in host_patterns:
        for value in glob.glob(str(host_pattern)):
            path = Path(value)
            try:
                path.lstat()
            except OSError:
                continue
            if path.is_dir():
                continue
            found.append(path)
    return list(dict.fromkeys(found))


def _nginx_file_key(path: Path) -> str:
    return os.path.normcase(os.path.normpath(str(path)))


def _nginx_plaintext_link_target(root: Path, path: Path) -> Path | None:
    """Resolve a symlink that a Windows forensic export exposed as a tiny text file.

    Some image/mount tools do not expose Linux symbolic links as Windows reparse
    points. Instead the directory entry is visible, but opening it yields only the
    original Linux link target (for example ``../sites-available/shop.example``).
    Treat only very small, single-line, path-looking files as such a surrogate.
    """
    try:
        if not path.is_file():
            return None
        size = path.stat().st_size
        if size <= 0 or size > 4096:
            return None
        raw = path.read_bytes()
    except OSError:
        return None
    try:
        text = raw.decode("utf-8", errors="strict").strip().strip("\x00")
    except UnicodeDecodeError:
        return None
    if not text or "\n" in text or "\r" in text or any(ch in text for ch in "{};"):
        return None
    # Be conservative so an ordinary one-line nginx config is not mistaken for a link.
    if not (text.startswith(("/", "../", "./")) or "/sites-available/" in text.replace("\\", "/")):
        return None
    target_text = text.replace("\\", "/")
    if target_text.startswith("/"):
        candidate = root / target_text.lstrip("/")
    else:
        candidate = Path(os.path.normpath(str(path.parent / target_text)))
    try:
        if candidate.is_file() and candidate.stat().st_size <= MAX_CONFIG_FILE:
            return candidate
    except OSError:
        return None
    return None


def _nginx_resolve_readable_file(root: Path, path: Path) -> tuple[Path | None, str]:
    """Resolve a nginx config entry and describe how it became readable.

    The fallback to a same-named file in ``sites-available`` is intentional: many
    Windows forensic mounts show the Linux symlink entry in ``sites-enabled`` but
    do not permit Python to follow it as a native Windows symlink.
    """
    try:
        if path.is_symlink():
            actual = _rooted_symlink_target(root, path)
            try:
                if actual.is_file() and actual.stat().st_size <= MAX_CONFIG_FILE:
                    return actual, "Linux-Symlink"
            except OSError:
                pass
    except OSError:
        pass

    # A mount/export may have converted the symlink into a regular text file that
    # contains only the Linux link target. Resolve that before treating it as config.
    surrogate = _nginx_plaintext_link_target(root, path)
    if surrogate is not None:
        return surrogate, "Symlink-Ziel als Textdatei"

    try:
        if path.is_file() and path.stat().st_size <= MAX_CONFIG_FILE:
            size = path.stat().st_size
            # Empty regular files in sites-enabled are sometimes how a forensic
            # export represents an otherwise un-followable Linux symlink. Give the
            # canonical sites-available target a chance before accepting emptiness.
            if size > 0 or "sites-enabled" not in [part.casefold() for part in path.parts]:
                return path, "direkt lesbare Datei"
    except OSError:
        pass

    # Last practical Windows-forensics fallback: sites-enabled/foo normally points
    # to sites-available/foo. Even when the mount driver cannot expose/follow the
    # original symlink, the target is often present and readable there.
    parts_cf = [part.casefold() for part in path.parts]
    if "sites-enabled" in parts_cf:
        try:
            idx = parts_cf.index("sites-enabled")
            parts = list(path.parts)
            parts[idx] = "sites-available"
            sibling = Path(*parts)
            # The target itself can again be a real Linux-style symlink.
            actual = _rooted_symlink_target(root, sibling)
            if actual.is_file() and actual.stat().st_size <= MAX_CONFIG_FILE:
                return actual, "über gleichnamige sites-available-Datei rekonstruiert"
        except (OSError, ValueError, IndexError):
            pass

    return None, "nicht lesbar"


def _nginx_readable_file(root: Path, path: Path) -> Path | None:
    """Return the actual readable file behind a Linux/forensic symlink, if any."""
    return _nginx_resolve_readable_file(root, path)[0]


def _discover_active_nginx_files(root: Path) -> set[str]:
    mains = [
        root / "etc/nginx/nginx.conf",
        root / "usr/local/etc/nginx/nginx.conf",
        root / "usr/local/nginx/conf/nginx.conf",
        root / "usr/local/openresty/nginx/conf/nginx.conf",
        root / "opt/nginx/conf/nginx.conf",
    ]
    queue: list[Path] = [p for p in mains if _nginx_readable_file(root, p) is not None]
    if not queue:
        return set()
    active: set[str] = set()
    seen: set[str] = set()
    while queue and len(seen) < 20_000:
        path = queue.pop(0)
        key = _nginx_file_key(path)
        if key in seen:
            continue
        seen.add(key)
        active.add(key)
        actual = _nginx_readable_file(root, path)
        if actual is None:
            continue
        active.add(_nginx_file_key(actual))
        text = _strip_nginx_comments(_read_text(actual))
        if not text:
            continue
        for match in NGINX_INCLUDE_RE.finditer(text):
            for candidate in _nginx_include_candidates(root, path, match.group(1)):
                queue.append(candidate)
    return active


def _expand_nginx_file(
    root: Path,
    path: Path,
    *,
    depth: int = 0,
    stack: set[str] | None = None,
    max_depth: int = 20,
) -> str:
    """Best-effort expansion of nginx include directives for forensic parsing."""
    if depth > max_depth:
        return ""
    stack = set() if stack is None else set(stack)
    key = _nginx_file_key(path)
    if key in stack:
        return ""
    stack.add(key)
    actual = _nginx_readable_file(root, path)
    if actual is None:
        return ""
    text = _strip_nginx_comments(_read_text(actual))
    if not text:
        return ""

    parts: list[str] = []
    last = 0
    for match in NGINX_INCLUDE_RE.finditer(text):
        parts.append(text[last:match.start()])
        candidates = _nginx_include_candidates(root, path, match.group(1))
        if candidates:
            for candidate in candidates:
                expanded = _expand_nginx_file(
                    root, candidate, depth=depth + 1, stack=stack, max_depth=max_depth
                )
                if expanded:
                    parts.append("\n/* K25 expanded include: " + _safe_rel(root, candidate) + " */\n")
                    parts.append(expanded)
                    parts.append("\n/* K25 end include */\n")
        else:
            parts.append(match.group(0))
        last = match.end()
    parts.append(text[last:])
    return "".join(parts)


def _discover_nginx_inventory_files(root: Path, active_files: set[str]) -> list[Path]:
    """Collect nginx candidates without relying on filename suffixes.

    A very common sites-available file name is the domain itself, for example
    ``shop.example.de``.  Path.suffix sees ``.de`` as an extension, so filtering
    for ``.conf`` accidentally drops genuine vhosts.

    ``sites-enabled`` and ``sites-available`` are enumerated explicitly first.
    This matters on Windows forensic mounts where Linux symlink entries can be
    visible in Explorer but fail normal ``Path.is_file()`` checks.
    """
    found: list[Path] = []

    for direct_dir in (root / "etc/nginx/sites-enabled", root / "etc/nginx/sites-available"):
        try:
            with os.scandir(direct_dir) as entries:
                for entry in entries:
                    if entry.name in {".", ".."}:
                        continue
                    candidate = Path(entry.path)
                    # Do not require stat/is_file here: special/symlink entries from
                    # forensic mount drivers are precisely what we need to retain.
                    found.append(candidate)
        except OSError:
            pass

    nginx_roots = [
        root / "etc/nginx",
        root / "usr/local/etc/nginx",
        root / "usr/local/nginx/conf",
        root / "usr/local/openresty/nginx/conf",
        root / "opt/nginx/conf",
    ]
    for nginx_root in nginx_roots:
        if not nginx_root.is_dir():
            continue
        try:
            for p in nginx_root.rglob("*"):
                try:
                    if p.is_dir() or _nginx_readable_file(root, p) is None:
                        continue
                except OSError:
                    continue
                found.append(p)
        except OSError:
            pass

    plesk_root = root / "var/www/vhosts/system"
    if plesk_root.is_dir():
        try:
            for p in plesk_root.rglob("*"):
                if "/conf/" not in p.as_posix():
                    continue
                try:
                    if p.is_dir() or _nginx_readable_file(root, p) is None:
                        continue
                except OSError:
                    continue
                found.append(p)
        except OSError:
            pass

    for key in active_files:
        p = Path(key)
        if _nginx_readable_file(root, p) is not None:
            found.append(p)

    main = root / "etc/nginx/nginx.conf"
    if _nginx_readable_file(root, main) is not None:
        found.append(main)

    return list(dict.fromkeys(found))


def _nginx_is_active(path: Path, active_files: set[str]) -> bool:
    if _nginx_file_key(path) in active_files:
        return True
    # sites-enabled is strong evidence of intended activation even if a forensic
    # export did not preserve the original symlink target perfectly.
    return "/sites-enabled/" in path.as_posix().casefold()


def _nginx_sites_diagnostics(root: Path) -> dict[str, Any]:
    """Summarize how Windows exposes Debian-style nginx vhost directories."""
    out: dict[str, Any] = {
        "enabled_total": 0,
        "available_total": 0,
        "enabled_resolution": Counter(),
        "available_resolution": Counter(),
        "enabled_names": [],
    }
    for label, directory in (
        ("enabled", root / "etc/nginx/sites-enabled"),
        ("available", root / "etc/nginx/sites-available"),
    ):
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    if entry.name in {".", ".."}:
                        continue
                    out[f"{label}_total"] += 1
                    path = Path(entry.path)
                    _actual, method = _nginx_resolve_readable_file(root, path)
                    out[f"{label}_resolution"][method] += 1
                    if label == "enabled" and len(out["enabled_names"]) < 100:
                        out["enabled_names"].append(entry.name)
        except OSError:
            continue
    return out


def _nginx_names_from_block(block: str) -> list[str]:
    names: list[str] = []
    for m in NGINX_SERVER_NAME_RE.finditer(block):
        for raw in m.group(1).split():
            name = raw.strip().strip('"\'')
            if not name or name == "_":
                continue
            names.append(name)
    return list(dict.fromkeys(names))


def _nginx_infer_plesk_domain(root: Path, path: Path) -> str:
    try:
        rel = path.relative_to(root / "var/www/vhosts/system")
        if len(rel.parts) >= 2 and rel.parts[1] == "conf":
            candidate = rel.parts[0]
            if "." in candidate and " " not in candidate:
                return candidate
    except Exception:
        pass
    return ""


def _urls_from_nginx(names: list[str], listens: list[str]) -> str:
    urls: list[str] = []
    if not names:
        return ""
    endpoints: list[tuple[str, str]] = []
    for listen in listens or ["80"]:
        low = listen.casefold()
        token = listen.split()[0] if listen.split() else ""
        port = ""
        m = re.search(r"(?::|^)(\d+)$", token.strip("[]"))
        if m:
            port = m.group(1)
        elif token.isdigit():
            port = token
        scheme = "https" if "ssl" in low or port == "443" else "http"
        endpoints.append((scheme, port))
    if not endpoints:
        endpoints = [("http", "")]
    for name in names:
        if name.startswith("~") or "$" in name or name.startswith("*") or name.startswith("."):
            continue
        for scheme, port in endpoints:
            suffix = ""
            if port and not ((scheme == "http" and port == "80") or (scheme == "https" and port == "443")):
                suffix = f":{port}"
            url = f"{scheme}://{name}{suffix}"
            if url not in urls:
                urls.append(url)
    return " | ".join(urls)

def scan_websites(root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    dedupe: set[tuple[str, ...]] = set()
    active_nginx_files = _discover_active_nginx_files(root)

    nginx_files = _discover_nginx_inventory_files(root, active_nginx_files)
    parsed_name_sources: set[tuple[str, str]] = set()
    parsed_names_global: set[str] = set()

    for path in sorted(set(nginx_files), key=_config_priority):
        actual_path = _nginx_readable_file(root, path)
        if actual_path is None:
            continue

        # Expand includes so a server block can inherit server_name/root/logging
        # directives stored in snippets.  If expansion fails, fall back to the
        # source file itself.
        text = _expand_nginx_file(root, path) or _strip_nginx_comments(_read_text(actual_path))
        if not text:
            continue

        blocks = _brace_blocks(text, "server")
        for block in blocks:
            names = _nginx_names_from_block(block)
            root_match = NGINX_ROOT_RE.search(block)
            docroot = root_match.group(1).strip().strip('"\'') if root_match else ""
            listens = [m.group(1).strip() for m in NGINX_LISTEN_RE.finditer(block)]
            proxy_pass = [m.group(1).strip().strip('"\'') for m in NGINX_PROXY_PASS_RE.finditer(block)]
            access_logs = [m.group(1).strip() for m in NGINX_ACCESS_LOG_RE.finditer(block)]
            error_logs = [m.group(1).strip() for m in NGINX_ERROR_LOG_RE.finditer(block)]
            ssl_certs = [m.group(1).strip().strip('"\'') for m in NGINX_SSL_CERT_RE.finditer(block)]
            fastcgi = [m.group(1).strip() for m in NGINX_FASTCGI_RE.finditer(block)]

            # Plesk path itself is useful corroborating evidence if the generated
            # block delegates server_name to another include or uses variables.
            inferred_plesk = _nginx_infer_plesk_domain(root, path)
            if not names and inferred_plesk:
                names = [inferred_plesk]

            if not names and not docroot and not proxy_pass:
                continue
            domain_text = ", ".join(dict.fromkeys(names)) if names else "(kein server_name)"
            listen_text = ", ".join(dict.fromkeys(listens))
            proxy_text = ", ".join(dict.fromkeys(proxy_pass))
            key = ("Nginx", domain_text, docroot, listen_text, proxy_text)
            if key in dedupe:
                continue
            dedupe.add(key)
            for name in names:
                parsed_name_sources.add((name.casefold(), _safe_rel(root, path).casefold()))
                parsed_names_global.add(name.casefold())
            active = _nginx_is_active(path, active_nginx_files)
            rows.append(
                {
                    "webserver": "Nginx",
                    "domains": domain_text,
                    "urls": _urls_from_nginx(names, listens),
                    "document_root": docroot,
                    "application": _app_for_root(root, docroot),
                    "listen": listen_text,
                    "proxy_pass": proxy_text,
                    "fastcgi_pass": ", ".join(dict.fromkeys(fastcgi)),
                    "access_log": " | ".join(dict.fromkeys(access_logs)),
                    "error_log": " | ".join(dict.fromkeys(error_logs)),
                    "ssl_certificate": " | ".join(dict.fromkeys(ssl_certs)),
                    "active": "Ja" if active else "Nicht sicher / nur Konfigurationsfund",
                    "source_file": _safe_rel(root, path),
                    "status_hint": "aktiv über nginx.conf/Include-Kette eingebunden" if active else _website_status(path),
                    "evidence": "server-Block in Nginx-Konfiguration" + ("; Includes rekonstruiert" if "K25 expanded include" in text else "") + ("; aktiv über Include-Kette" if active else ""),
                }
            )

        # Fallback inventory: even if a server block could not be reconstructed,
        # every literal server_name directive is valuable evidence.  This catches
        # unusual generated configs and partially recovered files.  Mark it as a
        # weaker config finding instead of claiming a fully parsed vhost.
        raw_text = _strip_nginx_comments(_read_text(actual_path))
        for m in NGINX_SERVER_NAME_RE.finditer(raw_text):
            raw_names = []
            for raw in m.group(1).split():
                name = raw.strip().strip('"\'')
                if name and name != "_":
                    raw_names.append(name)
            raw_names = list(dict.fromkeys(raw_names))
            if not raw_names:
                continue
            active = _nginx_is_active(path, active_nginx_files)
            for name in raw_names:
                marker = (name.casefold(), _safe_rel(root, path).casefold())
                if marker in parsed_name_sources or name.casefold() in parsed_names_global:
                    continue
                fallback_key = ("Nginx-server_name", name, _safe_rel(root, path))
                if fallback_key in dedupe:
                    continue
                dedupe.add(fallback_key)
                rows.append(
                    {
                        "webserver": "Nginx",
                        "domains": name,
                        "urls": "",
                        "document_root": "",
                        "application": "",
                        "listen": "",
                        "proxy_pass": "",
                        "fastcgi_pass": "",
                        "access_log": "",
                        "error_log": "",
                        "ssl_certificate": "",
                        "active": "Ja" if active else "Nicht sicher / nur Konfigurationsfund",
                        "source_file": _safe_rel(root, path),
                        "status_hint": "server_name-Fund; Datei aktiv eingebunden" if active else _website_status(path),
                        "evidence": "server_name-Direktive in Nginx-Konfiguration; server-Block nicht vollständig rekonstruiert",
                    }
                )

    # Last-resort clue: sites-available/sites-enabled are frequently named after
    # the domain.  If the file name itself is a valid-looking FQDN and no
    # server_name finding exists, retain it as a clearly labelled weak hint.
    known_domain_tokens: set[str] = set()
    for row in rows:
        if row.get("webserver") != "Nginx":
            continue
        for token in str(row.get("domains", "")).split(","):
            token = token.strip().casefold()
            if token and token not in {"(kein server_name)", "(nicht ermittelt)"}:
                known_domain_tokens.add(token)
    for path in nginx_files:
        posix = path.as_posix().casefold()
        in_enabled = "/sites-enabled/" in posix
        in_available = "/sites-available/" in posix
        if not in_available and not in_enabled:
            continue
        filename = path.name
        candidate = filename[:-5] if filename.casefold().endswith(".conf") else filename
        candidate = candidate.strip().casefold()
        if not NGINX_DOMAIN_FILENAME_RE.fullmatch(candidate) or candidate in known_domain_tokens:
            continue
        actual, resolution = _nginx_resolve_readable_file(root, path)
        raw = _strip_nginx_comments(_read_text(actual)) if actual is not None else ""
        config_like = any(token in raw for token in ("server", "listen", "proxy_pass", "root", "include"))

        # A domain-named entry in sites-enabled is useful evidence even when a
        # Windows mount cannot expose the underlying Linux symlink contents.
        # For sites-available alone, keep the older conservative requirement that
        # the target be readable and look like nginx config.
        if in_available and not in_enabled and not config_like:
            continue
        active = _nginx_is_active(path, active_nginx_files)
        evidence = "Dateiname unter sites-enabled entspricht einer Domain" if in_enabled else "Dateiname unter sites-available entspricht einer Domain"
        if actual is None:
            evidence += "; Inhalt/Symlink-Ziel unter Windows nicht lesbar"
        else:
            evidence += f"; Auflösung: {resolution}"
            if config_like:
                evidence += "; nginx-Konfigurationsinhalt erkannt"
        rows.append(
            {
                "webserver": "Nginx",
                "domains": candidate,
                "urls": "",
                "document_root": "",
                "application": "",
                "listen": "",
                "proxy_pass": "",
                "fastcgi_pass": "",
                "access_log": "",
                "error_log": "",
                "ssl_certificate": "",
                "active": "Ja" if active else "Nicht sicher / nur Konfigurationsfund",
                "source_file": _safe_rel(root, path),
                "status_hint": (
                    "Aktiver sites-enabled-Eintrag; Domain aus Dateiname rekonstruiert"
                    if in_enabled
                    else "Domain-Hinweis aus VHost-Dateiname; server_name nicht ausgelesen"
                ),
                "evidence": evidence,
            }
        )
        known_domain_tokens.add(candidate)

    apache_dirs = [
        root / "etc/apache2/sites-enabled",
        root / "etc/apache2/sites-available",
        root / "etc/httpd/conf.d",
        root / "var/www/vhosts/system",
    ]
    apache_files: list[Path] = []
    for base in apache_dirs:
        if not base.is_dir():
            continue
        try:
            for p in base.rglob("*"):
                if p.is_file() and p.stat().st_size <= MAX_CONFIG_FILE and (
                    p.suffix == ".conf" or p.name in ("httpd.conf", "apache2.conf")
                ):
                    if "vhosts/system" in p.as_posix() and "/conf/" not in p.as_posix():
                        continue
                    apache_files.append(p)
        except OSError:
            continue
    for main in (root / "etc/apache2/apache2.conf", root / "etc/httpd/conf/httpd.conf"):
        if main.is_file():
            apache_files.append(main)

    for path in sorted(set(apache_files), key=_config_priority):
        text = _read_text(path)
        if not text:
            continue
        for vh in APACHE_VHOST_RE.finditer(text):
            endpoint = vh.group(1).strip()
            block = vh.group(2)
            names: list[str] = []
            m = APACHE_NAME_RE.search(block)
            if m:
                names.append(m.group(1).strip())
            for am in APACHE_ALIAS_RE.finditer(block):
                names.extend(am.group(1).split())
            rm = APACHE_ROOT_RE.search(block)
            docroot = rm.group(1).strip() if rm else ""
            if not names and not docroot:
                continue
            domain_text = ", ".join(dict.fromkeys(names)) if names else "(kein ServerName)"
            key = ("Apache", domain_text, docroot)
            if key in dedupe:
                continue
            dedupe.add(key)
            rows.append(
                {
                    "webserver": "Apache",
                    "domains": domain_text,
                    "urls": " | ".join(
                        f"{'https' if '443' in endpoint else 'http'}://{n}" for n in names if n and not n.startswith("~")
                    ),
                    "document_root": docroot,
                    "application": _app_for_root(root, docroot),
                    "listen": endpoint,
                    "proxy_pass": "",
                    "fastcgi_pass": "",
                    "access_log": "",
                    "error_log": "",
                    "ssl_certificate": "",
                    "active": "Ja" if "/sites-enabled/" in path.as_posix().casefold() else "Nicht sicher / nur Konfigurationsfund",
                    "source_file": _safe_rel(root, path),
                    "status_hint": _website_status(path),
                    "evidence": "VirtualHost in Apache-Konfiguration",
                }
            )

    # Application markers can reveal sites that are not represented by enabled vhost configs.
    search_roots = [root / "var/www", root / "srv/www", root / "opt"]
    marker_count = 0
    for base in search_roots:
        if not base.is_dir() or marker_count >= MAX_APP_MARKERS:
            continue
        try:
            for marker in base.rglob("wp-config.php"):
                if marker_count >= MAX_APP_MARKERS:
                    break
                marker_count += 1
                docroot_host = marker.parent
                docroot = "/" + docroot_host.relative_to(root).as_posix()
                if not any(r["document_root"] == docroot for r in rows):
                    rows.append(
                        {
                            "webserver": "(nicht aus Konfiguration zugeordnet)",
                            "domains": "(nicht ermittelt)",
                            "urls": "",
                            "document_root": docroot,
                            "application": "WordPress",
                            "listen": "",
                            "proxy_pass": "",
                            "fastcgi_pass": "",
                            "access_log": "",
                            "error_log": "",
                            "ssl_certificate": "",
                            "active": "Nicht aus VHost-Konfiguration ableitbar",
                            "source_file": _safe_rel(root, marker),
                            "status_hint": "Webanwendung im Dateisystem gefunden",
                            "evidence": "wp-config.php gefunden",
                        }
                    )
            for marker in base.rglob("occ"):
                if marker_count >= MAX_APP_MARKERS:
                    break
                if not marker.is_file() or not (marker.parent / "config" / "config.php").is_file():
                    continue
                marker_count += 1
                docroot_host = marker.parent
                docroot = "/" + docroot_host.relative_to(root).as_posix()
                if not any(r["document_root"] == docroot and r["application"] == "Nextcloud" for r in rows):
                    rows.append(
                        {
                            "webserver": "(nicht aus Konfiguration zugeordnet)",
                            "domains": "(nicht ermittelt)",
                            "urls": "",
                            "document_root": docroot,
                            "application": "Nextcloud",
                            "listen": "",
                            "proxy_pass": "",
                            "fastcgi_pass": "",
                            "access_log": "",
                            "error_log": "",
                            "ssl_certificate": "",
                            "active": "Nicht aus VHost-Konfiguration ableitbar",
                            "source_file": _safe_rel(root, marker.parent / "config" / "config.php"),
                            "status_hint": "Webanwendung im Dateisystem gefunden",
                            "evidence": "Nextcloud occ + config/config.php gefunden",
                        }
                    )
        except (OSError, PermissionError):
            continue

    # Plesk directory structure is itself useful when configs are missing/rotated.
    plesk_system = root / "var/www/vhosts/system"
    if plesk_system.is_dir():
        try:
            for d in plesk_system.iterdir():
                if not d.is_dir():
                    continue
                domain = d.name
                if not any(domain in r.get("domains", "").split(", ") for r in rows):
                    rows.append(
                        {
                            "webserver": "Plesk-VHost",
                            "domains": domain,
                            "urls": "",
                            "document_root": f"/var/www/vhosts/{domain}/httpdocs",
                            "application": _app_for_root(root, f"/var/www/vhosts/{domain}/httpdocs"),
                            "listen": "",
                            "proxy_pass": "",
                            "fastcgi_pass": "",
                            "access_log": "",
                            "error_log": "",
                            "ssl_certificate": "",
                            "active": "Plesk-VHost-Struktur vorhanden",
                            "source_file": _safe_rel(root, d),
                            "status_hint": "Plesk-VHost-Struktur vorhanden",
                            "evidence": "Plesk vhost system directory",
                        }
                    )
        except OSError:
            pass

    rows.sort(key=lambda r: (r.get("domains", ""), r.get("webserver", ""), r.get("document_root", "")))
    return rows


SERVICE_SIGNATURES = [
    ("Remote Access", "OpenSSH", ("sshd", "ssh.service"), ("etc/ssh/sshd_config",)),
    ("Web", "Nginx", ("nginx",), ("etc/nginx/nginx.conf",)),
    ("Web", "Apache HTTP Server", ("apache2", "httpd"), ("etc/apache2", "etc/httpd")),
    ("Web", "PHP-FPM", ("php-fpm", "php8", "php7"), ("etc/php",)),
    ("Hosting/Admin", "Plesk", ("psa", "sw-cp-server", "plesk"), ("etc/psa", "opt/psa", "usr/local/psa", "etc/sw-cp-server")),
    ("Mail", "Postfix", ("postfix",), ("etc/postfix/main.cf",)),
    ("Mail", "Exim", ("exim4", "exim"), ("etc/exim4", "etc/exim")),
    ("Mail", "Dovecot", ("dovecot",), ("etc/dovecot",)),
    ("Mail", "Rspamd", ("rspamd",), ("etc/rspamd",)),
    ("Mail", "SpamAssassin", ("spamassassin", "spamd"), ("etc/spamassassin",)),
    ("Voice", "TeamSpeak", ("teamspeak", "ts3server"), ("etc/teamspeak3-server", "opt/teamspeak", "home/teamspeak")),
    ("Cloud", "Nextcloud", ("nextcloud",), ("var/www/nextcloud/config/config.php", "var/www/html/nextcloud/config/config.php")),
    ("Container", "Docker", ("docker", "containerd"), ("etc/docker", "var/lib/docker")),
    ("Container", "Podman", ("podman",), ("etc/containers", "var/lib/containers")),
    ("Datenbank", "MariaDB/MySQL", ("mariadb", "mysql", "mysqld"), ("etc/mysql", "var/lib/mysql")),
    ("Datenbank", "PostgreSQL", ("postgresql", "postgres"), ("etc/postgresql", "var/lib/postgresql")),
    ("Datenbank", "Redis", ("redis",), ("etc/redis", "var/lib/redis")),
    ("Dateitransfer", "vsftpd", ("vsftpd",), ("etc/vsftpd.conf",)),
    ("Dateitransfer", "ProFTPD", ("proftpd",), ("etc/proftpd",)),
    ("Sicherheit", "Fail2ban", ("fail2ban",), ("etc/fail2ban",)),
    ("VPN", "WireGuard", ("wg-quick", "wireguard"), ("etc/wireguard",)),
    ("VPN", "OpenVPN", ("openvpn",), ("etc/openvpn",)),
]


def _event_service_text(event: dict[str, Any]) -> str:
    return " ".join(
        str(event.get(k, "")) for k in ("service", "unit", "message")
    ).casefold()


def scan_services(root: Path, events: list[dict[str, Any]], websites: list[dict[str, Any]]) -> list[dict[str, Any]]:
    event_texts = [(_event_service_text(e), e.get("time_utc", "")) for e in events]
    rows: list[dict[str, Any]] = []

    for category, label, event_keys, fs_markers in SERVICE_SIGNATURES:
        matched_times: list[str] = []
        for text, ts in event_texts:
            if any(key.casefold() in text for key in event_keys):
                if ts:
                    matched_times.append(ts)
                else:
                    matched_times.append("")

        fs_hits = []
        for rel in fs_markers:
            p = root / rel
            if p.exists():
                fs_hits.append("/" + rel.replace("\\", "/"))

        # App detection from website scan may identify Nextcloud outside standard paths.
        if label == "Nextcloud":
            for site in websites:
                if site.get("application") == "Nextcloud":
                    fs_hits.append(site.get("document_root", "") + "/config/config.php")

        if not matched_times and not fs_hits:
            continue

        if matched_times and fs_hits:
            assessment = "Journal-Aktivität + Installation/Konfiguration nachgewiesen"
        elif matched_times:
            assessment = "Aktivität im Journal festgestellt"
        else:
            assessment = "Installation/Konfiguration im Dateisystem festgestellt"
        clean_times = sorted(t for t in matched_times if t)
        rows.append(
            {
                "category": category,
                "service": label,
                "assessment": assessment,
                "journal_count": len(matched_times),
                "first_seen": clean_times[0] if clean_times else "",
                "last_seen": clean_times[-1] if clean_times else "",
                "evidence": "; ".join(dict.fromkeys(fs_hits)) if fs_hits else "Journal-Einträge",
            }
        )

    # Include distinct active-looking systemd services even if not in curated signatures.
    unit_counter: Counter[str] = Counter()
    first_last: dict[str, list[str]] = defaultdict(list)
    for event in events:
        unit = str(event.get("unit", ""))
        if unit.endswith(".service"):
            unit_counter[unit] += 1
            if event.get("time_utc"):
                first_last[unit].append(event["time_utc"])
    known_text = " ".join(r["service"].casefold() for r in rows)
    for unit, count in unit_counter.most_common(75):
        stem = unit.removesuffix(".service")
        if stem.casefold() in known_text or count < 2:
            continue
        times = sorted(first_last.get(unit, []))
        rows.append(
            {
                "category": "Weitere systemd-Dienste",
                "service": unit,
                "assessment": "Aktivität im Journal festgestellt",
                "journal_count": count,
                "first_seen": times[0] if times else "",
                "last_seen": times[-1] if times else "",
                "evidence": "_SYSTEMD_UNIT im Journal",
            }
        )

    rows.sort(key=lambda r: (r["category"], r["service"]))
    return rows


def discover_access_logs(root: Path) -> list[Path]:
    candidates: list[Path] = []
    bases = [
        root / "var/log/nginx",
        root / "var/log/apache2",
        root / "var/log/httpd",
        root / "var/log/plesk",
        root / "var/log/sw-cp-server",
        root / "usr/local/psa/admin/logs",
        root / "opt/psa/admin/logs",
        root / "var/www/vhosts/system",
    ]
    for base in bases:
        if not base.is_dir():
            continue
        try:
            for p in base.rglob("*"):
                if len(candidates) >= MAX_ACCESS_LOGS:
                    break
                if not p.is_file():
                    continue
                name = p.name.casefold()
                posix = p.as_posix().casefold()
                is_access = (
                    "access" in name
                    or "httpsd_access_log" in name
                    or ("plesk" in posix and name == "panel.log")
                )
                if is_access and (p.suffix.casefold() in ("", ".log", ".gz") or ".log." in name or "access_log" in name):
                    candidates.append(p)
        except (OSError, PermissionError):
            continue
    return sorted(set(candidates), key=str)[:MAX_ACCESS_LOGS]


def _parse_access_time(value: str) -> str:
    for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%d/%b/%Y:%H:%M:%S"):
        try:
            dt = datetime.strptime(value, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        except ValueError:
            pass
    return value


def _host_hint_from_log(root: Path, path: Path) -> str:
    parts = path.parts
    try:
        idx = parts.index("system")
        if idx > 0 and "vhosts" in parts[:idx]:
            return parts[idx + 1] if idx + 1 < len(parts) else ""
    except ValueError:
        pass
    # Windows paths preserve case; use a case-insensitive fallback.
    lower = [p.casefold() for p in parts]
    if "vhosts" in lower and "system" in lower:
        idx = lower.index("system")
        if idx + 1 < len(parts):
            return parts[idx + 1]
    return ""


def _tool_from_request(
    source: Path,
    request_path: str,
    known_apps: set[str],
    host_hint: str,
    nextcloud_domains: set[str],
) -> str:
    src = source.as_posix().casefold()
    p = request_path.casefold()
    if "plesk" in src or "sw-cp-server" in src or "psa/admin/logs" in src or "/login_up.php3" in p:
        return "Plesk"
    if WORDPRESS_PATH_RE.search(request_path):
        return "WordPress"
    if PHPMYADMIN_PATH_RE.search(request_path):
        return "phpMyAdmin"
    if "Nextcloud" in known_apps and NEXTCLOUD_PATH_RE.search(request_path):
        # Generic /login paths are ambiguous on shared access logs. Only classify as
        # Nextcloud if the URL itself contains Nextcloud, the log is site-specific,
        # or the source path points to Nextcloud material.
        if "nextcloud" in p or "nextcloud" in src or (host_hint and host_hint.casefold() in nextcloud_domains):
            return "Nextcloud"
    if GENERIC_ADMIN_PATH_RE.search(request_path):
        return "Generisches Admin-Panel"
    return ""


def _basic_http_assessment(method: str, path: str, status: int, tool: str) -> tuple[str, str]:
    if status in (401, 403):
        return "Zugriff abgewiesen", "hoch"
    if status == 404:
        return "Admin-Pfad nicht vorhanden (404)", "hoch"
    if status >= 500:
        return "Serverfehler beim Zugriff", "hoch"
    if tool == "WordPress" and "wp-login.php" in path.casefold():
        if method == "POST" and status in (301, 302, 303, 307, 308):
            return "Login-POST mit Weiterleitung; Erfolg noch zu korrelieren", "mittel"
        if method == "POST" and status == 200:
            return "Login-POST ohne Erfolgsnachweis", "mittel"
        return "Loginseite aufgerufen; keine Anmeldung nachgewiesen", "hoch"
    if tool in ("Nextcloud", "phpMyAdmin", "Plesk") and method == "POST":
        if status in (301, 302, 303, 307, 308):
            return "Login-/Admin-POST mit Weiterleitung; möglicher Erfolg", "mittel"
        if 200 <= status < 300:
            return "Login-/Admin-POST beantwortet; Authentifizierung nicht allein nachweisbar", "mittel"
    if 200 <= status < 300:
        return "Admin-Endpunkt erfolgreich ausgeliefert; Login nicht allein nachweisbar", "hoch"
    if 300 <= status < 400:
        return "Weiterleitung; Authentifizierung nicht allein ableitbar", "hoch"
    return f"HTTP-Status {status}", "hoch"


def _open_log(path: Path):
    if path.suffix.casefold() == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return path.open("rt", encoding="utf-8", errors="replace")


def scan_admin_access(root: Path, websites: list[dict[str, Any]], ssh_rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[str]]:
    access_logs = discover_access_logs(root)
    known_apps = {r.get("application", "") for r in websites if r.get("application")}
    nextcloud_domains: set[str] = set()
    for site in websites:
        if site.get("application") != "Nextcloud":
            continue
        for domain in str(site.get("domains", "")).split(","):
            domain = domain.strip().casefold()
            if domain and not domain.startswith("("):
                nextcloud_domains.add(domain)
    ssh_success_ips = {
        r.get("ip", "") for r in ssh_rows if r.get("type") == SSH_SUCCESS_TEXT and r.get("ip")
    }
    log_site_map: dict[str, str] = {}
    for site in websites:
        domains = str(site.get("domains", "")).strip()
        if not domains or domains.startswith("("):
            continue
        for spec in str(site.get("access_log", "")).split("|"):
            token = spec.strip().split()[0] if spec.strip() else ""
            if token.startswith("/"):
                log_site_map[token.casefold()] = domains
    rows: list[dict[str, Any]] = []

    for path in access_logs:
        host_hint = _host_hint_from_log(root, path)
        if not host_hint:
            host_hint = log_site_map.get(_safe_rel(root, path).casefold(), "")
        try:
            with _open_log(path) as handle:
                line_no = 0
                while line_no < MAX_ACCESS_LINES_PER_FILE and len(rows) < MAX_ADMIN_FINDINGS:
                    line = handle.readline(MAX_ACCESS_LINE_LENGTH)
                    if not line:
                        break
                    line_no += 1
                    # An overlong line is treated as malformed and skipped. Consume its remainder.
                    if len(line) >= MAX_ACCESS_LINE_LENGTH and not line.endswith("\n"):
                        while True:
                            tail = handle.readline(MAX_ACCESS_LINE_LENGTH)
                            if not tail or tail.endswith("\n"):
                                break
                        continue
                    match = ACCESS_RE.match(line.rstrip("\n"))
                    if not match:
                        continue
                    gd = match.groupdict()
                    ip = gd["ip"].strip("[]")
                    try:
                        ipaddress.ip_address(ip)
                    except ValueError:
                        continue
                    request_path = gd["path"]
                    tool = _tool_from_request(path, request_path, known_apps, host_hint, nextcloud_domains)
                    if not tool:
                        continue
                    status = int(gd["status"])
                    assessment, confidence = _basic_http_assessment(gd["method"], request_path, status, tool)
                    rows.append(
                        {
                            "time_utc": _parse_access_time(gd["time"]),
                            "tool": tool,
                            "assessment": assessment,
                            "confidence": confidence,
                            "ip": ip,
                            "ssh_correlation": "Ja - gleiche IP mit erfolgreicher SSH-Anmeldung" if ip in ssh_success_ips else "",
                            "method": gd["method"],
                            "path": request_path,
                            "status": status,
                            "site": host_hint,
                            "user_agent": gd.get("ua") or "",
                            "source_file": _safe_rel(root, path),
                            "line": line_no,
                        }
                    )
        except (OSError, EOFError, gzip.BadGzipFile):
            continue

    # Correlate login redirect -> protected admin page from same IP shortly afterwards.
    rows.sort(key=lambda r: r.get("time_utc", ""))
    parsed_dt: list[datetime | None] = []
    for row in rows:
        try:
            parsed_dt.append(datetime.fromisoformat(str(row["time_utc"]).replace("Z", "+00:00")))
        except ValueError:
            parsed_dt.append(None)

    for i, row in enumerate(rows):
        if row["tool"] not in ("WordPress", "Nextcloud", "phpMyAdmin", "Plesk"):
            continue
        if row["method"] != "POST" or row["status"] not in (301, 302, 303, 307, 308):
            continue
        start_dt = parsed_dt[i]
        if start_dt is None:
            continue
        for j in range(i + 1, min(i + 200, len(rows))):
            candidate = rows[j]
            cdt = parsed_dt[j]
            if cdt is None or cdt - start_dt > timedelta(minutes=10):
                break
            if candidate["ip"] != row["ip"] or candidate["tool"] != row["tool"]:
                continue
            cp = candidate["path"].casefold()
            protected = False
            if row["tool"] == "WordPress":
                protected = "/wp-admin" in cp and "admin-ajax.php" not in cp and 200 <= candidate["status"] < 300
            elif row["tool"] == "Nextcloud":
                protected = ("/settings" in cp or "/apps/" in cp) and 200 <= candidate["status"] < 300
            elif row["tool"] == "phpMyAdmin":
                protected = 200 <= candidate["status"] < 300 and not ("login" in cp)
            elif row["tool"] == "Plesk":
                protected = 200 <= candidate["status"] < 300 and "login" not in cp
            if protected:
                row["assessment"] = f"Starker Hinweis auf erfolgreiche {row['tool']}-Anmeldung (POST/Redirect + anschließender Adminzugriff)"
                row["confidence"] = "hoch"
                candidate["assessment"] = f"Geschützter Bereich nach {row['tool']}-Login von gleicher IP erreicht"
                candidate["confidence"] = "hoch"
                break

    rows.sort(key=lambda r: r.get("time_utc", ""), reverse=True)
    return rows, [_safe_rel(root, p) for p in access_logs]


def scan_server_root(
    root: Path,
    events: list[dict[str, Any]],
    ssh_rows: list[dict[str, Any]],
    progress: Callable[[str], None] | None = None,
) -> ServerScanResult:
    result = ServerScanResult(linux_root=str(root))
    if progress:
        progress("Ermittle Webseiten und Webanwendungen …")
    result.websites = scan_websites(root)
    nginx_rows = [r for r in result.websites if r.get("webserver") == "Nginx"]
    nginx_diag = _nginx_sites_diagnostics(root)
    if nginx_rows:
        active_nginx = sum(1 for r in nginx_rows if r.get("active") == "Ja")
        result.scan_notes.append(
            f"NGINX-Inventar: {len(nginx_rows)} VHost-/server_name-Feststellungen, davon {active_nginx} als aktiv eingebunden erkannt. "
            "Zusätzlich zu nginx.conf/Includes wurden sites-available, sites-enabled und weitere Dateien unter /etc/nginx inventarisiert."
        )
    if nginx_diag.get("enabled_total") or nginx_diag.get("available_total"):
        enabled_res = ", ".join(
            f"{count}× {method}" for method, count in nginx_diag["enabled_resolution"].most_common()
        ) or "keine"
        available_res = ", ".join(
            f"{count}× {method}" for method, count in nginx_diag["available_resolution"].most_common()
        ) or "keine"
        result.scan_notes.append(
            f"NGINX-Verzeichnisdiagnose: sites-enabled={nginx_diag['enabled_total']} Einträge ({enabled_res}); "
            f"sites-available={nginx_diag['available_total']} Einträge ({available_res})."
        )
        unreadable = nginx_diag["enabled_resolution"].get("nicht lesbar", 0)
        if unreadable:
            names = ", ".join(nginx_diag.get("enabled_names", [])[:20])
            result.scan_notes.append(
                f"Hinweis: {unreadable} Einträge in sites-enabled konnten vom Windows-Dateisystem nicht direkt aufgelöst werden. "
                "Der Analyzer versucht deshalb die gleichnamige Datei in sites-available und domainartige Dateinamen als Rückfallebene zu verwenden."
                + (f" Sichtbare Eintragsnamen (Auszug): {names}." if names else "")
            )
    if progress:
        progress("Ermittle installierte/aktive Dienste …")
    result.services = scan_services(root, events, result.websites)
    if progress:
        progress("Prüfe Webserver-/Panel-Access-Logs auf Adminzugriffe …")
    result.admin_accesses, result.access_log_files = scan_admin_access(root, result.websites, ssh_rows)
    if progress:
        progress("Analysiere Mailserver, Konten, Aliase und authentifizierte Mailzugriffe …")
    mail_scan = scan_mail(root, events)
    result.mail_servers = mail_scan.servers
    result.mail_accounts = mail_scan.accounts
    result.mail_aliases = mail_scan.aliases
    result.mail_accesses = mail_scan.accesses
    result.mail_diagnostics = mail_scan.diagnostics
    result.mail_log_files = mail_scan.log_files
    result.scan_notes.extend(mail_scan.notes)
    if progress:
        progress("Analysiere TLS-/Let's-Encrypt-Zertifikate …")
    result.tls_certificates = scan_tls_certificates(root)
    if progress:
        progress("Analysiere Betreiber-Artefakte (SSH-Keys, Git, Shell-History, Cron) …")
    result.operator_artifacts, artifact_notes = scan_operator_artifacts(root)
    result.scan_notes.extend(artifact_notes)
    if len(result.admin_accesses) >= MAX_ADMIN_FINDINGS:
        result.scan_notes.append(
            f"Adminzugriffs-Auswertung aus Sicherheits-/Performancegründen auf {MAX_ADMIN_FINDINGS:,} Treffer begrenzt.".replace(",", ".")
        )
    if not result.access_log_files:
        result.scan_notes.append("Keine typischen Webserver-/Plesk-Access-Logs im ausgewählten Linux-Root gefunden.")
    if not result.websites:
        result.scan_notes.append("Keine Website/VHost-Konfiguration oder bekannte Webanwendung erkannt.")
    return result
