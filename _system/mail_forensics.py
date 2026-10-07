from __future__ import annotations

import gzip
import glob
import ipaddress
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

MAX_CONFIG_FILE = 8 * 1024 * 1024
MAX_MAIL_LOG_FILES = 120
MAX_MAIL_LOG_LINES = 2_000_000
MAX_MAIL_ACCOUNTS = 100_000
MAX_MAIL_ALIASES = 100_000
MAX_MAIL_ACCESSES = 200_000

EMAIL_RE = re.compile(r"(?i)(?<![A-Z0-9._%+\-])([A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,63})(?![A-Z0-9._%+\-])")
MAP_SPEC_RE = re.compile(r"(?i)\b(?:hash|btree|lmdb|texthash|regexp|pcre):(/[^\s,]+)")
ABS_PATH_RE = re.compile(r"(?<![A-Za-z0-9_.-])(/(?:etc|var|opt|usr|home|srv)/[^\s,;{}]+)")
DOVECOT_LOGIN_RE = re.compile(
    r"(?i)(?:imap|pop3|submission)(?:-login)?:.*?Login:\s*user=<(?P<user>[^>]+)>.*?rip=(?P<ip>[^,\s]+)"
)
POSTFIX_SASL_RE = re.compile(
    r"(?i)postfix/(?:smtpd|submission/smtpd).*?client=.*?\[(?P<ip>[0-9a-f:.]+)\].*?sasl_username=(?P<user>[^,\s]+)"
)
EXIM_AUTH_RE = re.compile(
    r"(?i)(?:dovecot_login|plain|login).*?auth(?:enticated)?(?:_id| as)?[=: ]+(?P<user>[^\s,]+).*?(?:H=|\[)(?P<ip>[0-9a-f:.]+)"
)


@dataclass
class MailScanResult:
    servers: list[dict[str, Any]] = field(default_factory=list)
    accounts: list[dict[str, Any]] = field(default_factory=list)
    aliases: list[dict[str, Any]] = field(default_factory=list)
    accesses: list[dict[str, Any]] = field(default_factory=list)
    log_files: list[str] = field(default_factory=list)
    diagnostics: list[dict[str, Any]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


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


def _root_path(root: Path, linux_path: str) -> Path:
    value = linux_path.strip().strip('"\'')
    if value.startswith("/"):
        value = value[1:]
    return root / value


def _rooted_symlink_target(root: Path, path: Path, max_depth: int = 8) -> Path:
    """Resolve Linux-style absolute symlinks inside a mounted/extracted root.

    An absolute target such as /var/qmail/mailnames must be interpreted relative to
    the evidence root rather than the Windows host root.
    """
    current = path
    seen: set[str] = set()
    for _ in range(max_depth):
        key = str(current)
        if key in seen:
            break
        seen.add(key)
        try:
            if not current.is_symlink():
                return current
            target = os.readlink(current)
        except OSError:
            return current
        target_text = str(target).replace("\\", "/")
        if target_text.startswith("/"):
            current = root / target_text.lstrip("/")
        else:
            current = Path(os.path.normpath(str(current.parent / target_text)))
    return current


def _plaintext_link_target(root: Path, path: Path) -> Path | None:
    """Resolve a symlink that a forensic export exposed as a tiny text file."""
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
    if not text.startswith(("/", "../", "./")):
        return None
    if text.startswith("/"):
        candidate = root / text.lstrip("/")
    else:
        candidate = Path(os.path.normpath(str(path.parent / text)))
    try:
        if candidate.exists():
            return candidate
    except OSError:
        pass
    return None


def _resolve_evidence_path(root: Path, path: Path) -> tuple[Path | None, str]:
    """Best-effort resolution for Linux paths exposed through a Windows mount."""
    try:
        if path.is_symlink():
            actual = _rooted_symlink_target(root, path)
            if actual.exists():
                return actual, "Linux-Symlink"
    except OSError:
        pass
    surrogate = _plaintext_link_target(root, path)
    if surrogate is not None:
        return surrogate, "Symlink-Ziel als Textdatei"
    try:
        if path.exists():
            return path, "direkt lesbar"
    except OSError:
        pass
    return None, "nicht lesbar"


def _iter_entries(path: Path) -> list[Path]:
    """Enumerate directory entries without requiring Path.is_file/is_dir first."""
    rows: list[Path] = []
    try:
        with os.scandir(path) as entries:
            for entry in entries:
                if entry.name not in {".", ".."}:
                    rows.append(Path(entry.path))
    except OSError:
        pass
    return rows


def _directory_accessible(path: Path) -> bool:
    try:
        with os.scandir(path):
            return True
    except OSError:
        return False


def _resolve_directory(root: Path, path: Path) -> tuple[Path | None, str]:
    actual, method = _resolve_evidence_path(root, path)
    if actual is not None:
        try:
            if actual.is_dir():
                return actual, method
        except OSError:
            pass
        if _directory_accessible(actual):
            return actual, method + " / Verzeichniszugriff"
    # Some forensic filesystem drivers expose a directory through enumeration even
    # though stat()/exists() fails. Try direct directory access as a final fallback.
    if _directory_accessible(path):
        return path, "direkt per Verzeichniszugriff"
    return None, "nicht lesbar"


def _read_text_evidence(root: Path, path: Path, limit: int = MAX_CONFIG_FILE) -> tuple[str, Path | None, str]:
    actual, method = _resolve_evidence_path(root, path)
    if actual is None:
        return "", None, method
    return _read_text(actual, limit), actual, method


def _valid_ip(value: str) -> str:
    value = value.strip("[](),;<>\"'")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return ""


def _uncomment_lines(text: str) -> list[str]:
    lines: list[str] = []
    pending = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # Common Postfix continuation: indented line continues previous value.
        if raw[:1].isspace() and pending:
            pending += " " + line
            continue
        if pending:
            lines.append(pending)
        pending = line
    if pending:
        lines.append(pending)
    return lines


def _postfix_kv(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in _uncomment_lines(text):
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip().casefold()
        if key:
            out[key] = value.strip()
    return out


def _tokens(value: str) -> list[str]:
    return [x.strip().strip(",") for x in re.split(r"[\s,]+", value or "") if x.strip().strip(",")]


def _expand_postfix_token(token: str, kv: dict[str, str]) -> str:
    replacements = {
        "$myhostname": kv.get("myhostname", ""),
        "${myhostname}": kv.get("myhostname", ""),
        "$mydomain": kv.get("mydomain", ""),
        "${mydomain}": kv.get("mydomain", ""),
    }
    out = token
    for key, value in replacements.items():
        out = out.replace(key, value)
    return out


def _extract_map_paths(value: str) -> list[str]:
    return list(dict.fromkeys(m.group(1) for m in MAP_SPEC_RE.finditer(value or "")))


def _parse_mapping_file(root: Path, linux_path: str) -> list[tuple[str, str, int]]:
    path = _root_path(root, linux_path)
    text, actual, _method = _read_text_evidence(root, path)
    if actual is not None:
        path = actual
    rows: list[tuple[str, str, int]] = []
    if not text:
        return rows
    for line_no, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # Avoid accidentally exposing passwords in common credential maps.
        if "password" in path.name.casefold() or "sasl_passwd" in path.name.casefold():
            continue
        parts = line.split(None, 1)
        if not parts:
            continue
        lhs = parts[0].strip()
        rhs = parts[1].strip() if len(parts) > 1 else ""
        rows.append((lhs, rhs, line_no))
    return rows


def _add_account(store: dict[str, dict[str, Any]], address: str, source: str, evidence: str, detail: str = "") -> None:
    address = address.strip().strip("<>").casefold()
    if not address or "@" not in address or len(store) >= MAX_MAIL_ACCOUNTS:
        return
    row = store.get(address)
    if row is None:
        store[address] = {
            "address": address,
            "domain": address.split("@", 1)[1],
            "assessment": "",
            "evidence": evidence,
            "source_file": source,
            "detail": detail,
        }
        return
    sources = {x.strip() for x in str(row.get("source_file", "")).split(" | ") if x.strip()}
    sources.add(source)
    row["source_file"] = " | ".join(sorted(sources))
    evidences = {x.strip() for x in str(row.get("evidence", "")).split(" | ") if x.strip()}
    evidences.add(evidence)
    row["evidence"] = " | ".join(sorted(evidences))
    if detail and detail not in str(row.get("detail", "")):
        row["detail"] = (str(row.get("detail", "")) + " | " + detail).strip(" |")


def _add_alias(store: dict[tuple[str, str], dict[str, Any]], alias: str, target: str, source: str, evidence: str) -> None:
    alias = alias.strip().strip("<>")
    target = target.strip().strip("<>")
    if not alias or not target or len(store) >= MAX_MAIL_ALIASES:
        return
    key = (alias.casefold(), target.casefold())
    if key in store:
        return
    alias_domain = alias.split("@", 1)[1].casefold() if "@" in alias else ""
    target_domain = target.split("@", 1)[1].casefold() if "@" in target else ""
    store[key] = {
        "alias": alias,
        "target": target,
        "external_forward": "Ja" if alias_domain and target_domain and alias_domain != target_domain else "",
        "evidence": evidence,
        "source_file": source,
    }


def _scan_postfix(root: Path, result: MailScanResult, accounts: dict[str, dict[str, Any]], aliases: dict[tuple[str, str], dict[str, Any]]) -> None:
    main_cf = root / "etc/postfix/main.cf"
    text, main_actual, main_method = _read_text_evidence(root, main_cf)
    if not text:
        return
    if main_actual is not None:
        main_cf = main_actual
    kv = _postfix_kv(text)
    domains: set[str] = set()
    for key in ("myhostname", "mydomain"):
        value = kv.get(key, "").strip()
        if value and "$" not in value:
            domains.add(value.casefold())
    for key in ("mydestination", "virtual_mailbox_domains", "relay_domains"):
        for token in _tokens(kv.get(key, "")):
            token = _expand_postfix_token(token, kv).strip()
            if not token or token.startswith(("$", "hash:", "btree:", "lmdb:", "mysql:", "pgsql:", "ldap:", "regexp:", "pcre:")):
                continue
            if "." in token and "/" not in token and "=" not in token and not token.casefold().startswith("localhost"):
                domains.add(token.casefold())
        for map_path in _extract_map_paths(kv.get(key, "")):
            for lhs, _rhs, _line in _parse_mapping_file(root, map_path):
                if "@" not in lhs and "." in lhs:
                    domains.add(lhs.casefold())

    result.servers.append(
        {
            "component": "Postfix",
            "hostname": kv.get("myhostname", ""),
            "domains": ", ".join(sorted(domains)),
            "relay": kv.get("relayhost", ""),
            "interfaces": kv.get("inet_interfaces", ""),
            "protocols": kv.get("inet_protocols", ""),
            "source_file": _safe_rel(root, main_cf),
            "notes": "Postfix-Hauptkonfiguration",
        }
    )

    _diag(result, "Postfix", "Erkannte Maildomains", len(domains), "OK", _safe_rel(root, main_cf))
    database_maps: list[str] = []
    for map_key in ("virtual_mailbox_maps", "virtual_alias_maps", "local_recipient_maps", "alias_maps"):
        value = kv.get(map_key, "")
        for m in re.finditer(r"(?i)\b(mysql|pgsql|ldap|sqlite):([^\s,]+)", value):
            database_maps.append(f"{map_key}: {m.group(1)}:{m.group(2)}")
    if database_maps:
        _diag(
            result, "Postfix", "Datenbankbasierte Maps", len(database_maps), "Info",
            " | ".join(database_maps[:12]),
        )

    for key in ("virtual_mailbox_maps", "local_recipient_maps"):
        for map_path in _extract_map_paths(kv.get(key, "")):
            src = map_path
            for lhs, rhs, line_no in _parse_mapping_file(root, map_path):
                for address in EMAIL_RE.findall(lhs):
                    _add_account(accounts, address, src, f"Postfix {key}", f"Zeile {line_no}; Ziel: {rhs[:180]}")

    for key in ("virtual_alias_maps", "alias_maps", "canonical_maps", "sender_canonical_maps", "recipient_canonical_maps"):
        for map_path in _extract_map_paths(kv.get(key, "")):
            for lhs, rhs, _line_no in _parse_mapping_file(root, map_path):
                targets = EMAIL_RE.findall(rhs)
                if not targets:
                    # Local alias target can still be useful.
                    targets = [x.strip() for x in rhs.split(",") if x.strip() and not x.strip().startswith("|")]
                for target in targets:
                    _add_alias(aliases, lhs, target, map_path, f"Postfix {key}")

    # Debian/Ubuntu local aliases are common even if alias_maps contains database notation.
    aliases_file = root / "etc/aliases"
    aliases_text, aliases_actual, _aliases_method = _read_text_evidence(root, aliases_file)
    if aliases_actual is not None:
        aliases_file = aliases_actual
    if aliases_text:
        for raw in aliases_text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or ":" not in line:
                continue
            lhs, rhs = line.split(":", 1)
            for target in [x.strip() for x in rhs.split(",") if x.strip()]:
                if target.startswith(("|", "/")):
                    continue
                _add_alias(aliases, lhs.strip(), target, _safe_rel(root, aliases_file), "/etc/aliases")


def _is_domain_name(value: str) -> bool:
    value = value.strip().strip(".").casefold()
    return bool(re.fullmatch(r"(?=.{3,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", value))


def _diag(result: MailScanResult, area: str, item: str, value: Any, status: str = "", source: str = "") -> None:
    result.diagnostics.append(
        {
            "area": area,
            "item": item,
            "value": str(value),
            "status": status,
            "source_file": source,
        }
    )


def _dovecot_include_candidates(root: Path, current: Path, spec: str) -> list[Path]:
    value = spec.strip().strip('"\'')
    if not value:
        return []
    if value.startswith("/"):
        host_pattern = str(root / value.lstrip("/"))
    else:
        host_pattern = str(current.parent / value)
    # Dovecot supports glob includes. glob() also handles ordinary paths.
    matches = [Path(x) for x in glob.glob(host_pattern)]
    if matches:
        return matches
    return [Path(host_pattern)]


def _collect_dovecot_configs(root: Path) -> list[tuple[Path, str]]:
    base = root / "etc/dovecot"
    if not (base.exists() or _directory_accessible(base)):
        return []
    queue: list[Path] = []
    main = base / "dovecot.conf"
    if main.exists() or main.is_symlink():
        queue.append(main)
    # Inventory every small entry, not only *.conf. Forensic exports and custom
    # deployments regularly use extension-less include files.
    try:
        for path in base.rglob("*"):
            if path.is_dir():
                continue
            queue.append(path)
    except OSError:
        pass

    out: list[tuple[Path, str]] = []
    seen: set[str] = set()
    while queue and len(seen) < 20_000:
        path = queue.pop(0)
        key = str(path)
        if key in seen:
            continue
        seen.add(key)
        actual, _method = _resolve_evidence_path(root, path)
        if actual is None:
            continue
        text = _read_text(actual)
        if not text:
            continue
        out.append((path, text))
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r"^!include(?:_try)?\s+(.+?)\s*$", line, re.I)
            if not m:
                continue
            queue.extend(_dovecot_include_candidates(root, path, m.group(1)))
    return out


def _expand_dovecot_user_path(root: Path, raw_path: str) -> list[Path]:
    value = raw_path.strip().strip('"\'')
    # Remove trailing punctuation often captured from old-style config syntax.
    value = value.rstrip(")};,")
    if not value.startswith("/"):
        return []
    pattern = value
    # Dynamic passwd-file paths can contain user/domain variables. Replace them
    # conservatively with a single path component wildcard for offline discovery.
    pattern = re.sub(r"%\{[^}]+\}", "*", pattern)
    pattern = re.sub(r"%(?:[udn])\b", "*", pattern)
    host_pattern = str(root / pattern.lstrip("/"))
    matches = [Path(x) for x in glob.glob(host_pattern)]
    if matches:
        return matches[:5000]
    return [root / value.lstrip("/")] if "*" not in pattern else []


def _infer_domain_from_path(path: Path, known_domains: set[str]) -> str:
    for part in reversed(path.parts):
        p = part.casefold()
        if p in known_domains or _is_domain_name(p):
            return p
    return ""


def _scan_dovecot(
    root: Path,
    result: MailScanResult,
    accounts: dict[str, dict[str, Any]],
    known_domains: set[str],
) -> None:
    base = root / "etc/dovecot"
    if not (base.exists() or _directory_accessible(base)):
        return
    texts = _collect_dovecot_configs(root)
    if not texts:
        _diag(result, "Dovecot", "Konfiguration", "vorhanden, aber nicht lesbar", "Warnung", _safe_rel(root, base))
        return
    merged = "\n".join(text for _path, text in texts)
    protocols = ""
    listen = ""
    mail_location = ""
    mail_driver = ""
    mail_path = ""
    for line in _uncomment_lines(merged):
        key, sep, value = line.partition("=")
        if not sep:
            continue
        k = key.strip().casefold()
        if k == "protocols" and not protocols:
            protocols = value.strip()
        elif k == "listen" and not listen:
            listen = value.strip()
        elif k == "mail_location" and not mail_location:
            mail_location = value.strip()
        elif k == "mail_driver" and not mail_driver:
            mail_driver = value.strip()
        elif k == "mail_path" and not mail_path:
            mail_path = value.strip()
    storage = mail_location or ": ".join(x for x in (mail_driver, mail_path) if x)
    result.servers.append(
        {
            "component": "Dovecot",
            "hostname": "",
            "domains": ", ".join(sorted(known_domains)),
            "relay": "",
            "interfaces": listen,
            "protocols": protocols,
            "source_file": _safe_rel(root, base / "dovecot.conf") if (base / "dovecot.conf").exists() else _safe_rel(root, base),
            "notes": f"Mailablage: {storage}" if storage else "Dovecot-Konfiguration vorhanden; Mailbox-Autodetektion möglich",
        }
    )
    _diag(result, "Dovecot", "Konfigurationsdateien ausgewertet", len(texts), "OK", _safe_rel(root, base))
    _diag(result, "Dovecot", "Mailablage", storage or "nicht explizit gesetzt / Autodetektion möglich", "Info", _safe_rel(root, base))

    candidate_paths: set[str] = {"/etc/dovecot/users", "/etc/dovecot/passwd"}
    for _path, text in texts:
        for match in ABS_PATH_RE.finditer(text):
            value = match.group(1).strip('"\'')
            name = Path(value).name.casefold()
            context = text[max(0, match.start()-120):match.end()+60].casefold()
            if "user" in name or "passwd" in name or "passdb" in context or "userdb" in context:
                candidate_paths.add(value)
        # Old and new passwd-file syntax can place the file after args/path keys.
        for m in re.finditer(r"(?mi)^\s*(?:args|passwd_file_path)\s*=\s*(?:[^/\r\n]*\s)?(/[^\r\n#]+)", text):
            candidate_paths.add(m.group(1).strip())

    readable_user_files = 0
    for linux_path in sorted(candidate_paths):
        for host_path in _expand_dovecot_user_path(root, linux_path):
            actual, method = _resolve_evidence_path(root, host_path)
            if actual is None:
                continue
            text = _read_text(actual)
            if not text:
                continue
            readable_user_files += 1
            inferred_domain = _infer_domain_from_path(actual, known_domains)
            for line_no, raw in enumerate(text.splitlines(), start=1):
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                username = line.split(":", 1)[0].strip()
                address = username
                if "@" not in address and inferred_domain:
                    address = f"{address}@{inferred_domain}"
                elif "@" not in address and len(known_domains) == 1:
                    address = f"{address}@{next(iter(known_domains))}"
                if "@" in address:
                    _add_account(
                        accounts,
                        address,
                        _safe_rel(root, actual),
                        "Dovecot Benutzerdatei",
                        f"Zeile {line_no}; Auflösung: {method}; Kennwort-/Hashfelder werden nicht ausgegeben",
                    )
    _diag(result, "Dovecot", "Lesbare Benutzer-/Passwd-Dateien", readable_user_files, "OK" if readable_user_files else "Info")


def _parse_plesk_mailnames_path(root: Path, result: MailScanResult) -> tuple[Path | None, str]:
    psa = root / "etc/psa/psa.conf"
    text, psa_actual, psa_method = _read_text_evidence(root, psa)
    if psa_actual is not None:
        psa = psa_actual
    configured = ""
    if text:
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r"^PLESK_MAILNAMES_D\s+(.+?)\s*$", line)
            if m:
                configured = m.group(1).strip().strip('"\'')
                break
    if configured:
        path = _root_path(root, configured)
        actual, method = _resolve_evidence_path(root, path)
        _diag(result, "Plesk", "PLESK_MAILNAMES_D", configured, method, _safe_rel(root, psa))
        return actual or path, configured
    default = root / "var/qmail/mailnames"
    default_visible = default.exists() or default.is_symlink() or any(p.name == "mailnames" for p in _iter_entries(default.parent))
    if default_visible:
        actual, method = _resolve_directory(root, default)
        _diag(result, "Plesk", "Mailstorage (Fallback)", "/var/qmail/mailnames", method, _safe_rel(root, default))
        return actual or default, "/var/qmail/mailnames"
    if text:
        _diag(result, "Plesk", "PLESK_MAILNAMES_D", "nicht gefunden", "Warnung", _safe_rel(root, psa))
    return None, ""


def _scan_qmail_forwarding(
    root: Path,
    user_dir: Path,
    address: str,
    aliases: dict[tuple[str, str], dict[str, Any]],
) -> int:
    count = 0
    for entry in _iter_entries(user_dir):
        if not entry.name.casefold().startswith(".qmail"):
            continue
        actual, _method = _resolve_evidence_path(root, entry)
        if actual is None:
            continue
        text = _read_text(actual)
        if not text:
            continue
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith(("|", "/", "./")):
                continue
            for target in EMAIL_RE.findall(line):
                _add_alias(aliases, address, target, _safe_rel(root, actual), "Plesk/Qmail .qmail-Weiterleitung")
                count += 1
    return count


def _scan_mail_storage_base(
    root: Path,
    base: Path,
    result: MailScanResult,
    accounts: dict[str, dict[str, Any]],
    aliases: dict[tuple[str, str], dict[str, Any]],
    evidence: str,
) -> tuple[int, int, int]:
    actual_base, method = _resolve_directory(root, base)
    if actual_base is None:
        return 0, 0, 0
    domains = accounts_found = unreadable = 0
    for domain_entry in _iter_entries(actual_base):
        domain = domain_entry.name.casefold()
        if not _is_domain_name(domain):
            continue
        domain_dir, _dmethod = _resolve_directory(root, domain_entry)
        if domain_dir is None:
            unreadable += 1
            continue
        domains += 1
        for user_entry in _iter_entries(domain_dir):
            user = user_entry.name
            if not user or user.startswith("."):
                continue
            user_dir, umethod = _resolve_directory(root, user_entry)
            if user_dir is None:
                unreadable += 1
                continue
            address = f"{user}@{domain}".casefold()
            markers: list[str] = []
            for candidate, label in (
                (user_dir / "Maildir", "Maildir"),
                (user_dir / "mdbox", "mdbox"),
                (user_dir / "sdbox", "sdbox"),
            ):
                resolved, _ = _resolve_evidence_path(root, candidate)
                if resolved is not None:
                    try:
                        if resolved.is_dir():
                            markers.append(label)
                    except OSError:
                        pass
            # Some Maildir layouts use the user directory itself as Maildir.
            if not markers:
                direct_parts = []
                for name in ("cur", "new", "tmp"):
                    resolved, _ = _resolve_evidence_path(root, user_dir / name)
                    if resolved is not None:
                        try:
                            if resolved.is_dir():
                                direct_parts.append(name)
                        except OSError:
                            pass
                if len(direct_parts) >= 2:
                    markers.append("Maildir")
            account_evidence = evidence + (" / Mailboxformat festgestellt" if markers else " / Account-Verzeichnis")
            _add_account(
                accounts,
                address,
                _safe_rel(root, user_dir),
                account_evidence,
                f"Storage-Auflösung: {method}/{umethod}" + (f"; Mailboxformat-Hinweis: {', '.join(markers)}" if markers else ""),
            )
            accounts_found += 1
            _scan_qmail_forwarding(root, user_dir, address, aliases)
    return domains, accounts_found, unreadable


def _scan_plesk_mail(
    root: Path,
    result: MailScanResult,
    accounts: dict[str, dict[str, Any]],
    aliases: dict[tuple[str, str], dict[str, Any]],
) -> set[str]:
    base, configured = _parse_plesk_mailnames_path(root, result)
    if base is None:
        return set()
    domains, account_count, unreadable = _scan_mail_storage_base(
        root, base, result, accounts, aliases, "Plesk Mailstorage / PLESK_MAILNAMES_D"
    )
    actual_rel = _safe_rel(root, base)
    result.servers.append(
        {
            "component": "Plesk Mail Storage",
            "hostname": "",
            "domains": "",
            "relay": "",
            "interfaces": "",
            "protocols": "Mailbox-Storage",
            "source_file": actual_rel,
            "notes": f"PLESK_MAILNAMES_D={configured}; erkannte Domainverzeichnisse: {domains}; Mailkonten: {account_count}",
        }
    )
    _diag(result, "Plesk", "Maildomain-Verzeichnisse", domains, "OK", actual_rel)
    _diag(result, "Plesk", "Mailbox-/Account-Verzeichnisse", account_count, "OK", actual_rel)
    _diag(result, "Plesk", "Nicht lesbare Storage-Einträge", unreadable, "Warnung" if unreadable else "OK", actual_rel)
    return {row["domain"] for row in accounts.values() if row.get("domain") and "Plesk" in row.get("evidence", "")}


def _scan_exim(root: Path, result: MailScanResult) -> None:
    candidates = [
        root / "etc/exim4/update-exim4.conf.conf",
        root / "etc/exim/exim.conf",
        root / "etc/exim4/exim4.conf.template",
    ]
    for path in candidates:
        text, actual, _method = _read_text_evidence(root, path)
        if not text:
            continue
        if actual is not None:
            path = actual
        kv: dict[str, str] = {}
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            kv[key.strip().casefold()] = value.strip().strip("'\"")
        result.servers.append(
            {
                "component": "Exim",
                "hostname": kv.get("primary_hostname", ""),
                "domains": kv.get("dc_other_hostnames", ""),
                "relay": kv.get("dc_smarthost", ""),
                "interfaces": kv.get("dc_local_interfaces", ""),
                "protocols": "SMTP",
                "source_file": _safe_rel(root, path),
                "notes": "Exim-Konfiguration",
            }
        )
        break


def _scan_maildir_structures(
    root: Path,
    result: MailScanResult,
    accounts: dict[str, dict[str, Any]],
    aliases: dict[tuple[str, str], dict[str, Any]],
    known_domains: set[str],
    skip_bases: set[str] | None = None,
) -> None:
    skip_bases = {x.casefold() for x in (skip_bases or set())}
    bases = [
        root / "var/vmail",
        root / "var/mail/vhosts",
        root / "var/qmail/mailnames",
        root / "srv/vmail",
        root / "srv/mail",
    ]
    for base in bases:
        if _safe_rel(root, base).casefold() in skip_bases:
            continue
        domains, count, unreadable = _scan_mail_storage_base(
            root, base, result, accounts, aliases, "Maildir/Vmail-Verzeichnisstruktur"
        )
        if domains or count or unreadable:
            _diag(result, "Mailstorage", f"{_safe_rel(root, base)} Domains/Konten", f"{domains}/{count}", "OK", _safe_rel(root, base))
            if unreadable:
                _diag(result, "Mailstorage", f"{_safe_rel(root, base)} nicht lesbare Einträge", unreadable, "Warnung", _safe_rel(root, base))

    # System-user Maildir locations. Only construct a full address when the domain
    # can be inferred with reasonable confidence; otherwise retain a diagnostic.
    home_count = 0
    homes = root / "home"
    if homes.exists():
        for user_dir in _iter_entries(homes):
            actual_user, _ = _resolve_evidence_path(root, user_dir)
            if actual_user is None:
                continue
            maildir, _ = _resolve_evidence_path(root, actual_user / "Maildir")
            if maildir is None:
                continue
            try:
                if not maildir.is_dir():
                    continue
            except OSError:
                continue
            home_count += 1
            if len(known_domains) == 1:
                domain = next(iter(known_domains))
                _add_account(
                    accounts,
                    f"{user_dir.name}@{domain}",
                    _safe_rel(root, maildir),
                    "Systembenutzer-Maildir",
                    "Adresse aus eindeutigem Maildomain-Kontext abgeleitet",
                )
    if home_count:
        _diag(result, "Mailstorage", "Systembenutzer-Maildir-Verzeichnisse", home_count, "Info", "/home/*/Maildir")

    # Traditional mbox inboxes under /var/mail or /var/spool/mail.
    mbox_count = 0
    for base in (root / "var/mail", root / "var/spool/mail"):
        actual_base, _ = _resolve_evidence_path(root, base)
        if actual_base is None:
            continue
        for entry in _iter_entries(actual_base):
            actual, _ = _resolve_evidence_path(root, entry)
            if actual is None:
                continue
            try:
                if not actual.is_file() or actual.stat().st_size < 0:
                    continue
            except OSError:
                continue
            # Ignore lock/index-ish files and domain directories handled above.
            if entry.name.startswith(".") or "." in entry.name:
                continue
            mbox_count += 1
            if len(known_domains) == 1:
                domain = next(iter(known_domains))
                _add_account(
                    accounts,
                    f"{entry.name}@{domain}",
                    _safe_rel(root, actual),
                    "System-mbox",
                    "Adresse aus eindeutigem Maildomain-Kontext abgeleitet",
                )
    if mbox_count:
        _diag(result, "Mailstorage", "System-mbox-Dateien", mbox_count, "Info", "/var/mail bzw. /var/spool/mail")



def _scan_application_mail_configs(root: Path, result: MailScanResult, accounts: dict[str, dict[str, Any]]) -> None:
    """Extract safe mail identity/settings from common web-application configs.

    Password/secret keys are intentionally ignored.
    """
    search_bases = [root / "var/www", root / "srv/www", root / "opt"]
    scanned = 0

    # Nextcloud config.php
    for base in search_bases:
        if not base.is_dir() or scanned >= 120:
            continue
        try:
            for occ in base.rglob("occ"):
                if scanned >= 120:
                    break
                config = occ.parent / "config" / "config.php"
                text = _read_text(config)
                if not occ.is_file() or not text:
                    continue
                scanned += 1
                values: dict[str, str] = {}
                for key in (
                    "mail_from_address", "mail_domain", "mail_smtpmode", "mail_sendmailmode",
                    "mail_smtphost", "mail_smtpport", "mail_smtpsecure", "mail_smtpauth", "mail_smtpname",
                ):
                    m = re.search(rf"(?i)['\"]{re.escape(key)}['\"]\s*=>\s*(?:['\"]([^'\"]*)['\"]|([0-9]+)|true|false)", text)
                    if m:
                        values[key] = (m.group(1) or m.group(2) or "").strip()
                if not values:
                    continue
                from_local = values.get("mail_from_address", "")
                domain = values.get("mail_domain", "")
                from_address = f"{from_local}@{domain}" if from_local and domain and "@" not in from_local else from_local
                smtp_user = values.get("mail_smtpname", "")
                if "@" in from_address:
                    _add_account(accounts, from_address, _safe_rel(root, config), "Nextcloud Mail-Konfiguration")
                if "@" in smtp_user:
                    _add_account(accounts, smtp_user, _safe_rel(root, config), "Nextcloud SMTP-Benutzer")
                relay = values.get("mail_smtphost", "")
                if values.get("mail_smtpport"):
                    relay = f"{relay}:{values['mail_smtpport']}" if relay else values["mail_smtpport"]
                notes = []
                if from_address:
                    notes.append(f"Absender: {from_address}")
                if smtp_user:
                    notes.append(f"SMTP-Benutzer: {smtp_user}")
                if values.get("mail_smtpsecure"):
                    notes.append(f"Transport: {values['mail_smtpsecure']}")
                result.servers.append(
                    {
                        "component": "Nextcloud Mail",
                        "hostname": "",
                        "domains": domain,
                        "relay": relay,
                        "interfaces": "",
                        "protocols": values.get("mail_smtpmode", "SMTP"),
                        "source_file": _safe_rel(root, config),
                        "notes": "; ".join(notes) or "Nextcloud Mail-Konfiguration",
                    }
                )
        except OSError:
            continue

    # Common .env mail settings (Laravel and similar). Only a strict allow-list is read.
    env_keys = {
        "MAIL_MAILER", "MAIL_DRIVER", "MAIL_HOST", "MAIL_PORT", "MAIL_USERNAME",
        "MAIL_FROM_ADDRESS", "MAIL_FROM_NAME", "MAIL_ENCRYPTION",
    }
    env_seen = 0
    for base in search_bases:
        if not base.is_dir() or env_seen >= 120:
            continue
        try:
            for env_file in base.rglob(".env"):
                if env_seen >= 120:
                    break
                text = _read_text(env_file)
                if not text:
                    continue
                values: dict[str, str] = {}
                for raw in text.splitlines():
                    line = raw.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, value = line.split("=", 1)
                    key = key.strip().upper()
                    if key not in env_keys:
                        continue
                    values[key] = value.strip().strip('"\'')
                if not values or not any(k in values for k in ("MAIL_HOST", "MAIL_USERNAME", "MAIL_FROM_ADDRESS")):
                    continue
                env_seen += 1
                username = values.get("MAIL_USERNAME", "")
                from_address = values.get("MAIL_FROM_ADDRESS", "")
                for address, evidence in ((username, "Anwendungs-.env SMTP-Benutzer"), (from_address, "Anwendungs-.env Absender")):
                    if "@" in address:
                        _add_account(accounts, address, _safe_rel(root, env_file), evidence)
                relay = values.get("MAIL_HOST", "")
                port = values.get("MAIL_PORT", "")
                if port:
                    relay = f"{relay}:{port}" if relay else port
                domain = from_address.split("@", 1)[1] if "@" in from_address else ""
                notes = []
                if from_address:
                    notes.append(f"Absender: {from_address}")
                if username:
                    notes.append(f"SMTP-Benutzer: {username}")
                if values.get("MAIL_ENCRYPTION"):
                    notes.append(f"Verschlüsselung: {values['MAIL_ENCRYPTION']}")
                result.servers.append(
                    {
                        "component": "Application .env Mail",
                        "hostname": "",
                        "domains": domain,
                        "relay": relay,
                        "interfaces": "",
                        "protocols": values.get("MAIL_MAILER", "") or values.get("MAIL_DRIVER", ""),
                        "source_file": _safe_rel(root, env_file),
                        "notes": "; ".join(notes) or "Mail-Konfiguration in .env",
                    }
                )
        except OSError:
            continue

def discover_mail_logs(root: Path) -> list[Path]:
    candidates: list[Path] = []
    bases = [root / "var/log", root / "usr/local/psa/var/log"]
    names = ("mail.log", "maillog", "mail.info", "mail.warn", "mail.err")
    for base in bases:
        if not base.is_dir():
            continue
        try:
            for path in base.iterdir():
                n = path.name.casefold()
                if not path.is_file():
                    continue
                if any(n == name or n.startswith(name + ".") for name in names):
                    candidates.append(path)
        except OSError:
            continue
    return sorted(candidates, key=lambda p: (p.name.casefold(), str(p)))[:MAX_MAIL_LOG_FILES]


def _open_log(path: Path):
    if path.suffix.casefold() == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return path.open("rt", encoding="utf-8", errors="replace")


def _raw_time_prefix(line: str) -> str:
    # Preserve the source representation; traditional syslog often has no year/timezone.
    iso = re.match(r"^(\d{4}-\d{2}-\d{2}T\S+)", line)
    if iso:
        return iso.group(1)
    traditional = re.match(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})", line)
    return traditional.group(1) if traditional else ""


def _mail_access_from_message(message: str, time_value: str, source: str, line_no: int | str = "") -> dict[str, Any] | None:
    match = DOVECOT_LOGIN_RE.search(message)
    if match:
        ip = _valid_ip(match.group("ip"))
        if ip:
            return {
                "time": time_value,
                "service": "Dovecot IMAP/POP3",
                "result": "Anmeldung erfolgreich",
                "user": match.group("user"),
                "ip": ip,
                "source_file": source,
                "line": line_no,
                "message": message.strip()[:1000],
            }
    match = POSTFIX_SASL_RE.search(message)
    if match:
        ip = _valid_ip(match.group("ip"))
        if ip:
            return {
                "time": time_value,
                "service": "Postfix SMTP AUTH",
                "result": "Authentifizierung erfolgreich",
                "user": match.group("user"),
                "ip": ip,
                "source_file": source,
                "line": line_no,
                "message": message.strip()[:1000],
            }
    match = EXIM_AUTH_RE.search(message)
    if match:
        ip = _valid_ip(match.group("ip"))
        if ip:
            return {
                "time": time_value,
                "service": "Exim Auth",
                "result": "Authentifizierungshinweis",
                "user": match.group("user"),
                "ip": ip,
                "source_file": source,
                "line": line_no,
                "message": message.strip()[:1000],
            }
    return None


def _scan_mail_accesses(root: Path, events: list[dict[str, Any]], result: MailScanResult) -> None:
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()

    for event in events:
        message = str(event.get("message", ""))
        ident = f"{event.get('service', '')} {event.get('unit', '')}".casefold()
        if not any(x in ident or x in message.casefold() for x in ("dovecot", "postfix", "exim")):
            continue
        row = _mail_access_from_message(
            message,
            str(event.get("time_utc", "")),
            str(event.get("source_file", "Journal")),
            "Journal",
        )
        if row:
            key = (row["time"], row["user"], row["ip"], row["service"])
            if key not in seen:
                seen.add(key)
                rows.append(row)

    logs = discover_mail_logs(root)
    result.log_files = [_safe_rel(root, path) for path in logs]
    for path in logs:
        if len(rows) >= MAX_MAIL_ACCESSES:
            break
        try:
            with _open_log(path) as handle:
                for line_no, line in enumerate(handle, start=1):
                    if line_no > MAX_MAIL_LOG_LINES or len(rows) >= MAX_MAIL_ACCESSES:
                        break
                    lower = line.casefold()
                    if "login:" not in lower and "sasl_username=" not in lower and "auth" not in lower:
                        continue
                    row = _mail_access_from_message(line, _raw_time_prefix(line), _safe_rel(root, path), line_no)
                    if not row:
                        continue
                    key = (row["time"], row["user"], row["ip"], row["service"])
                    if key not in seen:
                        seen.add(key)
                        rows.append(row)
        except (OSError, EOFError, gzip.BadGzipFile):
            continue
    result.accesses = sorted(rows, key=lambda r: str(r.get("time", "")), reverse=True)
    if len(rows) >= MAX_MAIL_ACCESSES:
        result.notes.append(f"Mail-Login-Auswertung auf {MAX_MAIL_ACCESSES:,} Treffer begrenzt.".replace(",", "."))


def _known_domains(result: MailScanResult, accounts: dict[str, dict[str, Any]]) -> set[str]:
    domains: set[str] = set()
    for row in result.servers:
        for token in re.split(r"[,\s]+", str(row.get("domains", ""))):
            token = token.strip().strip(".").casefold()
            if _is_domain_name(token):
                domains.add(token)
    for row in accounts.values():
        domain = str(row.get("domain", "")).casefold()
        if _is_domain_name(domain):
            domains.add(domain)
    return domains


def _finalize_accounts(
    accounts: dict[str, dict[str, Any]],
    accesses: list[dict[str, Any]],
    known_domains: set[str],
) -> None:
    # Authentication itself is independent corroboration of an account/login name.
    for access in accesses:
        user = str(access.get("user", "")).strip().strip("<>").casefold()
        address = user
        detail = f"{access.get('service', '')}; Quell-IP {access.get('ip', '')}; Zeit {access.get('time', '')}"
        if "@" not in address and len(known_domains) == 1 and address:
            address = f"{address}@{next(iter(known_domains))}"
            detail += "; Domain aus eindeutigem Maildomain-Kontext abgeleitet"
        if "@" in address:
            _add_account(accounts, address, str(access.get("source_file", "")), "Erfolgreiche Mail-Authentifizierung", detail)

    strong_terms = (
        "mailboxformat festgestellt", "system-mbox", "systembenutzer-maildir",
        "erfolgreiche mail-authentifizierung",
    )
    configured_terms = (
        "account-verzeichnis", "postfix virtual_mailbox", "postfix local_recipient", "dovecot benutzerdatei"
    )
    for row in accounts.values():
        evidence = str(row.get("evidence", "")).casefold()
        if any(term in evidence for term in strong_terms):
            row["assessment"] = "Belegt"
        elif any(term in evidence for term in configured_terms):
            row["assessment"] = "Konfiguriert"
        else:
            row["assessment"] = "Hinweis"


def scan_mail(root: Path, events: list[dict[str, Any]]) -> MailScanResult:
    result = MailScanResult()
    accounts: dict[str, dict[str, Any]] = {}
    aliases: dict[tuple[str, str], dict[str, Any]] = {}

    _scan_postfix(root, result, accounts, aliases)
    # Plesk can define a non-default mail storage root in /etc/psa/psa.conf.
    _scan_plesk_mail(root, result, accounts, aliases)
    known_domains = _known_domains(result, accounts)

    _scan_dovecot(root, result, accounts, known_domains)
    _scan_exim(root, result)
    known_domains = _known_domains(result, accounts)
    _scan_maildir_structures(root, result, accounts, aliases, known_domains)
    _scan_application_mail_configs(root, result, accounts)
    _scan_mail_accesses(root, events, result)

    known_domains = _known_domains(result, accounts)
    _finalize_accounts(accounts, result.accesses, known_domains)
    known_domains = _known_domains(result, accounts)

    result.accounts = sorted(accounts.values(), key=lambda r: (r.get("domain", ""), r.get("address", "")))
    result.aliases = sorted(aliases.values(), key=lambda r: (r.get("alias", ""), r.get("target", "")))

    _diag(result, "Zusammenfassung", "Erkannte Maildomains", len(known_domains), "OK")
    _diag(result, "Zusammenfassung", "Erkannte Mail-Adressen", len(result.accounts), "OK")
    _diag(result, "Zusammenfassung", "Aliase / Weiterleitungen", len(result.aliases), "OK")
    _diag(result, "Zusammenfassung", "Authentifizierte Mailzugriffe", len(result.accesses), "OK")
    _diag(result, "Zusammenfassung", "Ausgewertete Mail-Logdateien", len(result.log_files), "OK" if result.log_files else "Info")

    if not result.servers:
        result.notes.append("Keine unterstützte Postfix-/Dovecot-/Exim-/Plesk-Mailkonfiguration erkannt.")
    if not result.accounts:
        result.notes.append("Keine Mailkonten aus unterstützten Konfigurationen, Mailstorage-Strukturen oder Authentifizierungslogs abgeleitet.")
    if any(row.get("status") == "Warnung" for row in result.diagnostics):
        result.notes.append(
            "Mail-Diagnose enthält Warnungen zu nicht lesbaren oder nicht auflösbaren Pfaden. "
            "Dies kann bei unter Windows eingebundenen Linux-Dateisystemen auf Symlink-/Mount-Eigenschaften zurückzuführen sein."
        )
    return result

