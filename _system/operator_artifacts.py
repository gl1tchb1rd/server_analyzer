from __future__ import annotations

import base64
import configparser
import hashlib
import re
from pathlib import Path
from typing import Any

MAX_TEXT_FILE = 8 * 1024 * 1024
MAX_HISTORY_ROWS = 2500
MAX_CRON_ROWS = 2000
SSH_KEY_PREFIXES = ("ssh-", "ecdsa-", "sk-")
SECRET_PATTERNS = [
    re.compile(r"(?i)(--?password(?:=|\s+))([^\s'\"]+)"),
    re.compile(r"(?i)(\bpass(?:word)?=)([^\s&;'\"]+)"),
    re.compile(r"(?i)(\b(?:api[_-]?key|token|secret)=)([^\s&;'\"]+)"),
    re.compile(r"(?i)(\bmysql\b[^\n]*?\s-p)([^\s'\"]+)"),
]


def _safe_rel(root: Path, path: Path) -> str:
    try:
        return "/" + path.relative_to(root).as_posix()
    except (ValueError, OSError):
        return str(path)


def _read_text(path: Path, limit: int = MAX_TEXT_FILE) -> str:
    try:
        if not path.is_file() or path.stat().st_size > limit:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _owner_for_path(path: Path, root: Path) -> str:
    try:
        rel = path.relative_to(root).parts
    except ValueError:
        return ""
    if len(rel) >= 2 and rel[0] == "home":
        return rel[1]
    if rel and rel[0] == "root":
        return "root"
    if len(rel) >= 5 and rel[:4] == ("var", "spool", "cron", "crontabs"):
        return rel[4]
    return "system"


def _redact_secrets(text: str) -> str:
    out = text
    for pattern in SECRET_PATTERNS:
        out = pattern.sub(lambda m: f"{m.group(1)}[REDACTED]", out)
    return out


def _ssh_fingerprint(blob: str) -> str:
    try:
        raw = base64.b64decode(blob.encode("ascii"), validate=True)
    except Exception:
        return ""
    digest = hashlib.sha256(raw).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def _parse_authorized_keys(root: Path, path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    text = _read_text(path)
    if not text:
        return rows
    owner = _owner_for_path(path, root)
    for line_no, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        tokens = line.split()
        key_index = next((i for i, token in enumerate(tokens) if token.startswith(SSH_KEY_PREFIXES)), -1)
        if key_index < 0 or key_index + 1 >= len(tokens):
            continue
        key_type = tokens[key_index]
        blob = tokens[key_index + 1]
        comment = " ".join(tokens[key_index + 2 :])
        options = " ".join(tokens[:key_index])
        rows.append(
            {
                "category": "SSH-Schlüssel",
                "owner": owner,
                "artifact": "authorized_keys",
                "value": comment or "(kein Kommentar)",
                "detail": f"Typ: {key_type}; Fingerprint: {_ssh_fingerprint(blob)}" + (f"; Optionen: {options}" if options else ""),
                "source_file": _safe_rel(root, path),
                "line": line_no,
            }
        )
    return rows


def _parse_known_hosts(root: Path, path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    text = _read_text(path)
    if not text:
        return rows
    owner = _owner_for_path(path, root)
    for line_no, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        hosts, key_type, blob = parts[:3]
        value = "[gehashter Hostname]" if hosts.startswith("|1|") else hosts
        rows.append(
            {
                "category": "SSH-Zielsystem",
                "owner": owner,
                "artifact": "known_hosts",
                "value": value,
                "detail": f"Typ: {key_type}; Hostkey-Fingerprint: {_ssh_fingerprint(blob)}",
                "source_file": _safe_rel(root, path),
                "line": line_no,
            }
        )
    return rows


def _parse_gitconfig(root: Path, path: Path) -> list[dict[str, Any]]:
    text = _read_text(path)
    if not text:
        return []
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    try:
        parser.read_string(text)
    except configparser.Error:
        return []
    owner = _owner_for_path(path, root)
    name = parser.get("user", "name", fallback="").strip()
    email = parser.get("user", "email", fallback="").strip()
    rows: list[dict[str, Any]] = []
    if name or email:
        rows.append(
            {
                "category": "Git-Identität",
                "owner": owner,
                "artifact": ".gitconfig",
                "value": name,
                "detail": f"E-Mail: {email}" if email else "",
                "source_file": _safe_rel(root, path),
                "line": "",
            }
        )
    return rows


def _parse_history(root: Path, path: Path, remaining: int) -> list[dict[str, Any]]:
    if remaining <= 0:
        return []
    text = _read_text(path)
    if not text:
        return []
    owner = _owner_for_path(path, root)
    rows: list[dict[str, Any]] = []
    for line_no, raw in enumerate(text.splitlines(), start=1):
        if len(rows) >= remaining:
            break
        line = raw.strip()
        if not line:
            continue
        timestamp = ""
        command = line
        # zsh extended_history: ': 1699999999:0;command'
        match = re.match(r"^:\s*(\d+):\d+;(.*)$", line)
        if match:
            timestamp, command = match.group(1), match.group(2)
        rows.append(
            {
                "category": "Shell-History",
                "owner": owner,
                "artifact": path.name,
                "value": _redact_secrets(command)[:1200],
                "detail": f"Unix-Zeit: {timestamp}" if timestamp else "",
                "source_file": _safe_rel(root, path),
                "line": line_no,
            }
        )
    return rows


def _parse_cron_file(root: Path, path: Path, user_hint: str, system_format: bool) -> list[dict[str, Any]]:
    text = _read_text(path)
    if not text:
        return []
    rows: list[dict[str, Any]] = []
    for line_no, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#") or "=" in line.split(None, 1)[0]:
            continue
        parts = line.split()
        if line.startswith("@"):
            minimum = 3 if system_format else 2
            if len(parts) < minimum:
                continue
            schedule = parts[0]
            if system_format:
                owner = parts[1]
                command = " ".join(parts[2:])
            else:
                owner = user_hint
                command = " ".join(parts[1:])
        else:
            minimum = 7 if system_format else 6
            if len(parts) < minimum:
                continue
            schedule = " ".join(parts[:5])
            if system_format:
                owner = parts[5]
                command = " ".join(parts[6:])
            else:
                owner = user_hint
                command = " ".join(parts[5:])
        rows.append(
            {
                "category": "Zeitgesteuerter Auftrag",
                "owner": owner,
                "artifact": "cron",
                "value": _redact_secrets(command)[:1200],
                "detail": f"Zeitplan: {schedule}",
                "source_file": _safe_rel(root, path),
                "line": line_no,
            }
        )
    return rows



def _parse_passwd(root: Path) -> list[dict[str, Any]]:
    path = root / "etc/passwd"
    text = _read_text(path)
    rows: list[dict[str, Any]] = []
    if not text:
        return rows
    for line_no, raw in enumerate(text.splitlines(), start=1):
        parts = raw.split(":")
        if len(parts) < 7:
            continue
        user, _pw, uid, gid, gecos, home, shell = parts[:7]
        try:
            uid_int = int(uid)
        except ValueError:
            continue
        # Focus on root and interactive/non-system accounts.
        interactive = shell not in ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false", "")
        if user != "root" and uid_int < 1000 and not interactive:
            continue
        rows.append(
            {
                "category": "Lokales Benutzerkonto",
                "owner": user,
                "artifact": "/etc/passwd",
                "value": f"UID {uid}; GID {gid}; Home {home}; Shell {shell}",
                "detail": f"GECOS: {gecos}" if gecos else "",
                "source_file": _safe_rel(root, path),
                "line": line_no,
            }
        )
    return rows


def _scan_git_repositories(root: Path, limit: int = 300) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    bases = [root / "var/www", root / "srv", root / "opt", root / "home", root / "root"]
    for base in bases:
        if not base.is_dir() or len(seen) >= limit:
            continue
        try:
            for config_path in base.rglob("config"):
                if len(seen) >= limit:
                    break
                if config_path.parent.name != ".git" or not config_path.is_file():
                    continue
                key = str(config_path)
                if key in seen:
                    continue
                seen.add(key)
                text = _read_text(config_path)
                if not text:
                    continue
                parser = configparser.ConfigParser(interpolation=None, strict=False)
                try:
                    parser.read_string(text)
                except configparser.Error:
                    continue
                repo = config_path.parent.parent
                remotes: list[str] = []
                for section in parser.sections():
                    if section.casefold().startswith("remote "):
                        url = parser.get(section, "url", fallback="").strip()
                        if url:
                            remotes.append(url)
                user_name = parser.get("user", "name", fallback="").strip()
                user_email = parser.get("user", "email", fallback="").strip()
                detail_parts = []
                if remotes:
                    detail_parts.append("Remote(s): " + " | ".join(remotes[:10]))
                if user_name or user_email:
                    detail_parts.append(f"Repo-Identität: {user_name} <{user_email}>".strip())
                rows.append(
                    {
                        "category": "Git-Repository",
                        "owner": _owner_for_path(config_path, root),
                        "artifact": ".git/config",
                        "value": _safe_rel(root, repo),
                        "detail": "; ".join(detail_parts),
                        "source_file": _safe_rel(root, config_path),
                        "line": "",
                    }
                )
        except OSError:
            continue
    return rows

def scan_operator_artifacts(root: Path) -> tuple[list[dict[str, Any]], list[str]]:
    rows: list[dict[str, Any]] = []
    notes: list[str] = []

    rows.extend(_parse_passwd(root))

    user_homes: list[Path] = []
    root_home = root / "root"
    if root_home.is_dir():
        user_homes.append(root_home)
    home_base = root / "home"
    if home_base.is_dir():
        try:
            user_homes.extend(p for p in home_base.iterdir() if p.is_dir())
        except OSError:
            pass

    for home in user_homes:
        ssh_dir = home / ".ssh"
        rows.extend(_parse_authorized_keys(root, ssh_dir / "authorized_keys"))
        rows.extend(_parse_authorized_keys(root, ssh_dir / "authorized_keys2"))
        rows.extend(_parse_known_hosts(root, ssh_dir / "known_hosts"))
        rows.extend(_parse_gitconfig(root, home / ".gitconfig"))

    system_git = root / "etc/gitconfig"
    rows.extend(_parse_gitconfig(root, system_git))
    git_repos = _scan_git_repositories(root)
    rows.extend(git_repos)
    if len(git_repos) >= 300:
        notes.append("Git-Repository-Auswertung auf 300 Repositories begrenzt.")

    history_rows: list[dict[str, Any]] = []
    for home in user_homes:
        for name in (".bash_history", ".zsh_history"):
            history_rows.extend(_parse_history(root, home / name, MAX_HISTORY_ROWS - len(history_rows)))
            if len(history_rows) >= MAX_HISTORY_ROWS:
                break
        if len(history_rows) >= MAX_HISTORY_ROWS:
            break
    rows.extend(history_rows)
    if len(history_rows) >= MAX_HISTORY_ROWS:
        notes.append(f"Shell-History-Anzeige auf {MAX_HISTORY_ROWS} Befehle begrenzt; Quelldateien bleiben unverändert erhalten.")

    cron_rows: list[dict[str, Any]] = []
    cron_rows.extend(_parse_cron_file(root, root / "etc/crontab", "system", True))
    cron_d = root / "etc/cron.d"
    if cron_d.is_dir():
        try:
            for path in sorted(cron_d.iterdir()):
                if path.is_file():
                    cron_rows.extend(_parse_cron_file(root, path, "system", True))
                    if len(cron_rows) >= MAX_CRON_ROWS:
                        break
        except OSError:
            pass
    spool = root / "var/spool/cron/crontabs"
    if spool.is_dir() and len(cron_rows) < MAX_CRON_ROWS:
        try:
            for path in sorted(spool.iterdir()):
                if path.is_file():
                    cron_rows.extend(_parse_cron_file(root, path, path.name, False))
                    if len(cron_rows) >= MAX_CRON_ROWS:
                        break
        except OSError:
            pass
    rows.extend(cron_rows[:MAX_CRON_ROWS])
    if len(cron_rows) >= MAX_CRON_ROWS:
        notes.append(f"Cron-Auswertung auf {MAX_CRON_ROWS} Einträge begrenzt.")

    return rows, notes
