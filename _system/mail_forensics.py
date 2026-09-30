# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Gl1tchb1rd

from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from server_forensics import DOMAIN_RE, linux_to_host, rel_source, resolve_evidence_path, safe_read_text

EMAIL_RE = re.compile(r"(?i)(?<![\w.+-])([a-z0-9.!#$%&'*+/=?^_`{|}~-]+@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})(?![\w.-])")


@dataclass(slots=True)
class MailAccount:
    address: str
    assessment: str
    evidence: list[str]
    mailbox_path: str = ""
    forwarding: list[str] | None = None
    source: list[str] | None = None


@dataclass(slots=True)
class MailAccess:
    timestamp: str
    protocol: str
    user: str
    ip: str
    result: str
    source: str
    ssh_correlated: bool = False


def _valid_email(value: str) -> str | None:
    m = EMAIL_RE.fullmatch(value.strip().strip("<>,;\"'"))
    return m.group(1).lower() if m else None


def _add_account(accounts: dict[str, dict], address: str, evidence: str, source: str = "", mailbox_path: str = "", forwarding: list[str] | None = None, strong: bool = False) -> None:
    addr = _valid_email(address)
    if not addr:
        return
    row = accounts.setdefault(addr, {"address": addr, "evidence": [], "sources": [], "mailbox_path": "", "forwarding": [], "strong": False})
    if evidence and evidence not in row["evidence"]:
        row["evidence"].append(evidence)
    if source and source not in row["sources"]:
        row["sources"].append(source)
    if mailbox_path:
        row["mailbox_path"] = mailbox_path
    if forwarding:
        for f in forwarding:
            e = _valid_email(f)
            if e and e not in row["forwarding"]:
                row["forwarding"].append(e)
    row["strong"] = row["strong"] or strong


def _parse_psa_conf(root: Path) -> tuple[Path | None, dict]:
    path = root / "etc/psa/psa.conf"
    diag = {"plesk_detected": path.is_file(), "plesk_mailnames_d": "", "plesk_mailstorage_method": "", "plesk_domains": 0, "plesk_accounts": 0, "plesk_unreadable": 0}
    if not path.is_file():
        return None, diag
    text = safe_read_text(path)
    m = re.search(r"(?im)^\s*PLESK_MAILNAMES_D\s+(.+?)\s*$", text)
    linux_path = m.group(1).strip().strip('"\'') if m else "/var/qmail/mailnames"
    diag["plesk_mailnames_d"] = linux_path
    host = linux_to_host(root, linux_path)
    resolved, method = resolve_evidence_path(root, host)
    diag["plesk_mailstorage_method"] = method
    return resolved, diag


def _plesk_accounts(root: Path, accounts: dict[str, dict], diag: dict) -> None:
    storage, diag_update = _parse_psa_conf(root)
    diag.update(diag_update)
    if storage is None or not storage.exists():
        return
    try:
        domains = [p for p in storage.iterdir() if p.is_dir() and DOMAIN_RE.fullmatch(p.name)]
    except OSError:
        return
    diag["plesk_domains"] = len(domains)
    count = 0
    for domain_dir in domains:
        try:
            users = list(domain_dir.iterdir())
        except OSError:
            diag["plesk_unreadable"] += 1
            continue
        for user_dir in users:
            if not user_dir.is_dir():
                continue
            address = f"{user_dir.name}@{domain_dir.name}"
            mailbox = ""
            strong = False
            for candidate in (user_dir / "Maildir", user_dir / "maildir", user_dir):
                try:
                    if candidate.is_dir() and any((candidate / x).is_dir() for x in ("cur", "new", "tmp")):
                        mailbox = rel_source(root, candidate)
                        strong = True
                        break
                except OSError:
                    pass
            forwards: list[str] = []
            qmail = user_dir / ".qmail"
            if qmail.is_file():
                for line in safe_read_text(qmail).splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if line.startswith("&"):
                        line = line[1:].strip()
                    forwards.extend(EMAIL_RE.findall(line))
            _add_account(accounts, address, "Plesk Mailstorage", rel_source(root, user_dir), mailbox, forwards, strong=strong)
            count += 1
    diag["plesk_accounts"] = count


def _postfix_main(root: Path) -> tuple[dict[str, str], Path | None]:
    path = root / "etc/postfix/main.cf"
    if not path.is_file():
        return {}, None
    text = safe_read_text(path)
    merged: list[str] = []
    for line in text.splitlines():
        if line[:1].isspace() and merged:
            merged[-1] += " " + line.strip()
        else:
            merged.append(line)
    conf: dict[str, str] = {}
    for line in merged:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        conf[key.strip()] = value.strip()
    return conf, path


def _postfix_map_paths(root: Path, spec: str, base: Path) -> tuple[list[Path], list[str]]:
    paths: list[Path] = []
    non_file: list[str] = []
    for token in re.split(r"[\s,]+", spec):
        token = token.strip()
        if not token:
            continue
        if ":" in token:
            kind, value = token.split(":", 1)
            if kind.lower() in {"hash", "btree", "texthash", "lmdb", "cdb"}:
                paths.append(linux_to_host(root, value, base))
            elif kind.lower() in {"mysql", "pgsql", "ldap", "sqlite", "proxy"}:
                non_file.append(token)
            else:
                if value.startswith("/"):
                    paths.append(linux_to_host(root, value, base))
        elif token.startswith("/"):
            paths.append(linux_to_host(root, token, base))
    return paths, non_file


def _parse_map_file(root: Path, path: Path, accounts: dict[str, dict], evidence: str) -> int:
    resolved, _ = resolve_evidence_path(root, path)
    if not resolved.is_file():
        return 0
    count = 0
    for line in safe_read_text(resolved, 16 * 1024 * 1024).splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = re.split(r"\s+", line, maxsplit=1)
        left = _valid_email(parts[0])
        if not left:
            continue
        right = parts[1] if len(parts) > 1 else ""
        forwards = EMAIL_RE.findall(right)
        _add_account(accounts, left, evidence, rel_source(root, resolved), forwarding=forwards, strong=False)
        count += 1
    return count


def _postfix_accounts(root: Path, accounts: dict[str, dict], diag: dict) -> None:
    conf, main = _postfix_main(root)
    diag["postfix_detected"] = bool(main)
    diag["postfix_map_files"] = 0
    diag["postfix_database_maps"] = []
    diag["postfix_mail_domains"] = []
    if not main:
        return
    domain_values: list[str] = []
    for key in ("mydomain", "mydestination", "virtual_mailbox_domains", "relay_domains"):
        val = conf.get(key, "")
        domain_values.extend(DOMAIN_RE.findall(val))
    diag["postfix_mail_domains"] = list(dict.fromkeys(x.lower() for x in domain_values))

    for key, ev in (("virtual_mailbox_maps", "Postfix virtual_mailbox_maps"), ("virtual_alias_maps", "Postfix virtual_alias_maps"), ("alias_maps", "Postfix alias_maps")):
        spec = conf.get(key, "")
        if not spec:
            continue
        paths, non_file = _postfix_map_paths(root, spec, main.parent)
        diag["postfix_database_maps"].extend(non_file)
        for p in paths:
            diag["postfix_map_files"] += _parse_map_file(root, p, accounts, ev)


def _dovecot_files(root: Path) -> tuple[list[Path], dict]:
    start = root / "etc/dovecot/dovecot.conf"
    diag = {"dovecot_detected": start.is_file(), "dovecot_config_files": 0, "dovecot_mail_locations": [], "dovecot_user_files": []}
    queue = [start] if start.is_file() else []
    # Also recover configs if main file is absent/incomplete.
    confd = root / "etc/dovecot/conf.d"
    if confd.exists():
        try:
            queue.extend(p for p in confd.iterdir() if p.is_file())
        except OSError:
            pass
    seen: set[Path] = set()
    while queue:
        p, _ = resolve_evidence_path(root, queue.pop(0))
        if not p.is_file():
            continue
        k = p.resolve(strict=False)
        if k in seen:
            continue
        seen.add(k)
        text = safe_read_text(p)
        for m in re.finditer(r"(?im)^\s*!include(?:_try)?\s+(.+?)\s*$", text):
            token = m.group(1).strip().strip('"\'')
            host = linux_to_host(root, token, p.parent)
            if any(c in str(host) for c in "*?["):
                try:
                    queue.extend(x for x in host.parent.glob(host.name) if x.is_file())
                except OSError:
                    pass
            else:
                queue.append(host)
    diag["dovecot_config_files"] = len(seen)
    return sorted(seen, key=lambda p: str(p).casefold()), diag


def _expand_dovecot_pattern(root: Path, pattern: str) -> list[Path]:
    # %d/%u/%n cannot be fully resolved without account context. Use a bounded
    # recursive search for the fixed basename where possible.
    if "%" not in pattern:
        return [linux_to_host(root, pattern)]
    base_name = Path(pattern).name
    if "%" in base_name:
        # Try all regular text files below the fixed prefix.
        fixed = pattern.split("%", 1)[0].rstrip("/")
        base = linux_to_host(root, fixed or "/etc/dovecot")
        if base.is_file():
            base = base.parent
        try:
            return [p for p in base.rglob("*") if p.is_file()][:1000]
        except OSError:
            return []
    fixed_dir = pattern.rsplit("/", 1)[0].split("%", 1)[0].rstrip("/")
    base = linux_to_host(root, fixed_dir or "/etc/dovecot")
    try:
        return [p for p in base.rglob(base_name) if p.is_file()][:1000]
    except OSError:
        return []


def _dovecot_accounts(root: Path, accounts: dict[str, dict], diag: dict) -> None:
    files, d = _dovecot_files(root)
    diag.update(d)
    user_files: set[Path] = set()
    for p in files:
        text = safe_read_text(p)
        for m in re.finditer(r"(?im)^\s*(?:mail_location|mail_path)\s*=\s*(.+?)\s*$", text):
            val = m.group(1).strip()
            if val not in diag["dovecot_mail_locations"]:
                diag["dovecot_mail_locations"].append(val)
        # Passwd-file commonly uses args = /etc/dovecot/users or passwd_file_path.
        for m in re.finditer(r"(?im)^\s*(?:args|passwd_file_path)\s*=\s*(?:scheme=[^\s]+\s+)?(.+?)\s*$", text):
            val = m.group(1).strip().split()[0].strip('"\'')
            if val.startswith("/") and ("user" in val.lower() or "passwd" in val.lower() or "%" in val):
                user_files.update(_expand_dovecot_pattern(root, val))
    diag["dovecot_user_files"] = [rel_source(root, p) for p in sorted(user_files, key=lambda x: str(x).casefold())]
    for p in user_files:
        for line in safe_read_text(p, 16 * 1024 * 1024).splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            login = line.split(":", 1)[0].strip()
            if _valid_email(login):
                _add_account(accounts, login, "Dovecot userdb/passwd-file", rel_source(root, p), strong=False)


def _classic_mailboxes(root: Path, accounts: dict[str, dict], diag: dict) -> None:
    diag["classic_mailboxes"] = 0
    for rel in ("var/mail", "var/spool/mail"):
        base = root / rel
        if not base.exists():
            continue
        try:
            for p in base.iterdir():
                if p.is_file() and p.stat().st_size >= 0:
                    # Local Unix mailbox: address may not be known without domain.
                    diag["classic_mailboxes"] += 1
        except OSError:
            pass
    # Home Maildir can still be a strong mailbox existence signal; map to an
    # email only when the home directory name itself already looks like one.
    for rel in ("home", "root"):
        base = root / rel
        if not base.exists():
            continue
        try:
            for md in base.rglob("Maildir"):
                if not md.is_dir():
                    continue
                if not any((md / x).is_dir() for x in ("cur", "new", "tmp")):
                    continue
                owner = md.parent.name
                if _valid_email(owner):
                    _add_account(accounts, owner, "Maildir im Dateisystem", rel_source(root, md), rel_source(root, md), strong=True)
        except OSError:
            pass


def _parse_mail_time(value: str) -> str:
    # Syslog without year cannot be safely normalized without image acquisition
    # context; retain the literal value if conversion is ambiguous.
    value = value.strip()
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc).isoformat()
    except ValueError:
        return value


def _mail_log_paths(root: Path) -> list[Path]:
    patterns = ["var/log/mail.log*", "var/log/maillog*", "var/log/syslog*", "var/log/plesk/maillog*"]
    out: set[Path] = set()
    for pattern in patterns:
        try:
            out.update(p for p in root.glob(pattern) if p.is_file())
        except OSError:
            pass
    return sorted(out, key=lambda p: str(p).casefold())


def extract_mail_access(root: Path, journal_events: Iterable[dict[str, str]], ssh_logins: list[dict]) -> list[dict]:
    ssh_ips = {x.get("ip", "") for x in ssh_logins}
    out: list[MailAccess] = []
    seen: set[tuple[str, str, str, str]] = set()

    dovecot_rx = re.compile(r"(?i)(?:imap|pop3)-login:.*?Login: user=<(?P<user>[^>]+)>.*?(?:rip|remote_ip)=(?P<ip>[0-9a-f:.]+)")
    postfix_rx = re.compile(r"(?i)sasl_username=(?P<user>[^,\s]+).*(?:client=.*?\[(?P<ip1>[0-9a-f:.]+)\]|rip=(?P<ip2>[0-9a-f:.]+))")
    postfix_rx2 = re.compile(r"(?i)(?:client=.*?\[(?P<ip>[0-9a-f:.]+)\].*?)sasl_username=(?P<user>[^,\s]+)")

    def add(ts: str, protocol: str, user: str, ip: str, source: str) -> None:
        addr = _valid_email(user) or user
        key = (ts, protocol, addr, ip)
        if key in seen:
            return
        seen.add(key)
        out.append(MailAccess(ts, protocol, addr, ip, "erfolgreich", source, ip in ssh_ips))

    for e in journal_events:
        msg = e.get("MESSAGE", "")
        ts = e.get("__DATETIME_UTC") or e.get("__REALTIME_TIMESTAMP", "")
        m = dovecot_rx.search(msg)
        if m:
            proto = "POP3" if "pop3-login" in msg.lower() else "IMAP"
            add(ts, proto, m.group("user"), m.group("ip"), e.get("__SOURCE_FILE", "journal"))
            continue
        m = postfix_rx.search(msg) or postfix_rx2.search(msg)
        if m:
            ip = m.groupdict().get("ip") or m.groupdict().get("ip1") or m.groupdict().get("ip2") or ""
            add(ts, "SMTP AUTH", m.group("user"), ip, e.get("__SOURCE_FILE", "journal"))

    for p in _mail_log_paths(root):
        for line in safe_read_text(p, 64 * 1024 * 1024).splitlines():
            m = dovecot_rx.search(line)
            if m:
                proto = "POP3" if "pop3-login" in line.lower() else "IMAP"
                add(line[:15].strip(), proto, m.group("user"), m.group("ip"), rel_source(root, p))
                continue
            m = postfix_rx.search(line) or postfix_rx2.search(line)
            if m:
                ip = m.groupdict().get("ip") or m.groupdict().get("ip1") or m.groupdict().get("ip2") or ""
                add(line[:15].strip(), "SMTP AUTH", m.group("user"), ip, rel_source(root, p))

    return [asdict(x) for x in sorted(out, key=lambda x: x.timestamp)]


def analyze_mail(root: Path, journal_events: Iterable[dict[str, str]], ssh_logins: list[dict]) -> dict:
    accounts: dict[str, dict] = {}
    diag: dict = {}
    _plesk_accounts(root, accounts, diag)
    _postfix_accounts(root, accounts, diag)
    _dovecot_accounts(root, accounts, diag)
    _classic_mailboxes(root, accounts, diag)
    accesses = extract_mail_access(root, journal_events, ssh_logins)
    for access in accesses:
        user = access.get("user", "")
        if _valid_email(user):
            _add_account(accounts, user, f"Erfolgreicher {access['protocol']}-Login", access["source"], strong=True)

    final_accounts: list[MailAccount] = []
    for address, row in sorted(accounts.items()):
        physical = bool(row["mailbox_path"])
        authenticated = any(e.startswith("Erfolgreicher") for e in row["evidence"])
        if physical or authenticated or row["strong"]:
            assessment = "Belegt"
        elif any("Postfix" in e or "Dovecot" in e or "Plesk" in e for e in row["evidence"]):
            assessment = "Konfiguriert"
        else:
            assessment = "Hinweis"
        final_accounts.append(
            MailAccount(
                address=address,
                assessment=assessment,
                evidence=row["evidence"],
                mailbox_path=row["mailbox_path"],
                forwarding=row["forwarding"],
                source=row["sources"],
            )
        )

    diag["accounts_total"] = len(final_accounts)
    diag["accounts_belegt"] = sum(1 for x in final_accounts if x.assessment == "Belegt")
    diag["accounts_konfiguriert"] = sum(1 for x in final_accounts if x.assessment == "Konfiguriert")
    diag["forwardings"] = sum(len(x.forwarding or []) for x in final_accounts)
    diag["authenticated_accesses"] = len(accesses)
    return {
        "accounts": [asdict(x) for x in final_accounts],
        "accesses": accesses,
        "diagnostics": diag,
    }
