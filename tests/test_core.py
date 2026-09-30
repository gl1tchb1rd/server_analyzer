# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "_system"))

from journal_native import JournalReader
from mail_forensics import analyze_mail
from server_forensics import analyze_nginx, extract_successful_ssh


def align8(v: int) -> int:
    return (v + 7) & ~7


def build_journal(path: Path, fields: list[str]) -> None:
    header_size = 208
    buf = bytearray(header_size)
    buf[0:8] = b"LPKSHHRH"
    struct.pack_into("<I", buf, 8, 0)
    struct.pack_into("<I", buf, 12, 0)
    buf[24:40] = bytes(range(16))
    buf[72:88] = bytes(range(16, 32))
    struct.pack_into("<Q", buf, 88, header_size)
    struct.pack_into("<Q", buf, 152, 1)

    offsets = []
    pos = header_size
    for field in fields:
        pos = align8(pos)
        while len(buf) < pos:
            buf.append(0)
        payload = field.encode("utf-8")
        size = 64 + len(payload)
        obj = bytearray(size)
        obj[0] = 1
        struct.pack_into("<Q", obj, 8, size)
        obj[64:] = payload
        offsets.append(pos)
        buf.extend(obj)
        pos += size

    pos = align8(pos)
    while len(buf) < pos:
        buf.append(0)
    entry_size = 64 + 16 * len(offsets)
    entry = bytearray(entry_size)
    entry[0] = 3
    struct.pack_into("<Q", entry, 8, entry_size)
    struct.pack_into("<Q", entry, 16, 1)
    struct.pack_into("<Q", entry, 24, 1_700_000_000_000_000)
    struct.pack_into("<Q", entry, 32, 12345)
    entry[40:56] = b"\x11" * 16
    for i, off in enumerate(offsets):
        struct.pack_into("<Q", entry, 64 + i * 16, off)
    buf.extend(entry)
    struct.pack_into("<Q", buf, 96, len(buf) - header_size)
    struct.pack_into("<Q", buf, 136, pos)
    path.write_bytes(buf)


class CoreTests(unittest.TestCase):
    def test_native_journal_and_ssh(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "system.journal"
            build_journal(p, [
                "_HOSTNAME=testbox",
                "_SYSTEMD_UNIT=sshd.service",
                "MESSAGE=Accepted publickey for root from 203.0.113.5 port 51111 ssh2",
            ])
            with JournalReader(p) as reader:
                events = list(reader.entries())
            self.assertEqual(len(events), 1)
            ssh = extract_successful_ssh(events)
            self.assertEqual(ssh[0]["user"], "root")
            self.assertEqual(ssh[0]["ip"], "203.0.113.5")

    def test_nginx_text_symlinks_16_vhosts(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            av = root / "etc/nginx/sites-available"; en = root / "etc/nginx/sites-enabled"
            av.mkdir(parents=True); en.mkdir(parents=True)
            (root / "etc/nginx/nginx.conf").write_text("http { include /etc/nginx/sites-enabled/*; }", encoding="utf-8")
            for i in range(1, 17):
                domain = f"shop{i:02d}.example"
                (av / domain).write_text(f"server {{ listen 80; server_name {domain} www.{domain}; root /var/www/{domain}; }}", encoding="utf-8")
                # Common forensic-export representation of a Linux symlink.
                (en / domain).write_text(f"../sites-available/{domain}\n", encoding="utf-8")
            websites, diag = analyze_nginx(root)
            domains = {w["domain"] for w in websites}
            self.assertEqual(len(domains), 16)
            self.assertEqual(diag["sites_enabled_entries"], 16)
            self.assertEqual(diag["sites_enabled_textlink"], 16)

    def test_plesk_custom_mail_storage(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "etc/psa").mkdir(parents=True)
            (root / "etc/psa/psa.conf").write_text("PLESK_MAILNAMES_D /custom/mailnames\n", encoding="utf-8")
            md = root / "custom/mailnames/shop.example/info/Maildir"
            for sub in ("cur", "new", "tmp"):
                (md / sub).mkdir(parents=True, exist_ok=True)
            user = md.parent
            (user / ".qmail").write_text("&external@example.net\n", encoding="utf-8")
            result = analyze_mail(root, [], [])
            account = next(x for x in result["accounts"] if x["address"] == "info@shop.example")
            self.assertEqual(account["assessment"], "Belegt")
            self.assertIn("external@example.net", account["forwarding"])


if __name__ == "__main__":
    unittest.main()
