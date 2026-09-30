# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Gl1tchb1rd
"""Defensive, read-only parser for systemd journal files.

The implementation follows the publicly documented systemd journal on-disk
format. It deliberately does not modify journal files and does not require
journalctl/libsystemd, so it can run on Windows against extracted evidence.
"""

from __future__ import annotations

import hashlib
import lzma
import mmap
import struct
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

SIGNATURE = b"LPKSHHRH"
OBJECT_DATA = 1
OBJECT_ENTRY = 3
OBJECT_COMPRESSED_XZ = 1 << 0
OBJECT_COMPRESSED_LZ4 = 1 << 1
OBJECT_COMPRESSED_ZSTD = 1 << 2
HEADER_INCOMPATIBLE_COMPACT = 1 << 4
MAX_OBJECT_SIZE = 256 * 1024 * 1024
MAX_DECOMPRESSED = 128 * 1024 * 1024


class JournalError(RuntimeError):
    pass


@dataclass(slots=True)
class JournalMeta:
    path: str
    sha256: str
    size: int
    compact: bool
    compatible_flags: int
    incompatible_flags: int
    header_size: int
    declared_entries: int
    parsed_entries: int = 0
    errors: int = 0


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                return h.hexdigest()
            h.update(chunk)


def discover_journals(root: Path) -> list[Path]:
    candidates: set[Path] = set()
    for rel in (Path("var/log/journal"), Path("run/log/journal")):
        base = root / rel
        if not base.exists():
            continue
        try:
            for p in base.rglob("*"):
                if p.is_file() and (p.name.endswith(".journal") or p.name.endswith(".journal~")):
                    candidates.add(p)
        except OSError:
            continue
    return sorted(candidates, key=lambda p: str(p).casefold())


def _u32(buf: mmap.mmap, offset: int) -> int:
    return struct.unpack_from("<I", buf, offset)[0]


def _u64(buf: mmap.mmap, offset: int) -> int:
    return struct.unpack_from("<Q", buf, offset)[0]


def _align8(value: int) -> int:
    return (value + 7) & ~7


def _decode_lz4(payload: bytes) -> bytes:
    import lz4.block

    try:
        return lz4.block.decompress(payload)
    except Exception:
        guess = max(len(payload) * 4, 4096)
        while guess <= MAX_DECOMPRESSED:
            try:
                return lz4.block.decompress(payload, uncompressed_size=guess)
            except Exception:
                guess *= 2
    raise JournalError("LZ4-Daten konnten nicht dekomprimiert werden")


def _decode_zstd(payload: bytes) -> bytes:
    import zstandard

    try:
        return zstandard.ZstdDecompressor().decompress(payload, max_output_size=MAX_DECOMPRESSED)
    except Exception as exc:
        raise JournalError(f"ZSTD-Daten konnten nicht dekomprimiert werden: {exc}") from exc


def _decompress(flags: int, payload: bytes) -> bytes:
    comp = flags & (OBJECT_COMPRESSED_XZ | OBJECT_COMPRESSED_LZ4 | OBJECT_COMPRESSED_ZSTD)
    if comp == 0:
        return payload
    if comp == OBJECT_COMPRESSED_XZ:
        try:
            return lzma.decompress(payload)
        except lzma.LZMAError as exc:
            raise JournalError(f"XZ-Daten konnten nicht dekomprimiert werden: {exc}") from exc
    if comp == OBJECT_COMPRESSED_LZ4:
        return _decode_lz4(payload)
    if comp == OBJECT_COMPRESSED_ZSTD:
        return _decode_zstd(payload)
    raise JournalError("Ungültige Kombination von Kompressionsflags")


class JournalReader:
    def __init__(self, path: Path):
        self.path = Path(path)
        self._fh = None
        self._mm: mmap.mmap | None = None
        self.size = 0
        self.compact = False
        self.compatible_flags = 0
        self.incompatible_flags = 0
        self.header_size = 0
        self.declared_entries = 0
        self.file_id = b""
        self.seqnum_id = b""
        self._data_cache: dict[int, bytes] = {}

    def __enter__(self) -> "JournalReader":
        self._fh = self.path.open("rb")
        self.size = self.path.stat().st_size
        if self.size < 208:
            raise JournalError("Datei ist zu klein für einen systemd-Journalheader")
        self._mm = mmap.mmap(self._fh.fileno(), 0, access=mmap.ACCESS_READ)
        self._read_header()
        return self

    def __exit__(self, *_exc) -> None:
        if self._mm is not None:
            self._mm.close()
        if self._fh is not None:
            self._fh.close()

    @property
    def mm(self) -> mmap.mmap:
        if self._mm is None:
            raise JournalError("Journal ist nicht geöffnet")
        return self._mm

    def _read_header(self) -> None:
        mm = self.mm
        if mm[:8] != SIGNATURE:
            raise JournalError("Ungültige systemd-Journal-Signatur")
        self.compatible_flags = _u32(mm, 8)
        self.incompatible_flags = _u32(mm, 12)
        self.file_id = bytes(mm[24:40])
        self.seqnum_id = bytes(mm[72:88])
        self.header_size = _u64(mm, 88)
        self.declared_entries = _u64(mm, 152)
        self.compact = bool(self.incompatible_flags & HEADER_INCOMPATIBLE_COMPACT)
        if self.header_size < 208 or self.header_size > self.size:
            raise JournalError(f"Unplausible Headergröße: {self.header_size}")

    def _object_header(self, offset: int) -> tuple[int, int, int]:
        if offset < self.header_size or offset + 16 > self.size:
            raise JournalError(f"Objektoffset außerhalb der Datei: 0x{offset:x}")
        obj_type = self.mm[offset]
        flags = self.mm[offset + 1]
        size = _u64(self.mm, offset + 8)
        if size < 16 or size > MAX_OBJECT_SIZE or offset + size > self.size:
            raise JournalError(f"Ungültige Objektgröße bei 0x{offset:x}: {size}")
        return obj_type, flags, size

    def entry_offsets(self) -> Iterator[int]:
        """Scan objects in append order instead of trusting index chains.

        This is deliberately useful for forensic images where index metadata can
        be damaged while individual entry/data objects are still readable.
        """
        pos = _align8(self.header_size)
        failures = 0
        while pos + 16 <= self.size:
            try:
                obj_type, _flags, size = self._object_header(pos)
            except JournalError:
                failures += 1
                if failures > 64:
                    break
                pos += 8
                continue
            failures = 0
            if obj_type == OBJECT_ENTRY:
                yield pos
            pos = _align8(pos + size)

    def _data_payload(self, offset: int) -> bytes:
        cached = self._data_cache.get(offset)
        if cached is not None:
            return cached
        obj_type, flags, size = self._object_header(offset)
        if obj_type != OBJECT_DATA:
            raise JournalError(f"ENTRY referenziert kein DATA-Objekt bei 0x{offset:x}")
        payload_start = offset + (72 if self.compact else 64)
        end = offset + size
        if payload_start > end:
            raise JournalError("DATA-Objekt ist kürzer als sein Header")
        raw = bytes(self.mm[payload_start:end])
        value = _decompress(flags, raw)
        if len(value) > MAX_DECOMPRESSED:
            raise JournalError("Dekomprimiertes DATA-Objekt überschreitet Sicherheitsgrenze")
        self._data_cache[offset] = value
        return value

    def parse_entry(self, offset: int) -> dict[str, str]:
        obj_type, _flags, size = self._object_header(offset)
        if obj_type != OBJECT_ENTRY or size < 64:
            raise JournalError("Kein gültiges ENTRY-Objekt")
        seqnum = _u64(self.mm, offset + 16)
        realtime = _u64(self.mm, offset + 24)
        monotonic = _u64(self.mm, offset + 32)
        boot_id = bytes(self.mm[offset + 40: offset + 56]).hex()
        item_start = offset + 64
        step = 4 if self.compact else 16
        values: dict[str, list[str]] = {}
        pos = item_start
        end = offset + size
        while pos + step <= end:
            data_offset = _u32(self.mm, pos) if self.compact else _u64(self.mm, pos)
            pos += step
            if not data_offset:
                continue
            try:
                raw = self._data_payload(data_offset)
            except JournalError:
                continue
            if b"=" not in raw:
                continue
            key_b, val_b = raw.split(b"=", 1)
            key = key_b.decode("ascii", errors="replace")
            value = val_b.decode("utf-8", errors="replace")
            values.setdefault(key, []).append(value)

        result = {k: "\n".join(v) for k, v in values.items()}
        result["__SEQNUM"] = str(seqnum)
        result["__REALTIME_TIMESTAMP"] = str(realtime)
        result["__MONOTONIC_TIMESTAMP"] = str(monotonic)
        result.setdefault("_BOOT_ID", boot_id)
        result["__ENTRY_OFFSET"] = f"0x{offset:x}"
        result["__SOURCE_FILE"] = str(self.path)
        result["__CURSOR"] = f"sa:file={self.file_id.hex()};seq={seqnum};off={offset:x}"
        if realtime:
            try:
                result["__DATETIME_UTC"] = datetime.fromtimestamp(realtime / 1_000_000, tz=timezone.utc).isoformat()
            except (OverflowError, OSError, ValueError):
                pass
        return result

    def entries(self, limit: int | None = None) -> Iterator[dict[str, str]]:
        count = 0
        for offset in self.entry_offsets():
            try:
                yield self.parse_entry(offset)
            except JournalError:
                continue
            count += 1
            if limit is not None and count >= limit:
                break


def read_journal(path: Path, limit: int | None = None) -> tuple[list[dict[str, str]], JournalMeta]:
    path = Path(path)
    digest = sha256_file(path)
    errors = 0
    rows: list[dict[str, str]] = []
    with JournalReader(path) as reader:
        for offset in reader.entry_offsets():
            try:
                rows.append(reader.parse_entry(offset))
            except Exception:
                errors += 1
            if limit is not None and len(rows) >= limit:
                break
        meta = JournalMeta(
            path=str(path),
            sha256=digest,
            size=path.stat().st_size,
            compact=reader.compact,
            compatible_flags=reader.compatible_flags,
            incompatible_flags=reader.incompatible_flags,
            header_size=reader.header_size,
            declared_entries=reader.declared_entries,
            parsed_entries=len(rows),
            errors=errors,
        )
    return rows, meta
