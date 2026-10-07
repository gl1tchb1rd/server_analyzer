from __future__ import annotations

"""Small, read-only systemd journal file parser for K25 Server Analyzer.

The implementation follows systemd's documented on-disk Journal File Format.
It deliberately focuses on reading ENTRY and DATA objects sequentially. This
avoids dependence on libsystemd/journalctl and therefore works on Windows.
"""

import io
import lzma
import mmap
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import lz4.block as lz4_block
except Exception:  # optional until a compressed LZ4 object is encountered
    lz4_block = None

try:
    import zstandard as zstd
except Exception:  # optional until a compressed ZSTD object is encountered
    zstd = None

SIGNATURE = b"LPKSHHRH"

OBJECT_UNUSED = 0
OBJECT_DATA = 1
OBJECT_FIELD = 2
OBJECT_ENTRY = 3
OBJECT_DATA_HASH_TABLE = 4
OBJECT_FIELD_HASH_TABLE = 5
OBJECT_ENTRY_ARRAY = 6
OBJECT_TAG = 7

OBJECT_COMPRESSED_XZ = 1 << 0
OBJECT_COMPRESSED_LZ4 = 1 << 1
OBJECT_COMPRESSED_ZSTD = 1 << 2
KNOWN_OBJECT_FLAGS = OBJECT_COMPRESSED_XZ | OBJECT_COMPRESSED_LZ4 | OBJECT_COMPRESSED_ZSTD

HEADER_INCOMPATIBLE_COMPRESSED_XZ = 1 << 0
HEADER_INCOMPATIBLE_COMPRESSED_LZ4 = 1 << 1
HEADER_INCOMPATIBLE_KEYED_HASH = 1 << 2
HEADER_INCOMPATIBLE_COMPRESSED_ZSTD = 1 << 3
HEADER_INCOMPATIBLE_COMPACT = 1 << 4
KNOWN_INCOMPATIBLE_FLAGS = (
    HEADER_INCOMPATIBLE_COMPRESSED_XZ
    | HEADER_INCOMPATIBLE_COMPRESSED_LZ4
    | HEADER_INCOMPATIBLE_KEYED_HASH
    | HEADER_INCOMPATIBLE_COMPRESSED_ZSTD
    | HEADER_INCOMPATIBLE_COMPACT
)

MAX_OBJECT_SIZE = 512 * 1024 * 1024
MAX_DECOMPRESSED_FIELD = 128 * 1024 * 1024


class JournalParseError(RuntimeError):
    pass


@dataclass
class NativeParseResult:
    entries: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    header: dict[str, Any] = field(default_factory=dict)
    object_counts: dict[str, int] = field(default_factory=dict)


def _u32(buf: bytes, off: int) -> int:
    if off < 0 or off + 4 > len(buf):
        raise JournalParseError(f"Ungültiger 32-Bit-Zugriff bei Offset 0x{off:x}")
    return struct.unpack_from("<I", buf, off)[0]


def _u64(buf: bytes, off: int) -> int:
    if off < 0 or off + 8 > len(buf):
        raise JournalParseError(f"Ungültiger 64-Bit-Zugriff bei Offset 0x{off:x}")
    return struct.unpack_from("<Q", buf, off)[0]


def _align8(value: int) -> int:
    return (value + 7) & ~7


def _id128(buf: bytes) -> str:
    return bytes(buf).hex()


def _safe_decode(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def _decompress_payload(payload: bytes, flags: int) -> bytes:
    compression_flags = flags & KNOWN_OBJECT_FLAGS
    if compression_flags == 0:
        return payload
    if compression_flags & (compression_flags - 1):
        raise JournalParseError("DATA-Objekt enthält mehrere Kompressionsflags gleichzeitig")

    if flags & OBJECT_COMPRESSED_XZ:
        try:
            out = lzma.decompress(payload)
        except Exception as exc:
            raise JournalParseError(f"XZ-Dekompression fehlgeschlagen: {exc}") from exc
    elif flags & OBJECT_COMPRESSED_LZ4:
        if lz4_block is None:
            raise JournalParseError("LZ4-komprimierte Daten gefunden; Python-Paket 'lz4' ist nicht installiert")
        if len(payload) <= 8:
            raise JournalParseError("Ungültiger LZ4-Datenblock (kleiner/gleich 8 Byte)")
        expected_size = struct.unpack_from("<Q", payload, 0)[0]
        if expected_size > MAX_DECOMPRESSED_FIELD:
            raise JournalParseError(
                f"LZ4-Datenblock meldet {expected_size} Byte entpackte Größe; Sicherheitslimit überschritten"
            )
        try:
            out = lz4_block.decompress(payload[8:], uncompressed_size=expected_size)
        except Exception as exc:
            raise JournalParseError(f"LZ4-Dekompression fehlgeschlagen: {exc}") from exc
        if len(out) != expected_size:
            raise JournalParseError(
                f"LZ4-Dekompression ergab {len(out)} statt {expected_size} Byte"
            )
    elif flags & OBJECT_COMPRESSED_ZSTD:
        if zstd is None:
            raise JournalParseError(
                "ZSTD-komprimierte Daten gefunden; Python-Paket 'zstandard' ist nicht installiert"
            )
        try:
            dctx = zstd.ZstdDecompressor()
            with dctx.stream_reader(io.BytesIO(payload)) as reader:
                out = reader.read(MAX_DECOMPRESSED_FIELD + 1)
        except Exception as exc:
            raise JournalParseError(f"ZSTD-Dekompression fehlgeschlagen: {exc}") from exc
    else:
        raise JournalParseError(f"Unbekanntes Kompressionsflag 0x{flags:x}")

    if len(out) > MAX_DECOMPRESSED_FIELD:
        raise JournalParseError(
            f"Entpacktes DATA-Feld überschreitet Sicherheitslimit ({MAX_DECOMPRESSED_FIELD} Byte)"
        )
    return out


def _merge_field(target: dict[str, Any], key: str, value: str) -> None:
    if key not in target:
        target[key] = value
        return
    current = target[key]
    if isinstance(current, list):
        current.append(value)
    else:
        target[key] = [current, value]


def _cursor(seqnum_id: str, seqnum: int, boot_id: str, monotonic: int, realtime: int, xor_hash: int) -> str:
    # Same field vocabulary as systemd journal cursors. This is reconstructed
    # from the on-disk ENTRY/header metadata rather than requested from libsystemd.
    return (
        f"s={seqnum_id};i={seqnum:x};b={boot_id};"
        f"m={monotonic:x};t={realtime:x};x={xor_hash:x}"
    )


def _parse_journal_buffer(data: Any) -> NativeParseResult:
    result = NativeParseResult()

    if len(data) < 96:
        raise JournalParseError("Datei ist zu klein für einen systemd-Journal-Header")
    if data[:8] != SIGNATURE:
        raise JournalParseError("Ungültige Journal-Signatur (erwartet LPKSHHRH)")

    compatible_flags = _u32(data, 8)
    incompatible_flags = _u32(data, 12)
    unknown_incompat = incompatible_flags & ~KNOWN_INCOMPATIBLE_FLAGS
    if unknown_incompat:
        raise JournalParseError(
            f"Journal verwendet unbekannte inkompatible Formatflags 0x{unknown_incompat:x}"
        )

    state = data[16]
    file_id = _id128(data[24:40])
    machine_id = _id128(data[40:56])
    tail_entry_boot_id = _id128(data[56:72])
    seqnum_id = _id128(data[72:88])
    header_size = _u64(data, 88)
    arena_size = _u64(data, 96) if len(data) >= 104 else 0

    if header_size < 96 or header_size > len(data):
        raise JournalParseError(
            f"Unplausible Headergröße {header_size} Byte bei Dateigröße {len(data)} Byte"
        )

    def header_u64(off: int) -> int | None:
        return _u64(data, off) if header_size >= off + 8 and len(data) >= off + 8 else None

    result.header = {
        "compatible_flags": compatible_flags,
        "incompatible_flags": incompatible_flags,
        "compact": bool(incompatible_flags & HEADER_INCOMPATIBLE_COMPACT),
        "state": state,
        "file_id": file_id,
        "machine_id": machine_id,
        "tail_entry_boot_id": tail_entry_boot_id,
        "seqnum_id": seqnum_id,
        "header_size": header_size,
        "arena_size": arena_size,
        "tail_object_offset": header_u64(136),
        "n_objects": header_u64(144),
        "n_entries": header_u64(152),
        "head_entry_realtime": header_u64(184),
        "tail_entry_realtime": header_u64(192),
    }

    compact = bool(incompatible_flags & HEADER_INCOMPATIBLE_COMPACT)
    data_objects: dict[int, tuple[str, str]] = {}
    entry_objects: list[tuple[int, int, int, int, str, int, list[int]]] = []
    counts = {
        "DATA": 0,
        "FIELD": 0,
        "ENTRY": 0,
        "DATA_HASH_TABLE": 0,
        "FIELD_HASH_TABLE": 0,
        "ENTRY_ARRAY": 0,
        "TAG": 0,
        "UNUSED/UNKNOWN": 0,
    }

    offset = _align8(int(header_size))
    scan_end = len(data)
    advertised_end = int(header_size + arena_size) if arena_size else 0
    if advertised_end:
        if advertised_end > len(data):
            result.warnings.append(
                f"Header meldet {advertised_end} Byte genutzten Bereich, Datei ist nur {len(data)} Byte groß; "
                "es wird bis zum Dateiende gelesen."
            )
        else:
            scan_end = advertised_end

    object_index = 0
    while offset + 16 <= scan_end:
        object_index += 1
        obj_type = data[offset]
        flags = data[offset + 1]
        obj_size = _u64(data, offset + 8)

        if obj_size == 0:
            # Zero-filled preallocated tail is normal in journal files.
            break
        if obj_size < 16:
            result.warnings.append(
                f"Objekt #{object_index} bei 0x{offset:x}: unplausible Größe {obj_size}; Scan beendet."
            )
            break
        if obj_size > MAX_OBJECT_SIZE:
            result.warnings.append(
                f"Objekt #{object_index} bei 0x{offset:x}: Größe {obj_size} überschreitet Sicherheitslimit; Scan beendet."
            )
            break
        end = offset + obj_size
        if end > scan_end or end > len(data):
            result.warnings.append(
                f"Objekt #{object_index} bei 0x{offset:x} reicht über das verfügbare Dateiende; "
                "möglicherweise unvollständiges/aktives Journal."
            )
            break

        if obj_type == OBJECT_DATA:
            counts["DATA"] += 1
            fixed = 72 if compact else 64
            if obj_size < fixed:
                result.warnings.append(
                    f"DATA-Objekt bei 0x{offset:x} ist mit {obj_size} Byte kleiner als erwartet ({fixed})."
                )
            else:
                payload = data[offset + fixed:end]
                try:
                    payload = _decompress_payload(payload, flags)
                    eq = payload.find(b"=")
                    if eq <= 0:
                        result.warnings.append(
                            f"DATA-Objekt bei 0x{offset:x} enthält kein gültiges NAME=WERT-Feld."
                        )
                    else:
                        key = _safe_decode(payload[:eq])
                        value = _safe_decode(payload[eq + 1:])
                        data_objects[offset] = (key, value)
                except JournalParseError as exc:
                    result.warnings.append(f"DATA-Objekt bei 0x{offset:x}: {exc}")

        elif obj_type == OBJECT_FIELD:
            counts["FIELD"] += 1
        elif obj_type == OBJECT_ENTRY:
            counts["ENTRY"] += 1
            if obj_size < 64:
                result.warnings.append(
                    f"ENTRY-Objekt bei 0x{offset:x} ist mit {obj_size} Byte kleiner als 64 Byte."
                )
            else:
                seqnum = _u64(data, offset + 16)
                realtime = _u64(data, offset + 24)
                monotonic = _u64(data, offset + 32)
                boot_id = _id128(data[offset + 40:offset + 56])
                xor_hash = _u64(data, offset + 56)
                item_size = 4 if compact else 16
                payload_size = obj_size - 64
                if payload_size % item_size != 0:
                    result.warnings.append(
                        f"ENTRY-Objekt bei 0x{offset:x}: Item-Bereich {payload_size} Byte ist nicht durch {item_size} teilbar."
                    )
                item_count = payload_size // item_size
                refs: list[int] = []
                pos = offset + 64
                for _ in range(item_count):
                    ref = _u32(data, pos) if compact else _u64(data, pos)
                    if ref:
                        refs.append(int(ref))
                    pos += item_size
                entry_objects.append((offset, seqnum, realtime, monotonic, boot_id, xor_hash, refs))
        elif obj_type == OBJECT_DATA_HASH_TABLE:
            counts["DATA_HASH_TABLE"] += 1
        elif obj_type == OBJECT_FIELD_HASH_TABLE:
            counts["FIELD_HASH_TABLE"] += 1
        elif obj_type == OBJECT_ENTRY_ARRAY:
            counts["ENTRY_ARRAY"] += 1
        elif obj_type == OBJECT_TAG:
            counts["TAG"] += 1
        else:
            counts["UNUSED/UNKNOWN"] += 1

        offset = _align8(end)

    result.object_counts = counts

    missing_ref_count = 0
    for entry_offset, seqnum, realtime, monotonic, boot_id, xor_hash, refs in entry_objects:
        raw: dict[str, Any] = {}
        for ref in refs:
            pair = data_objects.get(ref)
            if pair is None:
                missing_ref_count += 1
                continue
            key, value = pair
            _merge_field(raw, key, value)

        raw["__REALTIME_TIMESTAMP"] = str(realtime)
        raw["__MONOTONIC_TIMESTAMP"] = str(monotonic)
        raw["__SEQNUM"] = str(seqnum)
        raw["__BOOT_ID"] = boot_id
        raw.setdefault("_BOOT_ID", boot_id)
        raw["__ENTRY_OFFSET"] = f"0x{entry_offset:x}"
        raw["__CURSOR"] = _cursor(seqnum_id, seqnum, boot_id, monotonic, realtime, xor_hash)
        result.entries.append(raw)

    if missing_ref_count:
        result.warnings.append(
            f"{missing_ref_count} DATA-Verweis(e) aus ENTRY-Objekten konnten nicht aufgelöst werden. "
            "Das kann bei beschädigten/unvollständigen Journaldateien vorkommen."
        )

    advertised_entries = result.header.get("n_entries")
    if isinstance(advertised_entries, int) and advertised_entries != len(result.entries):
        result.warnings.append(
            f"Header meldet {advertised_entries} ENTRY-Objekte, sequenziell gelesen wurden {len(result.entries)}."
        )

    return result


def parse_journal_file(path: str | Path) -> NativeParseResult:
    """Parse one journal file without modifying it.

    The source is memory-mapped read-only so large journal files do not have to
    be copied completely into Python heap memory.
    """
    p = Path(path)
    try:
        size = p.stat().st_size
    except OSError as exc:
        raise JournalParseError(f"Journal-Datei kann nicht gelesen werden: {exc}") from exc
    if size == 0:
        raise JournalParseError("Journal-Datei ist leer")
    try:
        with p.open("rb") as handle:
            with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
                return _parse_journal_buffer(mapped)
    except JournalParseError:
        raise
    except (OSError, ValueError) as exc:
        raise JournalParseError(f"Journal-Datei kann nicht verarbeitet werden: {exc}") from exc
