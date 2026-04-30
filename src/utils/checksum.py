# ==============================================================================
# WiperX — utils/checksum.py
#
# Пересчёт и валидация CRC32-контрольных сумм чанков .evtx файлов.
#
# Формат EVTX (двоичный):
#   ┌─────────────────────────────────────────────┐
#   │  File Header (4096 байт)                    │
#   │  ├── Magic: "ElfFile\x00" (8 байт)          │
#   │  ├── ...                                    │
#   │  └── Header CRC32 (offset 0x78, 4 байта)   │
#   ├─────────────────────────────────────────────┤
#   │  Chunk 0 (65536 байт)                       │
#   │  ├── Magic: "ElfChnk\x00" (8 байт)         │
#   │  ├── Header (512 байт total)                │
#   │  │   ├── Header CRC32  (offset 0x78, 4 б)  │
#   │  │   │   └─ CRC32 от байт [0:120]          │
#   │  │   └── Data CRC32    (offset 0x7C, 4 б)  │
#   │  │       └─ CRC32 от байт [512:chunk_end]  │
#   │  └── Event Records ...                     │
#   ├─────────────────────────────────────────────┤
#   │  Chunk 1 ...                                │
#   └─────────────────────────────────────────────┘
#
# Константы:
#   EVTX_CHUNK_SIZE        = 65536  (0x10000)
#   EVTX_FILE_HEADER_SIZE  = 4096   (0x1000)
#   EVTX_CHUNK_HEADER_SIZE = 512    (0x200)
#
# Зависимости (Python):
#   • binascii, struct, pathlib, typing — stdlib only
# ==============================================================================

from __future__ import annotations

import binascii
import struct
from pathlib import Path
from typing import Iterator, NamedTuple


# ── Константы формата EVTX ────────────────────────────────────────────────────

EVTX_FILE_MAGIC        = b"ElfFile\x00"
EVTX_CHUNK_MAGIC       = b"ElfChnk\x00"

EVTX_FILE_HEADER_SIZE  = 4096    # байт
EVTX_CHUNK_SIZE        = 65536   # байт (64 КБ)
EVTX_CHUNK_HEADER_SIZE = 512     # байт

# Смещения CRC32 внутри File Header
FILE_HEADER_CRC32_OFFSET   = 0x78  # 120
FILE_HEADER_CRC32_DATA_END = 0x78  # CRC32 считается от [0:120]

# Смещения CRC32 внутри Chunk Header
CHUNK_HEADER_CRC32_OFFSET       = 0x78  # 120 — CRC32 заголовка
CHUNK_DATA_CRC32_OFFSET         = 0x7C  # 124 — CRC32 данных
CHUNK_HEADER_CRC32_COVERED_END  = 0x78  # [0:120]
CHUNK_DATA_CRC32_START          = EVTX_CHUNK_HEADER_SIZE  # 512


# ── Вспомогательные типы ──────────────────────────────────────────────────────

class ChunkChecksumResult(NamedTuple):
    """Результат проверки/пересчёта одного чанка."""
    chunk_index:       int
    chunk_offset:      int    # абсолютный offset в файле

    # Заголовочная CRC32
    header_crc32_stored:    int   # что было в файле
    header_crc32_calculated: int  # что получили при пересчёте
    header_crc32_valid:     bool

    # Данных CRC32
    data_crc32_stored:      int
    data_crc32_calculated:  int
    data_crc32_valid:       bool

    @property
    def is_valid(self) -> bool:
        return self.header_crc32_valid and self.data_crc32_valid

    def __str__(self) -> str:
        status = "✅ OK" if self.is_valid else "❌ CORRUPT"
        return (
            f"Chunk[{self.chunk_index}] @ 0x{self.chunk_offset:08X}  {status}\n"
            f"  Header CRC32  stored=0x{self.header_crc32_stored:08X}  "
            f"calc=0x{self.header_crc32_calculated:08X}  "
            f"{'OK' if self.header_crc32_valid else 'MISMATCH'}\n"
            f"  Data   CRC32  stored=0x{self.data_crc32_stored:08X}  "
            f"calc=0x{self.data_crc32_calculated:08X}  "
            f"{'OK' if self.data_crc32_valid else 'MISMATCH'}"
        )


class FileHeaderChecksumResult(NamedTuple):
    """Результат проверки CRC32 File Header."""
    crc32_stored:     int
    crc32_calculated: int
    is_valid:         bool

    def __str__(self) -> str:
        status = "✅ OK" if self.is_valid else "❌ CORRUPT"
        return (
            f"FileHeader CRC32  {status}  "
            f"stored=0x{self.crc32_stored:08X}  "
            f"calc=0x{self.crc32_calculated:08X}"
        )


# ── Низкоуровневые CRC32 функции ──────────────────────────────────────────────

def crc32(data: bytes) -> int:
    """
    Беззнаковый CRC32 (стандарт ISO 3309 / ITU-T V.42).
    Возвращает int в диапазоне [0, 2^32).
    """
    return binascii.crc32(data) & 0xFFFFFFFF


def _read_u32_le(data: bytes, offset: int) -> int:
    """Читает little-endian uint32 из буфера."""
    return struct.unpack_from("<I", data, offset)[0]


def _write_u32_le(data: bytearray, offset: int, value: int) -> None:
    """Пишет little-endian uint32 в bytearray."""
    struct.pack_into("<I", data, offset, value)


# ── File Header ───────────────────────────────────────────────────────────────

def validate_file_header_checksum(header: bytes) -> FileHeaderChecksumResult:
    """
    Проверяет CRC32 File Header EVTX.

    CRC32 считается от байт [0:120], поле хранится по offset 0x78 (120).
    При вычислении поле CRC32 считается нулевым — то есть берём
    байты [0:120] как есть (поле CRC32 в них не входит).

    Args:
        header: bytes длиной >= 4096 (или хотя бы >= 128)

    Returns:
        FileHeaderChecksumResult
    """
    if header[:8] != EVTX_FILE_MAGIC:
        raise ValueError(
            f"Неверная магия File Header: {header[:8]!r} "
            f"(ожидалось {EVTX_FILE_MAGIC!r})"
        )

    stored = _read_u32_le(header, FILE_HEADER_CRC32_OFFSET)

    # CRC32 считается от первых 120 байт (до поля CRC32)
    calculated = crc32(header[:FILE_HEADER_CRC32_OFFSET])

    return FileHeaderChecksumResult(
        crc32_stored=stored,
        crc32_calculated=calculated,
        is_valid=(stored == calculated),
    )


def recalculate_file_header_checksum(header: bytes) -> bytes:
    """
    Пересчитывает и записывает CRC32 в File Header.

    Args:
        header: bytes File Header (4096 байт)

    Returns:
        bytes с обновлённым полем CRC32
    """
    if len(header) < EVTX_FILE_HEADER_SIZE:
        raise ValueError(
            f"File Header слишком короткий: {len(header)} байт "
            f"(нужно {EVTX_FILE_HEADER_SIZE})"
        )

    buf = bytearray(header)
    new_crc = crc32(bytes(buf[:FILE_HEADER_CRC32_OFFSET]))
    _write_u32_le(buf, FILE_HEADER_CRC32_OFFSET, new_crc)
    return bytes(buf)


# ── Chunk Header & Data ───────────────────────────────────────────────────────

def validate_chunk_checksum(chunk: bytes, chunk_index: int = 0) -> ChunkChecksumResult:
    """
    Проверяет обе CRC32 одного чанка EVTX.

    Header CRC32:
        - Хранится по offset 0x78 (120)
        - Считается от chunk[0:120]

    Data CRC32:
        - Хранится по offset 0x7C (124)
        - Считается от chunk[512:chunk_size]
          (весь блок данных после заголовка)

    Args:
        chunk:       bytes одного чанка (65536 байт)
        chunk_index: порядковый номер чанка (для отчёта)

    Returns:
        ChunkChecksumResult
    """
    if chunk[:8] != EVTX_CHUNK_MAGIC:
        raise ValueError(
            f"Chunk[{chunk_index}]: неверная магия: {chunk[:8]!r} "
            f"(ожидалось {EVTX_CHUNK_MAGIC!r})"
        )

    if len(chunk) < EVTX_CHUNK_SIZE:
        raise ValueError(
            f"Chunk[{chunk_index}]: размер {len(chunk)} байт "
            f"(ожидалось {EVTX_CHUNK_SIZE})"
        )

    # ── Header CRC32 ──────────────────────────────────────────────────────────
    header_stored     = _read_u32_le(chunk, CHUNK_HEADER_CRC32_OFFSET)
    header_calculated = crc32(chunk[:CHUNK_HEADER_CRC32_COVERED_END])

    # ── Data CRC32 ────────────────────────────────────────────────────────────
    data_stored     = _read_u32_le(chunk, CHUNK_DATA_CRC32_OFFSET)
    data_calculated = crc32(chunk[CHUNK_DATA_CRC32_START:EVTX_CHUNK_SIZE])

    chunk_offset = EVTX_FILE_HEADER_SIZE + chunk_index * EVTX_CHUNK_SIZE

    return ChunkChecksumResult(
        chunk_index=chunk_index,
        chunk_offset=chunk_offset,
        header_crc32_stored=header_stored,
        header_crc32_calculated=header_calculated,
        header_crc32_valid=(header_stored == header_calculated),
        data_crc32_stored=data_stored,
        data_crc32_calculated=data_calculated,
        data_crc32_valid=(data_stored == data_calculated),
    )


def recalculate_chunk_checksum(chunk: bytes, chunk_index: int = 0) -> bytes:
    """
    Пересчитывает обе CRC32 чанка и возвращает исправленный чанк.

    Args:
        chunk:       bytes одного чанка (65536 байт)
        chunk_index: порядковый номер (для сообщений об ошибках)

    Returns:
        bytes с обновлёнными полями Header CRC32 и Data CRC32
    """
    if chunk[:8] != EVTX_CHUNK_MAGIC:
        raise ValueError(
            f"Chunk[{chunk_index}]: неверная магия: {chunk[:8]!r}"
        )

    buf = bytearray(chunk)

    # 1. Header CRC32 — от buf[0:120]
    new_header_crc = crc32(bytes(buf[:CHUNK_HEADER_CRC32_COVERED_END]))
    _write_u32_le(buf, CHUNK_HEADER_CRC32_OFFSET, new_header_crc)

    # 2. Data CRC32 — от buf[512:65536]
    new_data_crc = crc32(bytes(buf[CHUNK_DATA_CRC32_START:EVTX_CHUNK_SIZE]))
    _write_u32_le(buf, CHUNK_DATA_CRC32_OFFSET, new_data_crc)

    return bytes(buf)


# ── Итераторы по файлу ────────────────────────────────────────────────────────

def iter_chunks(evtx_path: Path) -> Iterator[tuple[int, bytes]]:
    """
    Итерирует по всем чанкам EVTX файла.

    Yields:
        (chunk_index, chunk_bytes)
    """
    with open(evtx_path, "rb") as f:
        # Пропускаем File Header
        f.seek(EVTX_FILE_HEADER_SIZE)
        chunk_index = 0
        while True:
            chunk = f.read(EVTX_CHUNK_SIZE)
            if len(chunk) < EVTX_CHUNK_SIZE:
                break
            if chunk[:8] != EVTX_CHUNK_MAGIC:
                break
            yield chunk_index, chunk
            chunk_index += 1


# ── Высокоуровневые функции ───────────────────────────────────────────────────

def validate_evtx_file(evtx_path: Path) -> dict:
    """
    Полная валидация CRC32 всего EVTX файла.

    Проверяет:
      - File Header CRC32
      - Header CRC32 каждого чанка
      - Data CRC32 каждого чанка

    Args:
        evtx_path: путь к .evtx файлу

    Returns:
        dict с ключами:
            "file_header":  FileHeaderChecksumResult
            "chunks":       list[ChunkChecksumResult]
            "total_chunks": int
            "valid_chunks": int
            "corrupt_chunks": int
            "is_clean":     bool
    """
    evtx_path = Path(evtx_path)

    if not evtx_path.exists():
        raise FileNotFoundError(f"Файл не найден: {evtx_path}")

    with open(evtx_path, "rb") as f:
        raw_header = f.read(EVTX_FILE_HEADER_SIZE)

    file_header_result = validate_file_header_checksum(raw_header)

    chunk_results: list[ChunkChecksumResult] = []
    for chunk_index, chunk_bytes in iter_chunks(evtx_path):
        result = validate_chunk_checksum(chunk_bytes, chunk_index)
        chunk_results.append(result)

    total   = len(chunk_results)
    valid   = sum(1 for r in chunk_results if r.is_valid)
    corrupt = total - valid

    return {
        "file_header":    file_header_result,
        "chunks":         chunk_results,
        "total_chunks":   total,
        "valid_chunks":   valid,
        "corrupt_chunks": corrupt,
        "is_clean":       file_header_result.is_valid and corrupt == 0,
    }


def fix_evtx_checksums(evtx_path: Path, output_path: Path) -> dict:
    """
    Пересчитывает все CRC32 в EVTX файле и сохраняет исправленную копию.

    Не изменяет оригинальный файл — всегда пишет в output_path.

    Args:
        evtx_path:   исходный .evtx файл
        output_path: куда записать исправленный файл

    Returns:
        dict с ключами:
            "fixed_file_header": bool
            "fixed_chunks":      int   (кол-во исправленных чанков)
            "total_chunks":      int
            "output_path":       Path
    """
    evtx_path   = Path(evtx_path)
    output_path = Path(output_path)

    if not evtx_path.exists():
        raise FileNotFoundError(f"Файл не найден: {evtx_path}")

    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(evtx_path, "rb") as f:
        raw = f.read()

    buf = bytearray(raw)

    # ── Исправляем File Header ─────────────────────────────────────────────
    header_before = validate_file_header_checksum(bytes(buf[:EVTX_FILE_HEADER_SIZE]))
    fixed_header  = recalculate_file_header_checksum(bytes(buf[:EVTX_FILE_HEADER_SIZE]))
    buf[:EVTX_FILE_HEADER_SIZE] = fixed_header
    header_was_broken = not header_before.is_valid

    # ── Исправляем чанки ───────────────────────────────────────────────────
    fixed_chunks = 0
    total_chunks = 0
    offset       = EVTX_FILE_HEADER_SIZE

    while offset + EVTX_CHUNK_SIZE <= len(buf):
        chunk_slice = bytes(buf[offset : offset + EVTX_CHUNK_SIZE])

        if chunk_slice[:8] != EVTX_CHUNK_MAGIC:
            break

        chunk_index  = (offset - EVTX_FILE_HEADER_SIZE) // EVTX_CHUNK_SIZE
        result_before = validate_chunk_checksum(chunk_slice, chunk_index)

        if not result_before.is_valid:
            fixed_chunk = recalculate_chunk_checksum(chunk_slice, chunk_index)
            buf[offset : offset + EVTX_CHUNK_SIZE] = fixed_chunk
            fixed_chunks += 1

        total_chunks += 1
        offset       += EVTX_CHUNK_SIZE

    # ── Записываем результат ───────────────────────────────────────────────
    with open(output_path, "wb") as f:
        f.write(bytes(buf))

    return {
        "fixed_file_header": header_was_broken,
        "fixed_chunks":      fixed_chunks,
        "total_chunks":      total_chunks,
        "output_path":       output_path,
    }
