# ==============================================================================
# WiperX — utils/renumber.py
#
# Перенумерация EventRecordID в .evtx файлах.
#
# Зачем это нужно (forensics / anti-forensics detection):
#   При анализе следов вайпа EventRecordID помогает обнаружить:
#     • Пропуски в нумерации  → признак удаления записей
#     • Несоответствие chunk-header ↔ record-level ID → признак тампинга
#     • Несоответствие FileHeader.NextRecordID ↔ реальный последний ID
#
#   renumber.py умеет:
#     1. Сканировать все чанки и все записи — строить карту ID
#     2. Обнаруживать и репортить gap-ы (пропуски)
#     3. Перезаписывать EventRecordID последовательно (для тест-фикстур)
#     4. Синхронизировать chunk-header поля FirstEventRecordID /
#        LastEventRecordID / LastEventRecordNumber
#     5. Обновлять FileHeader.NextRecordID
#     6. После перезаписи — делегировать пересчёт CRC32 в checksum.py
#
# Структура EVTX (краткая):
#
#   File Header (4096 байт):
#     0x00  Magic            "ElfFile\x00"      8 байт
#     0x08  OldestChunk      uint64             8 байт
#     0x10  CurrentChunkNum  uint64             8 байт
#     0x18  NextRecordID     uint64  ← патчим   8 байт
#     0x20  HeaderSize       uint32             4 байт
#     ...
#     0x78  HeaderCRC32      uint32             4 байт  (байты 0..119)
#
#   Chunk Header (512 байт):
#     0x00  Magic                  "ElfChnk\x00"  8 байт
#     0x08  FirstEventRecordNum    uint64  ← патчим
#     0x10  LastEventRecordNum     uint64  ← патчим
#     0x18  FirstEventRecordID     uint64  ← патчим
#     0x20  LastEventRecordID      uint64  ← патчим
#     ...
#     0x78  HeaderCRC32            uint32         4 байт
#     0x7C  DataCRC32              uint32         4 байт
#
#   Event Record:
#     0x00  Magic        \x2a\x2a\x00\x00   4 байт
#     0x04  Size         uint32             4 байт
#     0x08  RecordID     uint64  ← патчим   8 байт
#     0x10  Timestamp    uint64             8 байт
#     ...
#     [Size-4]  SizeCopy uint32             4 байт
#
# Зависимости:
#   • utils/checksum.py  — для пересчёта CRC32 после патча
#   • stdlib only        — struct, pathlib, dataclasses, logging
# ==============================================================================

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

log = logging.getLogger(__name__)

# ── Константы формата EVTX ────────────────────────────────────────────────────

FILE_MAGIC        = b"ElfFile\x00"
CHUNK_MAGIC       = b"ElfChnk\x00"
RECORD_MAGIC      = b"\x2a\x2a\x00\x00"

FILE_HEADER_SIZE  = 4096          # байт
CHUNK_SIZE        = 65536         # байт
CHUNK_HEADER_SIZE = 512           # байт
RECORD_HDR_SIZE   = 24            # байт (magic+size+id+timestamp)

# Оффсеты в File Header
FH_OLDEST_CHUNK   = 0x08
FH_CURRENT_CHUNK  = 0x10
FH_NEXT_RECORD_ID = 0x18
FH_HEADER_CRC32   = 0x78

# Оффсеты в Chunk Header (относительно начала чанка)
CH_FIRST_REC_NUM  = 0x08
CH_LAST_REC_NUM   = 0x10
CH_FIRST_REC_ID   = 0x18
CH_LAST_REC_ID    = 0x20
CH_HEADER_CRC32   = 0x78
CH_DATA_CRC32     = 0x7C

# Оффсеты в Event Record (относительно начала записи)
ER_SIZE           = 0x04
ER_RECORD_ID      = 0x08
ER_TIMESTAMP      = 0x10


# ── Dataclasses ───────────────────────────────────────────────────────────────

@dataclass
class RecordInfo:
    """Информация об одной Event Record внутри чанка."""
    chunk_index:    int          # порядковый номер чанка (0-based)
    chunk_offset:   int          # абсолютный offset начала чанка в файле
    record_offset:  int          # абсолютный offset начала записи в файле
    record_size:    int          # размер записи в байтах (из поля Size)
    record_id:      int          # текущий EventRecordID


@dataclass
class ChunkInfo:
    """Метаданные одного чанка."""
    index:          int
    file_offset:    int          # абсолютный offset начала чанка
    first_rec_num:  int          # из chunk header: FirstEventRecordNum
    last_rec_num:   int          # из chunk header: LastEventRecordNum
    first_rec_id:   int          # из chunk header: FirstEventRecordID
    last_rec_id:    int          # из chunk header: LastEventRecordID
    records:        list[RecordInfo] = field(default_factory=list)


@dataclass
class EvtxMap:
    """Полная карта файла: все чанки и все записи."""
    path:           Path
    next_record_id: int          # из File Header
    chunks:         list[ChunkInfo] = field(default_factory=list)

    @property
    def all_records(self) -> list[RecordInfo]:
        """Плоский список всех записей по порядку чанков."""
        result: list[RecordInfo] = []
        for chunk in self.chunks:
            result.extend(chunk.records)
        return result

    @property
    def record_ids(self) -> list[int]:
        return [r.record_id for r in self.all_records]


@dataclass
class GapReport:
    """Отчёт о пропусках в EventRecordID."""
    gaps:        list[tuple[int, int]]   # список (expected_id, found_id)
    duplicates:  list[int]               # дублирующиеся ID
    total_gaps:  int
    is_clean:    bool


# ── Парсинг ───────────────────────────────────────────────────────────────────

def _read_file_header(data: bytes) -> dict:
    """Распарсить File Header и вернуть словарь полей."""
    if data[:8] != FILE_MAGIC:
        raise ValueError(
            f"Неверный File Magic: {data[:8]!r}, ожидалось {FILE_MAGIC!r}"
        )
    oldest_chunk, current_chunk, next_record_id = struct.unpack_from(
        "<QQQ", data, FH_OLDEST_CHUNK
    )
    header_crc32 = struct.unpack_from("<I", data, FH_HEADER_CRC32)[0]

    return {
        "oldest_chunk":   oldest_chunk,
        "current_chunk":  current_chunk,
        "next_record_id": next_record_id,
        "header_crc32":   header_crc32,
    }


def _read_chunk_header(chunk_data: bytes, chunk_index: int) -> ChunkInfo:
    """Распарсить заголовок чанка."""
    if chunk_data[:8] != CHUNK_MAGIC:
        raise ValueError(
            f"Чанк {chunk_index}: неверный magic {chunk_data[:8]!r}"
        )
    first_rec_num, last_rec_num, first_rec_id, last_rec_id = (
        struct.unpack_from("<QQQQ", chunk_data, CH_FIRST_REC_NUM)
    )
    return ChunkInfo(
        index=chunk_index,
        file_offset=FILE_HEADER_SIZE + chunk_index * CHUNK_SIZE,
        first_rec_num=first_rec_num,
        last_rec_num=last_rec_num,
        first_rec_id=first_rec_id,
        last_rec_id=last_rec_id,
    )


def _parse_records_in_chunk(
    chunk_data: bytes,
    chunk_info: ChunkInfo,
) -> list[RecordInfo]:
    """
    Сканировать чанк в поисках Event Records по magic \x2a\x2a\x00\x00.
    Возвращает список RecordInfo.
    """
    records: list[RecordInfo] = []
    pos = CHUNK_HEADER_SIZE  # записи начинаются после 512-байтного заголовка

    while pos < len(chunk_data) - RECORD_HDR_SIZE:
        magic = chunk_data[pos : pos + 4]
        if magic != RECORD_MAGIC:
            pos += 4
            continue

        # Читаем Size
        if pos + 8 > len(chunk_data):
            break
        rec_size = struct.unpack_from("<I", chunk_data, pos + ER_SIZE)[0]

        if rec_size < RECORD_HDR_SIZE or pos + rec_size > len(chunk_data):
            # Некорректный размер — двигаемся вперёд по 4 байта
            pos += 4
            continue

        # Проверяем копию Size в конце записи
        size_copy = struct.unpack_from("<I", chunk_data, pos + rec_size - 4)[0]
        if size_copy != rec_size:
            pos += 4
            continue

        record_id = struct.unpack_from("<Q", chunk_data, pos + ER_RECORD_ID)[0]

        records.append(
            RecordInfo(
                chunk_index=chunk_info.index,
                chunk_offset=chunk_info.file_offset,
                record_offset=chunk_info.file_offset + pos,
                record_size=rec_size,
                record_id=record_id,
            )
        )
        pos += rec_size

    return records


def build_evtx_map(evtx_path: Path) -> EvtxMap:
    """
    Прочитать .evtx файл и построить полную карту:
    File Header → все ChunkInfo → все RecordInfo.

    Args:
        evtx_path: путь к .evtx файлу (read-only на этом этапе)

    Returns:
        EvtxMap с полной структурой файла

    Raises:
        FileNotFoundError: если файл не существует
        ValueError: если magic не совпадает
    """
    if not evtx_path.exists():
        raise FileNotFoundError(f"Файл не найден: {evtx_path}")

    data = evtx_path.read_bytes()
    log.debug("Читаем EVTX: %s (%d байт)", evtx_path.name, len(data))

    fh = _read_file_header(data)
    evtx_map = EvtxMap(path=evtx_path, next_record_id=fh["next_record_id"])

    chunk_index = 0
    offset = FILE_HEADER_SIZE

    while offset + CHUNK_SIZE <= len(data):
        chunk_data = data[offset : offset + CHUNK_SIZE]

        if chunk_data[:8] != CHUNK_MAGIC:
            log.debug(
                "Offset 0x%X: не чанк (magic=%r), пропускаем",
                offset, chunk_data[:8]
            )
            offset += CHUNK_SIZE
            chunk_index += 1
            continue

        try:
            chunk_info = _read_chunk_header(chunk_data, chunk_index)
            records = _parse_records_in_chunk(chunk_data, chunk_info)
            chunk_info.records = records
            evtx_map.chunks.append(chunk_info)

            log.debug(
                "Чанк %d: %d записей, ID %d–%d",
                chunk_index,
                len(records),
                chunk_info.first_rec_id,
                chunk_info.last_rec_id,
            )
        except ValueError as exc:
            log.warning("Чанк %d: ошибка парсинга — %s", chunk_index, exc)

        offset += CHUNK_SIZE
        chunk_index += 1

    log.info(
        "EVTX карта готова: %d чанков, %d записей",
        len(evtx_map.chunks),
        len(evtx_map.all_records),
    )
    return evtx_map


# ── Анализ пропусков ──────────────────────────────────────────────────────────

def find_gaps(evtx_map: EvtxMap) -> GapReport:
    """
    Найти пропуски и дубликаты в EventRecordID.

    Логика:
      - Сортируем все ID
      - Проверяем последовательность: каждый следующий должен быть +1
      - Дубликаты: ID встречается > 1 раза

    Args:
        evtx_map: карта файла из build_evtx_map()

    Returns:
        GapReport с информацией о пропусках
    """
    ids = sorted(evtx_map.record_ids)
    if not ids:
        return GapReport(gaps=[], duplicates=[], total_gaps=0, is_clean=True)

    gaps: list[tuple[int, int]] = []
    duplicates: list[int] = []
    seen: set[int] = set()

    for i, current_id in enumerate(ids):
        if current_id in seen:
            duplicates.append(current_id)
        seen.add(current_id)

        if i > 0:
            prev_id = ids[i - 1]
            if current_id != prev_id + 1 and current_id != prev_id:
                # Пропуск: ожидали prev_id+1, нашли current_id
                gaps.append((prev_id + 1, current_id))

    total_gaps = sum(found - expected for expected, found in gaps)
    is_clean = not gaps and not duplicates

    log.info(
        "Gap-анализ: пропусков=%d (итого %d пропущенных ID), дубликатов=%d",
        len(gaps), total_gaps, len(duplicates),
    )

    return GapReport(
        gaps=gaps,
        duplicates=duplicates,
        total_gaps=total_gaps,
        is_clean=is_clean,
    )


def format_gap_report(report: GapReport, evtx_path: Path) -> str:
    """
    Сформировать читаемый текстовый отчёт о пропусках.

    Args:
        report:     результат find_gaps()
        evtx_path:  путь к файлу (для заголовка)

    Returns:
        Многострочная строка отчёта
    """
    lines: list[str] = [
        f"═══════════════════════════════════════════════",
        f"  Gap Report: {evtx_path.name}",
        f"═══════════════════════════════════════════════",
    ]

    if report.is_clean:
        lines.append("  ✓ Нумерация чистая — пропусков и дубликатов нет.")
    else:
        if report.gaps:
            lines.append(f"\n  ⚠ Пропуски EventRecordID ({len(report.gaps)}):")
            for expected, found in report.gaps:
                missing = found - expected
                lines.append(
                    f"    • Ожидался ID {expected}, найден {found} "
                    f"(пропущено {missing} записей)"
                )
        if report.duplicates:
            lines.append(f"\n  ⚠ Дублирующиеся ID ({len(report.duplicates)}):")
            for dup in report.duplicates:
                lines.append(f"    • ID {dup}")

        lines.append(
            f"\n  Итого пропущено ID: {report.total_gaps}"
        )

    lines.append("═══════════════════════════════════════════════")
    return "\n".join(lines)


# ── Перенумерация ─────────────────────────────────────────────────────────────

def renumber_records(
    evtx_path: Path,
    output_path: Path,
    start_id: int = 1,
    recalc_checksums: bool = True,
    dry_run: bool = False,
) -> EvtxMap:
    """
    Перенумеровать EventRecordID в .evtx файле последовательно,
    начиная с start_id. Обновляет:
      1. EventRecordID в каждой Event Record
      2. FirstEventRecordID / LastEventRecordID в каждом Chunk Header
      3. FirstEventRecordNum / LastEventRecordNum в каждом Chunk Header
      4. NextRecordID в File Header
      5. CRC32 (если recalc_checksums=True) — через utils/checksum.py

    Args:
        evtx_path:         исходный .evtx файл
        output_path:       куда сохранить результат
        start_id:          первый ID (по умолчанию 1)
        recalc_checksums:  пересчитать CRC32 после патча
        dry_run:           только симулировать, не писать файл

    Returns:
        Новая EvtxMap с обновлёнными данными

    Raises:
        FileNotFoundError: если evtx_path не существует
        ValueError:        если файл не валидный EVTX
    """
    # ── 1. Строим карту исходного файла ──────────────────────────────────────
    evtx_map = build_evtx_map(evtx_path)
    all_records = evtx_map.all_records

    if not all_records:
        log.warning("В файле нет записей — нечего перенумеровывать.")
        return evtx_map

    log.info(
        "Перенумерация: %d записей, start_id=%d, dry_run=%s",
        len(all_records), start_id, dry_run,
    )

    # ── 2. Загружаем байты в bytearray ───────────────────────────────────────
    data = bytearray(evtx_path.read_bytes())

    # ── 3. Патчим EventRecordID в каждой записи ───────────────────────────────
    current_id = start_id
    for record in all_records:
        offset = record.record_offset + ER_RECORD_ID
        struct.pack_into("<Q", data, offset, current_id)
        record.record_id = current_id          # обновляем in-place для маппинга
        current_id += 1

    final_last_id = current_id - 1

    # ── 4. Патчим Chunk Headers ───────────────────────────────────────────────
    for chunk in evtx_map.chunks:
        if not chunk.records:
            continue

        first_id = chunk.records[0].record_id
        last_id  = chunk.records[-1].record_id
        base     = chunk.file_offset

        # FirstEventRecordNum / LastEventRecordNum
        struct.pack_into("<Q", data, base + CH_FIRST_REC_NUM, first_id)
        struct.pack_into("<Q", data, base + CH_LAST_REC_NUM,  last_id)

        # FirstEventRecordID / LastEventRecordID
        struct.pack_into("<Q", data, base + CH_FIRST_REC_ID,  first_id)
        struct.pack_into("<Q", data, base + CH_LAST_REC_ID,   last_id)

        log.debug(
            "Чанк %d: header обновлён ID %d–%d", chunk.index, first_id, last_id
        )

    # ── 5. Патчим File Header: NextRecordID ──────────────────────────────────
    next_record_id = final_last_id + 1
    struct.pack_into("<Q", data, FH_NEXT_RECORD_ID, next_record_id)
    evtx_map.next_record_id = next_record_id
    log.debug("File Header: NextRecordID → %d", next_record_id)

    # ── 6. Пересчёт CRC32 ────────────────────────────────────────────────────
    if recalc_checksums:
        try:
            from utils.checksum import recalculate_all  # type: ignore
            data = bytearray(recalculate_all(bytes(data)))
            log.info("CRC32 пересчитан через utils/checksum.py")
        except ImportError:
            log.warning(
                "utils/checksum.py недоступен — CRC32 не пересчитан! "
                "Файл может быть невалидным для Event Viewer."
            )

    # ── 7. Запись результата ──────────────────────────────────────────────────
    if dry_run:
        log.info("dry_run=True — файл не записан. Перенумерация завершена (симуляция).")
    else:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(bytes(data))
        log.info("Результат записан: %s", output_path)

    return evtx_map


# ── Сводка по файлу ───────────────────────────────────────────────────────────

def summarize(evtx_map: EvtxMap) -> str:
    """
    Краткая текстовая сводка по EvtxMap.

    Args:
        evtx_map: карта файла

    Returns:
        Многострочная строка сводки
    """
    all_records = evtx_map.all_records
    ids = evtx_map.record_ids

    lines = [
        f"Файл:          {evtx_map.path.name}",
        f"Чанков:        {len(evtx_map.chunks)}",
        f"Записей:       {len(all_records)}",
        f"NextRecordID:  {evtx_map.next_record_id}",
    ]
    if ids:
        lines += [
            f"Первый ID:     {min(ids)}",
            f"Последний ID:  {max(ids)}",
        ]
    return "\n".join(lines)


# ── CLI точка входа (опционально) ─────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="WiperX renumber.py — анализ и перенумерация EventRecordID в .evtx"
    )
    parser.add_argument("evtx",           help="Путь к .evtx файлу")
    parser.add_argument("--output", "-o", help="Куда сохранить результат", default=None)
    parser.add_argument(
        "--start-id", "-s",
        type=int, default=1,
        help="Начальный EventRecordID (default: 1)"
    )
    parser.add_argument(
        "--dry-run", "-n",
        action="store_true",
        help="Только симулировать — не записывать файл"
    )
    parser.add_argument(
        "--gaps-only", "-g",
        action="store_true",
        help="Только показать gap-отчёт, без перенумерации"
    )
    parser.add_argument(
        "--no-crc", action="store_true",
        help="Не пересчитывать CRC32 (опасно, только для тестов)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Подробный вывод (DEBUG)"
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s  %(message)s",
    )

    evtx_path = Path(args.evtx)

    try:
        evtx_map = build_evtx_map(evtx_path)
    except (FileNotFoundError, ValueError) as e:
        print(f"[ОШИБКА] {e}", file=sys.stderr)
        sys.exit(1)

    print(summarize(evtx_map))
    print()

    gap_report = find_gaps(evtx_map)
    print(format_gap_report(gap_report, evtx_path))

    if args.gaps_only:
        sys.exit(0)

    output = Path(args.output) if args.output else evtx_path.with_suffix(".renumbered.evtx")

    renumber_records(
        evtx_path=evtx_path,
        output_path=output,
        start_id=args.start_id,
        recalc_checksums=not args.no_crc,
        dry_run=args.dry_run,
    )
