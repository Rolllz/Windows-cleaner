# ==============================================================================
# WiperX — src/modules/evtx_processor.py
#
# Модуль обработки .evtx файлов (Windows Event Logs).
#
# Возможности:
#   • Парсинг .evtx через PyEvtxParser (pyevtx-rs / import evtx)
#   • Фильтрация записей по EventID, Source, TimeCreated
#   • Удаление записей по критериям (forensics: selective log wiping)
#   • Очистка всего лога (полный вайп)
#   • Перезапись EventRecordID через utils/renumber.py
#   • Пересчёт CRC32 через utils/checksum.py
#   • Детектирование признаков тампинга (gap-анализ)
#   • Экспорт в XML / JSON для отчётов
#
# Зависимости:
#   • evtx (pyevtx-rs) — pip install pyevtx-rs
#   • utils.checksum   — внутренний модуль WiperX
#   • utils.renumber   — внутренний модуль WiperX
#   • config           — пути и константы
#
# Импорт: import evtx  ←  PyPi-имя: pyevtx-rs
# ==============================================================================

from __future__ import annotations

import json
import logging
import shutil
import struct
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Iterator, List, Optional

# pyevtx-rs: на PyPi называется pyevtx-rs, импортируется как evtx
try:
    from evtx import PyEvtxParser
    EVTX_AVAILABLE = True
except ImportError:
    EVTX_AVAILABLE = False

from config import Config
from utils.checksum import repair_evtx_checksums, validate_evtx_checksums
from utils.renumber import renumber_event_records, scan_record_ids

logger = logging.getLogger(__name__)


# ==============================================================================
# Константы
# ==============================================================================

EVTX_MAGIC       = b"ElfFile\x00"
CHUNK_MAGIC      = b"ElfChnk\x00"
EVTX_HEADER_SIZE = 4096
CHUNK_SIZE       = 65536

# Теги XML EventRecord
NS_EVTX = "http://schemas.microsoft.com/win/2004/08/events/event"


# ==============================================================================
# Датаклассы
# ==============================================================================

@dataclass
class EvtxRecord:
    """Представление одной записи EventLog."""
    event_record_id: int
    timestamp:       datetime
    event_id:        int
    level:           int               # 0=Verbose,1=Critical,2=Error,3=Warning,4=Info
    channel:         str
    computer:        str
    provider:        str
    raw_xml:         str
    raw_data:        bytes = field(default=b"", repr=False)

    @property
    def level_name(self) -> str:
        return {0: "Verbose", 1: "Critical", 2: "Error",
                3: "Warning", 4: "Information"}.get(self.level, "Unknown")


@dataclass
class EvtxScanResult:
    """Результат сканирования .evtx файла."""
    path:             Path
    total_records:    int               = 0
    total_chunks:     int               = 0
    id_gaps:          List[int]         = field(default_factory=list)
    crc_errors:       List[int]         = field(default_factory=list)  # chunk index
    tamper_suspected: bool              = False
    records:          List[EvtxRecord]  = field(default_factory=list)


@dataclass
class EvtxWipeResult:
    """Результат операции вайпа .evtx файла."""
    path:          Path
    success:       bool
    records_wiped: int   = 0
    method:        str   = ""   # "full_clear" | "selective" | "zeroed"
    error:         str   = ""


# ==============================================================================
# Вспомогательные функции
# ==============================================================================

def _parse_xml_record(raw_xml: str) -> Optional[EvtxRecord]:
    """
    Парсит XML-строку записи EVTX в EvtxRecord.
    Возвращает None при ошибке парсинга.
    """
    try:
        root = ET.fromstring(raw_xml)
        ns   = {"e": NS_EVTX}

        def find(path: str) -> Optional[ET.Element]:
            return root.find(path, ns)

        sys_node = find("e:System")
        if sys_node is None:
            return None

        # EventRecordID
        rec_id_node = sys_node.find("e:EventRecordID", ns)
        record_id   = int(rec_id_node.text) if rec_id_node is not None else 0

        # TimeCreated
        tc_node   = sys_node.find("e:TimeCreated", ns)
        ts_str    = tc_node.attrib.get("SystemTime", "") if tc_node is not None else ""
        timestamp = _parse_timestamp(ts_str)

        # EventID
        eid_node = sys_node.find("e:EventID", ns)
        event_id = int(eid_node.text) if eid_node is not None else 0

        # Level
        lvl_node = sys_node.find("e:Level", ns)
        level    = int(lvl_node.text) if lvl_node is not None else 0

        # Channel
        ch_node = sys_node.find("e:Channel", ns)
        channel = ch_node.text if ch_node is not None else ""

        # Computer
        comp_node = sys_node.find("e:Computer", ns)
        computer  = comp_node.text if comp_node is not None else ""

        # Provider
        prov_node = sys_node.find("e:Provider", ns)
        provider  = (prov_node.attrib.get("Name", "") or
                     prov_node.attrib.get("Guid", "")) if prov_node is not None else ""

        return EvtxRecord(
            event_record_id = record_id,
            timestamp       = timestamp,
            event_id        = event_id,
            level           = level,
            channel         = channel,
            computer        = computer,
            provider        = provider,
            raw_xml         = raw_xml,
        )

    except ET.ParseError as exc:
        logger.debug("XML parse error: %s", exc)
        return None


def _parse_timestamp(ts: str) -> datetime:
    """Парсит ISO-8601 timestamp из EVTX System/TimeCreated."""
    if not ts:
        return datetime.min
    ts = ts.rstrip("Z").split(".")[0]
    try:
        return datetime.fromisoformat(ts)
    except ValueError:
        return datetime.min


def _count_chunks(data: bytes) -> int:
    """Считает количество корректных чанков в бинарном образе EVTX."""
    count = 0
    offset = EVTX_HEADER_SIZE
    while offset + CHUNK_SIZE <= len(data):
        if data[offset:offset + 8] == CHUNK_MAGIC:
            count += 1
        offset += CHUNK_SIZE
    return count


# ==============================================================================
# Основной класс
# ==============================================================================

class EvtxProcessor:
    """
    Высокоуровневый процессор .evtx файлов для WiperX.

    Использование:
        proc = EvtxProcessor(config)

        # Сканирование
        result = proc.scan("/path/to/Security.evtx")

        # Полная очистка
        proc.wipe_full("/path/to/Security.evtx")

        # Избирательное удаление по EventID
        proc.wipe_selective(
            "/path/to/Security.evtx",
            filter_fn=lambda r: r.event_id in {4624, 4625, 4648}
        )
    """

    def __init__(self, config: Config) -> None:
        self.config = config
        self._check_dependencies()

    # ------------------------------------------------------------------
    # Зависимости
    # ------------------------------------------------------------------

    @staticmethod
    def _check_dependencies() -> None:
        if not EVTX_AVAILABLE:
            raise ImportError(
                "pyevtx-rs не установлен.\n"
                "  pip install pyevtx-rs\n"
                "  или: pip install --find-links packages/whl pyevtx-rs"
            )

    # ------------------------------------------------------------------
    # Парсинг
    # ------------------------------------------------------------------

    def parse_records(
        self,
        evtx_path: str | Path,
        as_json: bool = False,
    ) -> Iterator[EvtxRecord]:
        """
        Итерирует все записи .evtx файла.

        Args:
            evtx_path: Путь к .evtx файлу.
            as_json:   Использовать records_json() вместо records().
                       JSON быстрее для больших файлов, XML — точнее для парсинга.

        Yields:
            EvtxRecord для каждой корректной записи.
        """
        path = Path(evtx_path)
        if not path.exists():
            raise FileNotFoundError(f"EVTX не найден: {path}")

        logger.info("Парсинг: %s", path.name)

        parser = PyEvtxParser(str(path))

        if as_json:
            for raw in parser.records_json():
                # raw["data"] содержит JSON-строку
                try:
                    data = json.loads(raw["data"])
                    yield self._record_from_json(raw["event_record_id"], data)
                except (json.JSONDecodeError, KeyError):
                    continue
        else:
            for raw in parser.records():
                record = _parse_xml_record(raw["data"])
                if record:
                    yield record

    def _record_from_json(self, record_id: int, data: dict) -> EvtxRecord:
        """Конструирует EvtxRecord из JSON-представления pyevtx-rs."""
        try:
            sys_  = data.get("Event", {}).get("System", {})
            event_id  = int(sys_.get("EventID", {}).get("#text", 0)
                            if isinstance(sys_.get("EventID"), dict)
                            else sys_.get("EventID", 0))
            level     = int(sys_.get("Level", 0))
            channel   = sys_.get("Channel", "")
            computer  = sys_.get("Computer", "")
            provider  = (sys_.get("Provider", {}).get("@Name", "")
                         if isinstance(sys_.get("Provider"), dict) else "")
            ts_str    = (sys_.get("TimeCreated", {}).get("@SystemTime", "")
                         if isinstance(sys_.get("TimeCreated"), dict) else "")
            timestamp = _parse_timestamp(ts_str)
        except (TypeError, ValueError):
            event_id = level = 0
            channel = computer = provider = ""
            timestamp = datetime.min

        return EvtxRecord(
            event_record_id = record_id,
            timestamp       = timestamp,
            event_id        = event_id,
            level           = level,
            channel         = channel,
            computer        = computer,
            provider        = provider,
            raw_xml         = json.dumps(data),
        )

    # ------------------------------------------------------------------
    # Сканирование / детектирование тампинга
    # ------------------------------------------------------------------

    def scan(
        self,
        evtx_path: str | Path,
        load_records: bool = True,
    ) -> EvtxScanResult:
        """
        Сканирует .evtx файл: считает записи, чанки, ищет gap-ы и CRC-ошибки.

        Args:
            evtx_path:    Путь к файлу.
            load_records: Загружать ли все записи в EvtxScanResult.records.

        Returns:
            EvtxScanResult с полным отчётом.
        """
        path   = Path(evtx_path)
        result = EvtxScanResult(path=path)

        # --- Бинарный анализ ---
        raw = path.read_bytes()
        if raw[:8] != EVTX_MAGIC:
            logger.warning("%s — не валидный EVTX (нет магика)", path.name)
            return result

        result.total_chunks = _count_chunks(raw)

        # --- CRC32 валидация ---
        crc_report = validate_evtx_checksums(path)
        result.crc_errors = crc_report.get("bad_chunks", [])

        # --- Парсинг записей ---
        records = list(self.parse_records(path))
        result.total_records = len(records)

        if load_records:
            result.records = records

        # --- Gap-анализ ---
        if records:
            ids = sorted(r.event_record_id for r in records)
            gap_report = scan_record_ids(ids)
            result.id_gaps = gap_report.get("gaps", [])

        # --- Детектирование тампинга ---
        result.tamper_suspected = bool(result.id_gaps or result.crc_errors)

        if result.tamper_suspected:
            logger.warning(
                "%s — признаки тампинга: gaps=%d, crc_errors=%d",
                path.name, len(result.id_gaps), len(result.crc_errors)
            )

        return result

    # ------------------------------------------------------------------
    # Фильтрация
    # ------------------------------------------------------------------

    def filter_records(
        self,
        evtx_path: str | Path,
        filter_fn: Callable[[EvtxRecord], bool],
    ) -> List[EvtxRecord]:
        """
        Возвращает записи, для которых filter_fn(record) == True.

        Пример — все ошибки входа:
            proc.filter_records(path, lambda r: r.event_id == 4625)
        """
        return [r for r in self.parse_records(evtx_path) if filter_fn(r)]

    # ------------------------------------------------------------------
    # Вайп: полная очистка
    # ------------------------------------------------------------------

    def wipe_full(
        self,
        evtx_path: str | Path,
        backup: bool = True,
    ) -> EvtxWipeResult:
        """
        Полностью очищает .evtx файл:
          1. Обнуляет все данные после File Header
          2. Сбрасывает счётчики в File Header
          3. Пересчитывает CRC32 заголовка

        Args:
            evtx_path: Путь к файлу.
            backup:    Создать .bak копию перед вайпом.

        Returns:
            EvtxWipeResult
        """
        path = Path(evtx_path)
        result = EvtxWipeResult(path=path, success=False, method="full_clear")

        try:
            if backup:
                shutil.copy2(path, path.with_suffix(".evtx.bak"))
                logger.info("Backup: %s", path.with_suffix(".evtx.bak"))

            data = bytearray(path.read_bytes())

            if data[:8] != EVTX_MAGIC:
                result.error = "Не валидный EVTX (нет магика)"
                return result

            # Считаем записи ДО вайпа
            pre_count = len(list(self.parse_records(path)))

            # Обнуляем всё после заголовка
            data[EVTX_HEADER_SIZE:] = b"\x00" * (len(data) - EVTX_HEADER_SIZE)

            # Сбрасываем счётчики в File Header
            #   offset 0x18 (24): OldestChunkNumber  → 0
            #   offset 0x20 (32): CurrentChunkNumber → 0
            #   offset 0x28 (40): NextRecordNumber   → 1
            struct.pack_into("<Q", data, 0x18, 0)
            struct.pack_into("<Q", data, 0x20, 0)
            struct.pack_into("<Q", data, 0x28, 1)

            path.write_bytes(bytes(data))

            # Пересчёт CRC
            repair_evtx_checksums(path)

            result.success       = True
            result.records_wiped = pre_count
            logger.info("Полный вайп %s: удалено %d записей", path.name, pre_count)

        except (OSError, struct.error) as exc:
            result.error = str(exc)
            logger.error("wipe_full error [%s]: %s", path.name, exc)

        return result

    # ------------------------------------------------------------------
    # Вайп: избирательное удаление
    # ------------------------------------------------------------------

    def wipe_selective(
        self,
        evtx_path: str | Path,
        filter_fn: Callable[[EvtxRecord], bool],
        backup: bool = True,
        renumber: bool = True,
    ) -> EvtxWipeResult:
        """
        Избирательно удаляет записи, соответствующие filter_fn.

        Алгоритм:
          1. Парсим все записи → XML
          2. Исключаем записи, где filter_fn(r) == True
          3. Пересобираем .evtx через временный файл
             (нативный формат: обнуляем чанки → записываем оставшиеся)
          4. Если renumber=True — перенумеруем EventRecordID
          5. Пересчитываем CRC32

        ⚠️  Примечание: пересборка .evtx бинарно нетривиальна.
            Текущая реализация использует "zeroing" подход —
            обнуляет binary offset удалённых записей в чанках.
            Для production-grade пересборки см. utils/renumber.py.

        Args:
            evtx_path: Путь к файлу.
            filter_fn: Функция-предикат: True = удалить запись.
            backup:    Создать .bak копию.
            renumber:  Перенумеровать ID после удаления.

        Returns:
            EvtxWipeResult
        """
        path = Path(evtx_path)
        result = EvtxWipeResult(path=path, success=False, method="selective")

        try:
            if backup:
                shutil.copy2(path, path.with_suffix(".evtx.bak"))

            # Собираем записи на удаление
            to_delete = self.filter_records(path, filter_fn)
            if not to_delete:
                logger.info("Нет записей для удаления: %s", path.name)
                result.success = True
                return result

            delete_ids = {r.event_record_id for r in to_delete}
            logger.info(
                "Selective wipe %s: удаляем %d записей (IDs: %s...)",
                path.name, len(delete_ids),
                str(sorted(delete_ids)[:5])
            )

            # Бинарная работа: обнуляем записи в чанках
            wiped = self._zero_records_in_chunks(path, delete_ids)

            # Перенумерация и CRC
            if renumber:
                renumber_event_records(path)
            repair_evtx_checksums(path)

            result.success       = True
            result.records_wiped = wiped
            logger.info("Selective wipe завершён: удалено %d записей", wiped)

        except (OSError, struct.error) as exc:
            result.error = str(exc)
            logger.error("wipe_selective error [%s]: %s", path.name, exc)

        return result

    # ------------------------------------------------------------------
    # Внутренний: обнуление записей в чанках
    # ------------------------------------------------------------------

    @staticmethod
    def _zero_records_in_chunks(
        path: Path,
        delete_ids: set[int],
    ) -> int:
        """
        Обходит все чанки EVTX, находит записи по EventRecordID
        и обнуляет их байты.

        Структура BinXml-записи в чанке:
          offset+0x00 : magic "**\x00\x00" (0x00002A2A)  — 4 байта
          offset+0x04 : size                              — 4 байта
          offset+0x08 : EventRecordID                     — 8 байт
          offset+0x10 : timestamp                         — 8 байт
          offset+0x18 : BinXml data...
          offset+size-4: copy of size                     — 4 байта

        Returns:
            Количество обнулённых записей.
        """
        RECORD_MAGIC = b"\x2a\x2a\x00\x00"
        data  = bytearray(path.read_bytes())
        wiped = 0

        chunk_offset = EVTX_HEADER_SIZE
        while chunk_offset + CHUNK_SIZE <= len(data):
            if data[chunk_offset:chunk_offset + 8] != CHUNK_MAGIC:
                chunk_offset += CHUNK_SIZE
                continue

            # Данные записей начинаются с offset 512 внутри чанка
            rec_offset = chunk_offset + 512
            chunk_end  = chunk_offset + CHUNK_SIZE

            while rec_offset + 24 < chunk_end:
                if data[rec_offset:rec_offset + 4] != RECORD_MAGIC:
                    rec_offset += 4
                    continue

                rec_size = struct.unpack_from("<I", data, rec_offset + 4)[0]
                if rec_size < 24 or rec_offset + rec_size > chunk_end:
                    rec_offset += 4
                    continue

                rec_id = struct.unpack_from("<Q", data, rec_offset + 8)[0]

                if rec_id in delete_ids:
                    # Обнуляем тело записи (сохраняем размер для навигации)
                    data[rec_offset:rec_offset + rec_size] = b"\x00" * rec_size
                    wiped += 1

                rec_offset += rec_size

            chunk_offset += CHUNK_SIZE

        path.write_bytes(bytes(data))
        return wiped

    # ------------------------------------------------------------------
    # Экспорт
    # ------------------------------------------------------------------

    def export_xml(
        self,
        evtx_path: str | Path,
        output_path: str | Path,
        filter_fn: Optional[Callable[[EvtxRecord], bool]] = None,
    ) -> int:
        """
        Экспортирует записи в XML-файл.

        Args:
            evtx_path:   Источник.
            output_path: Файл назначения.
            filter_fn:   Опциональный фильтр.

        Returns:
            Количество экспортированных записей.
        """
        output = Path(output_path)
        count  = 0

        with output.open("w", encoding="utf-8") as fh:
            fh.write('<?xml version="1.0" encoding="utf-8"?>\n<Events>\n')
            for record in self.parse_records(evtx_path):
                if filter_fn is None or filter_fn(record):
                    fh.write(record.raw_xml)
                    fh.write("\n")
                    count += 1
            fh.write("</Events>\n")

        logger.info("XML export: %d записей → %s", count, output.name)
        return count

    def export_json(
        self,
        evtx_path: str | Path,
        output_path: str | Path,
        filter_fn: Optional[Callable[[EvtxRecord], bool]] = None,
    ) -> int:
        """
        Экспортирует записи в JSON-файл (массив объектов).

        Returns:
            Количество экспортированных записей.
        """
        output  = Path(output_path)
        records = []

        for record in self.parse_records(evtx_path, as_json=True):
            if filter_fn is None or filter_fn(record):
                records.append({
                    "event_record_id": record.event_record_id,
                    "timestamp":       record.timestamp.isoformat(),
                    "event_id":        record.event_id,
                    "level":           record.level_name,
                    "channel":         record.channel,
                    "computer":        record.computer,
                    "provider":        record.provider,
                })

        output.write_text(
            json.dumps(records, ensure_ascii=False, indent=2),
            encoding="utf-8"
        )

        logger.info("JSON export: %d записей → %s", len(records), output.name)
        return len(records)


# ==============================================================================
# CLI / быстрый тест
# ==============================================================================

if __name__ == "__main__":
    import sys
    from config import Config

    logging.basicConfig(
        level   = logging.DEBUG,
        format  = "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    if len(sys.argv) < 2:
        print("Использование: python evtx_processor.py <path.evtx> [scan|wipe|export]")
        sys.exit(1)

    target = Path(sys.argv[1])
    action = sys.argv[2] if len(sys.argv) > 2 else "scan"
    config = Config()
    proc   = EvtxProcessor(config)

    if action == "scan":
        res = proc.scan(target, load_records=False)
        print(f"\n{'='*50}")
        print(f"  Файл:     {res.path.name}")
        print(f"  Чанки:    {res.total_chunks}")
        print(f"  Записи:   {res.total_records}")
        print(f"  Gap-ы:    {len(res.id_gaps)}")
        print(f"  CRC ошиб: {len(res.crc_errors)}")
        print(f"  Тампинг:  {'⚠️  ДА' if res.tamper_suspected else '✅ НЕТ'}")
        print(f"{'='*50}\n")

    elif action == "wipe":
        res = proc.wipe_full(target, backup=True)
        print(f"Вайп: {'OK' if res.success else 'ОШИБКА'} | "
              f"удалено {res.records_wiped} записей")
        if res.error:
            print(f"Ошибка: {res.error}")

    elif action == "export":
        out = target.with_suffix(".xml")
        n   = proc.export_xml(target, out)
        print(f"Экспорт: {n} записей → {out}")

    else:
        print(f"Неизвестное действие: {action}")
        sys.exit(1)
