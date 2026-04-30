# ==============================================================================
# WiperX — src/modules/lnk.py
#
# Модуль обработки Windows Shortcut файлов (.lnk).
#
# Возможности:
#   • Парсинг .lnk файлов через LnkParse3
#   • Извлечение метаданных: target path, timestamps, volume info,
#     machine ID, drive type, drive serial, network share
#   • Извлечение данных Shell Link Header (file attributes, flags)
#   • Поиск .lnk файлов по критериям (target path, machine ID, дата)
#   • Удаление .lnk файлов по критериям
#   • Полная очистка директорий Recent / Desktop / SendTo
#   • Перезапись / фальсификация метаданных (timestamps, target path)
#   • Secure wipe (перезапись перед удалением)
#   • Детектирование признаков тампинга
#   • Экспорт метаданных в JSON / CSV для отчётов
#
# Зависимости:
#   • LnkParse3   — pip install LnkParse3
#   • config      — пути и константы WiperX
#
# Стандартные пути .lnk:
#   %APPDATA%\Microsoft\Windows\Recent\
#   %APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\
#   %APPDATA%\Microsoft\Windows\Recent\CustomDestinations\
#   %USERPROFILE%\Desktop\
# ==============================================================================

from __future__ import annotations

import os
import json
import struct
import shutil
import logging
import csv
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

import LnkParse3

from config import (
    LNK_RECENT_PATH,
    LNK_DESKTOP_PATH,
    LNK_SENDTO_PATH,
    LNK_AUTODEST_PATH,
    LNK_CUSTOMDEST_PATH,
    SECURE_WIPE_PASSES,
    LOG_LEVEL,
    EXPORT_DIR,
)

# ==============================================================================
# Логирование
# ==============================================================================

logging.basicConfig(level=getattr(logging, LOG_LEVEL, logging.INFO))
logger = logging.getLogger("wiperx.lnk")


# ==============================================================================
# Вспомогательные функции
# ==============================================================================

def _secure_wipe(path: Path, passes: int = 3) -> None:
    """
    Перезаписывает файл случайными байтами перед удалением.
    Снижает вероятность восстановления через forensics-инструменты.
    """
    try:
        size = path.stat().st_size
        with open(path, "r+b") as f:
            for _ in range(passes):
                f.seek(0)
                f.write(os.urandom(size))
                f.flush()
                os.fsync(f.fileno())
        path.unlink()
        logger.debug(f"[WIPE] Secure wiped: {path}")
    except Exception as e:
        logger.warning(f"[WIPE] Failed to wipe {path}: {e}")


def _parse_lnk(path: Path) -> Optional[dict]:
    """
    Парсит .lnk файл и возвращает словарь с метаданными.
    Возвращает None при ошибке парсинга.
    """
    try:
        with open(path, "rb") as f:
            lnk = LnkParse3.lnk_file(f)
            data = lnk.get_json()

        # Нормализуем в dict если get_json() вернул строку
        if isinstance(data, str):
            data = json.loads(data)

        data["__source_path__"] = str(path)
        return data

    except Exception as e:
        logger.warning(f"[PARSE] Failed to parse {path}: {e}")
        return None


def _extract_meta(lnk_data: dict) -> dict:
    """
    Извлекает ключевые forensics-артефакты из распарсенного .lnk.
    """
    header = lnk_data.get("header", {})
    link_info = lnk_data.get("link_info", {})
    string_data = lnk_data.get("string_data", {})
    extra_data = lnk_data.get("extra_data", {})

    return {
        "source_path":      lnk_data.get("__source_path__"),
        "target_path":      string_data.get("local_path")
                            or link_info.get("local_base_path"),
        "network_share":    link_info.get("net_name"),
        "drive_type":       link_info.get("drive_type"),
        "drive_serial":     link_info.get("drive_serial_number"),
        "volume_label":     link_info.get("volume_label"),
        "creation_time":    header.get("creation_time"),
        "access_time":      header.get("access_time"),
        "write_time":       header.get("write_time"),
        "file_size":        header.get("file_size"),
        "file_attributes":  header.get("file_attributes"),
        "machine_id":       extra_data.get("machine_id"),
        "mac_address":      extra_data.get("mac_address"),
        "relative_path":    string_data.get("relative_path"),
        "working_dir":      string_data.get("working_directory"),
        "arguments":        string_data.get("command_line_arguments"),
        "icon_location":    string_data.get("icon_location"),
    }


def _hash_file(path: Path) -> str:
    """SHA-256 хэш файла для идентификации и дедупликации."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ==============================================================================
# Сканирование
# ==============================================================================

def scan_directory(directory: Path) -> list[dict]:
    """
    Рекурсивно сканирует директорию на .lnk файлы.
    Возвращает список распарсенных метаданных.
    """
    results = []
    if not directory.exists():
        logger.warning(f"[SCAN] Directory not found: {directory}")
        return results

    lnk_files = list(directory.rglob("*.lnk"))
    logger.info(f"[SCAN] Found {len(lnk_files)} .lnk files in {directory}")

    for lnk_path in lnk_files:
        data = _parse_lnk(lnk_path)
        if data:
            meta = _extract_meta(data)
            meta["sha256"] = _hash_file(lnk_path)
            results.append(meta)
            logger.debug(f"[SCAN] Parsed: {lnk_path.name} → {meta['target_path']}")

    return results


def scan_all_lnk_dirs() -> list[dict]:
    """
    Сканирует все стандартные директории .lnk:
      - Recent
      - Desktop
      - SendTo
      - AutomaticDestinations
      - CustomDestinations
    """
    all_results = []
    for directory in [
        LNK_RECENT_PATH,
        LNK_DESKTOP_PATH,
        LNK_SENDTO_PATH,
        LNK_AUTODEST_PATH,
        LNK_CUSTOMDEST_PATH,
    ]:
        all_results.extend(scan_directory(Path(directory)))

    logger.info(f"[SCAN] Total .lnk artifacts found: {len(all_results)}")
    return all_results


# ==============================================================================
# Фильтрация
# ==============================================================================

def filter_by_target(
    records: list[dict],
    keyword: str,
    case_sensitive: bool = False,
) -> list[dict]:
    """
    Фильтрует записи по подстроке в target_path.
    """
    if not case_sensitive:
        keyword = keyword.lower()
    return [
        r for r in records
        if r.get("target_path") and (
            keyword in (r["target_path"].lower() if not case_sensitive else r["target_path"])
        )
    ]


def filter_by_machine_id(records: list[dict], machine_id: str) -> list[dict]:
    """
    Фильтрует записи по machine_id (Extra Data → TrackerDataBlock).
    """
    return [
        r for r in records
        if r.get("machine_id", "").lower() == machine_id.lower()
    ]


def filter_by_date_range(
    records: list[dict],
    field: str,
    start: datetime,
    end: datetime,
) -> list[dict]:
    """
    Фильтрует записи по диапазону дат.
    field: 'creation_time' | 'access_time' | 'write_time'
    """
    filtered = []
    for r in records:
        raw = r.get(field)
        if not raw:
            continue
        try:
            # LnkParse3 возвращает строки ISO или datetime
            if isinstance(raw, str):
                dt = datetime.fromisoformat(raw)
            else:
                dt = raw
            if start <= dt.replace(tzinfo=None) <= end:
                filtered.append(r)
        except Exception as e:
            logger.debug(f"[FILTER] Date parse error for {r.get('source_path')}: {e}")
    return filtered


# ==============================================================================
# Удаление
# ==============================================================================

def delete_lnk(path: Path, secure: bool = True) -> bool:
    """
    Удаляет один .lnk файл.
    secure=True → перезапись перед удалением.
    """
    if not path.exists():
        logger.warning(f"[DELETE] File not found: {path}")
        return False
    try:
        if secure:
            _secure_wipe(path, passes=SECURE_WIPE_PASSES)
        else:
            path.unlink()
        logger.info(f"[DELETE] Deleted: {path}")
        return True
    except Exception as e:
        logger.error(f"[DELETE] Failed to delete {path}: {e}")
        return False


def delete_by_criteria(
    records: list[dict],
    secure: bool = True,
) -> dict:
    """
    Удаляет все .lnk файлы из переданного списка записей.
    Возвращает статистику: deleted / failed.
    """
    stats = {"deleted": 0, "failed": 0, "paths": []}

    for record in records:
        src = record.get("source_path")
        if not src:
            continue
        path = Path(src)
        if delete_lnk(path, secure=secure):
            stats["deleted"] += 1
            stats["paths"].append(str(path))
        else:
            stats["failed"] += 1

    logger.info(
        f"[DELETE] Done — deleted: {stats['deleted']}, failed: {stats['failed']}"
    )
    return stats


def wipe_directory(directory: Path, secure: bool = True) -> dict:
    """
    Полностью очищает директорию от .lnk файлов.
    Не удаляет саму директорию.
    """
    stats = {"deleted": 0, "failed": 0, "paths": []}
    if not directory.exists():
        logger.warning(f"[WIPE_DIR] Directory not found: {directory}")
        return stats

    for lnk_path in directory.rglob("*.lnk"):
        if delete_lnk(lnk_path, secure=secure):
            stats["deleted"] += 1
            stats["paths"].append(str(lnk_path))
        else:
            stats["failed"] += 1

    logger.info(
        f"[WIPE_DIR] {directory} — deleted: {stats['deleted']}, failed: {stats['failed']}"
    )
    return stats


def wipe_all_recent(secure: bool = True) -> dict:
    """
    Очищает все стандартные директории Recent / Desktop / SendTo.
    """
    total = {"deleted": 0, "failed": 0, "paths": []}
    for directory in [
        LNK_RECENT_PATH,
        LNK_DESKTOP_PATH,
        LNK_SENDTO_PATH,
        LNK_AUTODEST_PATH,
        LNK_CUSTOMDEST_PATH,
    ]:
        result = wipe_directory(Path(directory), secure=secure)
        total["deleted"] += result["deleted"]
        total["failed"]  += result["failed"]
        total["paths"].extend(result["paths"])

    logger.info(
        f"[WIPE_ALL] Total — deleted: {total['deleted']}, failed: {total['failed']}"
    )
    return total


# ==============================================================================
# Фальсификация метаданных (Anti-Forensics)
# ==============================================================================

def _filetime_to_bytes(dt: datetime) -> bytes:
    """
    Конвертирует datetime → Windows FILETIME (8 байт, little-endian).
    FILETIME = количество 100-нс интервалов с 1601-01-01.
    """
    epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
    delta = dt.replace(tzinfo=timezone.utc) - epoch
    filetime = int(delta.total_seconds() * 10_000_000)
    return struct.pack("<Q", filetime)


def tamper_timestamps(
    path: Path,
    creation_time: Optional[datetime] = None,
    access_time: Optional[datetime] = None,
    write_time: Optional[datetime] = None,
) -> bool:
    """
    Перезаписывает временны́е метки в Shell Link Header .lnk файла.

    Shell Link Header layout (76 bytes total):
      Offset 0x00: HeaderSize (4 bytes) = 0x4C
      Offset 0x04: LinkCLSID (16 bytes)
      Offset 0x14: LinkFlags (4 bytes)
      Offset 0x18: FileAttributes (4 bytes)
      Offset 0x1C: CreationTime (8 bytes) ← FILETIME
      Offset 0x24: AccessTime (8 bytes)   ← FILETIME
      Offset 0x2C: WriteTime (8 bytes)    ← FILETIME
    """
    CREATION_OFFSET = 0x1C
    ACCESS_OFFSET   = 0x24
    WRITE_OFFSET    = 0x2C

    try:
        with open(path, "r+b") as f:
            if creation_time:
                f.seek(CREATION_OFFSET)
                f.write(_filetime_to_bytes(creation_time))
                logger.debug(f"[TAMPER] CreationTime → {creation_time}")

            if access_time:
                f.seek(ACCESS_OFFSET)
                f.write(_filetime_to_bytes(access_time))
                logger.debug(f"[TAMPER] AccessTime → {access_time}")

            if write_time:
                f.seek(WRITE_OFFSET)
                f.write(_filetime_to_bytes(write_time))
                logger.debug(f"[TAMPER] WriteTime → {write_time}")

        logger.info(f"[TAMPER] Timestamps patched: {path}")
        return True
    except Exception as e:
        logger.error(f"[TAMPER] Failed to patch {path}: {e}")
        return False


def tamper_target_path(path: Path, new_target: str) -> bool:
    """
    Перезаписывает StringData.LocalPath в .lnk файле.
    Использует сырую байтовую замену с выравниванием.

    ⚠️ Работает только если новый путь ≤ длины оригинального.
       Для увеличения длины требуется полная перестройка файла.
    """
    try:
        raw = path.read_bytes()

        # StringData хранит LocalPath как Unicode (UTF-16LE) с префиксом длины (2 bytes)
        # Ищем паттерн: находим существующий путь как UTF-16LE
        with open(path, "rb") as f:
            lnk = LnkParse3.lnk_file(f)
            lnk_json = lnk.get_json()
            if isinstance(lnk_json, str):
                lnk_json = json.loads(lnk_json)

        old_target = (
            lnk_json.get("string_data", {}).get("local_path") or
            lnk_json.get("link_info", {}).get("local_base_path") or ""
        )

        if not old_target:
            logger.warning(f"[TAMPER] No target path found in {path}")
            return False

        old_encoded = old_target.encode("utf-16-le")
        new_encoded = new_target.encode("utf-16-le")

        if len(new_encoded) > len(old_encoded):
            logger.error(
                f"[TAMPER] New target path too long "
                f"({len(new_encoded)} > {len(old_encoded)} bytes)"
            )
            return False

        # Паддинг нулями до оригинальной длины
        new_padded = new_encoded.ljust(len(old_encoded), b"\x00")
        patched = raw.replace(old_encoded, new_padded, 1)

        path.write_bytes(patched)
        logger.info(f"[TAMPER] Target path patched: {old_target} → {new_target}")
        return True

    except Exception as e:
        logger.error(f"[TAMPER] Failed to patch target path in {path}: {e}")
        return False


# ==============================================================================
# Детектирование тампинга
# ==============================================================================

def detect_tampering(records: list[dict]) -> list[dict]:
    """
    Анализирует .lnk метаданные на признаки тампинга:
      • creation_time > write_time (логически невозможно)
      • write_time > now (будущая дата)
      • Отсутствие machine_id при наличии target_path
      • Нулевые временны́е метки
    """
    suspicious = []
    now = datetime.now()

    for r in records:
        flags = []
        src = r.get("source_path", "unknown")

        def parse_dt(val):
            if not val:
                return None
            if isinstance(val, str):
                try:
                    return datetime.fromisoformat(val)
                except Exception:
                    return None
            return val

        ct = parse_dt(r.get("creation_time"))
        wt = parse_dt(r.get("write_time"))
        at = parse_dt(r.get("access_time"))

        if ct and wt:
            ct_n = ct.replace(tzinfo=None)
            wt_n = wt.replace(tzinfo=None)
            if ct_n > wt_n:
                flags.append("creation_time > write_time")

        if wt:
            if wt.replace(tzinfo=None) > now:
                flags.append("write_time in future")

        if ct:
            if ct.replace(tzinfo=None) > now:
                flags.append("creation_time in future")

        if r.get("target_path") and not r.get("machine_id"):
            flags.append("missing machine_id with valid target_path")

        # Нулевые метки (эпоха 1601-01-01 → часто означает обнуление)
        for field in ["creation_time", "write_time", "access_time"]:
            val = r.get(field)
            if isinstance(val, str) and "1601" in val:
                flags.append(f"{field} is zero epoch (1601)")

        if flags:
            suspicious.append({
                "source_path": src,
                "flags": flags,
                "meta": r,
            })
            logger.warning(f"[DETECT] Suspicious .lnk: {src} → {flags}")

    logger.info(
        f"[DETECT] Tampering check done — {len(suspicious)}/{len(records)} suspicious"
    )
    return suspicious


# ==============================================================================
# Экспорт
# ==============================================================================

def export_json(records: list[dict], output_path: Optional[Path] = None) -> Path:
    """Экспортирует метаданные .lnk в JSON файл."""
    if output_path is None:
        output_path = Path(EXPORT_DIR) / f"lnk_report_{_ts()}.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2, ensure_ascii=False, default=str)
    logger.info(f"[EXPORT] JSON report saved: {output_path}")
    return output_path


def export_csv(records: list[dict], output_path: Optional[Path] = None) -> Path:
    """Экспортирует метаданные .lnk в CSV файл."""
    if output_path is None:
        output_path = Path(EXPORT_DIR) / f"lnk_report_{_ts()}.csv"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if not records:
        logger.warning("[EXPORT] No records to export.")
        return output_path
    keys = list(records[0].keys())
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=keys, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(records)
    logger.info(f"[EXPORT] CSV report saved: {output_path}")
    return output_path


def _ts() -> str:
    """Timestamp для имён файлов экспорта."""
    return datetime.now().strftime("%Y%m%d_%H%M%S")


# ==============================================================================
# Публичный API модуля
# ==============================================================================

class LnkProcessor:
    """
    Высокоуровневый API для работы с .lnk файлами в WiperX.

    Пример использования:
        proc = LnkProcessor()
        records = proc.scan_all()
        suspicious = proc.detect_tampering(records)
        proc.export_json(suspicious)
        proc.wipe_all()
    """

    def __init__(self, secure_wipe: bool = True):
        self.secure_wipe = secure_wipe

    def scan_all(self) -> list[dict]:
        return scan_all_lnk_dirs()

    def scan(self, directory: Path) -> list[dict]:
        return scan_directory(directory)

    def filter_target(self, records, keyword) -> list[dict]:
        return filter_by_target(records, keyword)

    def filter_machine(self, records, machine_id) -> list[dict]:
        return filter_by_machine_id(records, machine_id)

    def filter_dates(self, records, field, start, end) -> list[dict]:
        return filter_by_date_range(records, field, start, end)

    def delete(self, path: Path) -> bool:
        return delete_lnk(path, secure=self.secure_wipe)

    def delete_records(self, records: list[dict]) -> dict:
        return delete_by_criteria(records, secure=self.secure_wipe)

    def wipe_dir(self, directory: Path) -> dict:
        return wipe_directory(directory, secure=self.secure_wipe)

    def wipe_all(self) -> dict:
        return wipe_all_recent(secure=self.secure_wipe)

    def tamper_ts(self, path, creation=None, access=None, write=None) -> bool:
        return tamper_timestamps(path, creation, access, write)

    def tamper_target(self, path, new_target) -> bool:
        return tamper_target_path(path, new_target)

    def detect_tampering(self, records: list[dict]) -> list[dict]:
        return detect_tampering(records)

    def export_json(self, records, output_path=None) -> Path:
        return export_json(records, output_path)

    def export_csv(self, records, output_path=None) -> Path:
        return export_csv(records, output_path)
