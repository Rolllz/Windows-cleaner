# ==============================================================================
# WiperX — src/modules/prefetch.py
#
# Модуль обработки Windows Prefetch файлов (.pf).
#
# Возможности:
#   • Парсинг .pf файлов через pyscca (libscca Python-биндинги)
#   • Извлечение метаданных: имя EXE, хэш, run_count, timestamps
#   • Извлечение информации о томах (volume path, serial, creation time)
#   • Удаление .pf файлов по критериям (имя, хэш, дата запуска)
#   • Полная очистка директории Prefetch
#   • Детектирование признаков тампинга (несоответствие дат)
#   • Экспорт метаданных в JSON / CSV для отчётов
#   • Secure wipe (перезапись перед удалением)
#
# Зависимости:
#   • pyscca (libscca)  — apt install python3-libscca  или  pip install libscca
#   • config            — пути и константы WiperX
#
# Стандартный путь Prefetch:
#   C:\Windows\Prefetch\  →  в Linux/forensics: mount-point + путь
#
# Формат имени файла:
#   <EXECNAME>-<HASH8>.pf
#   Пример: NOTEPAD.EXE-A1B2C3D4.pf
# ==============================================================================

from __future__ import annotations

import os
import re
import json
import csv
import struct
import logging
import hashlib
from pathlib        import Path
from datetime       import datetime, timezone
from dataclasses    import dataclass, field, asdict
from typing         import Optional

try:
    import pyscca
    PYSCCA_AVAILABLE = True
except ImportError:
    PYSCCA_AVAILABLE = False

# Внутренние модули WiperX
from config import (
    PREFETCH_DIR,
    SECURE_WIPE_PASSES,
    LOG_LEVEL,
    REPORTS_DIR,
)

# ==============================================================================
# Логирование
# ==============================================================================

logger = logging.getLogger("wiperx.prefetch")
logging.basicConfig(level=getattr(logging, LOG_LEVEL, logging.INFO))


# ==============================================================================
# Константы
# ==============================================================================

PF_EXTENSION        = ".pf"
PF_NAME_PATTERN     = re.compile(r"^(.+)-([0-9A-Fa-f]{8})\.pf$", re.IGNORECASE)
MAX_RUN_TIMESTAMPS  = 8     # Windows хранит до 8 последних запусков


# ==============================================================================
# Dataclasses
# ==============================================================================

@dataclass
class VolumeInfo:
    """Информация об одном томе из Prefetch-файла."""
    index           : int
    device_path     : str
    creation_time   : Optional[datetime]
    serial_number   : str


@dataclass
class PrefetchRecord:
    """Полная запись одного .pf файла."""
    file_path           : str
    file_name           : str                       # имя .pf файла
    executable_name     : str                       # имя EXE внутри файла
    prefetch_hash       : str                       # 8-символьный хэш
    run_count           : int
    last_run_times      : list[Optional[datetime]]  # до 8 значений
    volumes             : list[VolumeInfo]
    file_size_bytes     : int
    parse_error         : Optional[str]     = None
    tamper_detected     : bool              = False
    tamper_reasons      : list[str]         = field(default_factory=list)


# ==============================================================================
# Вспомогательные функции
# ==============================================================================

def _filetime_to_datetime(filetime: int) -> Optional[datetime]:
    """
    Конвертирует Windows FILETIME (100-нс интервалы с 1601-01-01)
    в datetime (UTC).
    Возвращает None при нулевом или невалидном значении.
    """
    if not filetime or filetime == 0:
        return None
    try:
        # 116444736000000000 = разница между 1601-01-01 и 1970-01-01 в 100-нс
        timestamp_us = (filetime - 116_444_736_000_000_000) // 10
        return datetime.fromtimestamp(timestamp_us / 1_000_000, tz=timezone.utc)
    except (OSError, OverflowError, ValueError):
        return None


def _parse_pf_name(filename: str) -> tuple[str, str]:
    """
    Извлекает (exe_name, hash) из имени .pf файла.
    Пример: 'NOTEPAD.EXE-A1B2C3D4.pf' → ('NOTEPAD.EXE', 'A1B2C3D4')
    При несоответствии паттерну возвращает (filename, '').
    """
    m = PF_NAME_PATTERN.match(filename)
    if m:
        return m.group(1).upper(), m.group(2).upper()
    return filename, ""


def _secure_wipe_file(path: Path, passes: int = 3) -> None:
    """
    Перезаписывает файл случайными байтами перед удалением.
    passes — количество проходов перезаписи.
    """
    try:
        size = path.stat().st_size
        with open(path, "r+b") as fh:
            for _ in range(passes):
                fh.seek(0)
                fh.write(os.urandom(size))
                fh.flush()
                os.fsync(fh.fileno())
        logger.debug(f"Secure wipe ({passes} passes): {path}")
    except Exception as exc:
        logger.warning(f"Secure wipe failed for {path}: {exc}")


# ==============================================================================
# Парсинг одного .pf файла
# ==============================================================================

def parse_prefetch_file(pf_path: Path) -> PrefetchRecord:
    """
    Парсит один .pf файл через pyscca.
    Возвращает PrefetchRecord с полными метаданными.
    """
    filename    = pf_path.name
    exe_name, pf_hash = _parse_pf_name(filename)

    record = PrefetchRecord(
        file_path       = str(pf_path),
        file_name       = filename,
        executable_name = exe_name,
        prefetch_hash   = pf_hash,
        run_count       = 0,
        last_run_times  = [],
        volumes         = [],
        file_size_bytes = pf_path.stat().st_size if pf_path.exists() else 0,
    )

    if not PYSCCA_AVAILABLE:
        record.parse_error = "pyscca not available — install python3-libscca"
        logger.error(record.parse_error)
        return record

    try:
        scca = pyscca.open(str(pf_path))

        # --- Основные поля ---
        record.executable_name  = (scca.executable_filename or exe_name).upper()
        record.run_count        = scca.run_count or 0
        record.prefetch_hash    = format(scca.prefetch_hash, "08X") if scca.prefetch_hash else pf_hash

        # --- Временны́е метки запусков (до 8) ---
        run_times = []
        for i in range(MAX_RUN_TIMESTAMPS):
            try:
                ft = scca.get_last_run_time(i)
                run_times.append(_filetime_to_datetime(ft))
            except Exception:
                run_times.append(None)
        record.last_run_times = run_times

        # --- Информация о томах ---
        volumes = []
        for i in range(scca.number_of_volumes):
            try:
                vol     = scca.get_volume_information(i)
                vi = VolumeInfo(
                    index           = i,
                    device_path     = vol.device_path or "",
                    creation_time   = _filetime_to_datetime(vol.creation_time),
                    serial_number   = format(vol.serial_number, "08X") if vol.serial_number else "",
                )
                volumes.append(vi)
            except Exception as ve:
                logger.debug(f"Volume {i} parse error in {filename}: {ve}")
        record.volumes = volumes

        # --- Детектирование тампинга ---
        record = _detect_tampering(record, pf_path)

    except Exception as exc:
        record.parse_error = str(exc)
        logger.error(f"Failed to parse {pf_path}: {exc}")

    return record


# ==============================================================================
# Детектирование тампинга
# ==============================================================================

def _detect_tampering(record: PrefetchRecord, pf_path: Path) -> PrefetchRecord:
    """
    Проверяет признаки тампинга Prefetch-файла:
      1. Хэш в имени файла ≠ prefetch_hash внутри файла
      2. run_count == 0 при наличии run_times
      3. Все run_times — None при run_count > 0
      4. Несоответствие имени EXE в filename vs внутри файла
      5. Аномально старые/будущие временны́е метки
    """
    reasons = []

    # 1. Хэш в имени vs внутренний хэш
    _, name_hash = _parse_pf_name(record.file_name)
    if name_hash and record.prefetch_hash:
        if name_hash.upper() != record.prefetch_hash.upper():
            reasons.append(
                f"Hash mismatch: filename={name_hash} vs internal={record.prefetch_hash}"
            )

    # 2. run_count == 0, но есть непустые run_times
    valid_times = [t for t in record.last_run_times if t is not None]
    if record.run_count == 0 and valid_times:
        reasons.append("run_count=0 but last_run_times are present")

    # 3. run_count > 0, но все run_times пусты
    if record.run_count > 0 and not valid_times:
        reasons.append("run_count>0 but all last_run_times are None")

    # 4. Имя EXE в filename vs внутри файла
    name_exe, _ = _parse_pf_name(record.file_name)
    if name_exe and record.executable_name:
        if name_exe.upper() != record.executable_name.upper():
            reasons.append(
                f"EXE name mismatch: filename={name_exe} vs internal={record.executable_name}"
            )

    # 5. Аномальные временны́е метки
    now = datetime.now(tz=timezone.utc)
    epoch_min = datetime(1970, 1, 1, tzinfo=timezone.utc)
    for i, ts in enumerate(valid_times):
        if ts < epoch_min:
            reasons.append(f"run_time[{i}] before Unix epoch: {ts}")
        elif ts > now:
            reasons.append(f"run_time[{i}] in the future: {ts}")

    record.tamper_detected  = bool(reasons)
    record.tamper_reasons   = reasons

    if record.tamper_detected:
        logger.warning(f"Tampering detected in {record.file_name}: {reasons}")

    return record


# ==============================================================================
# Сканирование директории
# ==============================================================================

def scan_prefetch_dir(prefetch_dir: Optional[Path] = None) -> list[PrefetchRecord]:
    """
    Сканирует директорию Prefetch и парсит все .pf файлы.
    Возвращает список PrefetchRecord.
    """
    pdir = Path(prefetch_dir or PREFETCH_DIR)

    if not pdir.exists():
        logger.error(f"Prefetch directory not found: {pdir}")
        return []

    pf_files = sorted(pdir.glob(f"*{PF_EXTENSION}"))
    logger.info(f"Found {len(pf_files)} .pf files in {pdir}")

    records = []
    for pf_path in pf_files:
        logger.debug(f"Parsing: {pf_path.name}")
        rec = parse_prefetch_file(pf_path)
        records.append(rec)

    return records


# ==============================================================================
# Фильтрация записей
# ==============================================================================

def filter_records(
    records     : list[PrefetchRecord],
    exe_name    : Optional[str]             = None,
    pf_hash     : Optional[str]             = None,
    run_after   : Optional[datetime]        = None,
    run_before  : Optional[datetime]        = None,
    tampered_only: bool                     = False,
) -> list[PrefetchRecord]:
    """
    Фильтрует список PrefetchRecord по критериям.

    Args:
        exe_name        : фильтр по имени EXE (case-insensitive, partial match)
        pf_hash         : фильтр по точному 8-символьному хэшу
        run_after       : оставить записи с хотя бы одним запуском после даты
        run_before      : оставить записи с хотя бы одним запуском до даты
        tampered_only   : только записи с признаками тампинга
    """
    result = records

    if exe_name:
        result = [r for r in result if exe_name.upper() in r.executable_name.upper()]

    if pf_hash:
        result = [r for r in result if r.prefetch_hash.upper() == pf_hash.upper()]

    if run_after:
        result = [
            r for r in result
            if any(t for t in r.last_run_times if t and t >= run_after)
        ]

    if run_before:
        result = [
            r for r in result
            if any(t for t in r.last_run_times if t and t <= run_before)
        ]

    if tampered_only:
        result = [r for r in result if r.tamper_detected]

    logger.info(f"Filter result: {len(result)}/{len(records)} records match")
    return result


# ==============================================================================
# Удаление файлов
# ==============================================================================

def delete_records(
    records         : list[PrefetchRecord],
    secure          : bool = True,
    dry_run         : bool = False,
) -> dict[str, list[str]]:
    """
    Удаляет .pf файлы из списка PrefetchRecord.

    Args:
        records : список записей для удаления
        secure  : перезаписать перед удалением (secure wipe)
        dry_run : только показать, что будет удалено (не удалять)

    Returns:
        dict с ключами 'deleted', 'failed', 'skipped'
    """
    result = {"deleted": [], "failed": [], "skipped": []}

    for rec in records:
        path = Path(rec.file_path)

        if not path.exists():
            logger.warning(f"File not found (skip): {path}")
            result["skipped"].append(str(path))
            continue

        if dry_run:
            logger.info(f"[DRY RUN] Would delete: {path}")
            result["skipped"].append(str(path))
            continue

        try:
            if secure:
                _secure_wipe_file(path, passes=SECURE_WIPE_PASSES)
            path.unlink()
            logger.info(f"Deleted: {path.name}")
            result["deleted"].append(str(path))
        except Exception as exc:
            logger.error(f"Failed to delete {path}: {exc}")
            result["failed"].append(str(path))

    return result


def wipe_all(
    prefetch_dir    : Optional[Path] = None,
    secure          : bool = True,
    dry_run         : bool = False,
) -> dict[str, list[str]]:
    """
    Полная очистка директории Prefetch.
    Эквивалент: scan → delete all.
    """
    records = scan_prefetch_dir(prefetch_dir)
    logger.info(f"Wiping {len(records)} prefetch files (secure={secure}, dry_run={dry_run})")
    return delete_records(records, secure=secure, dry_run=dry_run)


# ==============================================================================
# Экспорт
# ==============================================================================

def export_json(
    records     : list[PrefetchRecord],
    output_path : Optional[Path] = None,
) -> Path:
    """
    Экспортирует список записей в JSON.
    """
    out = Path(output_path or REPORTS_DIR) / "prefetch_report.json"
    out.parent.mkdir(parents=True, exist_ok=True)

    def _serialize(obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        raise TypeError(f"Not serializable: {type(obj)}")

    data = [asdict(r) for r in records]
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, default=_serialize, ensure_ascii=False)

    logger.info(f"JSON report saved: {out}")
    return out


def export_csv(
    records     : list[PrefetchRecord],
    output_path : Optional[Path] = None,
) -> Path:
    """
    Экспортирует плоский CSV (по одной строке на запись).
    run_times разворачиваются в отдельные колонки run_time_0..7.
    """
    out = Path(output_path or REPORTS_DIR) / "prefetch_report.csv"
    out.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "file_name", "executable_name", "prefetch_hash",
        "run_count", "file_size_bytes", "parse_error",
        "tamper_detected", "tamper_reasons",
        *[f"run_time_{i}" for i in range(MAX_RUN_TIMESTAMPS)],
        "volume_count",
    ]

    with open(out, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for rec in records:
            row = {
                "file_name"         : rec.file_name,
                "executable_name"   : rec.executable_name,
                "prefetch_hash"     : rec.prefetch_hash,
                "run_count"         : rec.run_count,
                "file_size_bytes"   : rec.file_size_bytes,
                "parse_error"       : rec.parse_error or "",
                "tamper_detected"   : rec.tamper_detected,
                "tamper_reasons"    : "; ".join(rec.tamper_reasons),
                "volume_count"      : len(rec.volumes),
            }
            for i in range(MAX_RUN_TIMESTAMPS):
                ts = rec.last_run_times[i] if i < len(rec.last_run_times) else None
                row[f"run_time_{i}"] = ts.isoformat() if ts else ""
            writer.writerow(row)

    logger.info(f"CSV report saved: {out}")
    return out


# ==============================================================================
# Публичный API модуля
# ==============================================================================

__all__ = [
    "PrefetchRecord",
    "VolumeInfo",
    "parse_prefetch_file",
    "scan_prefetch_dir",
    "filter_records",
    "delete_records",
    "wipe_all",
    "export_json",
    "export_csv",
]
