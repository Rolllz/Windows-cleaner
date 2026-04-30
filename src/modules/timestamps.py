# WiperX — src/modules/timestamps.py
# Манипуляция и очистка временных меток файлов Windows (NTFS $SI / $FN)
# Зависимости: ctypes, config

import os
import csv
import json
import struct
import logging
import ctypes
import ctypes.wintypes
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Optional

from config import (
    WIPERX_LOG_LEVEL,
    SECURE_WIPE_PASSES,
    TIMESTAMPS_DEFAULT_SPOOF,
)

logger = logging.getLogger(__name__)
logger.setLevel(WIPERX_LOG_LEVEL)

# Разница эпох: Windows FILETIME (1601) vs Unix (1970) в секундах
EPOCH_DELTA = 11_644_473_600

# ──────────────────────────────────────────────────────────────
# КОНВЕРТАЦИЯ ВРЕМЕНИ
# ──────────────────────────────────────────────────────────────

def unix_to_filetime(unix_ts: float) -> int:
    """Unix timestamp → Windows FILETIME (100-ns интервалы с 1601-01-01)."""
    return int((unix_ts + EPOCH_DELTA) * 10_000_000)


def filetime_to_unix(ft: int) -> float:
    """Windows FILETIME → Unix timestamp."""
    return (ft / 10_000_000) - EPOCH_DELTA


def filetime_to_dt(ft: int) -> datetime:
    """Windows FILETIME → datetime (UTC)."""
    return datetime.fromtimestamp(filetime_to_unix(ft), tz=timezone.utc)


def dt_to_filetime(dt: datetime) -> int:
    """datetime (UTC) → Windows FILETIME."""
    return unix_to_filetime(dt.timestamp())


def parse_timestamp_str(ts: str) -> datetime:
    """
    Парсит строку в datetime UTC.
    Форматы: ISO 8601, '%Y-%m-%d %H:%M:%S', '%Y-%m-%d'
    """
    formats = [
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
    ]
    for fmt in formats:
        try:
            dt = datetime.strptime(ts, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    raise ValueError(f"Неизвестный формат временной метки: {ts!r}")


# ──────────────────────────────────────────────────────────────
# WINAPI — SetFileTime / GetFileTime
# ──────────────────────────────────────────────────────────────

GENERIC_READ       = 0x80000000
GENERIC_WRITE      = 0x40000000
FILE_SHARE_READ    = 0x00000001
FILE_SHARE_WRITE   = 0x00000002
OPEN_EXISTING      = 3
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
INVALID_HANDLE     = ctypes.wintypes.HANDLE(-1).value


class FILETIME(ctypes.Structure):
    _fields_ = [
        ("dwLowDateTime",  ctypes.wintypes.DWORD),
        ("dwHighDateTime", ctypes.wintypes.DWORD),
    ]

    @classmethod
    def from_int(cls, ft: int) -> "FILETIME":
        obj = cls()
        obj.dwLowDateTime  = ft & 0xFFFFFFFF
        obj.dwHighDateTime = (ft >> 32) & 0xFFFFFFFF
        return obj

    def to_int(self) -> int:
        return (self.dwHighDateTime << 32) | self.dwLowDateTime


def _open_handle(path: Path, write: bool = False) -> ctypes.wintypes.HANDLE:
    access = GENERIC_READ | (GENERIC_WRITE if write else 0)
    share  = FILE_SHARE_READ | FILE_SHARE_WRITE
    handle = ctypes.windll.kernel32.CreateFileW(
        str(path),
        access,
        share,
        None,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        None,
    )
    if handle == INVALID_HANDLE:
        err = ctypes.GetLastError()
        raise OSError(f"CreateFileW failed (err={err}): {path}")
    return handle


def _close_handle(handle: ctypes.wintypes.HANDLE) -> None:
    ctypes.windll.kernel32.CloseHandle(handle)


def get_timestamps(path: Path) -> dict:
    """
    Читает $STANDARD_INFORMATION временные метки файла через GetFileTime.
    Возвращает dict с ключами: created, modified, accessed (datetime UTC).
    """
    handle = _open_handle(path, write=False)
    try:
        ctime = FILETIME()
        atime = FILETIME()
        wtime = FILETIME()
        ok = ctypes.windll.kernel32.GetFileTime(
            handle,
            ctypes.byref(ctime),
            ctypes.byref(atime),
            ctypes.byref(wtime),
        )
        if not ok:
            raise OSError(f"GetFileTime failed: {ctypes.GetLastError()}")
        return {
            "created":  filetime_to_dt(ctime.to_int()),
            "accessed": filetime_to_dt(atime.to_int()),
            "modified": filetime_to_dt(wtime.to_int()),
        }
    finally:
        _close_handle(handle)


def set_timestamps(
    path: Path,
    created:  Optional[datetime] = None,
    accessed: Optional[datetime] = None,
    modified: Optional[datetime] = None,
) -> None:
    """
    Устанавливает временные метки файла через SetFileTime (WinAPI).
    None = не изменять соответствующую метку.
    """
    handle = _open_handle(path, write=True)
    try:
        cur = get_timestamps(path)

        ctime_ft = FILETIME.from_int(dt_to_filetime(created  or cur["created"]))
        atime_ft = FILETIME.from_int(dt_to_filetime(accessed or cur["accessed"]))
        wtime_ft = FILETIME.from_int(dt_to_filetime(modified or cur["modified"]))

        ok = ctypes.windll.kernel32.SetFileTime(
            handle,
            ctypes.byref(ctime_ft),
            ctypes.byref(atime_ft),
            ctypes.byref(wtime_ft),
        )
        if not ok:
            raise OSError(f"SetFileTime failed: {ctypes.GetLastError()}")

        logger.info(
            "Timestamps set | %s | C=%s A=%s M=%s",
            path,
            (created  or cur["created"]).isoformat(),
            (accessed or cur["accessed"]).isoformat(),
            (modified or cur["modified"]).isoformat(),
        )
    finally:
        _close_handle(handle)


# ──────────────────────────────────────────────────────────────
# SPOOFING — подмена меток
# ──────────────────────────────────────────────────────────────

def spoof_timestamps(
    path: Path,
    target_dt: Optional[datetime] = None,
    randomize_sub_seconds: bool = True,
) -> dict:
    """
    Подменяет все три метки на target_dt (или TIMESTAMPS_DEFAULT_SPOOF из config).
    Если randomize_sub_seconds=True — добавляет случайные микросекунды (избегает ровных нулей).
    Возвращает dict с применёнными значениями.
    """
    if target_dt is None:
        if TIMESTAMPS_DEFAULT_SPOOF:
            target_dt = parse_timestamp_str(TIMESTAMPS_DEFAULT_SPOOF)
        else:
            raise ValueError("target_dt не задан и TIMESTAMPS_DEFAULT_SPOOF не установлен в config")

    if randomize_sub_seconds:
        import random
        target_dt = target_dt.replace(microsecond=random.randint(100_000, 999_999))

    set_timestamps(path, created=target_dt, accessed=target_dt, modified=target_dt)
    logger.info("Spoofed timestamps on %s → %s", path, target_dt.isoformat())

    return {
        "path":     str(path),
        "created":  target_dt.isoformat(),
        "accessed": target_dt.isoformat(),
        "modified": target_dt.isoformat(),
    }


def spoof_timestamps_bulk(
    paths: list[Path],
    target_dt: Optional[datetime] = None,
    randomize_sub_seconds: bool = True,
) -> list[dict]:
    """Пакетная подмена временных меток для списка файлов."""
    results = []
    for p in paths:
        try:
            r = spoof_timestamps(p, target_dt=target_dt, randomize_sub_seconds=randomize_sub_seconds)
            r["status"] = "ok"
        except Exception as e:
            logger.error("spoof failed: %s — %s", p, e)
            r = {"path": str(p), "status": "error", "error": str(e)}
        results.append(r)
    return results


# ──────────────────────────────────────────────────────────────
# СКАНИРОВАНИЕ — аудит меток в директории
# ──────────────────────────────────────────────────────────────

def scan_directory(
    root: Path,
    recursive: bool = True,
    extensions: Optional[list[str]] = None,
) -> list[dict]:
    """
    Читает временные метки всех файлов в директории.
    extensions: список расширений-фильтров, например ['.exe', '.dll'].
    """
    records = []
    pattern = "**/*" if recursive else "*"

    for fp in root.glob(pattern):
        if not fp.is_file():
            continue
        if extensions and fp.suffix.lower() not in extensions:
            continue
        try:
            ts = get_timestamps(fp)
            records.append({
                "path":     str(fp),
                "created":  ts["created"].isoformat(),
                "accessed": ts["accessed"].isoformat(),
                "modified": ts["modified"].isoformat(),
            })
        except Exception as e:
            logger.warning("Cannot read timestamps: %s — %s", fp, e)
            records.append({
                "path":   str(fp),
                "error":  str(e),
            })

    logger.info("Scanned %d files in %s", len(records), root)
    return records


def detect_anomalies(records: list[dict]) -> list[dict]:
    """
    Детектирует аномалии в метках:
      • created > modified  (creation после модификации — признак timestomping)
      • microsecond == 0    (точное нулевое значение — подозрительно)
      • modified < 1990     (нереально старые метки)
    """
    anomalies = []
    for rec in records:
        if "error" in rec:
            continue
        flags = []
        c = datetime.fromisoformat(rec["created"])
        a = datetime.fromisoformat(rec["accessed"])
        m = datetime.fromisoformat(rec["modified"])

        if c > m:
            flags.append("created_after_modified")
        if c.microsecond == 0 and m.microsecond == 0:
            flags.append("zero_microseconds")
        if m.year < 1990:
            flags.append("unrealistic_year")
        if a < m:
            flags.append("accessed_before_modified")

        if flags:
            anomalies.append({**rec, "anomalies": flags})

    logger.info("Detected %d anomalous entries", len(anomalies))
    return anomalies


# ──────────────────────────────────────────────────────────────
# ЭКСПОРТ
# ──────────────────────────────────────────────────────────────

def export_json(records: list[dict], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(records, f, ensure_ascii=False, indent=2)
    logger.info("Exported %d records → %s", len(records), out_path)


def export_csv(records: list[dict], out_path: Path) -> None:
    if not records:
        logger.warning("No records to export.")
        return
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list({k for r in records for k in r})
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(records)
    logger.info("Exported %d records → %s", len(records), out_path)


# ──────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────

def _cli():
    import argparse

    parser = argparse.ArgumentParser(
        prog="timestamps",
        description="WiperX — Windows file timestamp tool",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # get
    p_get = sub.add_parser("get", help="Получить метки файла")
    p_get.add_argument("path", type=Path)

    # set
    p_set = sub.add_parser("set", help="Установить метки вручную")
    p_set.add_argument("path", type=Path)
    p_set.add_argument("--created",  type=str, default=None)
    p_set.add_argument("--accessed", type=str, default=None)
    p_set.add_argument("--modified", type=str, default=None)

    # spoof
    p_spoof = sub.add_parser("spoof", help="Подменить метки на заданное время")
    p_spoof.add_argument("path", type=Path)
    p_spoof.add_argument("--datetime", dest="dt", type=str, default=None)
    p_spoof.add_argument("--no-random-sub", action="store_true")

    # spoof-bulk
    p_bulk = sub.add_parser("spoof-bulk", help="Пакетная подмена меток")
    p_bulk.add_argument("paths", type=Path, nargs="+")
    p_bulk.add_argument("--datetime", dest="dt", type=str, default=None)
    p_bulk.add_argument("--no-random-sub", action="store_true")

    # scan
    p_scan = sub.add_parser("scan", help="Сканирование директории")
    p_scan.add_argument("root", type=Path)
    p_scan.add_argument("--no-recursive", action="store_true")
    p_scan.add_argument("--ext", nargs="*", default=None)
    p_scan.add_argument("--anomalies", action="store_true")
    p_scan.add_argument("--export-json", type=Path, default=None)
    p_scan.add_argument("--export-csv",  type=Path, default=None)

    args = parser.parse_args()

    if args.cmd == "get":
        ts = get_timestamps(args.path)
        print(json.dumps({k: v.isoformat() for k, v in ts.items()}, indent=2))

    elif args.cmd == "set":
        c = parse_timestamp_str(args.created)  if args.created  else None
        a = parse_timestamp_str(args.accessed) if args.accessed else None
        m = parse_timestamp_str(args.modified) if args.modified else None
        set_timestamps(args.path, created=c, accessed=a, modified=m)
        print("Done.")

    elif args.cmd == "spoof":
        dt = parse_timestamp_str(args.dt) if args.dt else None
        result = spoof_timestamps(args.path, target_dt=dt, randomize_sub_seconds=not args.no_random_sub)
        print(json.dumps(result, indent=2))

    elif args.cmd == "spoof-bulk":
        dt = parse_timestamp_str(args.dt) if args.dt else None
        results = spoof_timestamps_bulk(args.paths, target_dt=dt, randomize_sub_seconds=not args.no_random_sub)
        print(json.dumps(results, indent=2))

    elif args.cmd == "scan":
        records = scan_directory(
            args.root,
            recursive=not args.no_recursive,
            extensions=args.ext,
        )
        if args.anomalies:
            records = detect_anomalies(records)
        if args.export_json:
            export_json(records, args.export_json)
        if args.export_csv:
            export_csv(records, args.export_csv)
        if not args.export_json and not args.export_csv:
            print(json.dumps(records, indent=2))


if __name__ == "__main__":
    _cli()
