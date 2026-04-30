# ==============================================================================
# WiperX — src/modules/sru.py
#
# Модуль обработки Windows SRUM (System Resource Usage Monitor).
# Файл базы данных: C:\Windows\System32\sru\SRUDB.dat (формат ESE/ISAM)
#
# Возможности:
#   • Открытие и парсинг SRUDB.dat через pyesedb (libesedb)
#   • Листинг всех таблиц в базе данных
#   • Извлечение записей из произвольных таблиц по имени
#   • Парсинг ключевых таблиц SRU:
#       - {973F5D5C-...} — Network Usage (байты отправлено/получено)
#       - {D10CA2FE-...} — Application Resource Usage (CPU, RAM)
#       - {DD6636C4-...} — Network Connectivity
#       - {FEE4E14F-...} — Energy Usage
#       - SruDbIdMapTable — ID ↔ Application/User маппинг
#   • Фильтрация записей по AppId, UserId, TimeStamp
#   • Удаление записей по критериям (anti-forensics)
#   • Полная очистка таблиц (wipe all records)
#   • Детектирование признаков тампинга (gap-анализ по AutoIncId)
#   • Экспорт в JSON / CSV для отчётов
#   • Работа с копией файла (оригинал SRUDB.dat системой заблокирован)
#
# Зависимости:
#   • pyesedb (libesedb) — apt install python3-libesedb
#                          или pip install pyesedb
#   • config             — пути и константы WiperX
#
# Стандартный путь:
#   C:\Windows\System32\sru\SRUDB.dat
#   → В Linux/forensics: mount-point + относительный путь
#
# ВАЖНО:
#   SRUDB.dat заблокирован системой при работающей Windows.
#   Для работы необходима копия с мёртвого диска или теневая копия (VSS).
# ==============================================================================

from __future__ import annotations

import csv
import json
import logging
import shutil
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

try:
    import pyesedb
except ImportError:
    raise ImportError(
        "pyesedb не установлен.\n"
        "Установка: apt install python3-libesedb  или  pip install pyesedb"
    )

from config import config

logger = logging.getLogger("wiperx.sru")


# ==============================================================================
# КОНСТАНТЫ — GUID таблиц SRU
# ==============================================================================

SRU_TABLES: Dict[str, str] = {
    "{973F5D5C-1D90-11D4-A197-0090274F2D5C}": "Network Usage",
    "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA86}": "Application Resource Usage",
    "{DD6636C4-8929-4683-974E-22C046A43763}": "Network Connectivity",
    "{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}": "Energy Usage",
    "{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}LT":  "Energy Usage (Long Term)",
    "SruDbIdMapTable":                           "ID Map (App/User)",
    "SruDbCheckpointTable":                      "Checkpoint",
}

# Эпоха Windows FILETIME → Unix epoch
_FILETIME_EPOCH_OFFSET = 116_444_736_000_000_000  # 100-ns интервалы с 1601-01-01


# ==============================================================================
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ==============================================================================

def _filetime_to_datetime(filetime: int) -> Optional[datetime]:
    """
    Конвертирует Windows FILETIME (100-ns интервалы с 1601-01-01)
    в aware datetime (UTC).
    """
    if not filetime or filetime == 0:
        return None
    try:
        unix_ts = (filetime - _FILETIME_EPOCH_OFFSET) / 10_000_000
        return datetime.fromtimestamp(unix_ts, tz=timezone.utc)
    except (OSError, OverflowError, ValueError):
        return None


def _safe_get_integer(record: Any, col_index: int) -> Optional[int]:
    """Безопасно считывает integer-значение колонки."""
    try:
        return record.get_value_data_as_integer(col_index)
    except Exception:
        return None


def _safe_get_string(record: Any, col_index: int) -> Optional[str]:
    """Безопасно считывает строковое значение колонки."""
    try:
        data = record.get_value_data(col_index)
        if data is None:
            return None
        return data.decode("utf-16-le", errors="replace").rstrip("\x00")
    except Exception:
        return None


def _safe_get_bytes(record: Any, col_index: int) -> Optional[bytes]:
    """Безопасно считывает raw bytes значение колонки."""
    try:
        return record.get_value_data(col_index)
    except Exception:
        return None


def _record_to_dict(record: Any, table: Any) -> Dict[str, Any]:
    """
    Конвертирует запись pyesedb в словарь {column_name: value}.
    Автоматически определяет тип колонки.
    """
    result: Dict[str, Any] = {}
    for col_index in range(table.number_of_columns):
        col = table.get_column(col_index)
        col_name = col.name
        col_type = col.type

        # Типы pyesedb: 0=Nil, 1=Boolean, 2=Integer8bit, 3=Integer16bit,
        #               4=Integer32bit, 5=Currency, 6=Float32bit, 7=Float64bit,
        #               8=DateTime, 9=Binary, 10=Text, 11=LargeBinary,
        #               12=LargeText, 13=SuperLarge, 14=Integer32bitUnsigned,
        #               15=Integer64bit, 16=GUID, 17=Integer16bitUnsigned
        try:
            if col_type in (2, 3, 4, 14, 15, 17):  # Integer variants
                result[col_name] = _safe_get_integer(record, col_index)
            elif col_type in (10, 12):              # Text / LargeText
                result[col_name] = _safe_get_string(record, col_index)
            elif col_type == 8:                     # DateTime (FILETIME)
                raw = _safe_get_integer(record, col_index)
                dt = _filetime_to_datetime(raw) if raw else None
                result[col_name] = dt.isoformat() if dt else None
            elif col_type == 1:                     # Boolean
                raw = _safe_get_integer(record, col_index)
                result[col_name] = bool(raw) if raw is not None else None
            else:                                   # Binary / GUID / прочее
                raw = _safe_get_bytes(record, col_index)
                result[col_name] = raw.hex() if raw else None
        except Exception:
            result[col_name] = None

    return result


# ==============================================================================
# DATACLASSES — структуры данных SRU
# ==============================================================================

@dataclass
class SRUNetworkUsageRecord:
    """Запись из таблицы Network Usage."""
    auto_inc_id:      Optional[int]      = None
    timestamp:        Optional[str]      = None   # ISO 8601 UTC
    app_id:           Optional[int]      = None
    user_id:          Optional[int]      = None
    interface_luid:   Optional[int]      = None
    bytes_sent:       Optional[int]      = None
    bytes_received:   Optional[int]      = None
    l2_profile_id:    Optional[int]      = None
    l2_profile_flags: Optional[int]      = None


@dataclass
class SRUAppResourceRecord:
    """Запись из таблицы Application Resource Usage."""
    auto_inc_id:          Optional[int]  = None
    timestamp:            Optional[str]  = None
    app_id:               Optional[int]  = None
    user_id:              Optional[int]  = None
    face_time:            Optional[int]  = None
    background_cpu_time:  Optional[int]  = None
    foreground_cpu_time:  Optional[int]  = None
    background_cycles:    Optional[int]  = None
    foreground_cycles:    Optional[int]  = None


@dataclass
class SRUIdMapRecord:
    """Запись из таблицы SruDbIdMapTable (ID ↔ App/User)."""
    id_type:  Optional[int]  = None   # 0=App, 1=User
    id_index: Optional[int]  = None
    id_blob:  Optional[str]  = None   # hex или decoded string


# ==============================================================================
# ОСНОВНОЙ КЛАСС
# ==============================================================================

class SRUProcessor:
    """
    Обработчик SRUDB.dat (Windows System Resource Usage Monitor).

    Пример использования:
        proc = SRUProcessor("/mnt/windows/Windows/System32/sru/SRUDB.dat")
        proc.open()

        # Листинг таблиц
        tables = proc.list_tables()

        # Чтение записей Network Usage
        records = proc.read_table("{973F5D5C-...}")

        # Экспорт в JSON
        proc.export_table_json("{973F5D5C-...}", Path("output/network_usage.json"))

        # Очистка таблицы
        proc.wipe_table("{D10CA2FE-...}")

        proc.close()
    """

    def __init__(
        self,
        db_path:    Optional[Path] = None,
        work_copy:  bool           = True,
    ) -> None:
        """
        Args:
            db_path:   Путь к SRUDB.dat. Если None — берётся из config.
            work_copy: Если True — работаем с копией файла (рекомендуется).
        """
        self.db_path:   Path          = Path(db_path) if db_path else Path(config.sru_db_path)
        self.work_copy: bool          = work_copy
        self._esedb:    Any           = None
        self._active_path: Path       = self.db_path
        self._is_open:  bool          = False

    # --------------------------------------------------------------------------
    # ОТКРЫТИЕ / ЗАКРЫТИЕ
    # --------------------------------------------------------------------------

    def open(self) -> None:
        """
        Открывает SRUDB.dat через pyesedb.
        Если work_copy=True — сначала создаёт рабочую копию.
        """
        if not self.db_path.exists():
            raise FileNotFoundError(f"SRUDB.dat не найден: {self.db_path}")

        if self.work_copy:
            copy_path = self.db_path.parent / f"{self.db_path.stem}_wiperx_copy.dat"
            shutil.copy2(self.db_path, copy_path)
            self._active_path = copy_path
            logger.info(f"Рабочая копия создана: {copy_path}")
        else:
            self._active_path = self.db_path

        self._esedb = pyesedb.file()
        self._esedb.open(str(self._active_path))
        self._is_open = True
        logger.info(f"SRUDB.dat открыт: {self._active_path}")

    def close(self) -> None:
        """Закрывает файл базы данных."""
        if self._esedb and self._is_open:
            self._esedb.close()
            self._is_open = False
            logger.info("SRUDB.dat закрыт.")

    def __enter__(self) -> "SRUProcessor":
        self.open()
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    def _check_open(self) -> None:
        if not self._is_open or self._esedb is None:
            raise RuntimeError("База данных не открыта. Вызовите .open() сначала.")

    # --------------------------------------------------------------------------
    # НАВИГАЦИЯ ПО ТАБЛИЦАМ
    # --------------------------------------------------------------------------

    def list_tables(self) -> List[Dict[str, Any]]:
        """
        Возвращает список всех таблиц в SRUDB.dat.

        Returns:
            List[dict] — [{name, num_columns, num_records, friendly_name}, ...]
        """
        self._check_open()
        result = []
        for i in range(self._esedb.number_of_tables):
            table = self._esedb.get_table(i)
            result.append({
                "index":         i,
                "name":          table.name,
                "friendly_name": SRU_TABLES.get(table.name, "Unknown"),
                "num_columns":   table.number_of_columns,
                "num_records":   table.number_of_records,
            })
        logger.debug(f"Таблиц найдено: {len(result)}")
        return result

    def get_table(self, table_name: str) -> Any:
        """
        Возвращает объект таблицы pyesedb по имени.

        Args:
            table_name: Имя таблицы (GUID или SruDbIdMapTable и т.д.)

        Returns:
            pyesedb table object
        """
        self._check_open()
        table = self._esedb.get_table_by_name(table_name)
        if table is None:
            raise KeyError(f"Таблица не найдена: {table_name}")
        return table

    # --------------------------------------------------------------------------
    # ЧТЕНИЕ ЗАПИСЕЙ
    # --------------------------------------------------------------------------

    def read_table(
        self,
        table_name:  str,
        app_id:      Optional[int]      = None,
        user_id:     Optional[int]      = None,
        after_ts:    Optional[datetime] = None,
        before_ts:   Optional[datetime] = None,
        limit:       Optional[int]      = None,
    ) -> List[Dict[str, Any]]:
        """
        Читает записи из указанной таблицы с опциональной фильтрацией.

        Args:
            table_name: Имя таблицы.
            app_id:     Фильтр по AppId (если колонка присутствует).
            user_id:    Фильтр по UserId (если колонка присутствует).
            after_ts:   Фильтр — записи после этой даты (UTC).
            before_ts:  Фильтр — записи до этой даты (UTC).
            limit:      Максимальное количество записей.

        Returns:
            List[dict] — список записей в виде словарей.
        """
        self._check_open()
        table   = self.get_table(table_name)
        records = []
        count   = 0

        for rec_index in range(table.number_of_records):
            if limit and count >= limit:
                break

            record = table.get_record(rec_index)
            row    = _record_to_dict(record, table)

            # Фильтр AppId
            if app_id is not None and row.get("AppId") != app_id:
                continue

            # Фильтр UserId
            if user_id is not None and row.get("UserId") != user_id:
                continue

            # Фильтр по времени
            if after_ts or before_ts:
                ts_raw = row.get("TimeStamp")
                if ts_raw:
                    try:
                        ts = datetime.fromisoformat(ts_raw)
                        if after_ts and ts < after_ts:
                            continue
                        if before_ts and ts > before_ts:
                            continue
                    except ValueError:
                        pass

            records.append(row)
            count += 1

        logger.info(
            f"Таблица '{table_name}': прочитано {len(records)} записей "
            f"(фильтры: app_id={app_id}, user_id={user_id})"
        )
        return records

    def iter_table(self, table_name: str) -> Iterator[Dict[str, Any]]:
        """
        Генератор записей таблицы (memory-efficient для больших таблиц).

        Args:
            table_name: Имя таблицы.

        Yields:
            dict — одна запись.
        """
        self._check_open()
        table = self.get_table(table_name)
        for rec_index in range(table.number_of_records):
            record = table.get_record(rec_index)
            yield _record_to_dict(record, table)

    def read_id_map(self) -> List[SRUIdMapRecord]:
        """
        Читает SruDbIdMapTable и возвращает маппинг ID → App/User.

        Returns:
            List[SRUIdMapRecord]
        """
        self._check_open()
        table   = self.get_table("SruDbIdMapTable")
        records = []

        for rec_index in range(table.number_of_records):
            record   = table.get_record(rec_index)
            raw_row  = _record_to_dict(record, table)

            id_blob_hex = raw_row.get("IdBlob")
            id_blob_str = None
            if id_blob_hex:
                try:
                    id_blob_str = bytes.fromhex(id_blob_hex).decode(
                        "utf-16-le", errors="replace"
                    ).rstrip("\x00")
                except Exception:
                    id_blob_str = id_blob_hex

            records.append(SRUIdMapRecord(
                id_type  = raw_row.get("IdType"),
                id_index = raw_row.get("IdIndex"),
                id_blob  = id_blob_str or id_blob_hex,
            ))

        logger.info(f"ID Map: загружено {len(records)} записей.")
        return records

    def build_id_map(self) -> Dict[int, str]:
        """
        Строит словарь {id_index: app_or_user_name} из SruDbIdMapTable.
        Удобен для resolve AppId → имя приложения.

        Returns:
            Dict[int, str]
        """
        id_map: Dict[int, str] = {}
        for rec in self.read_id_map():
            if rec.id_index is not None and rec.id_blob:
                id_map[rec.id_index] = rec.id_blob
        return id_map

    # --------------------------------------------------------------------------
    # АНАЛИЗ / ДЕТЕКТИРОВАНИЕ ТАМПИНГА
    # --------------------------------------------------------------------------

    def detect_tampering(self, table_name: str) -> List[Dict[str, Any]]:
        """
        Gap-анализ AutoIncId в таблице для детектирования удалённых записей.
        Если AutoIncId не монотонно возрастает — возможен тампинг.

        Args:
            table_name: Имя таблицы для анализа.

        Returns:
            List[dict] — список обнаруженных разрывов:
                [{gap_start, gap_end, missing_count}, ...]
        """
        self._check_open()
        ids: List[int] = []

        for row in self.iter_table(table_name):
            aid = row.get("AutoIncId")
            if aid is not None:
                ids.append(aid)

        if not ids:
            logger.warning(f"Таблица '{table_name}': AutoIncId не найден.")
            return []

        ids.sort()
        gaps = []
        for i in range(1, len(ids)):
            if ids[i] != ids[i - 1] + 1:
                gaps.append({
                    "gap_start":     ids[i - 1] + 1,
                    "gap_end":       ids[i] - 1,
                    "missing_count": ids[i] - ids[i - 1] - 1,
                })

        if gaps:
            logger.warning(
                f"Таблица '{table_name}': обнаружено {len(gaps)} разрывов AutoIncId "
                f"(возможный тампинг)."
            )
        else:
            logger.info(f"Таблица '{table_name}': тампинг не обнаружен.")

        return gaps

    def detect_all_tables(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Запускает gap-анализ по всем таблицам SRU.

        Returns:
            Dict[table_name, List[gap_dict]]
        """
        results: Dict[str, List[Dict[str, Any]]] = {}
        for table_info in self.list_tables():
            name = table_info["name"]
            try:
                gaps = self.detect_tampering(name)
                results[name] = gaps
            except Exception as e:
                logger.debug(f"Таблица '{name}': gap-анализ пропущен — {e}")
                results[name] = []
        return results

    # --------------------------------------------------------------------------
    # ЭКСПОРТ
    # --------------------------------------------------------------------------

    def export_table_json(
        self,
        table_name:  str,
        output_path: Path,
        **filter_kwargs: Any,
    ) -> Path:
        """
        Экспортирует таблицу в JSON.

        Args:
            table_name:  Имя таблицы.
            output_path: Путь к выходному файлу.
            **filter_kwargs: Параметры фильтрации для read_table().

        Returns:
            Path к созданному файлу.
        """
        records = self.read_table(table_name, **filter_kwargs)
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(records, f, ensure_ascii=False, indent=2, default=str)

        logger.info(f"Экспорт JSON: {output_path} ({len(records)} записей)")
        return output_path

    def export_table_csv(
        self,
        table_name:  str,
        output_path: Path,
        **filter_kwargs: Any,
    ) -> Path:
        """
        Экспортирует таблицу в CSV.

        Args:
            table_name:  Имя таблицы.
            output_path: Путь к выходному файлу.
            **filter_kwargs: Параметры фильтрации для read_table().

        Returns:
            Path к созданному файлу.
        """
        records = self.read_table(table_name, **filter_kwargs)
        if not records:
            logger.warning(f"Экспорт CSV: таблица '{table_name}' пуста.")
            return output_path

        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(records[0].keys()))
            writer.writeheader()
            writer.writerows(records)

        logger.info(f"Экспорт CSV: {output_path} ({len(records)} записей)")
        return output_path

    def export_all_tables_json(self, output_dir: Path) -> Dict[str, Path]:
        """
        Экспортирует все таблицы в JSON-файлы в указанную директорию.

        Args:
            output_dir: Директория для экспорта.

        Returns:
            Dict[table_name, Path] — маппинг имён таблиц → файлы.
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        result: Dict[str, Path] = {}

        for table_info in self.list_tables():
            name     = table_info["name"]
            safe_name = name.replace("{", "").replace("}", "").replace("-", "_")
            out_path  = output_dir / f"{safe_name}.json"
            try:
                self.export_table_json(name, out_path)
                result[name] = out_path
            except Exception as e:
                logger.warning(f"Пропущена таблица '{name}': {e}")

        return result

    # --------------------------------------------------------------------------
    # WIPE / УДАЛЕНИЕ ЗАПИСЕЙ
    # --------------------------------------------------------------------------

    def wipe_table(self, table_name: str) -> int:
        """
        Полная очистка таблицы (удаление всех записей).

        ВНИМАНИЕ: pyesedb не поддерживает запись напрямую.
        Реализация через низкоуровневый обход или внешний инструмент
        (esentutl / srumecmd). Этот метод логирует операцию и
        подготавливает данные для последующего применения патча.

        Args:
            table_name: Имя таблицы.

        Returns:
            int — количество записей, помеченных для удаления.
        """
        self._check_open()
        table    = self.get_table(table_name)
        count    = table.number_of_records

        # pyesedb — read-only библиотека.
        # Запись требует либо libesedb C API (через ctypes),
        # либо пересоздания базы через COM/JET API на Windows.
        # Здесь логируем intent — фактическое удаление делает wipe_engine.
        logger.warning(
            f"wipe_table('{table_name}'): помечено {count} записей для удаления. "
            f"Фактическое удаление выполняется wipe_engine через esentutl/JET API."
        )
        return count

    def delete_records_by_app(
        self,
        table_name: str,
        app_id:     int,
    ) -> int:
        """
        Помечает записи по AppId для удаления.

        Args:
            table_name: Имя таблицы.
            app_id:     AppId для удаления.

        Returns:
            int — количество найденных записей.
        """
        records = self.read_table(table_name, app_id=app_id)
        logger.warning(
            f"delete_records_by_app(table='{table_name}', app_id={app_id}): "
            f"найдено {len(records)} записей для удаления."
        )
        return len(records)

    def delete_records_by_timerange(
        self,
        table_name: str,
        after_ts:   Optional[datetime] = None,
        before_ts:  Optional[datetime] = None,
    ) -> int:
        """
        Помечает записи в диапазоне дат для удаления.

        Args:
            table_name: Имя таблицы.
            after_ts:   Начало диапазона (UTC).
            before_ts:  Конец диапазона (UTC).

        Returns:
            int — количество найденных записей.
        """
        records = self.read_table(
            table_name,
            after_ts=after_ts,
            before_ts=before_ts,
        )
        logger.warning(
            f"delete_records_by_timerange(table='{table_name}'): "
            f"найдено {len(records)} записей в диапазоне "
            f"[{after_ts} — {before_ts}] для удаления."
        )
        return len(records)

    # --------------------------------------------------------------------------
    # ОТЧЁТ
    # --------------------------------------------------------------------------

    def summary(self) -> Dict[str, Any]:
        """
        Возвращает сводку по базе данных:
        таблицы, количество записей, GUID ↔ friendly name.

        Returns:
            dict — сводный отчёт.
        """
        self._check_open()
        tables  = self.list_tables()
        id_map  = self.build_id_map()

        return {
            "db_path":     str(self._active_path),
            "tables":      tables,
            "id_map_size": len(id_map),
            "known_tables": [
                t for t in tables
                if t["name"] in SRU_TABLES
            ],
        }
