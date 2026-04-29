# ==============================================================================
# WiperX — utils/output.py
# Единый интерфейс записи результатов: JSON / CSV / TXT
# ==============================================================================

import csv
import json
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from utils.logger import get_logger

log = get_logger(__name__)


# ══════════════════════════════════════════════════════════════════════════════
# 1. Форматы вывода
# ══════════════════════════════════════════════════════════════════════════════

class OutputFormat(str, Enum):
    JSON = "json"
    CSV  = "csv"
    TXT  = "txt"


# ══════════════════════════════════════════════════════════════════════════════
# 2. Нормализация данных
# ══════════════════════════════════════════════════════════════════════════════

def _normalize(value: Any) -> Any:
    """
    Рекурсивно приводит значения к JSON-сериализуемому виду.
    datetime → ISO-строка, bytes → hex, остальное → str при необходимости.
    """
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, dict):
        return {k: _normalize(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_normalize(i) for i in value]
    if isinstance(value, Path):
        return str(value)
    return value


# ══════════════════════════════════════════════════════════════════════════════
# 3. Основной класс OutputWriter
# ══════════════════════════════════════════════════════════════════════════════

class OutputWriter:
    """
    Буферизованный запись результатов парсеров.

    Использование:
        writer = OutputWriter(output_dir=Path("results"), fmt=OutputFormat.JSON)
        writer.add("registry", {"key": "...", "value": "..."})
        writer.add("registry", {"key": "...", "value": "..."})
        writer.flush()          # записывает накопленное
        writer.save_summary()   # итоговый summary.json
    """

    def __init__(
        self,
        output_dir: Path,
        fmt: OutputFormat = OutputFormat.JSON,
        pretty: bool = True,
    ) -> None:
        self.output_dir = Path(output_dir)
        self.fmt = fmt
        self.pretty = pretty
        self._buffer: dict[str, list[dict]] = {}  # категория → список записей
        self._stats:  dict[str, int] = {}          # категория → кол-во записей

        self.output_dir.mkdir(parents=True, exist_ok=True)
        log.info("OutputWriter инициализирован [формат=%s, папка=%s]", fmt.value, output_dir)

    # ── Добавление записи ─────────────────────────────────────────────────────
    def add(self, category: str, record: dict) -> None:
        """
        Добавляет одну запись в буфер.

        Args:
            category: Имя категории (= имя файла без расширения).
                      Например: "registry", "eventlogs", "prefetch".
            record:   Словарь с данными артефакта.
        """
        normalized = _normalize(record)
        self._buffer.setdefault(category, []).append(normalized)
        self._stats[category] = self._stats.get(category, 0) + 1

    def add_many(self, category: str, records: list[dict]) -> None:
        """Добавляет список записей сразу."""
        for r in records:
            self.add(category, r)

    # ── Сброс буфера на диск ──────────────────────────────────────────────────
    def flush(self) -> None:
        """Записывает все накопленные буферы на диск и очищает их."""
        for category, records in self._buffer.items():
            if not records:
                continue
            out_path = self.output_dir / f"{category}.{self.fmt.value}"
            try:
                if self.fmt == OutputFormat.JSON:
                    self._write_json(out_path, records)
                elif self.fmt == OutputFormat.CSV:
                    self._write_csv(out_path, records)
                elif self.fmt == OutputFormat.TXT:
                    self._write_txt(out_path, records)
                log.info("Записано %d записей → %s", len(records), out_path)
            except Exception as e:
                log.error("Ошибка записи [%s]: %s", category, e)

        self._buffer.clear()

    # ── JSON ──────────────────────────────────────────────────────────────────
    def _write_json(self, path: Path, records: list[dict]) -> None:
        existing: list[dict] = []
        if path.exists():
            try:
                existing = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                pass

        combined = existing + records
        indent = 2 if self.pretty else None
        path.write_text(
            json.dumps(combined, ensure_ascii=False, indent=indent),
            encoding="utf-8",
        )

    # ── CSV ───────────────────────────────────────────────────────────────────
    def _write_csv(self, path: Path, records: list[dict]) -> None:
        if not records:
            return

        # Собираем все ключи из всех записей (union)
        fieldnames = list(dict.fromkeys(k for r in records for k in r))
        write_header = not path.exists()

        with path.open("a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            if write_header:
                writer.writeheader()
            writer.writerows(records)

    # ── TXT ───────────────────────────────────────────────────────────────────
    def _write_txt(self, path: Path, records: list[dict]) -> None:
        with path.open("a", encoding="utf-8") as f:
            for record in records:
                f.write("─" * 60 + "\n")
                for key, value in record.items():
                    f.write(f"  {key:<25} {value}\n")
            f.write("\n")

    # ── Итоговый отчёт ────────────────────────────────────────────────────────
    def save_summary(self, meta: Optional[dict] = None) -> Path:
        """
        Сохраняет summary.json с общей статистикой.

        Args:
            meta: Дополнительные поля (имя кейса, хэши образа и т.д.).

        Returns:
            Path до созданного файла.
        """
        summary = {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "output_format": self.fmt.value,
            "artifacts": self._stats,
            "total_records": sum(self._stats.values()),
        }
        if meta:
            summary.update(_normalize(meta))

        summary_path = self.output_dir / "summary.json"
        summary_path.write_text(
            json.dumps(summary, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        log.info("Summary сохранён → %s", summary_path)
        return summary_path

    # ── Статистика ────────────────────────────────────────────────────────────
    @property
    def stats(self) -> dict[str, int]:
        """Текущая статистика по категориям."""
        return dict(self._stats)

    def __repr__(self) -> str:
        return (
            f"OutputWriter(fmt={self.fmt.value!r}, "
            f"dir={self.output_dir!r}, "
            f"categories={list(self._stats.keys())})"
        )
