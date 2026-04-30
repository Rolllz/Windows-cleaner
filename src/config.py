# src/config.py
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional

# ---------------------------------------------------------------------------
# Вложенные структуры конфигурации
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Artifact:
    """Общая структура для артефактов Windows."""
    dir: str
    pattern: Optional[str] = None
    file: Optional[str] = None
    description: str = ""

@dataclass(frozen=True)
class EventLogConfig:
    dir: str
    pattern: str
    event_ids: Dict[int, str] = field(default_factory=dict)

@dataclass(frozen=True)
class AnalysisConfig:
    output_dir: str = "output"
    report_format: str = "json"
    include_raw: bool = False

@dataclass(frozen=True)
class LoggingConfig:
    level: str = "INFO"
    file: Optional[str] = None
    format: str = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    date_format: str = "%Y-%m-%d %H:%M:%S"
    use_rich: bool = True

@dataclass(frozen=True)
class ReportConfig:
    include_summary: bool = True
    include_details: bool = True
    output_format: str = "json"

# ---------------------------------------------------------------------------
# Главная конфигурация (immutable, единая точка правды)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Config:
    base_dir: Path = field(default_factory=lambda: Path(__file__).resolve().parent)

    # Windows артефакты
    prefetch: Artifact = field(default_factory=lambda: Artifact(
        dir="Windows/Prefetch", pattern="*.pf", description="Prefetch cache"
    ))
    shimcache: Artifact = field(default_factory=lambda: Artifact(
        dir="Windows/System32/config", file="SYSTEM", description="Shimcache registry hive"
    ))
    amcache: Artifact = field(default_factory=lambda: Artifact(
        dir="Windows/AppCompat/Programs", file="AmCache.hve", description="Amcache registry hive"
    ))
    event_logs: EventLogConfig = field(default_factory=lambda: EventLogConfig(
        dir="Windows/System32/winevt/Logs",
        pattern="*.evtx",
        event_ids={
            4624: "Успешный вход в систему",
            4625: "Ошибка входа",
            1102: "Очистка журнала аудита безопасности",
            104: "Очистка журнала событий",
        }
    ))
    useractivity: Artifact = field(default_factory=lambda: Artifact(
        dir="Users", file="UsrClass.dat", description="User activity / Recent docs"
    ))
    recent: Artifact = field(default_factory=lambda: Artifact(
        dir="Users", pattern="*.lnk", description="Recent files shortcuts"
    ))

    # Настройки анализа и отчётов
    analysis: AnalysisConfig = field(default_factory=AnalysisConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    report: ReportConfig = field(default_factory=ReportConfig)


# ---------------------------------------------------------------------------
# Глобальный экземпляр (импортируется в модулях)
# ---------------------------------------------------------------------------
CONFIG = Config()
