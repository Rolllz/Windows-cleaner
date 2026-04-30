from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Paths:
    """Относительные пути к артефактам Windows."""
    base_mount: Path = Path("/mnt/windows")
    prefetch: Path = Path("Windows/Prefetch")
    amcache: Path = Path("Windows/AppCompat/Programs/Amcache.hve")
    thumbcache_base: Path = Path("Users")
    recent_docs_base: Path = Path("Users")
    evtx_logs: Path = Path("Windows/System32/winevt/Logs")
    registry_hives: Path = Path("Windows/System32/config")


@dataclass(frozen=True)
class Artifacts:
    """Флаги включения/выключения модулей очистки."""
    clean_prefetch: bool = True
    clean_evtx: bool = True
    clean_registry: bool = True
    clean_user_traces: bool = True


@dataclass(frozen=True)
class Output:
    """Настройки вывода и режима работы."""
    dry_run: bool = False
    verbose: bool = False
    force_no_color: bool = False


@dataclass(frozen=True)
class Config:
    """Корневой объект конфигурации. Неизменяемый (frozen)."""
    paths: Paths = Paths()
    artifacts: Artifacts = Artifacts()
    output: Output = Output()
