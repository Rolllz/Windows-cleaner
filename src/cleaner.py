import logging
from pathlib import Path
from typing import Callable

from src.config import Config
from src.utils import resolve_path, find_user_paths, safe_remove

# Импорт библиотеки для работы с реестром (чтение/парсинг)
try:
    from Registry import Registry as WinRegistry
except ImportError:
    WinRegistry = None


def _clean_dir_files(
    target_dir: Path,
    pattern: str,
    config: Config,
    logger: logging.Logger,
    description: str
) -> bool:
    """Универсальная очистка директории по паттерну."""
    if not target_dir.is_dir():
        logger.warning(f"[SKIP] Директория не найдена: {target_dir}")
        return True

    files = list(target_dir.glob(pattern))
    if not files:
        logger.info(f"[SKIP] Файлы по паттерну '{pattern}' не найдены в {target_dir}")
        return True

    logger.info(f"Начало очистки: {description} ({len(files)} объектов)")
    for file_path in files:
        safe_remove(file_path, config.output.dry_run, logger)
    return True


def clean_prefetch(config: Config, logger: logging.Logger) -> bool:
    """Очистка папки Prefetch (.pf и .db)."""
    target = resolve_path(config.paths.base_mount, config.paths.prefetch)
    return _clean_dir_files(target, "*.pf", config, logger, "Prefetch *.pf") and \
           _clean_dir_files(target, "*.db", config, logger, "Prefetch *.db")


def clean_evtx(config: Config, logger: logging.Logger) -> bool:
    """Очистка системных журналов событий (.evtx)."""
    target = resolve_path(config.paths.base_mount, config.paths.evtx_logs)
    return _clean_dir_files(target, "*.evtx", config, logger, "Windows Event Logs")


def clean_amcache(config: Config, logger: logging.Logger) -> bool:
    """Очистка Amcache.hve (история запуска программ)."""
    target = resolve_path(config.paths.base_mount, config.paths.amcache)
    # Удаляем основной hive и сопутствующие транзакционные логи
    safe_remove(target, config.output.dry_run, logger)
    safe_remove(target.parent / f"{target.name}.LOG1", config.output.dry_run, logger)
    safe_remove(target.parent / f"{target.name}.LOG2", config.output.dry_run, logger)
    safe_remove(target.parent / f"{target.name}.regtrans-ms", config.output.dry_run, logger)
    return True


def clean_user_traces(config: Config, logger: logging.Logger) -> bool:
    """Очистка Recent Docs и ThumbCache по всем профилям."""
    success = True
    
    # 1. Recent Files
    recent_pattern = "*/AppData/Roaming/Microsoft/Windows/Recent/*.lnk"
    recent_paths = find_user_paths(config.paths.base_mount, config.paths.recent_docs_base, recent_pattern)
    if recent_paths:
        logger.info(f"Найдено Recent-файлов: {len(recent_paths)}")
        for p in recent_paths:
            if not safe_remove(p, config.output.dry_run, logger):
                success = False
    else:
        logger.info("[SKIP] Recent-файлы не найдены")

    # 2. ThumbCache
    thumb_pattern = "*/AppData/Local/Microsoft/Windows/Explorer/thumbcache_*.db"
    thumb_paths = find_user_paths(config.paths.base_mount, config.paths.thumbcache_base, thumb_pattern)
    if thumb_paths:
        logger.info(f"Найдено ThumbCache-файлов: {len(thumb_paths)}")
        for p in thumb_paths:
            if not safe_remove(p, config.output.dry_run, logger):
                success = False
    else:
        logger.info("[SKIP] ThumbCache не найден")

    return success


def clean_registry(config: Config, logger: logging.Logger) -> bool:
    """
    Очистка реестра: USBSTOR, Setup, Installer.
    Примечание: python-registry поддерживает только чтение.
    В dry-run режиме парсит и логирует ключи.
    В рабочем режиме удаляет транзакционные логи (.LOG*, .REGTRANS-MS),
    что сбрасывает незакоммиченные изменения и снижает forensic-артефакты.
    """
    if WinRegistry is None:
        logger.error("[ERR] Библиотека 'python-registry' не найдена. Пропускаю реестр.")
        return False

    reg_path = resolve_path(config.paths.base_mount, config.paths.registry_hives)
    if not reg_path.is_dir():
        logger.warning(f"[SKIP] Директория реестра не найдена: {reg_path}")
        return True

    target_keys = {
        "SYSTEM": [
            "Select",
            "ControlSet001\\Enum\\USBSTOR",
            "ControlSet001\\Enum\\SWD",
        ],
        "SOFTWARE": [
            "Microsoft\\Windows\\CurrentVersion\\Setup",
            "Microsoft\\Windows\\CurrentVersion\\Installer",
        ]
    }

    logger.info("Сканирование реестра на наличие артефактов...")
    for hive_name, keys in target_keys.items():
        hive_file = reg_path / hive_name
        if not hive_file.exists():
            continue

        try:
            reg = WinRegistry(str(hive_file))
            for key_path in keys:
                try:
                    reg.open(key_path)
                    logger.info(f"[DRY] Найден ключ для очистки: {hive_name}\\{key_path}")
                except Exception:
                    pass  # Ключ отсутствует — это норма
        except Exception as exc:
            logger.error(f"[ERR] Ошибка чтения {hive_file}: {exc}")

    # Удаление транзакционных логов реестра (безопасно для offline-образов)
    for log_ext in ("*.LOG1", "*.LOG2", "*.regtrans-ms", "*.blf"):
        _clean_dir_files(reg_path, log_ext, config, logger, f"Registry logs {log_ext}")
    
    return True


# Маппинг артефактов на функции
CLEANERS: dict[str, Callable[[Config, logging.Logger], bool]] = {
    "prefetch": clean_prefetch,
    "evtx": clean_evtx,
    "amcache": clean_amcache,
    "user_traces": clean_user_traces,
    "registry": clean_registry,
}


def run_cleanup(config: Config, logger: logging.Logger) -> None:
    """Оркестратор запуска всех модулей очистки."""
    logger.info("=" * 40)
    logger.info(f"ЗАПУСК ОЧИСТКИ | Dry-Run: {config.output.dry_run}")
    logger.info(f"Точка монтирования: {config.paths.base_mount}")
    logger.info("=" * 40)

    # Маппинг флагов артефактов на функции
    artifact_flags = {
        "prefetch": config.artifacts.clean_prefetch,
        "evtx": config.artifacts.clean_evtx,
        "amcache": config.artifacts.clean_prefetch,  # Amcache часто идёт вместе с Prefetch
        "user_traces": config.artifacts.clean_user_traces,
        "registry": config.artifacts.clean_registry,
    }

    for name, enabled in artifact_flags.items():
        if not enabled:
            logger.info(f"[SKIP] {name.upper()} отключён в конфигурации")
            continue

        cleaner_func = CLEANERS.get(name)
        if not cleaner_func:
            logger.error(f"[ERR] Неизвестный модуль очистки: {name}")
            continue

        try:
            cleaner_func(config, logger)
        except Exception as exc:
            logger.error(f"[ERR] Критическая ошибка в модуле {name}: {exc}")
        finally:
            logger.info("-" * 40)

    logger.info("✅ ОЧИСТКА ЗАВЕРШЕНА")
