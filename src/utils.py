import logging
import shutil
from pathlib import Path
from typing import List

from src.config import Config


def setup_logger(verbose: bool) -> logging.Logger:
    """Настраивает стандартный логгер. Rich-форматирование подключается в main.py."""
    logger = logging.getLogger("wiperx")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    if not logger.handlers:
        handler = logging.StreamHandler()
        # Префиксы уровней будут заменены Rich в main.py, если включен цветной вывод
        handler.setFormatter(logging.Formatter("%(levelname)-5s | %(message)s"))
        logger.addHandler(handler)
        logger.propagate = False

    return logger


def resolve_path(base: Path, relative: Path) -> Path:
    """Безопасно разрешает относительный путь относительно базовой директории."""
    resolved = (base / relative).resolve()
    # Защита от выхода за пределы смонтированного тома
    if not str(resolved).startswith(str(base.resolve())):
        raise ValueError(f"Path traversal blocked: {resolved}")
    return resolved


def find_user_paths(mount: Path, base_user_dir: Path, pattern: str) -> List[Path]:
    """Ищет пути по всем профилям пользователей Windows через glob."""
    users_root = mount / base_user_dir
    if not users_root.is_dir():
        return []
    return sorted(users_root.glob(pattern))


def safe_remove(target: Path, dry_run: bool, logger: logging.Logger) -> bool:
    """Удаляет файл/директорию с изоляцией ошибок и поддержкой dry-run."""
    if not target.exists():
        logger.debug(f"SKIP: Не найдено: {target}")
        return False

    if dry_run:
        logger.info(f"[DRY] Будет удалено: {target}")
        return True

    try:
        if target.is_dir():
            shutil.rmtree(target)
        else:
            target.unlink(missing_ok=True)
        logger.info(f"[OK] Удалено: {target}")
        return True
    except OSError as exc:
        logger.error(f"[ERR] Ошибка удаления {target}: {exc}")
        return False
    except Exception as exc:
        logger.error(f"[ERR] Неожиданная ошибка при удалении {target}: {exc}")
        return False


def validate_mount(mount: Path, logger: logging.Logger) -> bool:
    """Проверяет, что точка монтирования существует и похожа на Windows."""
    if not mount.exists():
        logger.error(f"[ERR] Точка монтирования не найдена: {mount}")
        return False
    if not mount.is_dir():
        logger.error(f"[ERR] Точка монтирования не является директорией: {mount}")
        return False

    windows_dir = mount / "Windows"
    if not windows_dir.is_dir():
        logger.warning(f"[WARN] {mount} не содержит папку 'Windows'. Проверьте точку монтирования.")
        return False

    logger.info(f"[OK] Windows обнаружен по пути: {mount}")
    return True
