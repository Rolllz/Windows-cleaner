# ==============================================================================
# WiperX — utils/logger.py
# Единый логгер: Rich для консоли, файловый handler для логов
# ==============================================================================

import logging
import os
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme

# ── Тема консоли ──────────────────────────────────────────────────────────────
_THEME = Theme(
    {
        "logging.level.debug":   "dim cyan",
        "logging.level.info":    "bold green",
        "logging.level.warning": "bold yellow",
        "logging.level.error":   "bold red",
        "logging.level.critical":"bold white on red",
    }
)

# ── Глобальный Console (можно импортировать в других модулях) ─────────────────
console = Console(theme=_THEME, highlight=True, soft_wrap=True)

# ── Имя корневого логгера приложения ──────────────────────────────────────────
_APP_LOGGER = "wiperx"


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """
    Возвращает логгер для модуля.

    Использование:
        from utils.logger import get_logger
        log = get_logger(__name__)
        log.info("Привет!")
    """
    return logging.getLogger(f"{_APP_LOGGER}.{name}" if name else _APP_LOGGER)


def setup_logging(
    log_level: str = "INFO",
    log_file: Optional[Path] = None,
    verbose: bool = False,
) -> None:
    """
    Инициализирует логирование.

    Args:
        log_level:  Уровень логирования (DEBUG / INFO / WARNING / ERROR).
        log_file:   Путь к файлу лога. Если None — только консоль.
        verbose:    Если True — форсирует уровень DEBUG.
    """
    level = logging.DEBUG if verbose else getattr(logging, log_level.upper(), logging.INFO)

    # ── Rich-хэндлер для консоли ──────────────────────────────────────────────
    rich_handler = RichHandler(
        console=console,
        level=level,
        show_time=True,
        show_path=verbose,          # путь к файлу — только в verbose-режиме
        rich_tracebacks=True,
        tracebacks_show_locals=verbose,
        log_time_format="[%H:%M:%S]",
        markup=True,
    )

    handlers: list[logging.Handler] = [rich_handler]

    # ── Файловый хэндлер ──────────────────────────────────────────────────────
    if log_file is not None:
        log_file = Path(log_file)
        log_file.parent.mkdir(parents=True, exist_ok=True)

        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)           # в файл всегда всё
        file_handler.setFormatter(
            logging.Formatter(
                fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        handlers.append(file_handler)

    # ── Корневой логгер приложения ────────────────────────────────────────────
    app_logger = logging.getLogger(_APP_LOGGER)
    app_logger.setLevel(logging.DEBUG)      # фильтрацию делают хэндлеры
    app_logger.handlers.clear()
    app_logger.propagate = False

    for h in handlers:
        app_logger.addHandler(h)

    # ── Заглушить шумные сторонние библиотеки ─────────────────────────────────
    for noisy in ("urllib3", "chardet", "charset_normalizer"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    app_logger.debug("Логгер инициализирован [уровень=%s]", log_level.upper())
