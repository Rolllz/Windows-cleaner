#!/usr/bin/env python3
import sys
import logging
import argparse
from pathlib import Path

from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.align import Align

from src.config import Config, Paths, Artifacts, Output
from src.utils import validate_mount
from src.cleaner import run_cleanup


def check_python_version() -> None:
    if sys.version_info < (3, 10):
        print("❌ Требуется Python 3.10 или выше.", file=sys.stderr)
        sys.exit(1)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="wiperx",
        description="WiperX: Очистка артефактов Windows (Prefetch, EVTX, Registry, User Traces)",
        epilog="Пример: bash run.sh --mount /media/win --dry-run --verbose"
    )
    parser.add_argument(
        "--mount", type=Path, default=Path("/mnt/windows"),
        help="Точка монтирования Windows (по умолчанию: /mnt/windows)"
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Режим предпросмотра: только логирование, файлы не удаляются"
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Подробный вывод (DEBUG уровень)"
    )
    parser.add_argument(
        "--no-color", action="store_true",
        help="Отключить цветовое форматирование консоли"
    )
    return parser.parse_args()


def main() -> None:
    check_python_version()
    args = parse_args()

    # Rich Console & Logger
    console = Console(no_color=args.no_color, force_terminal=True)
    logging.basicConfig(
        level="DEBUG" if args.verbose else "INFO",
        format="%(message)s",
        datefmt="[%H:%M:%S]",
        handlers=[RichHandler(
            console=console,
            rich_tracebacks=True,
            show_time=True,
            show_path=False,
            markup=False  # Отключаем парсинг rich-тегов в log-сообщениях
        )]
    )
    logger = logging.getLogger("wiperx")

    # Сборка конфигурации
    config = Config(
        paths=Paths(base_mount=args.mount),
        artifacts=Artifacts(),
        output=Output(dry_run=args.dry_run, verbose=args.verbose, force_no_color=args.no_color)
    )

    # Приветственный баннер
    console.print(Panel(
        Align.center("[bold cyan]WiperX v1.0.0[/bold cyan]\nОчистка forensic-артефактов Windows"),
        style="bold blue",
        expand=False,
        padding=(1, 2)
    ))
    console.print()

    # Валидация точки монтирования
    if not validate_mount(config.paths.base_mount, logger):
        console.print("[red]❌ Прерывание: точка монтирования некорректна или не содержит Windows.[/red]")
        sys.exit(1)

    # Запуск оркестратора
    try:
        run_cleanup(config, logger)
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️ Прервано пользователем (Ctrl+C).[/yellow]")
        sys.exit(130)
    except Exception as e:
        logger.error(f"[ERR] Неожиданная ошибка: {e}", exc_info=args.verbose)
        sys.exit(1)

    console.print("[bold green]✅ ОЧИСТКА УСПЕШНО ЗАВЕРШЕНА[/bold green]")
    sys.exit(0)


if __name__ == "__main__":
    main()
