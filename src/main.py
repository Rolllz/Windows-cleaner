#!/usr/bin/env python3
"""
WiperX — точка входа
Зачистка артефактов активности пользователя на Windows-системе
"""

import sys
import argparse
from pathlib import Path

# ── Минимальная проверка версии Python ───────────────────────────────────────
if sys.version_info < (3, 10):
    sys.exit("[✗] Требуется Python 3.10 или выше.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="wiperx",
        description="WiperX — зачистка артефактов активности Windows",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:
  sudo python3 main.py --drive /mnt/windows
  sudo python3 main.py --drive /mnt/windows --dry-run
  sudo python3 main.py --drive /mnt/windows --verbose
        """,
    )

    # ── Обязательный аргумент ─────────────────────────────────────────────────
    parser.add_argument(
        "--drive",
        type=Path,
        required=True,
        metavar="PATH",
        help="Точка монтирования Windows-раздела (например, /mnt/windows)",
    )

    # ── Режимы работы ─────────────────────────────────────────────────────────
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Симуляция: показать что будет удалено, не удалять",
    )

    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        default=False,
        help="Подробный вывод хода работы",
    )

    # ── Выбор модулей (заглушки, раскроем позже) ─────────────────────────────
    parser.add_argument(
        "--skip",
        nargs="+",
        metavar="MODULE",
        default=[],
        choices=[
            "prefetch", "evtx", "lnk", "registry",
            "sru", "amcache", "bam", "thumbcache"
        ],
        help="Пропустить указанные модули зачистки",
    )

    return parser.parse_args()


def validate_drive(drive: Path) -> None:
    """Проверяет, что путь к разделу существует и похож на Windows."""
    if not drive.exists():
        sys.exit(f"[✗] Путь не найден: {drive}")
    if not drive.is_dir():
        sys.exit(f"[✗] Путь не является директорией: {drive}")

    # Ищем характерные папки Windows
    windows_markers = ["Windows", "Users", "Program Files"]
    found = [m for m in windows_markers if (drive / m).exists()]

    if not found:
        sys.exit(
            f"[✗] Раздел по пути '{drive}' не похож на Windows-систему.\n"
            f"    Ожидались папки: {', '.join(windows_markers)}"
        )


def main() -> None:
    args = parse_args()

    # Проверка раздела
    validate_drive(args.drive)

    # ── Импорт после валидации (быстрый старт, ошибки импорта — позже) ────────
    try:
        from rich.console import Console
        from rich.panel import Panel
        from rich.text import Text
    except ImportError:
        sys.exit("[✗] Библиотека 'rich' не найдена. Запусти run.sh для установки.")

    console = Console()

    # ── Шапка ─────────────────────────────────────────────────────────────────
    console.print(Panel(
        Text("WiperX  —  Windows Artifact Cleaner", justify="center", style="bold cyan"),
        subtitle=f"Раздел: [bold]{args.drive}[/bold]",
        border_style="cyan",
    ))

    if args.dry_run:
        console.print("[bold yellow][!] Режим DRY-RUN — ничего не будет удалено[/bold yellow]\n")

    if args.verbose:
        console.print(f"[dim]Пропускаемые модули: {args.skip or 'нет'}[/dim]\n")

    # ── Запуск модулей (заглушки — раскроем в следующих файлах) ──────────────
    modules = [
        ("prefetch",    "Prefetch-файлы"),
        ("evtx",        "Журналы событий (.evtx)"),
        ("lnk",         "LNK-файлы (Recent)"),
        ("registry",    "Артефакты реестра"),
        ("sru",         "SRUDB.dat"),
        ("amcache",     "Amcache.hve"),
        ("bam",         "BAM (Background Activity Monitor)"),
        ("thumbcache",  "Thumbcache / IconCache"),
    ]

    for module_id, module_name in modules:
        if module_id in args.skip:
            console.print(f"  [dim]⊘  {module_name} — пропущен[/dim]")
            continue

        console.print(f"  [cyan]▶[/cyan]  {module_name} ...", end=" ")

        # TODO: заменить на реальный вызов модуля
        # result = run_module(module_id, args.drive, args.dry_run, args.verbose)
        console.print("[green]OK[/green]")  # заглушка

    console.print()
    console.print("[bold green][✓] WiperX завершил работу.[/bold green]")


if __name__ == "__main__":
    main()
