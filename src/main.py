#!/usr/bin/env python3

import sys
import logging
import importlib
import traceback
from pathlib import Path
from typing import Optional
from utils.logger import setup_logging

if sys.version_info < (3, 10):
    sys.exit("[✗] Требуется Python 3.10 или выше.")

try:
    import argparse
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text
    from rich.progress import (
        Progress, SpinnerColumn, TextColumn,
        BarColumn, TimeElapsedColumn, TaskProgressColumn,
    )
    from rich.table import Table
    from rich import box
except ImportError as e:
    sys.exit(f"[✗] Не найдена зависимость: {e}. Запусти run.sh для установки.")

console = Console()

ALL_MODULES = [
    ("prefetch",   "Prefetch-файлы"),
    ("evtx",       "Журналы событий (.evtx)"),
    ("lnk",        "LNK-файлы / Recent"),
    ("registry",   "Артефакты реестра"),
    ("sru",        "SRUDB.dat"),
    ("amcache",    "Amcache.hve"),
    ("jumplists",  "Jump Lists"),
    ("timestamps", "Временные метки (NTFS)"),
]

ALL_MODULE_IDS = [m[0] for m in ALL_MODULES]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="wiperx",
        description="WiperX — зачистка артефактов активности Windows",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры:
  python3 main.py --drive /mnt/windows
  python3 main.py --drive /mnt/windows --dry-run
  python3 main.py --drive /mnt/windows --only amcache jumplists
  python3 main.py --drive /mnt/windows --skip evtx registry --verbose
        """,
    )

    parser.add_argument(
        "--drive",
        type=Path,
        required=True,
        metavar="PATH",
        help="Точка монтирования Windows-раздела (например, /mnt/windows)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Симуляция: показать что будет затронуто, без изменений",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        default=False,
        help="Подробный вывод",
    )
    parser.add_argument(
        "--skip",
        nargs="+",
        metavar="MODULE",
        default=[],
        choices=ALL_MODULE_IDS,
        help="Пропустить указанные модули",
    )
    parser.add_argument(
        "--only",
        nargs="+",
        metavar="MODULE",
        default=[],
        choices=ALL_MODULE_IDS,
        help="Запустить только указанные модули",
    )
    parser.add_argument(
        "--log",
        type=Path,
        metavar="FILE",
        default=None,
        help="Путь к файлу лога (опционально)",
    )
    parser.add_argument(
        "--passes",
        type=int,
        default=None,
        metavar="N",
        help="Кол-во проходов перезаписи (переопределяет SECURE_WIPE_PASSES из config)",
    )
    parser.add_argument(
        "--report",
        type=Path,
        metavar="FILE",
        default=None,
        help="Сохранить итоговый отчёт в JSON-файл",
    )

    return parser.parse_args()


def validate_drive(drive: Path) -> None:
    if not drive.exists():
        sys.exit(f"[✗] Путь не найден: {drive}")
    if not drive.is_dir():
        sys.exit(f"[✗] Путь не является директорией: {drive}")

    markers = ["Windows", "Users", "Program Files"]
    found = [m for m in markers if (drive / m).exists()]
    if not found:
        sys.exit(
            f"[✗] Раздел '{drive}' не похож на Windows-систему.\n"
            f"    Ожидались папки: {', '.join(markers)}"
        )


def load_module(module_id: str):
    """Динамически загружает модуль из src/modules/<id>.py."""
    try:
        mod = importlib.import_module(f".modules.{module_id}", package="src")
        return mod
    except ModuleNotFoundError:
        return None


def run_module(
    module_id: str,
    drive: Path,
    dry_run: bool,
    verbose: bool,
    passes: int | None,
) -> dict:
    """
    Запускает модуль и возвращает результат в виде словаря:
      { "status": "ok"|"skipped"|"error", "cleaned": int, "details": str }
    """
    mod = load_module(module_id)

    if mod is None:
        return {"status": "missing", "cleaned": 0, "details": "модуль не найден"}

    if not hasattr(mod, "run"):
        return {"status": "error", "cleaned": 0, "details": "отсутствует функция run()"}

    kwargs = {"drive": drive, "dry_run": dry_run, "verbose": verbose}
    if passes is not None:
        kwargs["passes"] = passes

    try:
        result = mod.run(**kwargs)
        if not isinstance(result, dict):
            result = {"status": "ok", "cleaned": 0, "details": str(result)}
        return result
    except Exception as exc:
        tb = traceback.format_exc()
        logging.getLogger(module_id).debug(tb)
        return {"status": "error", "cleaned": 0, "details": str(exc)}


def build_report_table(results: dict[str, dict]) -> Table:
    table = Table(
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
        title="[bold]Итоговый отчёт WiperX[/bold]",
    )
    table.add_column("Модуль",    style="cyan",  no_wrap=True)
    table.add_column("Статус",    justify="center")
    table.add_column("Очищено",   justify="right", style="magenta")
    table.add_column("Детали",    style="dim")

    STATUS_STYLE = {
        "ok":      "[bold green]✓ OK[/bold green]",
        "skipped": "[dim]⊘ Пропущен[/dim]",
        "error":   "[bold red]✗ Ошибка[/bold red]",
        "missing": "[yellow]? Не найден[/yellow]",
    }

    for module_id, module_name in ALL_MODULES:
        if module_id not in results:
            continue
        r = results[module_id]
        status_str = STATUS_STYLE.get(r["status"], r["status"])
        cleaned = str(r.get("cleaned", 0)) if r["status"] == "ok" else "—"
        details = str(r.get("details", ""))[:72]
        table.add_row(module_name, status_str, cleaned, details)

    return table


def save_report(path: Path, results: dict, drive: Path, dry_run: bool) -> None:
    import json
    from datetime import datetime, timezone

    report = {
        "wiperx_version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "drive": str(drive),
        "dry_run": dry_run,
        "modules": results,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    console.print(f"\n[dim]Отчёт сохранён:[/dim] [bold]{path}[/bold]")


def main() -> None:
    args = parse_args()
    validate_drive(args.drive)
    setup_logging(
        log_level="DEBUG" if args.verbose else LOG_LEVEL,
        log_file=LOG_FILE if args.log is None else args.log,
        use_rich=LOG_USE_RICH
    )

    # ── Шапка ─────────────────────────────────────────────────
    console.print()
    console.print(Panel(
        Text("WiperX  —  Windows Artifact Cleaner", justify="center", style="bold cyan"),
        subtitle=f"Раздел: [bold]{args.drive}[/bold]",
        border_style="cyan",
    ))

    if args.dry_run:
        console.print("[bold yellow][!] DRY-RUN — реальных изменений не будет[/bold yellow]")
    if args.passes:
        console.print(f"[dim]Проходов перезаписи: {args.passes}[/dim]")
    console.print()

    # ── Формирование очереди модулей ──────────────────────────
    queue = []
    for module_id, module_name in ALL_MODULES:
        if args.only and module_id not in args.only:
            continue
        if module_id in args.skip:
            continue
        queue.append((module_id, module_name))

    skipped = [
        (mid, mname) for mid, mname in ALL_MODULES
        if (mid, mname) not in queue
    ]

    results: dict[str, dict] = {}

    # Сразу фиксируем пропущенные
    for module_id, _ in skipped:
        results[module_id] = {"status": "skipped", "cleaned": 0, "details": ""}

    # ── Прогресс-бар ──────────────────────────────────────────
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=36),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as progress:
        overall = progress.add_task("Общий прогресс", total=len(queue))

        for module_id, module_name in queue:
            progress.update(overall, description=f"[bold cyan]{module_name}")
            result = run_module(
                module_id,
                drive=args.drive,
                dry_run=args.dry_run,
                verbose=args.verbose,
                passes=args.passes,
            )
            results[module_id] = result
            progress.advance(overall)

            if args.verbose:
                color = "green" if result["status"] == "ok" else "red"
                console.log(
                    f"[{color}]{module_name}[/{color}] → "
                    f"{result['status']} | очищено: {result.get('cleaned', 0)}"
                )

    # ── Итоговая таблица ──────────────────────────────────────
    console.print()
    console.print(build_report_table(results))

    # ── Сводка ────────────────────────────────────────────────
    total_cleaned = sum(r.get("cleaned", 0) for r in results.values())
    errors = [mid for mid, r in results.items() if r["status"] == "error"]

    console.print()
    if errors:
        console.print(
            f"[bold red][✗] Завершено с ошибками:[/bold red] "
            f"{', '.join(errors)}"
        )
    else:
        console.print(
            f"[bold green][✓] WiperX завершил работу.[/bold green]  "
            f"Артефактов очищено: [bold magenta]{total_cleaned}[/bold magenta]"
        )

    if args.dry_run:
        console.print("[yellow]Напоминание: DRY-RUN, ничего не было удалено.[/yellow]")

    # ── Сохранение отчёта ─────────────────────────────────────
    if args.report:
        save_report(args.report, results, args.drive, args.dry_run)

    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
