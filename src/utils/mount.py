# ==============================================================================
# WiperX — utils/mount.py
#
# Монтирование forensic-образов и работа с путями.
# Поддерживает:
#   • RAW / dd  — через loop device (Linux) или прямой путь
#   • EWF / E01 — через ewfmount (libewf) + loop device
#   • Прямой путь к смонтированной директории (live / already mounted)
#
# Зависимости (системные):
#   • ewfmount  — пакет libewf-tools (apt install libewf-dev / ewf-tools)
#   • mount     — стандартный Linux
#   • losetup   — стандартный Linux
#
# Зависимости (Python):
#   • pathlib, subprocess, tempfile, shutil — stdlib only
# ==============================================================================

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from enum import Enum, auto
from pathlib import Path
from typing import Optional

from utils.logger import get_logger

log = get_logger(__name__)


# ══════════════════════════════════════════════════════════════════════════════
# Enum типов образа
# ══════════════════════════════════════════════════════════════════════════════

class ImageType(Enum):
    RAW       = auto()   # .dd, .img, .raw
    EWF       = auto()   # .E01, .ewf
    DIRECTORY = auto()   # Уже смонтированная директория или live-путь
    UNKNOWN   = auto()


# ══════════════════════════════════════════════════════════════════════════════
# Вспомогательные функции
# ══════════════════════════════════════════════════════════════════════════════

def detect_image_type(path: Path) -> ImageType:
    """
    Определяет тип образа по расширению файла или типу пути.

    Args:
        path: Путь к файлу образа или директории.

    Returns:
        ImageType — тип обнаруженного источника.
    """
    if path.is_dir():
        return ImageType.DIRECTORY

    suffix = path.suffix.lower()

    if suffix in {".dd", ".img", ".raw", ".bin"}:
        return ImageType.RAW

    # EWF может быть .E01, .E02 ... .Ex и .ewf
    if suffix.lower().startswith(".e0") or suffix.lower() == ".ewf":
        return ImageType.EWF

    log.warning(f"Неизвестный тип образа: {path.name} — попытка угадать по содержимому не реализована.")
    return ImageType.UNKNOWN


def _check_tool(tool: str) -> bool:
    """Проверяет наличие системной утилиты в PATH."""
    found = shutil.which(tool) is not None
    if not found:
        log.error(f"Системная утилита не найдена: '{tool}'. Установите её и повторите.")
    return found


def _run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    """
    Запускает системную команду.

    Args:
        cmd:   Список аргументов команды.
        check: Если True — бросает исключение при ненулевом коде возврата.

    Returns:
        CompletedProcess с stdout/stderr.

    Raises:
        subprocess.CalledProcessError: При check=True и ошибке выполнения.
    """
    log.debug(f"Выполняю команду: {' '.join(cmd)}")
    return subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=check,
    )


# ══════════════════════════════════════════════════════════════════════════════
# Основной класс
# ══════════════════════════════════════════════════════════════════════════════

class ImageMounter:
    """
    Менеджер контекста для монтирования forensic-образов.

    Использование:
        with ImageMounter(Path("/evidence/image.E01")) as mnt:
            # mnt.mount_point — Path к смонтированной файловой системе
            files = list(mnt.mount_point.rglob("*.evtx"))

    Поддерживаемые форматы:
        - .dd / .img / .raw  → loop mount (read-only)
        - .E01 / .ewf        → ewfmount → loop mount (read-only)
        - directory          → возвращает путь как есть (без монтирования)
    """

    def __init__(
        self,
        image_path: Path,
        partition_offset: Optional[int] = None,
    ) -> None:
        """
        Args:
            image_path:        Путь к образу или директории.
            partition_offset:  Смещение раздела в байтах (для образов с MBR).
                               Если None — монтируется весь образ.
        """
        self.image_path       = image_path.resolve()
        self.partition_offset = partition_offset
        self.image_type       = detect_image_type(self.image_path)

        # Внутреннее состояние
        self._tmp_dir:      Optional[tempfile.TemporaryDirectory] = None  # type: ignore[type-arg]
        self._ewf_dir:      Optional[Path] = None   # Куда ewfmount разворачивает .E01
        self._loop_dev:     Optional[str]  = None   # /dev/loopX
        self._mount_point:  Optional[Path] = None   # Итоговая точка монтирования
        self._mounted:      bool           = False

    # ── Публичный интерфейс ───────────────────────────────────────────────────

    @property
    def mount_point(self) -> Path:
        """
        Возвращает Path к смонтированной файловой системе.

        Raises:
            RuntimeError: Если образ ещё не смонтирован.
        """
        if not self._mounted or self._mount_point is None:
            raise RuntimeError("Образ не смонтирован. Используйте контекстный менеджер `with`.")
        return self._mount_point

    def mount(self) -> Path:
        """
        Монтирует образ и возвращает путь к файловой системе.

        Returns:
            Path к точке монтирования.

        Raises:
            FileNotFoundError:  Если файл образа не найден.
            RuntimeError:       Если монтирование завершилось с ошибкой.
            PermissionError:    Если нет прав root для mount/losetup.
        """
        if self._mounted:
            log.warning("Образ уже смонтирован. Повторное монтирование пропущено.")
            return self.mount_point

        log.info(f"Монтирую образ: {self.image_path} (тип: {self.image_type.name})")

        if not self.image_path.exists():
            raise FileNotFoundError(f"Файл образа не найден: {self.image_path}")

        # Создаём временную директорию для всех точек монтирования
        self._tmp_dir = tempfile.TemporaryDirectory(prefix="wiperx_mnt_")
        tmp = Path(self._tmp_dir.name)

        match self.image_type:
            case ImageType.DIRECTORY:
                self._mount_point = self.image_path
                self._mounted = True
                log.info(f"Директория используется напрямую: {self._mount_point}")

            case ImageType.RAW:
                raw_mount = tmp / "fs"
                raw_mount.mkdir()
                self._loop_mount(self.image_path, raw_mount)
                self._mount_point = raw_mount

            case ImageType.EWF:
                ewf_dir = tmp / "ewf"
                ewf_dir.mkdir()
                self._ewf_mount(self.image_path, ewf_dir)

                # ewfmount создаёт ewf1 внутри ewf_dir
                ewf_raw = ewf_dir / "ewf1"
                if not ewf_raw.exists():
                    raise RuntimeError(f"ewfmount не создал файл ewf1 в {ewf_dir}")

                self._ewf_dir = ewf_dir
                fs_mount = tmp / "fs"
                fs_mount.mkdir()
                self._loop_mount(ewf_raw, fs_mount)
                self._mount_point = fs_mount

            case ImageType.UNKNOWN:
                raise RuntimeError(
                    f"Неизвестный тип образа: {self.image_path.suffix}. "
                    "Поддерживаются: .dd, .img, .raw, .E01, .ewf, директория."
                )

        self._mounted = True
        log.info(f"Образ успешно смонтирован → {self._mount_point}")
        return self._mount_point

    def unmount(self) -> None:
        """
        Отмонтирует образ и освобождает все ресурсы.
        Безопасно вызывать несколько раз.
        """
        if not self._mounted:
            return

        log.info("Отмонтирую образ...")

        # 1. Отмонтируем файловую систему
        if self._mount_point and self.image_type != ImageType.DIRECTORY:
            self._run_unmount(self._mount_point)

        # 2. Освобождаем loop device
        if self._loop_dev:
            self._detach_loop(self._loop_dev)
            self._loop_dev = None

        # 3. Отмонтируем EWF
        if self._ewf_dir:
            self._run_unmount(self._ewf_dir)
            self._ewf_dir = None

        # 4. Удаляем временную директорию
        if self._tmp_dir:
            try:
                self._tmp_dir.cleanup()
            except Exception as exc:
                log.warning(f"Не удалось удалить временную директорию: {exc}")
            self._tmp_dir = None

        self._mounted      = False
        self._mount_point  = None
        log.info("Образ отмонтирован.")

    # ── Контекстный менеджер ──────────────────────────────────────────────────

    def __enter__(self) -> "ImageMounter":
        self.mount()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.unmount()

    # ── Внутренние методы ─────────────────────────────────────────────────────

    def _ewf_mount(self, ewf_path: Path, target: Path) -> None:
        """
        Монтирует EWF/E01 образ через ewfmount (libewf).

        Args:
            ewf_path: Путь к .E01 файлу.
            target:   Директория для монтирования.

        Raises:
            RuntimeError: Если ewfmount не найден или завершился с ошибкой.
        """
        if not _check_tool("ewfmount"):
            raise RuntimeError("ewfmount не найден. Установите: sudo apt install ewf-tools")

        try:
            _run(["ewfmount", str(ewf_path), str(target)])
            log.debug(f"ewfmount: {ewf_path} → {target}")
        except subprocess.CalledProcessError as exc:
            raise RuntimeError(
                f"ewfmount завершился с ошибкой:\n"
                f"  STDOUT: {exc.stdout.strip()}\n"
                f"  STDERR: {exc.stderr.strip()}"
            ) from exc

    def _loop_mount(self, image: Path, target: Path) -> None:
        """
        Монтирует RAW-образ (или ewf1) через loop device в read-only режиме.

        Args:
            image:  Путь к RAW-файлу.
            target: Точка монтирования.

        Raises:
            PermissionError: Если нет прав root.
            RuntimeError:    Если mount завершился с ошибкой.
        """
        if os.geteuid() != 0:
            raise PermissionError(
                "Для монтирования образа необходимы права root. "
                "Запустите WiperX через sudo."
            )

        if not _check_tool("mount"):
            raise RuntimeError("Утилита mount не найдена.")

        cmd = [
            "mount",
            "--read-only",
            "--options", "noexec,nosuid,nodev",
        ]

        if self.partition_offset is not None:
            cmd += ["--options", f"offset={self.partition_offset}"]

        cmd += [str(image), str(target)]

        try:
            result = _run(cmd)
            log.debug(f"loop mount: {image} → {target}")
            # Сохраняем loop device для последующего detach
            self._loop_dev = self._find_loop_device(target)
        except subprocess.CalledProcessError as exc:
            raise RuntimeError(
                f"mount завершился с ошибкой:\n"
                f"  STDOUT: {exc.stdout.strip()}\n"
                f"  STDERR: {exc.stderr.strip()}\n\n"
                "Подсказка: если образ содержит таблицу разделов, "
                "укажите partition_offset вручную."
            ) from exc

    def _find_loop_device(self, mount_point: Path) -> Optional[str]:
        """
        Находит loop device, связанный с точкой монтирования.

        Args:
            mount_point: Путь к точке монтирования.

        Returns:
            Строка вида '/dev/loop0' или None.
        """
        try:
            result = _run(["findmnt", "--noheadings", "--output", "SOURCE", str(mount_point)])
            dev = result.stdout.strip()
            if dev.startswith("/dev/loop"):
                return dev
        except Exception:
            pass
        return None

    def _run_unmount(self, path: Path) -> None:
        """
        Безопасно отмонтирует директорию (umount -l для lazy unmount).

        Args:
            path: Точка монтирования.
        """
        if not path.exists():
            return
        try:
            _run(["umount", "-l", str(path)])
            log.debug(f"umount: {path}")
        except subprocess.CalledProcessError as exc:
            log.warning(f"umount не удался для {path}: {exc.stderr.strip()}")

    def _detach_loop(self, loop_dev: str) -> None:
        """
        Освобождает loop device через losetup -d.

        Args:
            loop_dev: Строка вида '/dev/loop0'.
        """
        try:
            _run(["losetup", "-d", loop_dev])
            log.debug(f"losetup -d {loop_dev}")
        except subprocess.CalledProcessError as exc:
            log.warning(f"losetup -d не удался: {exc.stderr.strip()}")


# ══════════════════════════════════════════════════════════════════════════════
# Вспомогательные функции уровня модуля
# ══════════════════════════════════════════════════════════════════════════════

def resolve_evidence_path(raw_input: str) -> Path:
    """
    Принимает строку пути (от пользователя или CLI) и возвращает
    абсолютный Path с проверкой существования.

    Args:
        raw_input: Строка пути — может содержать `~`, относительные пути.

    Returns:
        Абсолютный Path.

    Raises:
        FileNotFoundError: Если путь не существует.
    """
    path = Path(raw_input).expanduser().resolve()
    if not path.exists():
        raise FileNotFoundError(f"Путь не существует: {path}")
    log.debug(f"Путь к артефактам разрешён: {path}")
    return path


def list_evtx_files(root: Path) -> list[Path]:
    """
    Рекурсивно ищет все .evtx файлы начиная с root.

    Args:
        root: Корневая директория поиска.

    Returns:
        Список Path к .evtx файлам (сортированный).

    Raises:
        NotADirectoryError: Если root — не директория.
    """
    if not root.is_dir():
        raise NotADirectoryError(f"Ожидалась директория, получено: {root}")

    files = sorted(root.rglob("*.evtx"))
    log.info(f"Найдено .evtx файлов: {len(files)} в {root}")
    return files


def list_registry_hives(root: Path) -> list[Path]:
    """
    Ищет стандартные файлы реестра Windows (SAM, SYSTEM, SECURITY, SOFTWARE, NTUSER.DAT).

    Args:
        root: Корневая директория (обычно C:\\Windows\\System32\\config или аналог).

    Returns:
        Список найденных файлов реестра.
    """
    HIVE_NAMES = {"SAM", "SYSTEM", "SECURITY", "SOFTWARE", "NTUSER.DAT", "UsrClass.dat"}
    found = []

    for hive_name in HIVE_NAMES:
        # Ищем без учёта регистра
        matches = [
            p for p in root.rglob("*")
            if p.name.upper() == hive_name.upper() and p.is_file()
        ]
        found.extend(matches)

    found.sort()
    log.info(f"Найдено файлов реестра: {len(found)} в {root}")
    return found
