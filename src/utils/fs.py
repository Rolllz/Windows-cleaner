# ==============================================================================
# WiperX — utils/fs.py
# Файловые утилиты: поиск, проверка, монтирование образов
# ==============================================================================

import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Generator, Optional

from utils.logger import get_logger

log = get_logger(__name__)


# ══════════════════════════════════════════════════════════════════════════════
# 1. Поиск файлов
# ══════════════════════════════════════════════════════════════════════════════

def find_files(
    root: Path,
    patterns: list[str],
    case_sensitive: bool = False,
) -> Generator[Path, None, None]:
    """
    Рекурсивно ищет файлы по glob-паттернам.

    Args:
        root:           Корневая директория поиска.
        patterns:       Список паттернов, например ["*.evtx", "SAM", "SYSTEM"].
        case_sensitive: Учитывать регистр имени файла.

    Yields:
        Path — найденные файлы.

    Example:
        for p in find_files(Path("/mnt/c"), ["*.evtx"]):
            print(p)
    """
    if not root.exists():
        log.warning("Директория не найдена: %s", root)
        return

    for pattern in patterns:
        for match in root.rglob(pattern):
            if not match.is_file():
                continue
            if not case_sensitive:
                # Повторная проверка без учёта регистра (rglob чувствителен на Linux)
                if match.name.lower() != Path(pattern).name.lower() and "*" not in pattern:
                    continue
            yield match


def find_first(
    root: Path,
    patterns: list[str],
) -> Optional[Path]:
    """Возвращает первый найденный файл или None."""
    for p in find_files(root, patterns):
        return p
    return None


# ══════════════════════════════════════════════════════════════════════════════
# 2. Проверка путей
# ══════════════════════════════════════════════════════════════════════════════

def ensure_dir(path: Path) -> Path:
    """Создаёт директорию (включая родителей), если не существует."""
    path.mkdir(parents=True, exist_ok=True)
    log.debug("Директория обеспечена: %s", path)
    return path


def is_readable(path: Path) -> bool:
    """Проверяет, доступен ли файл для чтения."""
    return path.exists() and os.access(path, os.R_OK)


def require_file(path: Path) -> Path:
    """
    Возвращает путь, если файл доступен для чтения.
    Иначе — бросает FileNotFoundError.
    """
    if not is_readable(path):
        raise FileNotFoundError(f"Файл недоступен или не существует: {path}")
    return path


def safe_stat(path: Path) -> Optional[os.stat_result]:
    """Возвращает os.stat() или None при ошибке доступа."""
    try:
        return path.stat()
    except (PermissionError, OSError) as e:
        log.debug("stat() недоступен для %s: %s", path, e)
        return None


# ══════════════════════════════════════════════════════════════════════════════
# 3. Монтирование образов (raw / E01 / VMDK / VHD)
# ══════════════════════════════════════════════════════════════════════════════

class MountedImage:
    """
    Контекстный менеджер для монтирования дискового образа.

    Поддерживаемые форматы:
        - .raw / .dd / .img  → mount -o loop
        - .E01               → ewfmount + mount
        - .vmdk / .vhd       → qemu-nbd + mount

    Требования:
        - root-привилегии (или sudo)
        - Установлены: ewfmount (для E01), qemu-nbd (для vmdk/vhd)

    Использование:
        with MountedImage(Path("disk.raw")) as mnt:
            for f in find_files(mnt, ["*.evtx"]):
                ...
    """

    _NBD_DEVICE = "/dev/nbd0"

    def __init__(self, image_path: Path, partition_index: int = 1) -> None:
        self.image_path = require_file(image_path)
        self.partition_index = partition_index
        self._mount_point: Optional[Path] = None
        self._ewf_dir: Optional[Path] = None
        self._nbd_used: bool = False

    # ── Вход в контекст ───────────────────────────────────────────────────────
    def __enter__(self) -> Path:
        suffix = self.image_path.suffix.lower()

        if suffix in (".raw", ".dd", ".img", ""):
            self._mount_point = self._mount_raw(self.image_path)

        elif suffix == ".e01":
            self._mount_point = self._mount_e01(self.image_path)

        elif suffix in (".vmdk", ".vhd", ".vhdx"):
            self._mount_point = self._mount_nbd(self.image_path)

        else:
            raise ValueError(f"Неподдерживаемый формат образа: {suffix}")

        log.info("Образ смонтирован: %s → %s", self.image_path.name, self._mount_point)
        return self._mount_point

    # ── Выход из контекста ────────────────────────────────────────────────────
    def __exit__(self, *_) -> None:
        self._cleanup()

    # ── RAW / DD / IMG ────────────────────────────────────────────────────────
    def _mount_raw(self, image: Path) -> Path:
        mnt = Path(tempfile.mkdtemp(prefix="wiperx_raw_"))
        offset = self._get_partition_offset(image, self.partition_index)
        cmd = ["mount", "-o", f"loop,ro,offset={offset}", str(image), str(mnt)]
        self._run(cmd, f"Не удалось смонтировать RAW-образ: {image}")
        return mnt

    # ── E01 (EWF) ─────────────────────────────────────────────────────────────
    def _mount_e01(self, image: Path) -> Path:
        if not shutil.which("ewfmount"):
            raise RuntimeError("ewfmount не найден. Установи libewf-tools.")

        self._ewf_dir = Path(tempfile.mkdtemp(prefix="wiperx_ewf_"))
        self._run(
            ["ewfmount", str(image), str(self._ewf_dir)],
            "ewfmount завершился с ошибкой",
        )

        ewf_raw = self._ewf_dir / "ewf1"
        mnt = Path(tempfile.mkdtemp(prefix="wiperx_ewf_mnt_"))
        offset = self._get_partition_offset(ewf_raw, self.partition_index)
        self._run(
            ["mount", "-o", f"loop,ro,offset={offset}", str(ewf_raw), str(mnt)],
            "Не удалось смонтировать E01-образ",
        )
        return mnt

    # ── VMDK / VHD (qemu-nbd) ─────────────────────────────────────────────────
    def _mount_nbd(self, image: Path) -> Path:
        if not shutil.which("qemu-nbd"):
            raise RuntimeError("qemu-nbd не найден. Установи qemu-utils.")

        self._run(["modprobe", "nbd", "max_part=16"], "Не удалось загрузить модуль nbd")
        self._run(
            ["qemu-nbd", "--connect", self._NBD_DEVICE, str(image)],
            "qemu-nbd завершился с ошибкой",
        )
        self._nbd_used = True

        nbd_part = Path(f"{self._NBD_DEVICE}p{self.partition_index}")
        mnt = Path(tempfile.mkdtemp(prefix="wiperx_nbd_"))
        self._run(
            ["mount", "-o", "ro", str(nbd_part), str(mnt)],
            "Не удалось смонтировать NBD-раздел",
        )
        return mnt

    # ── Смещение раздела ──────────────────────────────────────────────────────
    @staticmethod
    def _get_partition_offset(image: Path, index: int) -> int:
        """
        Возвращает байтовое смещение раздела через fdisk -l.
        При ошибке возвращает 0 (монтирование без смещения).
        """
        try:
            result = subprocess.run(
                ["fdisk", "-l", "-u", str(image)],
                capture_output=True, text=True, timeout=15,
            )
            for line in result.stdout.splitlines():
                parts = line.split()
                # Ищем строку раздела: /dev/... или img1 / p1 и т.д.
                if len(parts) >= 3 and (
                    parts[0].endswith(str(index)) or
                    f"p{index}" in parts[0]
                ):
                    sector_start = int(parts[1])
                    # Размер сектора — 512 байт по умолчанию
                    return sector_start * 512
        except Exception as e:
            log.debug("fdisk не смог определить смещение: %s", e)
        return 0

    # ── Размонтирование ───────────────────────────────────────────────────────
    def _cleanup(self) -> None:
        if self._mount_point and self._mount_point.exists():
            subprocess.run(["umount", str(self._mount_point)], check=False)
            try:
                self._mount_point.rmdir()
            except OSError:
                pass
            log.debug("Размонтировано: %s", self._mount_point)

        if self._ewf_dir and self._ewf_dir.exists():
            subprocess.run(["umount", str(self._ewf_dir)], check=False)
            try:
                self._ewf_dir.rmdir()
            except OSError:
                pass

        if self._nbd_used:
            subprocess.run(
                ["qemu-nbd", "--disconnect", self._NBD_DEVICE], check=False
            )

    # ── Запуск команды ────────────────────────────────────────────────────────
    @staticmethod
    def _run(cmd: list[str], error_msg: str) -> None:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"{error_msg}\nSTDERR: {result.stderr.strip()}")
