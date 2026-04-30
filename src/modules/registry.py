# ==============================================================================
# WiperX — src/modules/registry.py
#
# Модуль работы с реестром Windows (.hive файлы).
# Поддерживает:
#   • Чтение / навигацию по ключам и значениям
#   • Удаление ключей и значений (anti-forensics следы)
#   • Правку значений (подмена данных)
#   • Работу с MRU-списками (Most Recently Used)
#   • Очистку UserAssist, RunMRU, RecentDocs, TypedPaths
#   • Работу с SYSTEM, SOFTWARE, NTUSER.DAT, SAM
#
# Зависимости:
#   • hivex          — системная библиотека (libhivex)
#   • python3-hivex  — Python-биндинги
#
# Установка:
#   apt install python3-hivex libhivex-bin
# ==============================================================================

from __future__ import annotations

import struct
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    import hivex
    from hivex import Hivex
except ImportError:
    raise ImportError(
        "[registry] python3-hivex не установлен.\n"
        "Запустите: apt install python3-hivex"
    )

from utils.logger import get_logger

log = get_logger("registry")


# ==============================================================================
# Константы — пути внутри образа к hive-файлам
# ==============================================================================

HIVE_PATHS: dict[str, list[str]] = {
    "SYSTEM":   [
        "Windows/System32/config/SYSTEM",
        "WINDOWS/system32/config/SYSTEM",
    ],
    "SOFTWARE": [
        "Windows/System32/config/SOFTWARE",
        "WINDOWS/system32/config/SOFTWARE",
    ],
    "SAM":      [
        "Windows/System32/config/SAM",
        "WINDOWS/system32/config/SAM",
    ],
    "SECURITY": [
        "Windows/System32/config/SECURITY",
        "WINDOWS/system32/config/SECURITY",
    ],
    "NTUSER":   [
        "Users/{user}/NTUSER.DAT",
        "Documents and Settings/{user}/NTUSER.DAT",
    ],
    "USRCLASS": [
        "Users/{user}/AppData/Local/Microsoft/Windows/UsrClass.dat",
    ],
}

# Ключи MRU / артефакты активности пользователя — цели для очистки
MRU_TARGETS: list[dict] = [
    {
        "hive":    "NTUSER",
        "path":    "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU",
        "desc":    "Run MRU (Win+R история)",
        "mode":    "clear_values",
    },
    {
        "hive":    "NTUSER",
        "path":    "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs",
        "desc":    "RecentDocs (последние файлы)",
        "mode":    "clear_subkeys",
    },
    {
        "hive":    "NTUSER",
        "path":    "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths",
        "desc":    "TypedPaths (адресная строка Explorer)",
        "mode":    "clear_values",
    },
    {
        "hive":    "NTUSER",
        "path":    "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist",
        "desc":    "UserAssist (статистика запуска приложений)",
        "mode":    "clear_subkeys",
    },
    {
        "hive":    "NTUSER",
        "path":    "Software\\Microsoft\\Windows\\CurrentVersion\\Search\\RecentApps",
        "desc":    "RecentApps (поиск)",
        "mode":    "clear_subkeys",
    },
    {
        "hive":    "NTUSER",
        "path":    "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU",
        "desc":    "OpenSave диалог MRU",
        "mode":    "clear_subkeys",
    },
    {
        "hive":    "NTUSER",
        "path":    "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRU",
        "desc":    "LastVisited диалог MRU",
        "mode":    "clear_subkeys",
    },
    {
        "hive":    "SOFTWARE",
        "path":    "Microsoft\\Windows\\CurrentVersion\\UFH\\SHC",
        "desc":    "Shell History Cache",
        "mode":    "clear_values",
    },
]


# ==============================================================================
# Вспомогательные функции
# ==============================================================================

def _find_hive(root: Path, hive_name: str, user: str = "") -> Optional[Path]:
    """
    Ищет hive-файл на смонтированном образе.

    Args:
        root:      Корень смонтированного образа (/mnt/image).
        hive_name: Имя hive (SYSTEM, SOFTWARE, NTUSER, ...).
        user:      Имя пользователя (для NTUSER / USRCLASS).

    Returns:
        Path к hive-файлу или None если не найден.
    """
    patterns = HIVE_PATHS.get(hive_name.upper(), [])
    for pattern in patterns:
        candidate = root / pattern.replace("{user}", user)
        if candidate.exists():
            log.debug(f"Hive найден: {candidate}")
            return candidate
    log.warning(f"Hive не найден: {hive_name} (user={user!r})")
    return None


def _navigate(h: Hivex, path: str) -> Optional[int]:
    """
    Навигация по ключам hive по пути вида:
      "Software\\Microsoft\\Windows\\..."

    Args:
        h:    Открытый Hivex объект.
        path: Путь через \\

    Returns:
        Node handle (int) или None если путь не найден.
    """
    node = h.root()
    parts = [p for p in path.replace("/", "\\").split("\\") if p]
    for part in parts:
        try:
            node = h.node_get_child(node, part)
            if node is None:
                log.debug(f"Ключ не найден на этапе: {part!r}")
                return None
        except hivex.HivexError:
            log.debug(f"HivexError при навигации: {part!r}")
            return None
    return node


def _read_value(h: Hivex, node: int, value_name: str) -> Optional[bytes]:
    """
    Читает raw-bytes значения по имени.

    Returns:
        bytes или None.
    """
    try:
        val = h.node_get_value(node, value_name)
        _type, data = h.value_value(val)
        return data
    except hivex.HivexError:
        return None


def _value_as_string(h: Hivex, node: int, value_name: str) -> Optional[str]:
    """
    Читает REG_SZ / REG_EXPAND_SZ значение как строку UTF-16LE.
    """
    raw = _read_value(h, node, value_name)
    if raw is None:
        return None
    try:
        return raw.decode("utf-16-le").rstrip("\x00")
    except UnicodeDecodeError:
        return raw.hex()


# ==============================================================================
# Класс HiveEditor — основной инструмент правки hive
# ==============================================================================

class HiveEditor:
    """
    Обёртка над Hivex для безопасного чтения и записи hive-файлов.

    Пример использования:
        with HiveEditor(Path("/mnt/img/Windows/System32/config/SOFTWARE")) as ed:
            node = ed.navigate("Microsoft\\Windows NT\\CurrentVersion")
            val  = ed.read_string(node, "ProductName")
            ed.set_value(node, "RegisteredOwner", hivex.REG_SZ, "User")
            ed.commit()
    """

    def __init__(self, hive_path: Path, write: bool = True):
        """
        Args:
            hive_path: Путь к hive-файлу.
            write:     True = открыть на запись (требуется для commit).
        """
        if not hive_path.exists():
            raise FileNotFoundError(f"Hive не найден: {hive_path}")

        self.hive_path = hive_path
        self._write    = write
        self._h: Optional[Hivex] = None
        self._dirty    = False

        log.info(f"HiveEditor: открываем {hive_path.name} "
                 f"({'rw' if write else 'ro'})")

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> "HiveEditor":
        flags = hivex.OPEN_WRITE if self._write else 0
        self._h = Hivex(str(self.hive_path), flags=flags)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._h is not None:
            # Не коммитим автоматически — только явный commit()
            self._h = None
        return False

    # ------------------------------------------------------------------
    # Навигация
    # ------------------------------------------------------------------

    def navigate(self, path: str) -> Optional[int]:
        """Возвращает node handle по пути или None."""
        self._ensure_open()
        return _navigate(self._h, path)

    def children(self, node: int) -> list[str]:
        """Список имён дочерних ключей."""
        self._ensure_open()
        return [self._h.node_name(c) for c in self._h.node_children(node)]

    def values(self, node: int) -> dict[str, tuple[int, bytes]]:
        """
        Словарь всех значений узла.
        Returns: {name: (type, bytes)}
        """
        self._ensure_open()
        result = {}
        for val in self._h.node_values(node):
            name = self._h.value_key(val)
            typ, data = self._h.value_value(val)
            result[name] = (typ, data)
        return result

    # ------------------------------------------------------------------
    # Чтение
    # ------------------------------------------------------------------

    def read_raw(self, node: int, name: str) -> Optional[bytes]:
        """Читает raw bytes значения."""
        self._ensure_open()
        return _read_value(self._h, node, name)

    def read_string(self, node: int, name: str) -> Optional[str]:
        """Читает REG_SZ как строку."""
        self._ensure_open()
        return _value_as_string(self._h, node, name)

    def read_dword(self, node: int, name: str) -> Optional[int]:
        """Читает REG_DWORD как int."""
        raw = self.read_raw(node, name)
        if raw and len(raw) >= 4:
            return struct.unpack_from("<I", raw)[0]
        return None

    # ------------------------------------------------------------------
    # Запись
    # ------------------------------------------------------------------

    def set_value(
        self,
        node:  int,
        name:  str,
        typ:   int,
        data:  bytes | str | int,
    ) -> None:
        """
        Устанавливает значение в узле.

        Args:
            node: Node handle.
            name: Имя значения.
            typ:  Тип (hivex.REG_SZ, REG_DWORD, REG_BINARY, ...).
            data: Данные — bytes / str (для REG_SZ) / int (для REG_DWORD).
        """
        self._ensure_open()
        self._ensure_writable()

        # Преобразуем данные
        if isinstance(data, str):
            raw = (data + "\x00").encode("utf-16-le")
        elif isinstance(data, int):
            raw = struct.pack("<I", data)
        else:
            raw = data

        self._h.node_set_value(node, {
            "key":   name,
            "t":     typ,
            "value": raw,
        })
        self._dirty = True
        log.debug(f"  set_value: {name!r} type={typ} len={len(raw)}")

    def delete_value(self, node: int, name: str) -> bool:
        """
        Удаляет значение из узла.

        Returns:
            True если удалено, False если не найдено.
        """
        self._ensure_open()
        self._ensure_writable()
        try:
            self._h.node_set_values(
                node,
                [
                    v for v in self._h.node_values(node)
                    if self._h.value_key(v) != name
                ],
            )
            self._dirty = True
            log.debug(f"  delete_value: {name!r}")
            return True
        except hivex.HivexError:
            return False

    def delete_subkey(self, node: int, child_name: str) -> bool:
        """
        Рекурсивно удаляет дочерний ключ по имени.

        Returns:
            True если удалён.
        """
        self._ensure_open()
        self._ensure_writable()
        try:
            child = self._h.node_get_child(node, child_name)
            if child is None:
                return False
            self._h.node_delete_child(child)
            self._dirty = True
            log.debug(f"  delete_subkey: {child_name!r}")
            return True
        except hivex.HivexError as e:
            log.warning(f"  delete_subkey failed: {child_name!r} — {e}")
            return False

    def clear_all_values(self, node: int) -> int:
        """
        Удаляет все значения в узле (кроме структуры ключей).

        Returns:
            Количество удалённых значений.
        """
        self._ensure_open()
        self._ensure_writable()
        vals = self._h.node_values(node)
        count = len(vals)
        self._h.node_set_values(node, [])
        self._dirty = True
        log.debug(f"  clear_all_values: удалено {count}")
        return count

    def clear_all_subkeys(self, node: int) -> int:
        """
        Рекурсивно удаляет все дочерние ключи узла.

        Returns:
            Количество удалённых ключей.
        """
        self._ensure_open()
        self._ensure_writable()
        children = self._h.node_children(node)
        count = 0
        for child in children:
            try:
                self._h.node_delete_child(child)
                count += 1
            except hivex.HivexError as e:
                log.warning(f"  clear_all_subkeys: не удалось удалить — {e}")
        self._dirty = True
        log.debug(f"  clear_all_subkeys: удалено {count}")
        return count

    # ------------------------------------------------------------------
    # Фиксация изменений
    # ------------------------------------------------------------------

    def commit(self, backup: bool = True) -> None:
        """
        Записывает изменения в hive-файл.

        Args:
            backup: Если True — создаёт .bak перед записью.
        """
        self._ensure_open()
        if not self._dirty:
            log.info("  commit: нет изменений, пропускаем")
            return

        if backup:
            bak = self.hive_path.with_suffix(".bak")
            shutil.copy2(self.hive_path, bak)
            log.info(f"  Backup: {bak}")

        self._h.commit(str(self.hive_path))
        self._dirty = False
        log.info(f"  commit: записано → {self.hive_path}")

    # ------------------------------------------------------------------
    # Внутренние
    # ------------------------------------------------------------------

    def _ensure_open(self):
        if self._h is None:
            raise RuntimeError("HiveEditor не открыт. Используй 'with HiveEditor(...)'")

    def _ensure_writable(self):
        if not self._write:
            raise RuntimeError("Hive открыт только для чтения.")


# ==============================================================================
# Высокоуровневые функции — основная логика модуля
# ==============================================================================

def clean_mru_artifacts(
    mount_root: Path,
    users: Optional[list[str]] = None,
    dry_run: bool = False,
) -> dict:
    """
    Очищает MRU-артефакты и следы активности пользователя из реестра.

    Обрабатывает:
      • RunMRU, RecentDocs, TypedPaths, UserAssist
      • OpenSavePidlMRU, LastVisitedPidlMRU
      • RecentApps, Shell History Cache

    Args:
        mount_root: Корень смонтированного образа.
        users:      Список пользователей. None = автодетект.
        dry_run:    True = только репорт, без записи.

    Returns:
        Словарь с результатами по каждому hive/ключу.
    """
    results: dict = {"cleaned": [], "skipped": [], "errors": []}

    # Автодетект пользователей
    if users is None:
        users = _detect_users(mount_root)
        log.info(f"Обнаружены пользователи: {users}")

    for target in MRU_TARGETS:
        hive_name = target["hive"]
        key_path  = target["path"]
        desc      = target["desc"]
        mode      = target["mode"]

        # Системные hive — один раз
        if hive_name in ("SYSTEM", "SOFTWARE", "SAM"):
            _process_mru_target(
                mount_root, hive_name, key_path, desc, mode,
                dry_run, results, user=""
            )

        # Пользовательские hive — для каждого пользователя
        elif hive_name in ("NTUSER", "USRCLASS"):
            for user in users:
                _process_mru_target(
                    mount_root, hive_name, key_path, desc, mode,
                    dry_run, results, user=user
                )

    return results


def _process_mru_target(
    mount_root: Path,
    hive_name:  str,
    key_path:   str,
    desc:       str,
    mode:       str,
    dry_run:    bool,
    results:    dict,
    user:       str = "",
) -> None:
    """Внутренний хелпер — обрабатывает один MRU-таргет."""
    hive_path = _find_hive(mount_root, hive_name, user=user)
    if hive_path is None:
        results["skipped"].append({
            "hive": hive_name, "user": user, "key": key_path,
            "reason": "hive не найден"
        })
        return

    label = f"{hive_name}[{user}]\\{key_path}" if user else f"{hive_name}\\{key_path}"

    try:
        with HiveEditor(hive_path, write=not dry_run) as ed:
            node = ed.navigate(key_path)
            if node is None:
                results["skipped"].append({
                    "hive": hive_name, "user": user, "key": key_path,
                    "reason": "ключ не найден в hive"
                })
                log.debug(f"  Пропуск (не найден): {label}")
                return

            count = 0
            if dry_run:
                # Только считаем что нашли
                if mode == "clear_values":
                    count = len(ed.values(node))
                elif mode == "clear_subkeys":
                    count = len(ed.children(node))
                log.info(f"  [DRY-RUN] {desc}: найдено {count} элементов")
            else:
                if mode == "clear_values":
                    count = ed.clear_all_values(node)
                elif mode == "clear_subkeys":
                    count = ed.clear_all_subkeys(node)
                ed.commit(backup=True)
                log.info(f"  ✓ {desc}: очищено {count} элементов")

            results["cleaned"].append({
                "hive":  hive_name,
                "user":  user,
                "key":   key_path,
                "desc":  desc,
                "count": count,
                "mode":  mode,
            })

    except Exception as e:
        log.error(f"  Ошибка при обработке {label}: {e}")
        results["errors"].append({
            "hive": hive_name, "user": user, "key": key_path, "error": str(e)
        })


def patch_system_info(
    mount_root: Path,
    owner:      Optional[str] = None,
    org:        Optional[str] = None,
    dry_run:    bool = False,
) -> dict:
    """
    Правит информацию о владельце системы в SOFTWARE hive.

    Затрагивает:
      • HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion
        - RegisteredOwner
        - RegisteredOrganization

    Args:
        mount_root: Корень образа.
        owner:      Новое имя владельца (None = оставить).
        org:        Новая организация (None = оставить).
        dry_run:    Только логировать, не писать.

    Returns:
        dict с результатом.
    """
    import hivex as _hx

    result: dict = {"patched": {}, "errors": []}
    hive_path = _find_hive(mount_root, "SOFTWARE")
    if hive_path is None:
        return {"error": "SOFTWARE hive не найден"}

    key_path = "Microsoft\\Windows NT\\CurrentVersion"

    try:
        with HiveEditor(hive_path, write=not dry_run) as ed:
            node = ed.navigate(key_path)
            if node is None:
                return {"error": f"Ключ не найден: {key_path}"}

            if owner is not None:
                old = ed.read_string(node, "RegisteredOwner")
                if not dry_run:
                    ed.set_value(node, "RegisteredOwner", _hx.REG_SZ, owner)
                result["patched"]["RegisteredOwner"] = {"old": old, "new": owner}
                log.info(f"  RegisteredOwner: {old!r} → {owner!r}")

            if org is not None:
                old = ed.read_string(node, "RegisteredOrganization")
                if not dry_run:
                    ed.set_value(node, "RegisteredOrganization", _hx.REG_SZ, org)
                result["patched"]["RegisteredOrganization"] = {"old": old, "new": org}
                log.info(f"  RegisteredOrganization: {old!r} → {org!r}")

            if not dry_run and result["patched"]:
                ed.commit(backup=True)

    except Exception as e:
        log.error(f"patch_system_info error: {e}")
        result["errors"].append(str(e))

    return result


def get_current_control_set(mount_root: Path) -> Optional[int]:
    """
    Определяет активный ControlSet из SYSTEM hive.

    Читает: SYSTEM\\Select\\Current (REG_DWORD)

    Returns:
        Номер ControlSet (обычно 1 или 2) или None.
    """
    hive_path = _find_hive(mount_root, "SYSTEM")
    if hive_path is None:
        return None

    with HiveEditor(hive_path, write=False) as ed:
        node = ed.navigate("Select")
        if node is None:
            return None
        return ed.read_dword(node, "Current")


# ==============================================================================
# Утилиты обнаружения
# ==============================================================================

def _detect_users(mount_root: Path) -> list[str]:
    """
    Автодетект пользователей по наличию NTUSER.DAT.

    Проверяет:
      • mount_root/Users/*/NTUSER.DAT
      • mount_root/Documents and Settings/*/NTUSER.DAT
    """
    users: list[str] = []

    for base in ["Users", "Documents and Settings"]:
        base_path = mount_root / base
        if not base_path.exists():
            continue
        for entry in base_path.iterdir():
            if not entry.is_dir():
                continue
            if entry.name.lower() in ("public", "default", "all users", "default user"):
                continue
            ntuser = entry / "NTUSER.DAT"
            if ntuser.exists():
                users.append(entry.name)
                log.debug(f"  Пользователь обнаружен: {entry.name}")

    return users


def list_registry_artifacts(mount_root: Path) -> dict:
    """
    Сканирует образ и возвращает список всех найденных hive-файлов.

    Используется для диагностики / предстартового отчёта.

    Returns:
        dict: {hive_name: path_str или None}
    """
    report = {}
    for hive_name in HIVE_PATHS:
        if hive_name in ("NTUSER", "USRCLASS"):
            users = _detect_users(mount_root)
            report[hive_name] = {}
            for user in users:
                p = _find_hive(mount_root, hive_name, user=user)
                report[hive_name][user] = str(p) if p else None
        else:
            p = _find_hive(mount_root, hive_name)
            report[hive_name] = str(p) if p else None
    return report


# ==============================================================================
# Точка входа модуля (вызывается из main.py)
# ==============================================================================

def run(mount_root: Path, config: dict) -> dict:
    """
    Главная точка входа модуля registry.

    Args:
        mount_root: Path к корню смонтированного образа.
        config:     Словарь настроек из config.py:
                      - dry_run       (bool)
                      - users         (list[str] | None)
                      - patch_owner   (str | None)
                      - patch_org     (str | None)
                      - clean_mru     (bool)

    Returns:
        dict с результатами всех операций.
    """
    dry_run = config.get("dry_run", False)
    results: dict = {}

    log.info("=" * 60)
    log.info("Модуль: registry.py")
    log.info(f"  mount_root : {mount_root}")
    log.info(f"  dry_run    : {dry_run}")
    log.info("=" * 60)

    # 1. Диагностика — какие hive вообще есть
    artifacts = list_registry_artifacts(mount_root)
    log.info(f"Найденные hive: {artifacts}")
    results["artifacts"] = artifacts

    # 2. Определяем активный ControlSet
    cs = get_current_control_set(mount_root)
    log.info(f"CurrentControlSet: {cs}")
    results["control_set"] = cs

    # 3. Очистка MRU / артефактов активности
    if config.get("clean_mru", True):
        log.info("Запускаем очистку MRU-артефактов...")
        mru_result = clean_mru_artifacts(
            mount_root,
            users=config.get("users"),
            dry_run=dry_run,
        )
        results["mru"] = mru_result
        log.info(
            f"MRU: очищено={len(mru_result['cleaned'])}, "
            f"пропущено={len(mru_result['skipped'])}, "
            f"ошибок={len(mru_result['errors'])}"
        )

    # 4. Патч системной информации
    if config.get("patch_owner") or config.get("patch_org"):
        log.info("Патчим системную информацию...")
        patch_result = patch_system_info(
            mount_root,
            owner=config.get("patch_owner"),
            org=config.get("patch_org"),
            dry_run=dry_run,
        )
        results["patch"] = patch_result

    log.info("registry.py завершён.")
    return results
