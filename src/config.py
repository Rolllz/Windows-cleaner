# ==============================================================================
# WiperX — config.py
# Централизованная конфигурация: пути, константы, параметры анализа
# ==============================================================================

from pathlib import Path

# ── Корень проекта ────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent

# ==============================================================================
# 📂 Структура директорий
# ==============================================================================

DIRS = {
    "output":   BASE_DIR / "output",       # итоговые JSON / HTML / отчёты
    "reports":  BASE_DIR / "reports",      # финальные форматированные отчёты
    "temp":     BASE_DIR / "temp",         # временные файлы в процессе анализа
    "logs":     BASE_DIR / "logs",         # логи выполнения
}

# ==============================================================================
# 🪟 Артефакты Windows — пути относительно корня образа / примонтированного раздела
# ==============================================================================

WINDOWS_ARTIFACTS = {

    # ── Реестр ────────────────────────────────────────────────────────────────
    "registry": {
        "SYSTEM":   "Windows/System32/config/SYSTEM",
        "SOFTWARE": "Windows/System32/config/SOFTWARE",
        "SAM":      "Windows/System32/config/SAM",
        "SECURITY": "Windows/System32/config/SECURITY",
        # NTUSER.DAT — ищется динамически по профилям пользователей
        # путь-шаблон: Users/{username}/NTUSER.DAT
        "NTUSER":   "Users/{username}/NTUSER.DAT",
        "UsrClass": "Users/{username}/AppData/Local/Microsoft/Windows/UsrClass.dat",
    },

    # ── Event Logs ────────────────────────────────────────────────────────────
    "evtx": {
        "System":      "Windows/System32/winevt/Logs/System.evtx",
        "Security":    "Windows/System32/winevt/Logs/Security.evtx",
        "Application": "Windows/System32/winevt/Logs/Application.evtx",
        "PowerShell":  "Windows/System32/winevt/Logs/Windows PowerShell.evtx",
        "PSOperational": (
            "Windows/System32/winevt/Logs/"
            "Microsoft-Windows-PowerShell%4Operational.evtx"
        ),
        "TaskScheduler": (
            "Windows/System32/winevt/Logs/"
            "Microsoft-Windows-TaskScheduler%4Operational.evtx"
        ),
        "WMI": (
            "Windows/System32/winevt/Logs/"
            "Microsoft-Windows-WMI-Activity%4Operational.evtx"
        ),
        "RDPLocal": (
            "Windows/System32/winevt/Logs/"
            "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx"
        ),
        "RDPRemote": (
            "Windows/System32/winevt/Logs/"
            "Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx"
        ),
    },

    # ── Prefetch ──────────────────────────────────────────────────────────────
    "prefetch": {
        "dir": "Windows/Prefetch",
        "pattern": "*.pf",
    },

    # ── LNK / Recent ─────────────────────────────────────────────────────────
    "lnk": {
        # шаблон: Users/{username}/...
        "recent":       "Users/{username}/AppData/Roaming/Microsoft/Windows/Recent",
        "recent_auto":  "Users/{username}/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations",
        "recent_custom":"Users/{username}/AppData/Roaming/Microsoft/Windows/Recent/CustomDestinations",
    },

    # ── SRUDB / Amcache / Shimcache ───────────────────────────────────────────
    "ese": {
        "SRUDB":    "Windows/System32/sru/SRUDB.dat",
        "Amcache":  "Windows/AppCompat/Programs/Amcache.hve",
    },

    # ── Prefetch (альтернативный путь на некоторых сборках) ───────────────────
    "scca": {
        "dir": "Windows/Prefetch",
    },

    # ── MFT / USNJrnl (опционально, если образ полный) ────────────────────────
    "mft": {
        "MFT":     "$MFT",
        "USNJrnl": "$Extend/$UsnJrnl",
    },
}

# ==============================================================================
# 🔍 Event ID — ключевые идентификаторы событий
# ==============================================================================

EVENT_IDS = {

    # ── Аутентификация / сессии ───────────────────────────────────────────────
    "auth": {
        4624: "Successful logon",
        4625: "Failed logon",
        4634: "Logoff",
        4647: "User-initiated logoff",
        4648: "Logon with explicit credentials (runas)",
        4672: "Special privileges assigned (admin logon)",
        4776: "NTLM authentication attempt",
        4768: "Kerberos TGT request",
        4769: "Kerberos service ticket request",
        4771: "Kerberos pre-auth failed",
    },

    # ── Управление учётными записями ──────────────────────────────────────────
    "accounts": {
        4720: "User account created",
        4722: "User account enabled",
        4723: "Password change attempt",
        4724: "Password reset",
        4725: "User account disabled",
        4726: "User account deleted",
        4728: "Member added to global group",
        4732: "Member added to local group",
        4756: "Member added to universal group",
        4738: "User account changed",
        4740: "Account locked out",
    },

    # ── Процессы ─────────────────────────────────────────────────────────────
    "processes": {
        4688: "New process created",
        4689: "Process terminated",
    },

    # ── Политики и аудит ──────────────────────────────────────────────────────
    "policy": {
        4719: "Audit policy changed",
        4907: "Auditing settings changed on object",
        1102: "Audit log cleared (Security)",
        104:  "Audit log cleared (System)",
    },

    # ── Сеть / RDP / SMB ──────────────────────────────────────────────────────
    "network": {
        4778: "RDP session reconnected",
        4779: "RDP session disconnected",
        4800: "Workstation locked",
        4801: "Workstation unlocked",
        5140: "Network share accessed",
        5145: "Network share object access check",
        5156: "Windows Filtering Platform: allowed connection",
        5157: "Windows Filtering Platform: blocked connection",
    },

    # ── Службы ───────────────────────────────────────────────────────────────
    "services": {
        7034: "Service crashed unexpectedly",
        7035: "Service sent start/stop control",
        7036: "Service changed state",
        7040: "Service start type changed",
        7045: "New service installed",
    },

    # ── PowerShell ────────────────────────────────────────────────────────────
    "powershell": {
        4103: "PS module logging",
        4104: "PS script block logging",
        400:  "PS engine started",
        403:  "PS engine stopped",
        600:  "PS provider started",
    },

    # ── WMI ───────────────────────────────────────────────────────────────────
    "wmi": {
        5857: "WMI provider loaded",
        5858: "WMI query error",
        5859: "WMI subscription created",
        5860: "WMI temporary subscription",
        5861: "WMI permanent subscription",
    },

    # ── Задачи планировщика ───────────────────────────────────────────────────
    "scheduler": {
        106:  "Task registered",
        140:  "Task updated",
        141:  "Task deleted",
        200:  "Task action started",
        201:  "Task action completed",
    },

    # ── USB / устройства ──────────────────────────────────────────────────────
    "usb": {
        6416: "New external device recognized",
        6419: "Request to disable device",
        6420: "Device disabled",
        6421: "Request to enable device",
        6422: "Device enabled",
        6423: "Device installation blocked by policy",
        6424: "Device installation allowed after block",
    },
}

# ==============================================================================
# ⚙️ Параметры анализа
# ==============================================================================

ANALYSIS = {
    # Максимальное число событий, загружаемых из одного .evtx (0 = без лимита)
    "evtx_max_records":     0,

    # Минимальный уровень важности для включения события в отчёт
    # 0=Verbose, 1=Info, 2=Warning, 3=Error, 4=Critical
    "evtx_min_level":       0,

    # Глубина рекурсии при обходе директорий LNK / Recent
    "lnk_scan_depth":       3,

    # Таймаут (сек) на один вызов внешней утилиты (esedbexport и т.п.)
    "subprocess_timeout":   120,

    # Включить парсинг MFT (требует полного образа диска)
    "parse_mft":            False,

    # Формат временных меток в отчёте
    "timestamp_format":     "%Y-%m-%d %H:%M:%S UTC",

    # Часовой пояс для нормализации (UTC рекомендован для forensics)
    "timezone":             "UTC",
}

# ==============================================================================
# 📝 Логирование
# ==============================================================================

LOGGING = {
    "level":        "INFO",          # DEBUG | INFO | WARNING | ERROR
    "file":         DIRS["logs"] / "wiperx.log",
    "max_bytes":    10 * 1024 * 1024,  # 10 МБ
    "backup_count": 3,
    "format":       "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    "date_format":  "%Y-%m-%d %H:%M:%S",
}

# ==============================================================================
# 📤 Вывод / отчёты
# ==============================================================================

REPORT = {
    "formats":          ["json", "html"],   # поддерживаемые форматы
    "default_format":   "json",
    "indent":           2,                  # отступ JSON
    "html_template":    BASE_DIR / "templates" / "report.html",
}
