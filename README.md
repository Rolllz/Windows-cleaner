# 🧹 WiperX

> **Инструмент глубокой зачистки артефактов активности пользователя на Windows-системах**
> Работает офлайн, на примонтированных разделах, из Linux / macOS / WSL окружения.

---

## ⚡ Что делает WiperX

WiperX — это CLI-инструмент для судебно-криминалистической очистки Windows-систем.
Он уничтожает следы активности, которые оставляют ОС и приложения:
артефакты реестра, Prefetch-кеш, журналы событий, LNK-файлы, Jump Lists,
Amcache, SRUDB и временны́е метки файлов NTFS.

Все операции выполняются **офлайн** — на примонтированном образе или разделе диска,
без загрузки целевой Windows-системы.

---

## 🗂️ Структура проекта

```
wiperx/
│
├── run.sh                          # Точка входа: установка + запуск
│
├── packages/
│   ├── deb/                        # .deb-пакеты + зависимости (для apt)
│   └── whl/                        # pip-пакеты (wheels + tar.gz)
│
├── venv/                           # Создаётся автоматически через run.sh
│
├── src/
│   ├── main.py                     # Главный оркестратор
│   ├── config.py                   # Пути, константы, настройки
│   │
│   ├── modules/
│   │   ├── __init__.py
│   │   ├── registry.py             # Правка реестра (hivex + python3-hivex)
│   │   ├── evtx_processor.py       # Обработка .evtx (pyevtx-rs)
│   │   ├── prefetch.py             # Удаление/обработка Prefetch
│   │   ├── lnk.py                  # Обработка .lnk-файлов (LnkParse3)
│   │   ├── sru.py                  # Обработка SRUDB.dat (libesedb-utils)
│   │   ├── amcache.py              # Обработка Amcache.hve (hivex)
│   │   ├── jumplists.py            # Обработка Jump Lists (construct + LnkParse3)
│   │   └── timestamps.py           # Перебивка временных меток
│   │
│   └── utils/
│       ├── __init__.py
│       ├── checksum.py             # Пересчёт CRC32 чанков .evtx
│       ├── renumber.py             # Перенумерация EventRecordID в .evtx
│       ├── mount.py                # Монтирование образа / работа с путями
│       └── logger.py               # Логирование через rich
│
└── README.md
```

---

## 🧩 Модули

### `modules/` — Модули зачистки

| Файл | Артефакт | Библиотека |
|---|---|---|
| `registry.py` | Кусты реестра (SAM, SYSTEM, NTUSER.DAT) | `hivex`, `python3-hivex` |
| `evtx_processor.py` | Журналы событий Windows (`.evtx`) | `pyevtx-rs` |
| `prefetch.py` | Prefetch-файлы запуска приложений | `prefetch_parser`, `libscca` |
| `lnk.py` | LNK-ярлыки последних файлов | `LnkParse3` |
| `sru.py` | База ресурсов SRUDB.dat | `libesedb-utils`, `python3-libesedb` |
| `amcache.py` | Amcache.hve — история запусков | `hivex` |
| `jumplists.py` | Jump Lists (AutomaticDestinations) | `construct`, `LnkParse3` |
| `timestamps.py` | Временны́е метки файлов NTFS | — |

### `utils/` — Вспомогательные утилиты

| Файл | Назначение |
|---|---|
| `checksum.py` | Пересчёт CRC32 чанков внутри `.evtx`-файлов |
| `renumber.py` | Перенумерация `EventRecordID` в `.evtx` для консистентности |
| `mount.py` | Монтирование образа диска / нормализация путей |
| `logger.py` | Цветное логирование через `rich` |

---

## 📦 Зависимости

### Системные пакеты (`.deb`)

Устанавливаются офлайн из `packages/deb/` через `apt`:

- `python3-hivex` — Python-биндинги для работы с реестром
- `libesedb-utils` — утилиты для работы с базами ESE (SRUDB.dat)
- `python3-libesedb` — Python-биндинги для libesedb
- `libscca` — библиотека для парсинга Prefetch-файлов

### Python-пакеты (`.whl` / `.tar.gz`)

Устанавливаются офлайн из `packages/whl/` через `pip`:

- `pyevtx-rs` — высокопроизводительный парсер `.evtx` на Rust
- `LnkParse3` — парсер `.lnk`-файлов Windows
- `prefetch_parser` — парсер Prefetch
- `construct` — декларативный бинарный парсер (Jump Lists)
- `rich` — красивое терминальное логирование

---

## 🚀 Быстрый старт

### 1. Клонирование репозитория

```bash
git clone https://github.com/yourname/wiperx.git
cd wiperx
```

### 2. Запуск

```bash
chmod +x run.sh
sudo ./run.sh
```

`run.sh` автоматически:

1. Устанавливает `.deb`-пакеты из `packages/deb/`
2. Создаёт виртуальное окружение `venv/`
3. Устанавливает Python-пакеты из `packages/whl/`
4. Запускает `src/main.py`

> ⚠️ **Требуется `sudo`** — для установки системных `.deb`-пакетов и монтирования образов.

---

## ⚙️ Конфигурация

Все пути и константы задаются в `src/config.py`.

```python
# Пример настроек
MOUNT_POINT   = "/mnt/windows"   # Точка монтирования целевого раздела
LOG_LEVEL     = "INFO"           # Уровень логирования
DRY_RUN       = False            # True — только анализ, без изменений
```

---

## 🖥️ Требования к системе

| Параметр | Значение |
|---|---|
| ОС | Linux / macOS / WSL2 |
| Python | >= 3.9 |
| Права | `root` / `sudo` |
| Диск | Офлайн-образ или примонтированный раздел NTFS |

---

## ⚠️ Disclaimer

Инструмент предназначен **исключительно для легальных целей**:
пентестинга, форензики, тестирования на собственных системах.
Используйте только на системах, которыми вы владеете или имеете письменное разрешение на тестирование.
Авторы не несут ответственности за любое неправомерное использование.

---

## 📄 Лицензия

MIT License © 2025 WiperX Contributors
