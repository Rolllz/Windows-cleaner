# Windows-cleaner
# 🧹 WiperX

> **Инструмент глубокой зачистки артефактов активности пользователя на Windows-системах**  
> Работает офлайн, на примонтированных разделах, из Linux/macOS/WSL окружения.

---

## ⚡ Что делает WiperX

WiperX — это CLI-инструмент для судебно-криминалистической очистки Windows-систем.  
Он уничтожает следы активности, которые оставляет операционная система и приложения:
артефакты реестра, Prefetch-кеш, журналы событий, LNK-файлы, Amcache, SRUDB и временны́е метки файлов.

---

## 🗂️ Модули

| Модуль | Артефакт | Описание |
|---|---|---|
| `prefetch` | `C:\Windows\Prefetch\*.pf` | Удаление Prefetch-файлов запуска приложений |
| `evtx` | `C:\Windows\System32\winevt\Logs\*.evtx` | Очистка журналов событий Windows |
| `lnk` | `Recent\*.lnk`, `AutomaticDestinations` | Удаление LNK-ярлыков и Jump Lists |
| `registry` | Куст реестра (SAM, SYSTEM, NTUSER) | Зачистка артефактов реестра |
| `sru` | `C:\Windows\System32\sru\SRUDB.dat` | Очистка базы данных ресурсов (SRU) |
| `amcache` | `C:\Windows\AppCompat\Programs\Amcache.hve` | Удаление записей запуска программ |
| `timestamps` | NTFS `$SI` / `$FN` | Манипуляция временны́ми метками файлов |

---

## 📁 Структура проекта

```
WiperX/
├── main.py                  # Точка входа
├── config.py                # Конфигурация (пути, флаги, уровень логов)
├── run.sh                   # Офлайн-установка зависимостей + запуск
│
├── src/
│   └── modules/
│       ├── prefetch.py
│       ├── evtx.py
│       ├── lnk.py
│       ├── registry.py
│       ├── sru.py
│       ├── amcache.py
│       └── timestamps.py
│
├── packages/
│   ├── deb/                 # .deb пакеты для офлайн-установки
│   └── whl/                 # Python .whl / .tar.gz пакеты
│
├── logs/                    # Генерируется при запуске
├── reports/                 # CSV / JSON отчёты
└── .venv/                   # Виртуальное окружение Python
```

---

## 🔧 Требования

- **OS:** Linux, macOS, WSL2
- **Python:** 3.10+
- **Права:** `sudo` (для монтирования разделов и работы с системными файлами)
- **Режим:** Офлайн — все зависимости поставляются локально в `packages/`

### Python-зависимости

| Библиотека | Назначение |
|---|---|
| `rich` | Цветной CLI-интерфейс, прогресс-бары, таблицы |
| `regipy` | Парсинг кустов реестра Windows |
| `python-evtx` | Чтение `.evtx` журналов событий |
| `LnkParse3` | Разбор LNK-файлов |

---

## 🚀 Быстрый старт

### 1. Клонируй репозиторий

```bash
git clone https://github.com/yourname/wiperx.git
cd wiperx
```

### 2. Примонтируй Windows-раздел

```bash
sudo mkdir -p /mnt/windows
sudo mount -o ro /dev/sdXN /mnt/windows
```

### 3. Запусти через `run.sh`

```bash
chmod +x run.sh
sudo ./run.sh --drive /mnt/windows
```

> `run.sh` автоматически установит все зависимости из `packages/` в виртуальное окружение `.venv` и запустит `main.py`.

---

## 🖥️ Использование

```bash
# Стандартная очистка
sudo python3 main.py --drive /mnt/windows

# Режим предпросмотра (без реального удаления)
sudo python3 main.py --drive /mnt/windows --dry-run

# Подробный вывод
sudo python3 main.py --drive /mnt/windows --verbose

# Выбрать конкретные модули
sudo python3 main.py --drive /mnt/windows --modules prefetch evtx lnk

# Сохранить отчёт в JSON
sudo python3 main.py --drive /mnt/windows --report json

# Отключить запись логов
sudo python3 main.py --drive /mnt/windows --no-log
```

### Все флаги

| Флаг | Описание |
|---|---|
| `--drive PATH` | Путь к примонтированному Windows-разделу **(обязательный)** |
| `--dry-run` | Только анализ — без удаления данных |
| `--verbose` | Расширенный вывод в консоль |
| `--modules` | Выбрать отдельные модули (по умолчанию — все) |
| `--report [csv\|json]` | Сохранить отчёт в `reports/` |
| `--no-log` | Не записывать лог-файл |
| `--passes N` | Количество проходов перезаписи (по умолчанию из `config.py`) |

---

## ⚙️ Конфигурация (`config.py`)

```python
WIPERX_LOG_LEVEL      = logging.INFO
SECURE_WIPE_PASSES    = 3
AMCACHE_PATH          = "Windows/AppCompat/Programs/Amcache.hve"
TIMESTAMPS_DEFAULT_SPOOF = True
# ... остальные пути задаются относительно --drive
```

Все пути в `config.py` задаются **относительно** точки монтирования, переданной через `--drive`.

---

## 📊 Отчёты

После завершения WiperX генерирует отчёт в директории `reports/`:

```
reports/
└── wiperx_2026-04-30_14-32-01.json
```

Отчёт содержит:
- список обработанных артефактов
- количество удалённых / изменённых объектов
- ошибки и пропущенные файлы
- хэши (SHA-256) до и после операции *(если включено)*

---

## ⚠️ Важные предупреждения

> **WiperX вносит необратимые изменения в данные.**  
> Всегда используй `--dry-run` перед реальным запуском.

- Работай **только** на примонтированных разделах, не на живой системе
- Убедись, что раздел примонтирован в нужном режиме (`ro` для анализа, `rw` для очистки)
- Не запускай без `sudo` — большинство системных файлов требуют прав суперпользователя
- Автор **не несёт ответственности** за случайную потерю данных

---

## 🛡️ Лицензия

```
MIT License — используй свободно, на свой страх и риск.
```

---

## 👤 Автор

Разработано как специализированный инструмент для форензик-аналитиков и исследователей безопасности.  
Issues и Pull Requests приветствуются.

---

*WiperX v1.0.0 · Python 3.10+ · Офлайн · Linux/macOS/WSL2*
