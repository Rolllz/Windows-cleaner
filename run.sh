#!/usr/bin/env bash
# ==============================================================================
# WiperX — run.sh
# Офлайн-установка зависимостей и запуск приложения
# ==============================================================================

set -euo pipefail

# ── Цвета для вывода ──────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ── Пути ─────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEB_DIR="${SCRIPT_DIR}/packages/deb"
WHL_DIR="${SCRIPT_DIR}/packages/whl"
VENV_DIR="${SCRIPT_DIR}/.venv"
MAIN="${SCRIPT_DIR}/main.py"

# ── Вспомогательные функции ───────────────────────────────────────────────────
info()    { echo -e "${CYAN}[*]${NC} $*"; }
success() { echo -e "${GREEN}[✓]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
die()     { echo -e "${RED}[✗]${NC} $*" >&2; exit 1; }

# ── 1. Проверка прав ──────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    die "Запусти скрипт с правами root: sudo bash run.sh"
fi

# ── 2. Установка .deb-пакетов через dpkg ─────────────────────────────────────
info "Установка системных пакетов из ${DEB_DIR} ..."

if [[ ! -d "${DEB_DIR}" ]]; then
    die "Директория ${DEB_DIR} не найдена."
fi

DEB_COUNT=$(find "${DEB_DIR}" -maxdepth 1 -name "*.deb" | wc -l)

if [[ "${DEB_COUNT}" -eq 0 ]]; then
    warn "В ${DEB_DIR} нет .deb-файлов. Пропускаем."
else
    # Устанавливаем все .deb сразу — dpkg разберёт порядок зависимостей
    dpkg -i --force-depends "${DEB_DIR}"/*.deb 2>&1 | tail -5
    # Чиним возможные неудовлетворённые зависимости (на случай порядка)
    dpkg -i --force-depends "${DEB_DIR}"/*.deb 2>&1 | tail -3
    success "Системные пакеты установлены (${DEB_COUNT} .deb файлов)."
fi

# ── 3. Создание виртуального окружения ───────────────────────────────────────
if [[ -d "${VENV_DIR}" ]]; then
    warn "Виртуальное окружение уже существует: ${VENV_DIR}"
    warn "Пересоздаём..."
    rm -rf "${VENV_DIR}"
fi

info "Создание venv в ${VENV_DIR} ..."
python3 -m venv "${VENV_DIR}" --system-site-packages
success "venv создан."

# ── 4. Установка pip-пакетов из whl/ ─────────────────────────────────────────
info "Установка pip-пакетов из ${WHL_DIR} ..."

if [[ ! -d "${WHL_DIR}" ]]; then
    die "Директория ${WHL_DIR} не найдена."
fi

PYTHON="${VENV_DIR}/bin/python3"
PIP="${VENV_DIR}/bin/pip3"

# Устанавливаем все .whl и .tar.gz из папки, без обращения в интернет
"${PIP}" install \
    --no-index \
    --no-deps \
    --find-links="${WHL_DIR}" \
    "${WHL_DIR}"/*.whl 2>&1

# libscca-python поставляется как tar.gz — ставим отдельно
SCCA_TARBALL=$(find "${WHL_DIR}" -maxdepth 1 -name "libscca-python-*.tar.gz" | head -1)
if [[ -n "${SCCA_TARBALL}" ]]; then
    info "Сборка и установка libscca-python из исходников: $(basename "${SCCA_TARBALL}") ..."
    "${PIP}" install \
        --no-index \
        --no-build-isolation \
        "${SCCA_TARBALL}" 2>&1
    success "libscca-python установлен."
else
    warn "libscca-python-*.tar.gz не найден в ${WHL_DIR} — пропускаем."
fi

success "Все pip-пакеты установлены."

# ── 5. Запуск WiperX ─────────────────────────────────────────────────────────
echo ""
info "Запуск WiperX..."
echo ""

exec "${PYTHON}" "${MAIN}" "$@"
