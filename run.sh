#!/usr/bin/env bash
set -euo pipefail

# Переход в директорию проекта для корректной работы python -m
cd "$(dirname "${BASH_SOURCE[0]}")"

VENV_DIR="./venv"

if [[ ! -d "${VENV_DIR}" ]]; then
    echo "❌ Виртуальное окружение не найдено: ${VENV_DIR}"
    echo "💡 Создайте его вручную:"
    echo "   python3 -m venv venv --system-site-packages"
    echo "   source venv/bin/activate && pip install -r requirements.txt"
    exit 1
fi

# Активация venv
source "${VENV_DIR}/bin/activate"

echo "🚀 Запуск WiperX..."
python -m src.main "$@"
