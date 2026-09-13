#!/usr/bin/env bash
# ==============================================================================
# install_service.sh — Установка и регистрация службы vpn-daemon в systemd
# ==============================================================================
set -e

SERVICE_NAME="vpn-daemon.service"
INSTALL_DIR="/opt/vpn-manager"
CURRENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== Установка службы VPN Daemon в systemd ==="

# 1. Проверка прав суперпользователя
if [[ $EUID -ne 0 ]]; then
   echo "[ERROR] Этот скрипт должен быть запущен с правами root (sudo ./install_service.sh)"
   exit 1
fi

# 2. Создание рабочей директории
echo "[1/4] Создание рабочей директории: $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"

# 3. Копирование файлов модулей
echo "[2/4] Копирование скриптов..."
cp -u "$CURRENT_DIR"/fetcher.py "$INSTALL_DIR/"
cp -u "$CURRENT_DIR"/ping_tester.py "$INSTALL_DIR/"
cp -u "$CURRENT_DIR"/config_generator.py "$INSTALL_DIR/"
cp -u "$CURRENT_DIR"/vpn_daemon.py "$INSTALL_DIR/"
[[ -f "$CURRENT_DIR"/configs_raw.json ]] && cp -u "$CURRENT_DIR"/configs_raw.json "$INSTALL_DIR/" || true
[[ -f "$CURRENT_DIR"/configs_tested.json ]] && cp -u "$CURRENT_DIR"/configs_tested.json "$INSTALL_DIR/" || true
[[ -f "$CURRENT_DIR"/singbox_config.json ]] && cp -u "$CURRENT_DIR"/singbox_config.json "$INSTALL_DIR/" || true

# 4. Установка unit-файла systemd
echo "[3/4] Установка unit-файла в /etc/systemd/system/$SERVICE_NAME..."
cp "$CURRENT_DIR"/vpn-daemon.service /etc/systemd/system/

# 5. Перезагрузка демона systemd и включение автозапуска
echo "[4/4] Активация автозапуска службы..."
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"

echo "=============================================================================="
echo "✓ Служба $SERVICE_NAME успешно установлена и запущена!"
echo "  Просмотр статуса:  sudo systemctl status $SERVICE_NAME"
echo "  Просмотр логов:    sudo journalctl -u $SERVICE_NAME -f"
echo "  Лог-файл демона:   $INSTALL_DIR/vpn_daemon.log"
echo "=============================================================================="
