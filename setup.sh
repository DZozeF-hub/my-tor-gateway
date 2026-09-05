#!/data/data/com.termux/files/usr/bin/bash
#
# setup.sh
# =========
# Разовая первоначальная установка. Запускать один раз после
# первого клонирования репозитория.
#
# Использование:
#   chmod +x setup.sh && ./setup.sh

set -e

echo "[*] Обновляю списки пакетов..."
pkg update -y

echo "[*] Устанавливаю базовые пакеты (tor, python, git)..."
pkg install tor python git -y

echo "[*] Пробую установить lyrebird (поддержка webtunnel/obfs4)..."
pkg install lyrebird -y 2>/dev/null || {
    echo "[!] lyrebird недоступен в репозитории, ставлю obfs4proxy как запасной вариант..."
    pkg install obfs4proxy -y
}

echo "[*] Включаю wake-lock, чтобы Android не убивал процесс в фоне..."
termux-wake-lock 2>/dev/null || echo "    (termux-wake-lock недоступен, установите пакет termux-api при желании)"

chmod +x start_tor_vpn.sh
chmod +x new_identity.sh 2>/dev/null || true

echo ""
echo "======================================================"
echo " Установка завершена!"
echo ""
echo " Дальше:"
echo " 1. Откройте настройки батареи Android и уберите"
echo "    ограничения для Termux (важно для стабильной работы)"
echo " 2. Отредактируйте bridges.txt — вставьте свои мосты"
echo " 3. Отредактируйте config.env — задайте логин/пароль"
echo " 4. Запускайте: ./start_tor_vpn.sh"
echo "======================================================"
