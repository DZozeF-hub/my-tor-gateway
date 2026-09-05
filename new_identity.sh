#!/data/data/com.termux/files/usr/bin/bash
#
# new_identity.sh
# =================
# Просит Tor построить новые цепочки (новый выходной узел, новый
# "видимый" IP для внешних сайтов) без перезапуска Tor и без разрыва
# работы шлюза. Полезно, если хотите явно "оторвать" последующий
# трафик от предыдущего с точки зрения внешнего наблюдателя.
#
# Важно: это НЕ мгновенно рвёт уже открытые соединения — активные
# закачки/сессии на старых цепочках продолжатся на них до завершения,
# а вот все НОВЫЕ соединения после этой команды пойдут через свежие
# цепочки. Именно поэтому это не влияет на скорость текущей работы.
#
# Использование:
#   ./new_identity.sh

set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TOR_DATA_DIR="$PREFIX/var/lib/tor"
COOKIE_FILE="$TOR_DATA_DIR/control_auth_cookie"
CONTROL_HOST="127.0.0.1"
CONTROL_PORT="9051"

if [ ! -f "$COOKIE_FILE" ]; then
    echo "Не найден cookie-файл авторизации ($COOKIE_FILE)."
    echo "Убедитесь, что Tor запущен через start_tor_vpn.sh (ControlPort должен быть включён)."
    exit 1
fi

COOKIE_HEX="$(python3 -c "import sys; print(open(sys.argv[1], 'rb').read().hex())" "$COOKIE_FILE" 2>/dev/null)"
if [ -z "$COOKIE_HEX" ]; then
    echo "Не удалось прочитать cookie-файл."
    exit 1
fi

exec 3<>"/dev/tcp/$CONTROL_HOST/$CONTROL_PORT" || {
    echo "Не удалось подключиться к control-порту Tor ($CONTROL_HOST:$CONTROL_PORT)."
    echo "Убедитесь, что start_tor_vpn.sh сейчас запущен."
    exit 1
}

printf 'AUTHENTICATE %s\r\nSIGNAL NEWNYM\r\nQUIT\r\n' "$COOKIE_HEX" >&3

RESPONSE="$(cat <&3)"
exec 3<&- 3>&-

if echo "$RESPONSE" | grep -q "250 OK"; then
    echo "Готово — Tor построит новые цепочки для последующих подключений."
else
    echo "Что-то пошло не так. Ответ Tor:"
    echo "$RESPONSE"
    exit 1
fi
