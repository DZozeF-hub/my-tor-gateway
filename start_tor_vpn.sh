#!/data/data/com.termux/files/usr/bin/bash
#
# start_tor_vpn.sh (v3)
# ======================
# Полностью автоматический запуск "домашнего VPN" на Tor в Termux.
#
# Что нового по сравнению с v1/v2:
#   - Сам ставит недостающие пакеты (tor, lyrebird/obfs4proxy, python)
#   - Сам генерирует torrc из bridges.txt — редактировать torrc руками
#     больше не нужно вообще
#   - Сам определяет транспорт (obfs4 / webtunnel / snowflake) по первому
#     слову каждой строки в bridges.txt
#   - Сам подтягивает обновления кода из GitHub (git pull), если включено
#     в config.env
#   - Watchdog: если Tor или сам шлюз неожиданно упадут — перезапускает сам
#   - Ротация лога Tor для многодневной работы без перезапуска
#   - Цветной, понятный вывод статуса
#
# Приватность (новое):
#   - SocksPort Tor теперь ТОЛЬКО на localhost — раньше он был виден
#     всей локальной сети напрямую на порту 9050, и теоретически можно
#     было обойти авторизацию шлюза, подключившись к Tor напрямую.
#     Теперь единственная дверь в сеть — авторизованный шлюз.
#   - SafeLogging и AvoidDiskWrites в torrc — Tor не пишет на диск
#     ничего лишнего и маскирует адреса в собственных логах.
#   - LOG_MODE в config.env управляет тем, что попадает в лог шлюза
#     (по умолчанию "off" — ни IP клиентов, ни адресов назначения).
#   - Изоляция цепочек Tor между вашими устройствами (реализовано
#     в tor_socks_gateway.py).
#   - Помощник new_identity.sh — команда "сбросить личность" (новые
#     цепочки Tor) по требованию, без перезапуска всего сервиса.
#
# Использование:
#   ./start_tor_vpn.sh
#
# Все настройки — в config.env и bridges.txt рядом со скриптом.

set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

CONFIG_FILE="$SCRIPT_DIR/config.env"
BRIDGES_FILE="$SCRIPT_DIR/bridges.txt"
GATEWAY_SCRIPT="$SCRIPT_DIR/tor_socks_gateway.py"
TORRC_FILE="$PREFIX/etc/tor/torrc"
TOR_LOG="$PREFIX/var/log/tor.log"
TOR_DATA_DIR="$PREFIX/var/lib/tor"
TOR_CONTROL_COOKIE="$TOR_DATA_DIR/control_auth_cookie"
TOR_PORT="9050"
TOR_CONTROL_PORT="9051"

# --- Цвета для вывода ---
C_RESET='\033[0m'
C_GREEN='\033[1;32m'
C_YELLOW='\033[1;33m'
C_RED='\033[1;31m'
C_CYAN='\033[1;36m'
C_BOLD='\033[1m'

info()  { echo -e "${C_CYAN}[*]${C_RESET} $1"; }
ok()    { echo -e "${C_GREEN}[✓]${C_RESET} $1"; }
warn()  { echo -e "${C_YELLOW}[!]${C_RESET} $1"; }
fail()  { echo -e "${C_RED}[✗]${C_RESET} $1"; }

banner() {
    echo -e "${C_BOLD}${C_CYAN}"
    echo "  ████████╗ ██████╗ ██████╗       ██╗   ██╗██████╗ ███╗   ██╗"
    echo "  ╚══██╔══╝██╔═══██╗██╔══██╗      ██║   ██║██╔══██╗████╗  ██║"
    echo "     ██║   ██║   ██║██████╔╝█████╗██║   ██║██████╔╝██╔██╗ ██║"
    echo "     ██║   ██║   ██║██╔══██╗╚════╝╚██╗ ██╔╝██╔═══╝ ██║╚██╗██║"
    echo "     ██║   ╚██████╔╝██║  ██║       ╚████╔╝ ██║     ██║ ╚████║"
    echo "     ╚═╝    ╚═════╝ ╚═╝  ╚═╝        ╚═══╝  ╚═╝     ╚═╝  ╚═══╝"
    echo -e "${C_RESET}"
}

# --- Обработка Ctrl+C ---
TOR_PID_FILE="$SCRIPT_DIR/.tor.pid"
GATEWAY_PID_FILE="$SCRIPT_DIR/.gateway.pid"
TOR_WATCHDOG_PID=""
GATEWAY_WATCHDOG_PID=""
LOG_ROTATION_PID=""

cleanup() {
    echo ""
    info "Останавливаю сервисы..."
    [ -n "$LOG_ROTATION_PID" ] && kill "$LOG_ROTATION_PID" 2>/dev/null
    [ -n "$TOR_WATCHDOG_PID" ] && kill "$TOR_WATCHDOG_PID" 2>/dev/null
    [ -n "$GATEWAY_WATCHDOG_PID" ] && kill "$GATEWAY_WATCHDOG_PID" 2>/dev/null
    if [ -f "$GATEWAY_PID_FILE" ]; then
        kill "$(cat "$GATEWAY_PID_FILE")" 2>/dev/null
        rm -f "$GATEWAY_PID_FILE"
    fi
    if [ -f "$TOR_PID_FILE" ]; then
        kill "$(cat "$TOR_PID_FILE")" 2>/dev/null
        rm -f "$TOR_PID_FILE"
    fi
    pkill -f "tor$" 2>/dev/null
    ok "Остановлено."
    exit 0
}
trap cleanup INT TERM

banner

# --- Wake-lock — чтобы Android не "усыплял" процесс в фоне ---
# Включаем при каждом запуске (не переживает перезагрузку телефона)
if command -v termux-wake-lock >/dev/null 2>&1; then
    termux-wake-lock
    ok "Wake-lock включён (устройство не будет 'усыплено')"
else
    warn "termux-wake-lock недоступен — установите пакет termux-api для стабильности в фоне"
fi

# --- Загрузка конфига ---
if [ ! -f "$CONFIG_FILE" ]; then
    fail "Не найден config.env рядом со скриптом. Создайте его (см. README)."
    exit 1
fi
# shellcheck disable=SC1090
source "$CONFIG_FILE"

GATEWAY_USER="${GATEWAY_USER:-myuser}"
GATEWAY_PASSWORD="${GATEWAY_PASSWORD:-mypassword}"
GATEWAY_PORT="${GATEWAY_PORT:-1080}"
AUTO_UPDATE="${AUTO_UPDATE:-1}"
AUTO_RESTART="${AUTO_RESTART:-1}"
LOG_MODE="${LOG_MODE:-off}"
PARANOID_WIPE_STATE="${PARANOID_WIPE_STATE:-0}"
DISABLE_CONN_PADDING="${DISABLE_CONN_PADDING:-0}"

# --- Автообновление из GitHub ---
if [ "$AUTO_UPDATE" = "1" ] && [ -d "$SCRIPT_DIR/.git" ]; then
    info "Проверяю обновления..."
    if git -C "$SCRIPT_DIR" pull --ff-only 2>/dev/null; then
        ok "Код обновлён (если были изменения)."
    else
        warn "Не удалось обновиться (нет сети или локальные правки) — продолжаю с текущей версией."
    fi
fi

# --- Автоустановка недостающих пакетов ---
install_if_missing() {
    local bin="$1"
    local pkgname="$2"
    if ! command -v "$bin" >/dev/null 2>&1; then
        info "Устанавливаю $pkgname..."
        pkg install "$pkgname" -y >/dev/null 2>&1
    fi
}

info "Проверяю зависимости..."
install_if_missing "tor" "tor"
install_if_missing "python" "python"

# Транспорт для мостов: пробуем lyrebird (новее, поддерживает webtunnel),
# при неудаче — obfs4proxy (только obfs4)
TRANSPORT_BIN=""
if command -v lyrebird >/dev/null 2>&1; then
    TRANSPORT_BIN="$(command -v lyrebird)"
elif command -v obfs4proxy >/dev/null 2>&1; then
    TRANSPORT_BIN="$(command -v obfs4proxy)"
else
    info "Ставлю lyrebird (или obfs4proxy как запасной вариант)..."
    pkg install lyrebird -y >/dev/null 2>&1
    if command -v lyrebird >/dev/null 2>&1; then
        TRANSPORT_BIN="$(command -v lyrebird)"
    else
        pkg install obfs4proxy -y >/dev/null 2>&1
        if command -v obfs4proxy >/dev/null 2>&1; then
            TRANSPORT_BIN="$(command -v obfs4proxy)"
            warn "lyrebird недоступен — используется obfs4proxy (только мосты типа obfs4, webtunnel работать не будет)."
        fi
    fi
fi

if [ ! -f "$GATEWAY_SCRIPT" ]; then
    fail "Не найден $GATEWAY_SCRIPT рядом со скриптом."
    exit 1
fi
ok "Зависимости на месте."

# --- Определение локального IP ---
LOCAL_IP=""
for iface in wlan0 ap0 eth0; do
    ip_try="$(ip addr show "$iface" 2>/dev/null | grep "inet " | awk '{print $2}' | cut -d/ -f1)"
    if [ -n "$ip_try" ]; then
        LOCAL_IP="$ip_try"
        break
    fi
done

if [ -z "$LOCAL_IP" ]; then
    fail "Не удалось определить локальный IP. Подключитесь к Wi-Fi или включите точку доступа."
    exit 1
fi
ok "Локальный IP: $LOCAL_IP"

# --- Сбор строк мостов из bridges.txt ---
BRIDGE_LINES=()
TRANSPORTS_NEEDED=()
if [ -f "$BRIDGES_FILE" ]; then
    while IFS= read -r line; do
        # пропускаем пустые строки и комментарии
        [[ -z "$line" || "$line" =~ ^# ]] && continue
        BRIDGE_LINES+=("$line")
        transport_word="$(echo "$line" | awk '{print $1}')"
        TRANSPORTS_NEEDED+=("$transport_word")
    done < "$BRIDGES_FILE"
fi

if [ ${#BRIDGE_LINES[@]} -eq 0 ]; then
    warn "bridges.txt пуст — Tor будет подключаться напрямую, без мостов."
fi

# --- Автогенерация torrc ---
info "Собираю конфигурацию Tor..."
mkdir -p "$TOR_DATA_DIR"

# По требованию — полная зачистка состояния Tor перед стартом (кэш
# дескрипторов узлов, guard-ноды и т.п.). Не влияет на скорость уже
# установленных соединений, только увеличивает время начального
# bootstrap. Включается через PARANOID_WIPE_STATE=1 в config.env.
if [ "$PARANOID_WIPE_STATE" = "1" ]; then
    info "PARANOID_WIPE_STATE=1 — зачищаю состояние Tor перед стартом..."
    rm -rf "${TOR_DATA_DIR:?}"/*
fi

{
    echo "# Автоматически сгенерировано start_tor_vpn.sh — не редактируйте руками,"
    echo "# правьте bridges.txt и config.env вместо этого."
    echo ""
    echo "DataDirectory $TOR_DATA_DIR"
    echo ""
    echo "# SocksPort только на localhost — единственный вход в сеть для LAN-"
    echo "# устройств это авторизованный шлюз (tor_socks_gateway.py), не сам Tor."
    echo "SocksPort 127.0.0.1:$TOR_PORT"
    echo "SocksPolicy accept 127.0.0.1"
    echo "SocksPolicy reject *"
    echo ""
    echo "# Локальный control-порт для ручного сброса цепочек (new_identity.sh)."
    echo "# Тоже только на localhost, с авторизацией по cookie-файлу."
    echo "ControlPort 127.0.0.1:$TOR_CONTROL_PORT"
    echo "CookieAuthentication 1"
    echo ""
    echo "# Не писать на диск ничего, кроме необходимого минимума"
    echo "AvoidDiskWrites 1"
    echo "# Маскировать чувствительные адреса в собственных логах Tor"
    echo "SafeLogging 1"
    echo ""
    if [ "$DISABLE_CONN_PADDING" = "1" ]; then
        echo "# Отключено через DISABLE_CONN_PADDING=1: чуть меньше служебного"
        echo "# трафика и накладных расходов ценой части защиты от анализа"
        echo "# трафика по объёму/таймингам. По умолчанию padding включён."
        echo "ConnectionPadding 0"
        echo ""
    fi
    if [ ${#BRIDGE_LINES[@]} -gt 0 ]; then
        echo "UseBridges 1"
        # Подключаем нужные транспорты (без дублей)
        declare -A seen_transports
        for t in "${TRANSPORTS_NEEDED[@]}"; do
            if [ -z "${seen_transports[$t]:-}" ]; then
                seen_transports[$t]=1
                if [ -n "$TRANSPORT_BIN" ]; then
                    echo "ClientTransportPlugin $t exec $TRANSPORT_BIN"
                fi
            fi
        done
        echo ""
        for line in "${BRIDGE_LINES[@]}"; do
            echo "Bridge $line"
        done
    fi
} > "$TORRC_FILE"

ok "torrc сгенерирован ($TORRC_FILE)"

# --- Запуск Tor с автоперезапуском (watchdog) ---
mkdir -p "$(dirname "$TOR_LOG")"

# Лог не должен бесконечно расти при работе по многу дней подряд —
# обрезаем, если он раздулся больше ~5 МБ
MAX_LOG_BYTES=$((5 * 1024 * 1024))
if [ -f "$TOR_LOG" ]; then
    log_size=$(wc -c < "$TOR_LOG" 2>/dev/null || echo 0)
    if [ "$log_size" -gt "$MAX_LOG_BYTES" ]; then
        tail -c 200000 "$TOR_LOG" > "$TOR_LOG.tmp" 2>/dev/null && mv "$TOR_LOG.tmp" "$TOR_LOG"
        info "Лог Tor был большим — обрезан до последних ~200 КБ."
    fi
fi

run_tor_with_watchdog() {
    while true; do
        tor > "$TOR_LOG" 2>&1 &
        echo $! > "$TOR_PID_FILE"
        wait $!
        exit_code=$?
        if [ "$AUTO_RESTART" != "1" ]; then
            break
        fi
        warn "Tor завершился (код $exit_code), перезапускаю через 5 секунд..."
        sleep 5
    done
}

info "Запускаю Tor..."
run_tor_with_watchdog &
TOR_WATCHDOG_PID=$!

# --- Фоновая ротация лога для непрерывной работы по многу дней ---
# Обрезка при старте не спасает, если скрипт работает сутками без
# перезапуска — Tor всё это время пишет в один и тот же файл.
log_rotation_loop() {
    while true; do
        sleep 14400  # каждые 4 часа
        if [ -f "$TOR_LOG" ]; then
            log_size=$(wc -c < "$TOR_LOG" 2>/dev/null || echo 0)
            if [ "$log_size" -gt "$MAX_LOG_BYTES" ]; then
                : > "$TOR_LOG"
            fi
        fi
    done
}
log_rotation_loop &
LOG_ROTATION_PID=$!

# --- Ожидание bootstrap ---
info "Жду подключения к сети Tor..."
ATTEMPTS=0
MAX_ATTEMPTS=150
SPINNER="⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
while [ $ATTEMPTS -lt $MAX_ATTEMPTS ]; do
    if grep -q "Bootstrapped 100%" "$TOR_LOG" 2>/dev/null; then
        echo ""
        ok "Tor подключен (100%)."
        break
    fi
    idx=$((ATTEMPTS % 10))
    printf "\r${C_CYAN}%s${C_RESET} Подключаюсь... " "${SPINNER:$idx:1}"
    sleep 2
    ATTEMPTS=$((ATTEMPTS + 1))
done

if [ $ATTEMPTS -ge $MAX_ATTEMPTS ]; then
    echo ""
    fail "Tor не подключился за отведённое время. Проверьте мосты в bridges.txt."
    tail -n 15 "$TOR_LOG"
    cleanup
    exit 1
fi

# --- Запуск gateway (тоже с автоперезапуском, на случай если упадёт) ---
run_gateway_with_watchdog() {
    while true; do
        python "$GATEWAY_SCRIPT" \
            --listen "$LOCAL_IP:$GATEWAY_PORT" \
            --tor "127.0.0.1:$TOR_PORT" \
            --user "$GATEWAY_USER" \
            --password "$GATEWAY_PASSWORD" \
            --log-mode "$LOG_MODE" &
        echo $! > "$GATEWAY_PID_FILE"
        wait $!
        exit_code=$?
        if [ "$AUTO_RESTART" != "1" ]; then
            break
        fi
        warn "Шлюз завершился (код $exit_code), перезапускаю через 3 секунды..."
        sleep 3
    done
}

info "Запускаю SOCKS5-шлюз на $LOCAL_IP:$GATEWAY_PORT..."
run_gateway_with_watchdog &
GATEWAY_WATCHDOG_PID=$!

echo ""
echo -e "${C_GREEN}======================================================${C_RESET}"
echo -e " ${C_BOLD}Готово! Подключайтесь с других устройств:${C_RESET}"
echo -e "   Тип:    SOCKS5"
echo -e "   Хост:   ${C_BOLD}$LOCAL_IP${C_RESET}"
echo -e "   Порт:   ${C_BOLD}$GATEWAY_PORT${C_RESET}"
echo -e "   Логин:  ${C_BOLD}$GATEWAY_USER${C_RESET}"
echo -e "   Пароль: ${C_BOLD}$GATEWAY_PASSWORD${C_RESET}"
echo -e "${C_GREEN}======================================================${C_RESET}"
echo -e " Режим логов: ${C_BOLD}$LOG_MODE${C_RESET} (off/minimal/verbose — меняется в config.env)"
echo " Сбросить цепочки Tor без перезапуска: ./new_identity.sh"
echo " Ctrl+C — остановить всё."
echo ""

wait "$GATEWAY_WATCHDOG_PID"
cleanup
