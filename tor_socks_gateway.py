#!/usr/bin/env python3
"""
Tor SOCKS5 Gateway
==================

Небольшой SOCKS5-прокси-сервер с авторизацией по логину/паролю,
который принимает подключения из локальной сети и перенаправляет
их в локально запущенный Tor SOCKS5-порт (обычно 127.0.0.1:9050).

Зачем это нужно:
    Стандартный SocksPort в Tor НЕ поддерживает авторизацию по
    логину/паролю для входящих клиентов. Если открыть его напрямую
    в локальную сеть (0.0.0.0:9050), доступ получит любой, кто
    попадёт в вашу Wi-Fi/LAN сеть, без какой-либо проверки.

    Этот скрипт держит сам Tor только на localhost (безопасно),
    а наружу (в LAN) отдаёт отдельный SOCKS5-порт с обязательной
    авторизацией. Только устройства, знающие логин и пароль,
    смогут подключиться и пойти через Tor.

Приватность (новое):
    - --log-mode off (по умолчанию): в логах не остаётся ни IP
      клиента, ни того, к каким сайтам он подключался — только
      факт ошибок без деталей. --log-mode minimal добавляет только
      факт подключения без адресов. --log-mode verbose — как раньше,
      для отладки.
    - Изоляция цепочек Tor между устройствами: у каждого клиентского
      IP свой токен, который передаётся в Tor как SOCKS5-логин
      (IsolateSOCKSAuth). Разные устройства не делят цепочки между
      собой. Токен на устройство один и тот же в течение окна
      ISOLATION_ROTATE_SEC (по умолчанию 10 минут, совпадает с
      MaxCircuitDirtiness самого Tor) — это важно для скорости: все
      параллельные соединения браузера при загрузке одной страницы
      уходят на одни и те же уже готовые цепочки, а не строят каждое
      свою с нуля.

Скорость (новое):
    - TCP_NODELAY на обеих сторонах туннеля (клиент и Tor) — убирает
      задержку Нэгла, ощутимо для интерактивного трафика (открытие
      страниц, а не только объёмных закачек).
    - Увеличенный буфер перекачки данных (64 КБ вместо 8 КБ) — меньше
      системных вызовов на большой поток данных.
    - Изоляция теперь на устройство, а не на каждое TCP-соединение
      (см. выше) — резко меньше "холодных" цепочек при обычном
      сёрфинге с параллельными запросами.

Требования:
    - Python 3.8+
    - Работающий Tor с SocksPort 127.0.0.1:9050 (по умолчанию)
    - Никаких внешних библиотек не нужно (только стандартная библиотека)

Запуск:
    python3 tor_socks_gateway.py --listen 0.0.0.0:1080 \
        --tor 127.0.0.1:9050 \
        --user myuser --password mypassword

    После этого на клиентских устройствах указываете:
        SOCKS5, хост = IP этого ПК, порт = 1080,
        логин/пароль = как указали выше
"""

import argparse
import hmac
import logging
import secrets
import socket
import struct
import threading
import time
import sys

# Окно, в течение которого одно и то же устройство получает один и
# тот же изоляционный токен для Tor (совпадает с дефолтным
# MaxCircuitDirtiness Tor, чтобы не создавать новых цепочек чаще,
# чем сам Tor их всё равно бы обновил).
ISOLATION_ROTATE_SEC = 600

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("tor-gateway")

SOCKS_VERSION = 0x05

# --- Коды методов авторизации SOCKS5 ---
METHOD_NO_AUTH = 0x00
METHOD_USER_PASS = 0x02
METHOD_NO_ACCEPTABLE = 0xFF

# --- Коды команд ---
CMD_CONNECT = 0x01

# --- Типы адресов ---
ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x03
ATYP_IPV6 = 0x04


class GatewayConfig:
    def __init__(self, listen_host, listen_port, tor_host, tor_port,
                 username, password, allowed_ips=None, log_mode="off"):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.tor_host = tor_host
        self.tor_port = tor_port
        self.username = username
        self.password = password
        self.allowed_ips = allowed_ips  # список строк IP, либо None = все
        self.log_mode = log_mode  # "off" | "minimal" | "verbose"
        # {client_ip: (token, expires_at)} — не персистится, живёт
        # только в памяти процесса, теряется при перезапуске.
        self._isolation_tokens = {}
        self._isolation_lock = threading.Lock()

    def get_isolation_token(self, client_ip: str) -> str:
        """Возвращает изоляционный токен для устройства, создавая новый
        раз в ISOLATION_ROTATE_SEC. Одно устройство = одна и та же
        группа цепочек Tor в течение окна — быстрее для параллельных
        соединений браузера, но разные устройства всё равно не делят
        цепочки друг с другом."""
        now = time.monotonic()
        with self._isolation_lock:
            entry = self._isolation_tokens.get(client_ip)
            if entry is not None and entry[1] > now:
                return entry[0]
            token = secrets.token_hex(16)
            self._isolation_tokens[client_ip] = (token, now + ISOLATION_ROTATE_SEC)
            return token


def log_event(cfg: GatewayConfig, level: str, generic_msg: str, detailed_msg: str = None, *args):
    """Логирует событие с учётом режима приватности.

    off      — вообще не пишет ничего, что может выдать, кто и куда
                подключался (только критические ошибки без деталей).
    minimal  — пишет факт события, но без IP клиента и без адреса
                назначения.
    verbose  — пишет всё, включая IP и целевой хост (для отладки).
    """
    if cfg.log_mode == "off":
        return
    msg = detailed_msg if (cfg.log_mode == "verbose" and detailed_msg) else generic_msg
    getattr(log, level)(msg, *args)


def recv_exact(sock: socket.socket, n: int) -> bytes:
    """Читает ровно n байт из сокета или кидает исключение."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Соединение закрыто клиентом")
        buf += chunk
    return buf


def client_handshake(conn: socket.socket, cfg: GatewayConfig) -> bool:
    """Выполняет приветствие SOCKS5 и авторизацию по логину/паролю.

    Возвращает True, если клиент успешно авторизован.
    """
    # --- Приветствие: VER, NMETHODS, METHODS ---
    header = recv_exact(conn, 2)
    ver, nmethods = header[0], header[1]
    if ver != SOCKS_VERSION:
        log_event(cfg, "warning", "Неверная версия протокола от клиента", "Неверная версия протокола от клиента: %s", ver)
        return False

    methods = recv_exact(conn, nmethods)

    if METHOD_USER_PASS not in methods:
        # Клиент не поддерживает авторизацию логином/паролем — отказ
        conn.sendall(bytes([SOCKS_VERSION, METHOD_NO_ACCEPTABLE]))
        log_event(cfg, "warning", "Клиент не предложил метод USER/PASS, отказано")
        return False

    # Сообщаем клиенту, что выбираем авторизацию по логину/паролю
    conn.sendall(bytes([SOCKS_VERSION, METHOD_USER_PASS]))

    # --- Подпереговоры авторизации (RFC 1929) ---
    auth_header = recv_exact(conn, 2)
    auth_ver, ulen = auth_header[0], auth_header[1]
    username = recv_exact(conn, ulen).decode("utf-8", errors="replace")

    plen = recv_exact(conn, 1)[0]
    password = recv_exact(conn, plen).decode("utf-8", errors="replace")

    if hmac.compare_digest(username, cfg.username) and hmac.compare_digest(password, cfg.password):
        conn.sendall(bytes([0x01, 0x00]))  # успех
        return True
    else:
        conn.sendall(bytes([0x01, 0x01]))  # ошибка авторизации
        # Логин из попытки НЕ пишем даже в minimal-режиме — это тоже
        # потенциально идентифицирующие данные, если кто-то перебирает пароль.
        log_event(cfg, "warning", "Неверный логин/пароль от клиента", "Неверный логин/пароль от клиента (login=%r)", username)
        return False


def parse_target_address(conn: socket.socket):
    """Читает запрос CONNECT от клиента и возвращает (host, port)."""
    req_header = recv_exact(conn, 4)
    ver, cmd, rsv, atyp = req_header

    if ver != SOCKS_VERSION:
        raise ValueError("Неверная версия в запросе")
    if cmd != CMD_CONNECT:
        raise ValueError("Поддерживается только команда CONNECT")

    if atyp == ATYP_IPV4:
        addr_bytes = recv_exact(conn, 4)
        host = socket.inet_ntoa(addr_bytes)
    elif atyp == ATYP_DOMAIN:
        length = recv_exact(conn, 1)[0]
        host = recv_exact(conn, length).decode("utf-8")
    elif atyp == ATYP_IPV6:
        addr_bytes = recv_exact(conn, 16)
        host = socket.inet_ntop(socket.AF_INET6, addr_bytes)
    else:
        raise ValueError("Неподдерживаемый тип адреса")

    port_bytes = recv_exact(conn, 2)
    port = struct.unpack(">H", port_bytes)[0]

    return host, port, atyp


def connect_to_tor(cfg: GatewayConfig, target_host: str, target_port: int,
                    isolation_token: str) -> socket.socket:
    """Открывает соединение к Tor SOCKS5 и просит его самого сделать
    CONNECT до реального адреса назначения.

    Изоляция цепочек: передаёт Tor'у одноразовый случайный логин
    (isolation_token) через авторизацию SOCKS5. Tor использует разные
    логины как сигнал для IsolateSOCKSAuth (включена по умолчанию) —
    это гарантирует, что два разных подключения (например, с двух
    разных устройств в вашей сети) не окажутся на одной и той же
    цепочке Tor, даже если идут почти одновременно. Пароль в этой
    паре Tor не проверяет — сам факт разных логинов уже достаточен
    для разделения цепочек.
    """
    tor_sock = socket.create_connection((cfg.tor_host, cfg.tor_port), timeout=15)
    try:
        tor_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        pass

    # Предлагаем Tor'у оба метода: авторизация по логину/паролю (для
    # изоляции цепочек) и без авторизации (запасной вариант, если
    # Tor почему-то не поддержит первый метод).
    tor_sock.sendall(bytes([SOCKS_VERSION, 2, METHOD_USER_PASS, METHOD_NO_AUTH]))
    resp = recv_exact(tor_sock, 2)
    chosen_method = resp[1]

    if chosen_method == METHOD_USER_PASS:
        user_bytes = isolation_token.encode("utf-8")[:255]
        pass_bytes = b"x"  # Tor не проверяет пароль, важен только логин
        auth_req = bytes([0x01, len(user_bytes)]) + user_bytes
        auth_req += bytes([len(pass_bytes)]) + pass_bytes
        tor_sock.sendall(auth_req)
        auth_resp = recv_exact(tor_sock, 2)
        if auth_resp[1] != 0x00:
            tor_sock.close()
            raise ConnectionError("Tor отклонил isolation-логин (неожиданно)")
    elif chosen_method != METHOD_NO_AUTH:
        tor_sock.close()
        raise ConnectionError("Tor запросил неподдерживаемый метод авторизации")
    # иначе chosen_method == METHOD_NO_AUTH — просто продолжаем без изоляции

    # Формируем запрос CONNECT к целевому хосту через домен (ATYP_DOMAIN),
    # чтобы DNS резолвился на стороне Tor, а не локально (защита от утечек DNS)
    host_bytes = target_host.encode("utf-8")
    request = bytes([SOCKS_VERSION, CMD_CONNECT, 0x00, ATYP_DOMAIN])
    request += bytes([len(host_bytes)]) + host_bytes
    request += struct.pack(">H", target_port)

    tor_sock.sendall(request)

    reply_header = recv_exact(tor_sock, 4)
    rep = reply_header[1]
    if rep != 0x00:
        tor_sock.close()
        raise ConnectionError(f"Tor отклонил подключение, код ошибки: {rep}")

    # Дочитываем оставшуюся часть ответа (bind address + port), не используем
    atyp = reply_header[3]
    if atyp == ATYP_IPV4:
        recv_exact(tor_sock, 4 + 2)
    elif atyp == ATYP_DOMAIN:
        l = recv_exact(tor_sock, 1)[0]
        recv_exact(tor_sock, l + 2)
    elif atyp == ATYP_IPV6:
        recv_exact(tor_sock, 16 + 2)

    return tor_sock


def relay(a: socket.socket, b: socket.socket):
    """Двусторонняя перекачка данных между двумя сокетами."""
    def pipe(src, dst):
        try:
            while True:
                # 64 КБ вместо 8 КБ — меньше системных вызовов на
                # больших закачках, заметно для пропускной способности.
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        except OSError:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    t1 = threading.Thread(target=pipe, args=(a, b), daemon=True)
    t2 = threading.Thread(target=pipe, args=(b, a), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()


def handle_client(conn: socket.socket, addr, cfg: GatewayConfig):
    client_ip = addr[0]
    # Токен для этого устройства — один и тот же в течение окна
    # ISOLATION_ROTATE_SEC (не логируется и не сохраняется на диск).
    isolation_token = cfg.get_isolation_token(client_ip)

    # Убираем задержку Нэгла — заметно для отзывчивости при открытии
    # страниц (много мелких пакетов), почти бесплатно по ресурсам.
    try:
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        pass
    try:
        if cfg.allowed_ips and client_ip not in cfg.allowed_ips:
            log_event(cfg, "warning", "Отклонено подключение с неразрешённого IP", "Отклонено подключение с неразрешённого IP: %s", client_ip)
            conn.close()
            return

        # Таймаут только на этап рукопожатия/авторизации — если клиент
        # подключился и молчит (случайно или специально), не держим поток
        # вечно. Многодневная работа без утечки "зависших" потоков.
        conn.settimeout(30)

        if not client_handshake(conn, cfg):
            conn.close()
            return

        target_host, target_port, _ = parse_target_address(conn)
        log_event(cfg, "info", "Клиент установил соединение", "Клиент %s запросил соединение с %s:%s", client_ip, target_host, target_port)

        try:
            tor_sock = connect_to_tor(cfg, target_host, target_port, isolation_token)
        except Exception as e:
            log_event(cfg, "error", "Ошибка подключения через Tor", "Ошибка подключения через Tor (%s -> %s:%s): %s", client_ip, target_host, target_port, e)
            # Сообщаем клиенту об ошибке (общий код отказа)
            bind_addr = socket.inet_aton("0.0.0.0")
            conn.sendall(bytes([SOCKS_VERSION, 0x01, 0x00, ATYP_IPV4]) + bind_addr + struct.pack(">H", 0))
            conn.close()
            return

        # Успешный ответ клиенту
        bind_addr = socket.inet_aton("0.0.0.0")
        conn.sendall(bytes([SOCKS_VERSION, 0x00, 0x00, ATYP_IPV4]) + bind_addr + struct.pack(">H", 0))

        # Снимаем таймаут — дальше это уже длительный поток данных
        # (загрузка страниц, видео и т.п.), рвать его по таймауту не нужно.
        conn.settimeout(None)
        tor_sock.settimeout(None)

        relay(conn, tor_sock)

    except Exception as e:
        log_event(cfg, "error", "Ошибка обработки клиента", "Ошибка обработки клиента %s: %s", client_ip, e)
    finally:
        try:
            conn.close()
        except OSError:
            pass


def main():
    parser = argparse.ArgumentParser(description="SOCKS5 gateway перед Tor с авторизацией")
    parser.add_argument("--listen", default="0.0.0.0:1080",
                         help="Адрес:порт для приёма клиентов (по умолчанию 0.0.0.0:1080)")
    parser.add_argument("--tor", default="127.0.0.1:9050",
                         help="Адрес:порт локального Tor SOCKS5 (по умолчанию 127.0.0.1:9050)")
    parser.add_argument("--user", required=True, help="Логин для клиентов")
    parser.add_argument("--password", required=True, help="Пароль для клиентов")
    parser.add_argument("--allow-ip", action="append", default=None,
                         help="Разрешить только этот IP (можно указать несколько раз). "
                              "Если не указано — разрешены все, кто знает логин/пароль.")
    parser.add_argument("--log-mode", choices=["off", "minimal", "verbose"], default="off",
                         help="off (по умолчанию) — не логировать IP/адреса вообще; "
                              "minimal — только факт событий без адресов; "
                              "verbose — полные логи для отладки.")
    args = parser.parse_args()

    listen_host, listen_port = args.listen.split(":")
    tor_host, tor_port = args.tor.split(":")

    cfg = GatewayConfig(
        listen_host=listen_host,
        listen_port=int(listen_port),
        tor_host=tor_host,
        tor_port=int(tor_port),
        username=args.user,
        password=args.password,
        allowed_ips=args.allow_ip,
        log_mode=args.log_mode,
    )

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((cfg.listen_host, cfg.listen_port))
    server.listen(50)

    # Эти строки — не про конкретных клиентов, а про сам сервис, поэтому
    # печатаются всегда (полезно, чтобы понимать, что шлюз вообще стартовал).
    log.info("Gateway слушает на %s:%s", cfg.listen_host, cfg.listen_port)
    log.info("Трафик направляется в Tor на %s:%s", cfg.tor_host, cfg.tor_port)
    log.info("Режим логирования: %s", cfg.log_mode)

    try:
        while True:
            conn, addr = server.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr, cfg), daemon=True)
            t.start()
    except KeyboardInterrupt:
        log.info("Остановка по Ctrl+C")
    finally:
        server.close()


if __name__ == "__main__":
    main()
