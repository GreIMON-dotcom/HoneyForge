"""Authorized laboratory test client. Sends one harmless interaction to a decoy.

Usage inside the laboratory decoy network::

    python -m honeypots.probe tcp <alias> <port>
    python -m honeypots.probe http <alias> <port> [login-path]
    python -m honeypots.probe shell <alias> <port>

Only fictitious credentials are sent. The client never scans: it contacts
exactly the address given on the command line.
"""
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


def tcp(host: str, port: int) -> str:
    with socket.create_connection((host, port), timeout=5) as connection:
        banner = connection.recv(256).decode("utf-8", errors="replace").strip()
        try:
            connection.sendall(b"LAB-CLIENT synthetic probe\r\n")
        except OSError:
            pass
    return banner


def shell(host: str, port: int) -> str:
    """Log in with a fictitious account, look around with harmless commands and leave."""
    answer = bytearray()
    with socket.create_connection((host, port), timeout=5) as connection:
        connection.settimeout(3)
        for line in (b"root", b"fictitious-only", b"uname -a", b"cat /etc/hostname", b"exit"):
            time.sleep(0.4)
            connection.sendall(line + b"\r\n")
        try:
            while chunk := connection.recv(4096):
                answer += chunk
        except OSError:
            pass
    text = bytes(b for b in answer if b in (10, 13) or 32 <= b < 127).decode("ascii")
    return next((row.strip() for row in text.splitlines() if row.startswith("Linux ")), "")


def http(host: str, port: int, login_path: str = "/login") -> tuple[int, int]:
    base = f"http://{host}:{port}"
    with urllib.request.urlopen(base + "/", timeout=5) as page:
        opened = page.status
    form = urllib.parse.urlencode({"username": "synthetic_operator", "password": "fictitious-only"}).encode()
    try:
        with urllib.request.urlopen(base + login_path, data=form, timeout=5) as result:
            submitted = result.status
    except urllib.error.HTTPError as error:
        submitted = error.code
    return opened, submitted


def main(arguments):
    if len(arguments) < 3 or arguments[0] not in {"tcp", "http", "shell"}:
        raise SystemExit("Использование: python -m honeypots.probe tcp|http|shell <адрес> <порт> [путь входа]")
    kind, host, port = arguments[0], arguments[1], int(arguments[2])
    if kind == "shell":
        print(f"Telnet {host}:{port} → ответ оболочки: {shell(host, port) or 'нет ответа'}")
    elif kind == "tcp":
        print(f"TCP {host}:{port} → баннер: {tcp(host, port)}")
    else:
        opened, submitted = http(host, port, *arguments[3:4])
        print(f"HTTP {host}:{port} → главная страница: {opened}, вымышленный вход: {submitted}")


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    main(sys.argv[1:])
