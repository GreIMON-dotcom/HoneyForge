"""Подготовка параметров HTTPS на выбранном сервере без публикации секретов."""
import argparse
import ipaddress
import re

from setup import ROOT, main as setup_lab


def public_domain(value: str) -> str:
    value = value.strip().lower().rstrip(".")
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise argparse.ArgumentTypeError("Некорректное доменное имя") from exc
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise argparse.ArgumentTypeError("Укажите доменное имя, а не IP-адрес")
    labels = value.split(".")
    if (len(value) > 253 or len(labels) < 2
            or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels)
            or labels[-1] in {"localhost", "local", "test", "invalid", "example"}):
        raise argparse.ArgumentTypeError("Нужно публичное доменное имя без https://, пути и порта")
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("domain", type=public_domain)
    args = parser.parse_args()
    setup_lab()
    target = ROOT / ".server.env"
    target.write_text(f"PUBLIC_DOMAIN={args.domain}\n", encoding="utf-8")
    target.chmod(0o600)
    print(f"Адрес панели: https://{args.domain}")
    print("Для внешнего доступа доверять локальному CA в браузере не требуется.")
    print("После настройки DNS и портов 80/443 выполните:")
    print("docker compose --env-file .env --env-file .server.env -f compose.yaml -f compose.server.yaml up --build -d --wait")


if __name__ == "__main__":
    main()
