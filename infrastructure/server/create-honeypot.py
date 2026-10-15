"""Развернуть одну ловушку на этом сервере. Запускается через SSH со стороны .bat.

Читает учётные данные панели из /opt/honeyforge/.env и не выводит их.
Аргумент 1 — тип сервиса (по умолчанию telnet-shell), аргумент 2 — название (необязательно).
Ловушка остаётся во внутренней лабораторной сети; публикацию в интернет выполняет администратор в панели.
"""
import http.cookiejar
import ssl
import sys
import time
import urllib.error
import urllib.request
import json
from datetime import datetime
from pathlib import Path

ROOT = Path("/opt/honeyforge")
env = dict(line.split("=", 1) for line in (ROOT / ".env").read_text().splitlines() if "=" in line)
context = ssl.create_default_context(cafile=str(ROOT / "infrastructure/certs/ca.crt"))
context.verify_flags &= ~ssl.VERIFY_X509_STRICT
opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context),
                                     urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))


def api(method, path, body=None):
    request = urllib.request.Request("https://localhost:8443/api/v1" + path, method=method,
                                     data=None if body is None else json.dumps(body).encode(),
                                     headers={"X-HoneyForge": "1", "Origin": env.get("ALLOWED_ORIGIN", "https://localhost:8443"),
                                              "Content-Type": "application/json"})
    try:
        with opener.open(request, timeout=20) as response:
            raw = response.read()
    except urllib.error.HTTPError as error:
        raise SystemExit(f"Ошибка {error.code} при {method} {path}: {error.read()[:300].decode('utf-8', 'replace')}")
    return json.loads(raw) if raw else None


service_key = (sys.argv[1] if len(sys.argv) > 1 else "telnet-shell").strip()
name = (sys.argv[2].strip() if len(sys.argv) > 2 and sys.argv[2].strip() else
        f"Ловушка {service_key} {datetime.now():%d.%m %H:%M}")

api("POST", "/auth/login", {"username": env["ADMIN_USERNAME"], "password": env["ADMIN_PASSWORD"]})
services = {s["key"]: s for s in api("GET", "/service-types")}
if service_key not in services:
    raise SystemExit("Неизвестный тип сервиса: " + service_key + ". Доступны: " + ", ".join(services))
profile = next((p for p in api("GET", "/profiles") if p["service_key"] == service_key and p["spec"]["enabled"]), None)
if not profile:
    defaults = api("GET", "/service-types/" + service_key)["defaults"]
    profile = api("POST", "/profiles", defaults | {"name": "Профиль " + service_key})
print(f"Тип: {services[service_key]['display_name']} · профиль: {profile['name']}")

pot = api("POST", "/honeypots", {"name": name, "profile_id": profile["id"], "host_id": "lab-docker", "deploy": True})
print("Создаётся:", name)
deadline = time.time() + 120
while time.time() < deadline:
    pot = api("GET", "/honeypots/" + pot["id"])
    if pot["status"] == "running" and pot["synchronized"]:
        endpoint = pot["endpoint"]
        print(f"Готово. Состояние: работает. Адрес в лаборатории: {endpoint['alias']}:{endpoint['port']}")
        print("Опубликовать в интернет можно в панели: страница ловушки → «Опубликовать порт».")
        break
    if pot["status"] == "failed":
        raise SystemExit("Развёртывание не удалось: " + (pot.get("error") or "см. журнал ловушки в панели"))
    time.sleep(2)
else:
    print("Ловушка создана, но ещё не подтвердила запуск. Проверьте её состояние в панели.")
