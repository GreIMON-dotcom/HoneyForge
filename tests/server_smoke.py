"""Проверка серверного HTTPS-прокси в отдельной одноразовой лаборатории Docker.

Запуск: python tests/server_smoke.py. Нужны собранные honeyforge:local и
honeyforge-edge:local. Все тестовые порты привязаны только к loopback.
"""
import asyncio
import json
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import uuid

import httpx
from dotenv import dotenv_values
from websockets.asyncio.client import connect

ROOT = Path(__file__).resolve().parents[1]


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


async def main():
    (ROOT / "artifacts").mkdir(exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="server-smoke-", dir=ROOT / "artifacts"))
    project = "hf-server-test-" + uuid.uuid4().hex[:10]
    for name in ("compose.yaml", "compose.server.yaml", "infrastructure/nginx/nginx.conf",
                 "infrastructure/server/Caddyfile", "infrastructure/scripts/setup.py"):
        target = work / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
    subprocess.run([sys.executable, str(work / "infrastructure/scripts/setup.py")], check=True,
                   capture_output=True)
    http_port, https_port, nginx_port = free_port(), free_port(), free_port()
    base = f"https://localhost:{https_port}"
    with (work / ".env").open("a") as env:
        env.write(f"PUBLIC_DOMAIN=localhost\nMANAGEMENT_PORT={nginx_port}\n")
    (work / "test.yaml").write_text(f"""services:
  backend:
    environment:
      ALLOWED_ORIGIN: {base}
  edge:
    ports: !override
      - "127.0.0.1:{http_port}:80"
      - "127.0.0.1:{https_port}:443"
""", encoding="utf-8")
    prefix = ["docker", "compose", "-p", project, "--env-file", ".env",
              "-f", "compose.yaml", "-f", "compose.server.yaml"]

    def run(args):
        result = subprocess.run(args, cwd=work, capture_output=True, text=True,
                                encoding="utf-8", errors="replace", timeout=240)
        if result.returncode:
            raise RuntimeError(result.stderr[-5000:])
        return result.stdout.strip()

    def compose(*args):
        return run(prefix + ["-f", "test.yaml", *args])

    config = json.loads(run(prefix + ["config", "--format", "json"]))
    services = config["services"]
    exposed = [(name, port["host_ip"], str(port["published"]))
               for name, service in services.items() for port in service.get("ports", [])]
    assert sorted(exposed) == [("edge", "0.0.0.0", "443"), ("edge", "0.0.0.0", "80"),
                               ("nginx", "127.0.0.1", str(nginx_port))]
    assert set(services["edge"]["networks"]) == {"ingress"}
    assert all(config["networks"][name]["internal"] for name in ("decoy", "database", "management", "control"))
    try:
        print("Запуск отдельной лаборатории HTTPS...", flush=True)
        await asyncio.to_thread(compose, "up", "--no-build", "-d", "--wait", "--wait-timeout", "150")
        edge = compose("ps", "-q", "edge")
        for attempt in range(30):
            try:
                run(["docker", "cp", edge + ":/data/caddy/pki/authorities/local/root.crt", str(work / "edge-ca.crt")])
                break
            except RuntimeError:
                if attempt == 29:
                    raise
                await asyncio.sleep(1)
        context = ssl.create_default_context(cafile=str(work / "edge-ca.crt"))
        secrets = dotenv_values(work / ".env")
        async with httpx.AsyncClient(base_url=base, verify=context, trust_env=False, timeout=15,
                headers={"X-HoneyForge": "1", "Origin": base}) as client:
            for attempt in range(30):
                try:
                    response = await client.get("/api/v1/ready")
                    response.raise_for_status()
                    break
                except httpx.HTTPError:
                    if attempt == 29:
                        raise
                    await asyncio.sleep(1)
            assert (await client.get("/")).status_code == 200
            assert (await client.get("/api/v1/auth/me")).status_code == 401
            assert (await client.post("/api/v1/agents/heartbeat", json={})).status_code == 403
            login = await client.post("/api/v1/auth/login", json={
                "username": secrets["ADMIN_USERNAME"], "password": secrets["ADMIN_PASSWORD"]})
            login.raise_for_status()
            assert "secure" in login.headers["set-cookie"].lower()
            assert "httponly" in login.headers["set-cookie"].lower()
            assert (await client.get("/api/v1/auth/me")).status_code == 200
            denied = await client.post("/api/v1/profiles", json={}, headers={"Origin": "https://untrusted.invalid"})
            assert denied.status_code == 403
            profiles = (await client.get("/api/v1/profiles")).json()
            for kind, service in (("low", "tcp"), ("medium", "http")):
                profile = next(p for p in profiles if p["spec"]["service_type"] == service)
                deployment = await client.post("/api/v1/deployments", json={
                    "name": "Проверка HTTPS " + kind, "host_id": "lab-" + kind, "profile_id": profile["id"]})
                deployment.raise_for_status()
            for attempt in range(90):
                pots = (await client.get("/api/v1/honeypots")).json()
                if len(pots) == 2 and all(p["status"] == "running" and p["synchronized"] for p in pots):
                    break
                if attempt == 89:
                    raise AssertionError("Ловушки не запустились")
                await asyncio.sleep(1)
            cookie = "hf_session=" + client.cookies.get("hf_session")
            async with connect(base.replace("https://", "wss://") + "/api/v1/ws", ssl=context,
                    origin=base, additional_headers={"Cookie": cookie}, proxy=None) as ws:
                assert json.loads(await asyncio.wait_for(ws.recv(), 10))["type"] == "connected"
                await asyncio.to_thread(compose, "--profile", "demo", "run", "--rm", "--no-deps", "test-client")
                async with asyncio.timeout(45):
                    while json.loads(await ws.recv())["type"] != "events":
                        pass
            assert (await client.get("/api/v1/events")).json()["total"] >= 4
            redirect = await client.get(f"http://localhost:{http_port}/", follow_redirects=False)
            assert redirect.status_code == 308 and redirect.headers["location"].startswith("https://")
        print("УСПЕШНО: TLS, вход, cookie, Origin, закрытые API агентов, запуск TCP/HTTP, PostgreSQL и WebSocket.", flush=True)
    except Exception:
        print(compose("logs", "--tail", "15", "edge", "backend"), file=sys.stderr)
        raise
    finally:
        await asyncio.to_thread(compose, "down", "--volumes", "--remove-orphans")
        print("Одноразовые контейнеры и тома удалены; отчётный каталог: " + str(work), flush=True)


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    asyncio.run(main())
