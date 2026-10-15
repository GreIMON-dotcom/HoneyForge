import hashlib
import os
import secrets
import pytest
import httpx
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.pool import NullPool

os.environ["DATABASE_URL"] = "sqlite+aiosqlite://"
os.environ["ADMIN_PASSWORD"] = secrets.token_urlsafe(24)
os.environ["CONTROLLER_TOKEN"] = secrets.token_urlsafe(48)
os.environ["COOKIE_SECURE"] = "false"
os.environ["ALLOWED_ORIGIN"] = "http://test"
os.environ["BOOTSTRAP_LAB"] = "true"

from backend.app.main import app
from backend.app.db import database
from backend.app.models import Base
from backend.app.services import bootstrap

HOST = "lab-docker"


@pytest.fixture
async def factory(tmp_path):
    url = os.getenv("TEST_DATABASE_URL", "sqlite+aiosqlite:///" + str(tmp_path / "test.db"))
    if url.startswith("postgresql") and not url.rsplit("/", 1)[-1].startswith("honeyforge_test"):
        raise RuntimeError("Tests only reset databases named honeyforge_test*")
    engine = create_async_engine(url, poolclass=NullPool)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.drop_all)
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as db:
        await bootstrap(db)

    async def override():
        async with factory() as db:
            yield db
    app.dependency_overrides[database] = override
    yield factory
    app.dependency_overrides.clear()
    await engine.dispose()


@pytest.fixture
async def client(factory):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test",
                                 headers={"X-HoneyForge": "1", "Origin": "http://test"}) as client:
        response = await client.post("/api/v1/auth/login", json={"username":"admin", "password":os.environ["ADMIN_PASSWORD"]})
        assert response.status_code == 200, response.text
        yield client


@pytest.fixture
def controller_headers():
    return {"X-Controller-ID": HOST, "Authorization": "Bearer " + os.environ["CONTROLLER_TOKEN"]}


async def controller_online(client, controller_headers, **report):
    """What a live host controller does every cycle: report, which also proves the host is reachable."""
    response = await client.post("/api/v1/runtime/report", headers=controller_headers,
                                 json={"docker": {"version": "test", "ncpu": 8, "memory_bytes": 8 * 1024 ** 3}, **report})
    assert response.status_code == 200, response.text


async def profile_for(client, service_key):
    return next(p for p in (await client.get("/api/v1/profiles")).json() if p["service_key"] == service_key)


async def create_pot(client, service_key="tcp-banner", name=None, **extra):
    profile = await profile_for(client, service_key)
    body = {"name": name or "test-" + secrets.token_hex(4), "profile_id": profile["id"], "host_id": HOST, **extra}
    response = await client.post("/api/v1/honeypots", json=body)
    assert response.status_code == 201, response.text
    return response.json(), profile


async def provision(client, controller_headers, honeypot_id):
    """Controller-side agent provisioning: only the hash of a host-generated secret is registered."""
    token = secrets.token_urlsafe(48)
    response = await client.post(f"/api/v1/runtime/instances/{honeypot_id}/credential", headers=controller_headers,
                                 json={"credential_sha256": hashlib.sha256(token.encode()).hexdigest()})
    assert response.status_code == 200, response.text
    return {"X-Agent-ID": response.json()["agent_id"], "Authorization": "Bearer " + token}


async def deployed_pot(client, controller_headers, service_key="tcp-banner", name=None, **extra):
    """Instance whose deployment was requested and whose agent identity exists; not yet confirmed running."""
    await controller_online(client, controller_headers)
    pot, profile = await create_pot(client, service_key, name, deploy=True, **extra)
    return pot, profile, await provision(client, controller_headers, pot["id"])


async def confirm(client, agent_headers, honeypot_id, status=None, **changes):
    """The agent reports that the decoy applied the newest generation."""
    pot = (await client.get("/api/v1/honeypots/" + honeypot_id)).json()
    body = {"honeypot_id": honeypot_id, "generation": pot["generation"], "profile_version": pot["profile_version"],
            "status": status or ("running" if pot["desired_state"] == "running" else "stopped"), "queue_size": 0, **changes}
    response = await client.post("/api/v1/agents/heartbeat", headers=agent_headers, json=body)
    assert response.status_code == 200, response.text
    return (await client.get("/api/v1/honeypots/" + honeypot_id)).json()


async def running_pot(client, controller_headers, service_key="tcp-banner", name=None, **extra):
    pot, profile, agent = await deployed_pot(client, controller_headers, service_key, name, **extra)
    return await confirm(client, agent, pot["id"]), profile, agent
