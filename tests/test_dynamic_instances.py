"""The two-slot limit is gone: many independent instances per profile, host and service type."""
import asyncio
import os
from datetime import timedelta
import pytest
from backend.app.models import Honeypot, NetworkEndpoint, Agent, Event, now
from backend.app.services import maintenance_once
from sqlalchemy import select, func
from conftest import HOST, controller_online, create_pot, deployed_pot, running_pot, confirm, provision, profile_for
from test_backend import event


async def six_instances(client, controller_headers):
    """Three TCP and three HTTP instances created only through the management API."""
    result = []
    for service_key, label in (("tcp-banner", "tcp"), ("http-admin", "http")):
        for number in (1, 2, 3):
            result.append(await running_pot(client, controller_headers, service_key, f"{label}-{number}"))
    return result


async def test_six_instances_from_two_profiles_are_independent(client, controller_headers, factory):
    instances = await six_instances(client, controller_headers)
    pots = [pot for pot, _, _ in instances]
    assert len({p["id"] for p in pots}) == 6
    assert len({p["agent"]["id"] for p in pots}) == 6
    assert all(p["status"] == "running" and p["synchronized"] for p in pots)
    assert len({p["profile_id"] for p in pots}) == 2
    assert [p["endpoint"]["port"] for p in pots] == [8022, 8023, 8024, 8080, 8081, 8082]
    assert len({p["endpoint"]["alias"] for p in pots}) == 6
    assert all(p["configuration"]["port"] == p["endpoint"]["port"] for p in pots)
    inventory = (await client.get("/api/v1/honeypots")).json()
    assert len(inventory) == 6 and {p["service_key"] for p in inventory} == {"tcp-banner", "http-admin"}
    assert len((await client.get("/api/v1/honeypots?service_key=http-admin")).json()) == 3
    assert [p["name"] for p in (await client.get("/api/v1/honeypots?q=tcp-2")).json()] == ["tcp-2"]

    for pot, _, agent in instances:
        response = await client.post(f'/api/v1/agents/{agent["X-Agent-ID"]}/telemetry', headers=agent,
                                     json={"events": [event(honeypot_id=pot["id"], destination_port=pot["endpoint"]["port"])]})
        assert response.json()["inserted"] == 1
    first, second = instances[0], instances[1]
    foreign = await client.post(f'/api/v1/agents/{first[2]["X-Agent-ID"]}/telemetry', headers=first[2],
                                json={"events": [event(honeypot_id=second[0]["id"])]})
    assert foreign.status_code == 409
    for pot in pots:
        events = (await client.get("/api/v1/events", params={"honeypot_id": pot["id"]})).json()
        assert events["total"] == 1 and events["items"][0]["destination_port"] == pot["endpoint"]["port"]
    assert all(p["event_count"] == 1 for p in (await client.get("/api/v1/honeypots")).json())

    target = pots[1]
    stopping = (await client.post(f'/api/v1/honeypots/{target["id"]}/stop')).json()
    assert stopping["status"] == "stopping"
    assert (await confirm(client, instances[1][2], target["id"]))["status"] == "stopped"
    others = [p for p in (await client.get("/api/v1/honeypots")).json() if p["id"] != target["id"]]
    assert len(others) == 5 and all(p["status"] == "running" and p["generation"] == 2 for p in others)
    assert (await client.post(f'/api/v1/honeypots/{target["id"]}/start')).json()["status"] == "starting"
    assert (await confirm(client, instances[1][2], target["id"]))["status"] == "running"

    capacity = (await client.get(f"/api/v1/hosts/{HOST}/capacity")).json()
    assert capacity["allocated"]["instances"] == 6 and capacity["allocated"]["endpoints"] == 6
    assert capacity["allocated"]["memory_mb"] == 6 * (128 + 96)
    async with factory() as db:
        assert await db.scalar(select(func.count()).select_from(Agent)) == 6


async def test_instance_override_and_update_do_not_touch_siblings(client, controller_headers):
    first, profile, agent = await running_pot(client, controller_headers, name="alpha",
                                              overrides={"banner": "SSH-2.0-Alpha"})
    second, _, second_agent = await running_pot(client, controller_headers, name="beta")
    config = (await client.get(f'/api/v1/agents/{agent["X-Agent-ID"]}/configuration', headers=agent)).json()
    assert config["spec"]["banner"] == "SSH-2.0-Alpha" and config["spec"]["port"] == 8022
    changed = await client.patch("/api/v1/honeypots/" + first["id"], json={"overrides": {"banner": "SSH-2.0-Alpha_2", "max_input_bytes": 64}})
    assert changed.status_code == 200 and changed.json()["status"] == "updating"
    assert (await confirm(client, agent, first["id"]))["status"] == "running"
    sibling = (await client.get("/api/v1/honeypots/" + second["id"])).json()
    assert sibling["generation"] == second["generation"] and sibling["configuration"]["banner"] == profile["spec"]["banner"]
    assert (await client.patch("/api/v1/honeypots/" + first["id"], json={"overrides": {"service_key": "http-admin"}})).status_code == 422
    assert (await client.patch("/api/v1/honeypots/" + first["id"], json={"overrides": {"memory_mb": 99999}})).status_code == 422
    assert (await client.patch("/api/v1/honeypots/" + first["id"], json={"command": "id"})).status_code == 422


async def test_profile_change_follows_each_instance_policy(client, controller_headers):
    manual, profile, manual_agent = await running_pot(client, controller_headers, name="manual")
    automatic, _, auto_agent = await running_pot(client, controller_headers, name="automatic", update_policy="auto")
    response = await client.patch("/api/v1/profiles/" + profile["id"], json=profile["spec"] | {"banner": "SSH-2.0-Updated_Lab"})
    assert response.json()["version"] == 2
    automatic = (await client.get("/api/v1/honeypots/" + automatic["id"])).json()
    assert automatic["status"] == "updating" and automatic["configuration"]["banner"] == "SSH-2.0-Updated_Lab"
    assert not automatic["update_available"]
    manual = (await client.get("/api/v1/honeypots/" + manual["id"])).json()
    assert manual["status"] == "running" and manual["update_available"]
    assert manual["configuration"]["banner"] == profile["spec"]["banner"] and manual["profile_version"] == 1
    stored = (await client.get(f'/api/v1/honeypots/{manual["id"]}/configuration')).json()
    assert stored["update_available"] and stored["profile_latest_version"] == 2
    applied = (await client.post(f'/api/v1/honeypots/{manual["id"]}/apply-updates')).json()
    assert applied["status"] == "updating" and applied["profile_version"] == 2
    config = (await client.get(f'/api/v1/agents/{manual_agent["X-Agent-ID"]}/configuration', headers=manual_agent)).json()
    assert config["spec"]["banner"] == "SSH-2.0-Updated_Lab" and config["profile_version"] == 2
    assert (await confirm(client, manual_agent, manual["id"]))["synchronized"]
    assert (await confirm(client, auto_agent, automatic["id"]))["synchronized"]


async def test_endpoint_allocation_conflicts_and_release(client, controller_headers, factory):
    await controller_online(client, controller_headers)
    first, profile = await create_pot(client, name="first")
    assert first["status"] == "draft" and first["endpoint"]["port"] == 8022 and first["endpoint"]["mode"] == "auto"
    body = {"name": "second", "profile_id": profile["id"], "host_id": HOST, "port_mode": "manual", "port": 8022}
    conflict = await client.post("/api/v1/honeypots", json=body)
    assert conflict.status_code == 409 and "Конфликт портов" in conflict.json()["detail"]
    assert (await client.post("/api/v1/honeypots", json=body | {"port": 20000})).status_code == 422
    assert (await client.post("/api/v1/honeypots", json=body | {"port": None})).status_code == 422
    manual = await client.post("/api/v1/honeypots", json=body | {"port": 8500})
    assert manual.status_code == 201 and manual.json()["endpoint"]["address"].endswith(":8500")
    check = "/api/v1/network-endpoints/validate"
    assert (await client.post(check, json={"host_id": HOST, "mode": "manual", "port": 8500})).json()["available"] is False
    free = (await client.post(check, json={"host_id": HOST, "preferred_port": 8022})).json()
    assert free["available"] and free["port"] == 8023 and free["published"] is False
    listing = (await client.get("/api/v1/network-endpoints", params={"host_id": HOST})).json()
    assert [e["internal_port"] for e in listing] == [8022, 8500] and all(e["published_port"] is None for e in listing)
    assert (await client.patch("/api/v1/honeypots/" + first["id"], json={"port": 8500})).status_code == 409
    moved = (await client.patch("/api/v1/honeypots/" + first["id"], json={"port": 8100})).json()
    assert moved["endpoint"]["port"] == 8100 and moved["configuration"]["port"] == 8100
    assert (await client.delete("/api/v1/honeypots/" + first["id"])).json()["deleted"] is True
    reused, _ = await create_pot(client, name="third", port_mode="manual", port=8100)
    assert reused["endpoint"]["port"] == 8100
    async with factory() as db:
        assert await db.scalar(select(func.count()).select_from(NetworkEndpoint)) == 2


async def test_capacity_policy_rejects_overcommit(client, controller_headers):
    await controller_online(client, controller_headers)
    policy = await client.patch(f"/api/v1/hosts/{HOST}", json={"max_instances": 2, "memory_budget_mb": 4096, "cpu_budget": 8})
    assert policy.status_code == 200 and policy.json()["capacity"]["policy"]["max_instances"] == 2
    await create_pot(client, name="one", deploy=True)
    await create_pot(client, name="two", deploy=True)
    profile = await profile_for(client, "tcp-banner")
    third = await client.post("/api/v1/honeypots", json={"name": "three", "profile_id": profile["id"], "host_id": HOST, "deploy": True})
    assert third.status_code == 409 and "предел числа ловушек" in third.json()["detail"]
    assert len((await client.get("/api/v1/honeypots")).json()) == 2
    assert len((await client.get("/api/v1/network-endpoints")).json()) == 2
    draft, _ = await create_pot(client, name="three")
    await client.patch(f"/api/v1/hosts/{HOST}", json={"max_instances": 10, "memory_budget_mb": 2 * (128 + 96) + 100})
    memory = await client.post(f'/api/v1/honeypots/{draft["id"]}/deploy')
    assert memory.status_code == 409 and memory.json()["detail"] == "Недостаточно оперативной памяти для запуска новой ловушки"
    await client.patch(f"/api/v1/hosts/{HOST}", json={"memory_budget_mb": 4096, "cpu_budget": 2 * 0.75 + 0.5})
    cpu = await client.post(f'/api/v1/honeypots/{draft["id"]}/deploy')
    assert cpu.status_code == 409 and "процессора" in cpu.json()["detail"]
    await client.patch(f"/api/v1/hosts/{HOST}", json={"cpu_budget": 8})
    assert (await client.post(f'/api/v1/honeypots/{draft["id"]}/deploy')).json()["status"] == "deploying"
    assert (await client.patch(f"/api/v1/hosts/{HOST}", json={"port_range_start": 8500})).status_code == 409
    assert (await client.patch(f"/api/v1/hosts/{HOST}", json={"port_range_start": 9000, "port_range_end": 8000})).status_code == 422


async def test_clone_is_a_new_independent_instance(client, controller_headers):
    source, _, agent = await running_pot(client, controller_headers, name="origin", tags=["web", "демо"],
                                         description="Исходная", overrides={"banner": "SSH-2.0-Origin"})
    await client.post(f'/api/v1/agents/{agent["X-Agent-ID"]}/telemetry', headers=agent, json={"events": [event(honeypot_id=source["id"])]})
    response = await client.post(f'/api/v1/honeypots/{source["id"]}/clone', json={"name": "copy", "deploy": True})
    assert response.status_code == 201, response.text
    clone = response.json()
    assert clone["id"] != source["id"] and clone["endpoint"]["port"] == 8023 and clone["endpoint"]["alias"] != source["endpoint"]["alias"]
    assert clone["configuration"]["banner"] == "SSH-2.0-Origin" and clone["tags"] == ["web", "демо"]
    assert clone["event_count"] == 0 and clone["agent"] is None and clone["status"] == "deploying" and clone["runtime"] == {}
    clone_agent = await provision(client, controller_headers, clone["id"])
    assert clone_agent["X-Agent-ID"] != agent["X-Agent-ID"]
    await client.patch("/api/v1/honeypots/" + clone["id"], json={"overrides": {"banner": "SSH-2.0-Copy"}})
    assert (await client.get("/api/v1/honeypots/" + source["id"])).json()["configuration"]["banner"] == "SSH-2.0-Origin"
    assert (await client.post(f'/api/v1/honeypots/{source["id"]}/clone', json={"name": "copy"})).status_code == 409


async def test_delete_waits_for_runtime_cleanup_and_releases_everything(client, controller_headers, factory):
    pot, _, agent = await running_pot(client, controller_headers, name="short-lived")
    keeper, _, keeper_agent = await running_pot(client, controller_headers, name="keeper")
    await client.post(f'/api/v1/agents/{agent["X-Agent-ID"]}/telemetry', headers=agent, json={"events": [event(honeypot_id=pot["id"])]})
    await client.post(f'/api/v1/honeypots/{pot["id"]}/stop')
    assert (await confirm(client, agent, pot["id"]))["status"] == "stopped"
    response = await client.delete("/api/v1/honeypots/" + pot["id"])
    assert response.json() == {"ok": True, "deleted": False, "status": "deleting"}
    desired = (await client.get("/api/v1/runtime/desired", headers=controller_headers)).json()["instances"]
    assert {i["honeypot_id"]: i["desired"] for i in desired} == {pot["id"]: "absent", keeper["id"]: "present"}
    for operation in ("start", "restart", "stop"):
        assert (await client.post(f'/api/v1/honeypots/{pot["id"]}/{operation}')).status_code == 409
    assert (await client.patch("/api/v1/honeypots/" + pot["id"], json={"overrides": {"banner": "x"}})).status_code == 409
    assert (await client.get("/api/v1/honeypots/" + pot["id"])).json()["status"] == "deleting"
    await controller_online(client, controller_headers, removed=[pot["id"]])
    assert (await client.get("/api/v1/honeypots/" + pot["id"])).status_code == 404
    assert (await client.post("/api/v1/agents/heartbeat", headers=agent, json={"generation": 1, "status": "stopped", "queue_size": 0})).status_code == 401
    assert (await confirm(client, keeper_agent, keeper["id"]))["status"] == "running"
    async with factory() as db:
        assert await db.scalar(select(func.count()).select_from(Honeypot)) == 1
        assert await db.scalar(select(func.count()).select_from(NetworkEndpoint)) == 1
        assert await db.scalar(select(func.count()).select_from(Event)) == 0
    audit = [a["action"] for a in (await client.get("/api/v1/audit")).json()["items"]]
    assert "honeypot.delete_requested" in audit and "honeypot.delete" in audit
    reused, _ = await create_pot(client, name="reuse", port_mode="manual", port=8022)
    assert reused["endpoint"]["port"] == 8022


async def test_forced_delete_and_unconfirmed_operation(client, controller_headers, factory):
    pot, _, _ = await deployed_pot(client, controller_headers, name="stuck")
    async with factory() as db:
        obj = await db.get(Honeypot, pot["id"])
        obj.transition_at = now() - timedelta(minutes=10)
        await db.commit()
        await maintenance_once(db)
    failed = (await client.get("/api/v1/honeypots/" + pot["id"])).json()
    assert failed["status"] == "failed" and "не подтверждена" in failed["error"]
    assert failed["deployments"][0]["status"] == "failed" and failed["commands"][0]["status"] == "failed"
    assert any(row["code"] == "operation.timeout" for row in (await client.get(f'/api/v1/honeypots/{pot["id"]}/logs')).json())
    running, _, _ = await running_pot(client, controller_headers, name="lost-host")
    assert (await client.delete("/api/v1/honeypots/" + running["id"])).status_code == 409
    assert (await client.delete("/api/v1/honeypots/" + running["id"] + "?force=true")).json()["deleted"] is True
    assert (await client.delete("/api/v1/honeypots/" + pot["id"])).json()["status"] == "deleting"


async def test_lifecycle_requests_are_idempotent_and_guarded(client, controller_headers):
    draft, _ = await create_pot(client, name="draft")
    assert (await client.post(f'/api/v1/honeypots/{draft["id"]}/start')).status_code == 409
    pot, _, agent = await running_pot(client, controller_headers, name="steady")
    again = (await client.post(f'/api/v1/honeypots/{pot["id"]}/start')).json()
    assert again["generation"] == pot["generation"] and again["status"] == "running"
    assert (await client.post(f'/api/v1/honeypots/{pot["id"]}/deploy')).json()["generation"] == pot["generation"]
    stopped = (await client.post(f'/api/v1/honeypots/{pot["id"]}/stop')).json()
    assert (await client.post(f'/api/v1/honeypots/{pot["id"]}/stop')).json()["generation"] == stopped["generation"]
    assert (await client.post(f'/api/v1/honeypots/{pot["id"]}/deploy')).status_code == 409
    assert (await confirm(client, agent, pot["id"]))["status"] == "stopped"
    restarted = (await client.post(f'/api/v1/honeypots/{pot["id"]}/restart')).json()
    assert restarted["status"] == "restarting" and restarted["generation"] == stopped["generation"] + 1
    await client.post("/api/v1/agents/heartbeat", headers=agent, json={"honeypot_id": pot["id"], "generation": stopped["generation"],
                      "profile_version": 1, "status": "stopped", "queue_size": 0})
    assert (await client.get("/api/v1/honeypots/" + pot["id"])).json()["status"] == "restarting"


async def test_roles_and_machine_identities_are_separated(client, controller_headers):
    pot, profile, agent = await running_pot(client, controller_headers, name="guarded")
    create = {"name": "denied", "profile_id": profile["id"], "host_id": HOST}
    assert (await client.get("/api/v1/runtime/desired")).status_code == 401
    assert (await client.get("/api/v1/runtime/desired", headers=agent)).status_code == 401
    assert (await client.get("/api/v1/runtime/desired", headers=controller_headers | {"Authorization": "Bearer wrong"})).status_code == 401
    assert (await client.post(f'/api/v1/runtime/instances/{pot["id"]}/credential', headers=agent, json={"credential_sha256": "a" * 64})).status_code == 401
    desired = (await client.get("/api/v1/runtime/desired", headers=controller_headers)).text
    assert "token" not in desired and "password" not in desired and "image" not in desired
    for path in ("/api/v1/hosts", f"/api/v1/hosts/{HOST}", "/api/v1/agent-enrollments", "/api/v1/honeypots/" + pot["id"]):
        text = (await client.get(path)).text
        assert "token_hash" not in text and agent["Authorization"][7:] not in text
    for extra in ({"image": "alpine"}, {"command": ["sh"]}, {"volumes": ["/:/host"]}, {"privileged": True}):
        assert (await client.post("/api/v1/honeypots", json=create | extra)).status_code == 422
    assert (await client.post("/api/v1/honeypots", json=create | {"overrides": {"image": "alpine"}})).status_code == 422
    for role, allowed in (("operator", True), ("viewer", False)):
        password = "synthetic-" + role + "-password"
        await client.post("/api/v1/auth/login", json={"username": "admin", "password": os.environ["ADMIN_PASSWORD"]})
        await client.post("/api/v1/users", json={"username": role, "password": password, "role": role})
        await client.post("/api/v1/auth/login", json={"username": role, "password": password})
        assert (await client.get("/api/v1/honeypots")).status_code == 200
        assert (await client.post("/api/v1/honeypots", json=create)).status_code == 403
        assert (await client.post(f'/api/v1/honeypots/{pot["id"]}/clone', json={"name": "c"})).status_code == 403
        assert (await client.post(f'/api/v1/honeypots/{pot["id"]}/deploy')).status_code == 403
        assert (await client.delete("/api/v1/honeypots/" + pot["id"])).status_code == 403
        assert (await client.patch(f"/api/v1/hosts/{HOST}", json={"max_instances": 99})).status_code == 403
        assert (await client.post(f'/api/v1/honeypots/{pot["id"]}/restart')).status_code == (200 if allowed else 403)
        assert (await client.patch("/api/v1/honeypots/" + pot["id"], json={"description": "x"})).status_code == (200 if allowed else 403)


async def test_service_catalog_lists_only_implemented_plugins(client):
    catalog = (await client.get("/api/v1/service-types")).json()
    assert [item["key"] for item in catalog] == ["tcp-banner", "http-admin", "http-site", "http-api", "http-store", "http-portal", "telnet-shell", "linux-sandbox"]
    assert all(item["image_reference"] == "honeyforge:local" and item["is_enabled"] for item in catalog)
    detail = (await client.get("/api/v1/service-types/http-site")).json()
    assert detail["interaction_level"] == "medium" and detail["defaults"]["routes"] and "home" in detail["defaults"]["pages"]
    assert (await client.post("/api/v1/profiles", json=detail["defaults"] | {"name": "Сайт из каталога"})).status_code == 201
    schema = (await client.get("/api/v1/service-types/tcp-banner/schema")).json()
    assert "banner" in schema["fields"] and "routes" not in schema["fields"] and "banner" in schema["schema"]["properties"]
    assert (await client.get("/api/v1/service-types/ssh-shell")).status_code == 404
    bad = detail["defaults"] | {"name": "Плохой маршрут"}
    for routes in ([{"path": "/static/x", "response": "json", "json_body": {}}],
                   [{"path": "/a", "response": "page", "page": "missing"}],
                   [{"path": "/a", "response": "json", "json_body": {}}, {"path": "/a", "response": "json", "json_body": {}}],
                   [{"path": "/a/../b", "response": "json", "json_body": {}}],
                   [{"path": "/login", "method": "GET", "response": "login"}]):
        assert (await client.post("/api/v1/profiles", json=bad | {"routes": routes})).status_code == 422
    script = bad | {"pages": {"home": {"title": "x", "components": [{"type": "script", "text": "alert(1)"}]}}}
    assert (await client.post("/api/v1/profiles", json=script)).status_code == 422


@pytest.mark.skipif(not os.getenv('TEST_DATABASE_URL', '').startswith('postgresql'), reason='PostgreSQL concurrency semantics')
async def test_concurrent_creation_reserves_distinct_endpoints(client, controller_headers):
    await controller_online(client, controller_headers)
    profile = await profile_for(client, "http-admin")
    responses = await asyncio.gather(*(client.post("/api/v1/honeypots", json={
        "name": f"parallel-{number}", "profile_id": profile["id"], "host_id": HOST, "deploy": True}) for number in range(8)))
    assert all(r.status_code == 201 for r in responses), [r.text for r in responses]
    pots = [r.json() for r in responses]
    assert len({p["id"] for p in pots}) == 8
    assert sorted(p["endpoint"]["port"] for p in pots) == list(range(8080, 8088))
    assert len((await client.get("/api/v1/deployments")).json()) == 8
    assert (await client.get(f"/api/v1/hosts/{HOST}/capacity")).json()["allocated"]["instances"] == 8


async def test_values_equal_to_the_profile_are_not_stored_as_overrides(client, controller_headers):
    """The interface sends the whole edited configuration; only real differences may stick to the instance."""
    await controller_online(client, controller_headers)
    pot, profile = await create_pot(client, "http-site", "own-settings", overrides={"identity": "Свой портал"})
    assert pot["overrides"] == {"identity": "Свой портал"}
    reordered = {key: profile["spec"][key] for key in reversed(list(profile["spec"]))}
    echoed = {key: reordered[key] for key in ("routes", "pages", "site_description", "memory_mb")} | {"identity": "Свой портал 2"}
    changed = await client.patch("/api/v1/honeypots/" + pot["id"], json={"overrides": echoed})
    assert changed.status_code == 200 and changed.json()["overrides"] == {"identity": "Свой портал 2"}
    await client.patch("/api/v1/profiles/" + profile["id"], json=profile["spec"] | {"site_description": "Новое описание"})
    applied = (await client.post("/api/v1/honeypots/" + pot["id"] + "/apply-updates")).json()
    assert applied["configuration"]["site_description"] == "Новое описание" and applied["configuration"]["identity"] == "Свой портал 2"
    reset = (await client.patch("/api/v1/honeypots/" + pot["id"], json={"overrides": {"identity": profile["spec"]["identity"]}})).json()
    assert reset["overrides"] == {}
