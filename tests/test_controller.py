"""Deployment controller against the real management API and an in-memory Docker Engine API."""
import json
import os
from types import SimpleNamespace
import httpx
import pytest
from backend.app.main import app
from controller.docker_api import Docker, DockerError, Policy, LABEL, parse_ports
from controller.main import Controller
from conftest import HOST, controller_online, create_pot, confirm

IMAGE = "honeyforge:local"
NETWORKS = {"lab_decoy", "lab_management"}
EXPOSED = "lab_exposed"
EXPOSED_OPTIONS = {"com.docker.network.bridge.enable_ip_masquerade": "false", "com.docker.network.bridge.enable_icc": "false"}
PUBLISHABLE = frozenset({2222, 2323})


class FakeDocker:
    """Just enough of the Engine API to observe exactly what the controller asks Docker to do."""
    def __init__(self):
        self.containers, self.volumes, self.created, self.fail_create = {}, {}, [], None
        self.sequence = 0
        self.exposed = {"Internal": False, "Driver": "bridge", "Options": dict(EXPOSED_OPTIONS)}

    @staticmethod
    def matches(labels, request):
        wanted = json.loads(request.url.params["filters"])["label"]
        return all(labels.get(item.split("=", 1)[0]) == item.split("=", 1)[1] for item in wanted)

    def view(self, identifier):
        item = self.containers[identifier]
        return {"Id": identifier, "Labels": item["spec"]["Labels"], "State": item["state"]}

    def handle(self, request: httpx.Request) -> httpx.Response:
        path, method = request.url.path, request.method
        if path == "/info":
            return httpx.Response(200, json={"ServerVersion": "fake", "NCPU": 4, "MemTotal": 8 * 1024 ** 3, "ContainersRunning": len(self.containers)})
        if path.startswith("/networks/"):
            if path.split("/")[-1] == EXPOSED and self.exposed:
                return httpx.Response(200, json=self.exposed)
            return httpx.Response(200, json={"Internal": True}) if path.split("/")[-1] in NETWORKS else httpx.Response(404)
        if path.startswith("/images/"):
            return httpx.Response(200, json={})
        if path == "/containers/json":
            return httpx.Response(200, json=[self.view(i) for i, c in self.containers.items() if self.matches(c["spec"]["Labels"], request)])
        if path == "/containers/create":
            spec = json.loads(request.content)
            self.created.append((request.url.params["name"], spec))
            if self.fail_create:
                return httpx.Response(self.fail_create)
            self.sequence += 1
            identifier = f"c{self.sequence:063d}"
            self.containers[identifier] = {"spec": spec, "state": "created", "name": request.url.params["name"]}
            return httpx.Response(201, json={"Id": identifier})
        if path == "/volumes":
            return httpx.Response(200, json={"Volumes": [{"Name": n, "Labels": l} for n, l in self.volumes.items() if self.matches(l, request)]})
        if path == "/volumes/create":
            body = json.loads(request.content)
            self.volumes[body["Name"]] = body["Labels"]
            return httpx.Response(201, json={})
        if path.startswith("/volumes/"):
            return httpx.Response(204 if self.volumes.pop(path.split("/")[-1], None) is not None else 404)
        identifier = path.split("/")[2]
        if identifier not in self.containers:
            return httpx.Response(404)
        item = self.containers[identifier]
        if path.endswith("/start"):
            item["state"] = "running"
            return httpx.Response(204)
        if path.endswith("/update"):
            item["spec"]["HostConfig"].update(json.loads(request.content))
            return httpx.Response(200, json={})
        if path.endswith("/stats"):
            return httpx.Response(200, json={"memory_stats": {"usage": 30 * 1024 ** 2}, "cpu_stats": {}, "precpu_stats": {}})
        if method == "DELETE":
            del self.containers[identifier]
            return httpx.Response(204)
        return httpx.Response(200, json={"Id": identifier, "State": {"Status": item["state"], "StartedAt": "2026-10-12T00:00:00Z"},
                                         "HostConfig": item["spec"]["HostConfig"], "RestartCount": 0})

    def role(self, honeypot_id, role):
        return next((c for c in self.containers.values() if c["spec"]["Labels"][LABEL + "honeypot"] == honeypot_id
                     and c["spec"]["Labels"][LABEL + "role"] == role), None)


@pytest.fixture
async def lab(client, controller_headers):
    fake = FakeDocker()
    settings = SimpleNamespace(project="lab", host_id=HOST, image=IMAGE, decoy_network="lab_decoy",
                               management_network="lab_management", management_url="https://nginx:9443",
                               ca_pem="-----BEGIN CERTIFICATE-----\npublic\n-----END CERTIFICATE-----\n",
                               orphan_policy="remove", volume_prefix="hf-lab-", interval=0, health_file=os.devnull,
                               exposed_network=EXPOSED, publish_address="127.0.0.1", publish_ports=PUBLISHABLE)
    policy = Policy(IMAGE, NETWORKS, settings.volume_prefix, exposed_network=EXPOSED, publish_address="127.0.0.1",
                    publish_ports=PUBLISHABLE, decoy_network="lab_decoy")
    docker = Docker(httpx.AsyncClient(transport=httpx.MockTransport(fake.handle), base_url="http://docker"), policy)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test", headers=controller_headers) as api:
        controller = Controller(settings, docker, api)
        await controller.preflight()
        await controller.cycle()
        yield SimpleNamespace(controller=controller, docker=fake, client=client, policy=policy)


def agent_headers(container):
    env = dict(item.split("=", 1) for item in container["spec"]["Env"])
    return {"X-Agent-ID": env["AGENT_ID"], "Authorization": "Bearer " + env["AGENT_TOKEN"]}


async def test_controller_creates_isolated_runtime_for_each_instance(lab):
    tcp, _ = await create_pot(lab.client, "tcp-banner", "tcp-one", deploy=True, overrides={"memory_mb": 96, "cpu_limit": 0.3})
    web, _ = await create_pot(lab.client, "http-site", "web-one", deploy=True)
    await lab.controller.cycle()
    assert len(lab.docker.containers) == 4 and len(lab.docker.volumes) == 2
    for pot, emulator in ((tcp, "tcp"), (web, "http")):
        decoy, agent = lab.docker.role(pot["id"], "decoy"), lab.docker.role(pot["id"], "agent")
        for container in (decoy, agent):
            spec, host = container["spec"], container["spec"]["HostConfig"]
            assert spec["Image"] == IMAGE and spec["User"] == "10001:10001" and container["state"] == "running"
            assert host["ReadonlyRootfs"] and host["CapDrop"] == ["ALL"] and not host["Privileged"]
            assert "no-new-privileges:true" in host["SecurityOpt"] and host["PidsLimit"] == 128
            assert "Binds" not in host and "PortBindings" not in host
            assert [m["Type"] for m in host["Mounts"]] == ["volume"] and host["Mounts"][0]["Source"] == "hf-lab-" + pot["id"]
            labels = spec["Labels"]
            assert labels[LABEL + "managed"] == "true" and labels[LABEL + "host"] == HOST and labels[LABEL + "honeypot"] == pot["id"]
            assert labels[LABEL + "profile"] == pot["profile_id"] and labels[LABEL + "deployment"]
        assert decoy["spec"]["HostConfig"]["NetworkMode"] == "lab_decoy"
        assert decoy["spec"]["Env"] == ["SERVICE_TYPE=" + emulator]
        assert decoy["spec"]["NetworkingConfig"]["EndpointsConfig"]["lab_decoy"]["Aliases"] == [pot["endpoint"]["alias"]]
        assert agent["spec"]["HostConfig"]["NetworkMode"] == "lab_management"
        assert agent["spec"]["Cmd"] == ["python", "-m", "agent.main"] and decoy["spec"]["Cmd"] == ["python", "-m", "honeypots.service"]
    limits = lab.docker.role(tcp["id"], "decoy")["spec"]["HostConfig"]
    assert limits["Memory"] == 96 * 1024 ** 2 and limits["NanoCpus"] == 300_000_000
    state = (await lab.client.get("/api/v1/honeypots/" + tcp["id"])).json()
    assert state["status"] == "starting" and state["runtime"]["decoy"]["state"] == "running"
    assert state["runtime"]["decoy"]["memory_limit"] == 96 * 1024 ** 2 and state["agent"]["approved"]
    headers = agent_headers(lab.docker.role(tcp["id"], "agent"))
    assert (await confirm(lab.client, headers, tcp["id"]))["status"] == "running"
    other = agent_headers(lab.docker.role(web["id"], "agent"))
    assert other["X-Agent-ID"] != headers["X-Agent-ID"] and other["Authorization"] != headers["Authorization"]
    codes = [row["code"] for row in (await lab.client.get(f'/api/v1/honeypots/{tcp["id"]}/logs')).json()]
    assert {"runtime.volume_created", "runtime.agent_created", "runtime.decoy_created", "runtime.ready", "agent.provisioned"} <= set(codes)
    created = len(lab.docker.created)
    await lab.controller.cycle()
    assert len(lab.docker.created) == created


async def test_controller_recovers_lost_containers_and_applies_limits(lab):
    pot, _ = await create_pot(lab.client, "tcp-banner", "resilient", deploy=True)
    await lab.controller.cycle()
    headers = agent_headers(lab.docker.role(pot["id"], "agent"))
    await confirm(lab.client, headers, pot["id"])
    lost = next(i for i, c in lab.docker.containers.items() if c["spec"]["Labels"][LABEL + "role"] == "decoy")
    del lab.docker.containers[lost]
    await lab.controller.cycle()
    assert lab.docker.role(pot["id"], "decoy")["state"] == "running"
    audit = [a["action"] for a in (await lab.client.get("/api/v1/audit")).json()["items"]]
    assert "runtime.recovered" in audit
    assert agent_headers(lab.docker.role(pot["id"], "agent")) == headers
    await lab.client.patch("/api/v1/honeypots/" + pot["id"], json={"overrides": {"memory_mb": 200, "cpu_limit": 0.8}})
    await lab.controller.cycle()
    limits = lab.docker.role(pot["id"], "decoy")["spec"]["HostConfig"]
    assert limits["Memory"] == limits["MemorySwap"] == 200 * 1024 ** 2 and limits["NanoCpus"] == 800_000_000
    lab.docker.role(pot["id"], "agent")["state"] = "exited"
    await lab.controller.cycle()
    assert lab.docker.role(pot["id"], "agent")["state"] == "running"
    del lab.docker.containers[next(i for i, c in lab.docker.containers.items() if c["spec"]["Labels"][LABEL + "role"] == "agent")]
    await lab.controller.cycle()
    rotated = agent_headers(lab.docker.role(pot["id"], "agent"))
    assert rotated["X-Agent-ID"] == headers["X-Agent-ID"] and rotated["Authorization"] != headers["Authorization"]
    body = {"honeypot_id": pot["id"], "generation": 0, "status": "pending", "queue_size": 0}
    assert (await lab.client.post("/api/v1/agents/heartbeat", headers=headers, json=body)).status_code == 401
    assert (await lab.client.post("/api/v1/agents/heartbeat", headers=rotated, json=body)).status_code == 200


async def test_controller_removes_deleted_instances_and_orphans(lab):
    pot, _ = await create_pot(lab.client, "tcp-banner", "to-delete", deploy=True)
    keep, _ = await create_pot(lab.client, "http-api", "to-keep", deploy=True)
    await lab.controller.cycle()
    await lab.client.post(f'/api/v1/honeypots/{pot["id"]}/stop')
    await confirm(lab.client, agent_headers(lab.docker.role(pot["id"], "agent")), pot["id"])
    assert (await lab.client.delete("/api/v1/honeypots/" + pot["id"])).json()["status"] == "deleting"
    await lab.controller.cycle()
    assert lab.docker.role(pot["id"], "decoy") is None and lab.docker.role(pot["id"], "agent") is None
    assert list(lab.docker.volumes) == ["hf-lab-" + keep["id"]]
    assert (await lab.client.get("/api/v1/honeypots/" + pot["id"])).status_code == 404
    assert len(lab.docker.containers) == 2
    assert (await lab.client.delete("/api/v1/honeypots/" + keep["id"] + "?force=true")).json()["deleted"] is True
    foreign = {"spec": {"Labels": {LABEL + "managed": "true", LABEL + "project": "another", LABEL + "host": HOST,
                                   LABEL + "honeypot": "x", LABEL + "role": "decoy"}}, "state": "running"}
    lab.docker.containers["foreign"] = foreign
    await lab.controller.cycle()
    assert list(lab.docker.containers) == ["foreign"] and not lab.docker.volumes
    audit = {a["action"]: a["resource"] for a in (await lab.client.get("/api/v1/audit")).json()["items"]}
    assert audit["runtime.orphan_removed"] == keep["id"]


async def test_controller_reports_creation_failure_without_claiming_success(lab):
    lab.docker.fail_create = 404
    pot, _ = await create_pot(lab.client, "tcp-banner", "no-image", deploy=True)
    await lab.controller.cycle()
    state = (await lab.client.get("/api/v1/honeypots/" + pot["id"])).json()
    assert state["status"] == "failed" and "Образ сервиса не найден" in state["error"]
    assert state["deployments"][0]["status"] == "failed" and not lab.docker.containers
    lab.docker.fail_create = None
    assert (await lab.client.post(f'/api/v1/honeypots/{pot["id"]}/deploy')).status_code == 200
    await lab.controller.cycle()
    assert (await lab.client.get("/api/v1/honeypots/" + pot["id"])).json()["status"] == "starting"


@pytest.mark.parametrize("change", [
    {"Image": "alpine:latest"}, {"User": "0:0"}, {"User": None},
    {"HostConfig": {"Privileged": True}}, {"HostConfig": {"Binds": ["/:/host"]}},
    {"HostConfig": {"NetworkMode": "host"}}, {"HostConfig": {"NetworkMode": "bridge"}},
    {"HostConfig": {"CapAdd": ["NET_ADMIN"]}}, {"HostConfig": {"CapDrop": []}},
    {"HostConfig": {"ReadonlyRootfs": False}}, {"HostConfig": {"SecurityOpt": []}},
    {"HostConfig": {"Memory": 0}}, {"HostConfig": {"PortBindings": {"8080/tcp": [{"HostPort": "80"}]}}},
    {"HostConfig": {"PidMode": "host"}}, {"HostConfig": {"Mounts": [{"Type": "bind", "Source": "/var/run/docker.sock", "Target": "/s"}]}},
    {"HostConfig": {"Mounts": [{"Type": "volume", "Source": "postgres-data", "Target": "/data"}]}},
])
def test_policy_rejects_every_unsafe_container_specification(lab, change):
    instance = {"honeypot_id": "0" * 36, "emulator": "tcp", "alias": "hp-test", "memory_mb": 128, "cpu_limit": 0.5}
    spec = lab.controller.decoy_spec(instance)
    lab.policy.assert_safe(spec)
    host = change.pop("HostConfig", {})
    spec.update(change)
    spec["HostConfig"].update(host)
    with pytest.raises(DockerError):
        lab.policy.assert_safe(spec)



async def test_publication_forwards_exactly_one_allowed_port_and_can_be_withdrawn(lab):
    pot, _ = await create_pot(lab.client, "tcp-banner", "published", deploy=True)
    other, _ = await create_pot(lab.client, "http-site", "neighbour", deploy=True)
    await lab.controller.cycle()
    agent_before = lab.docker.role(pot["id"], "agent")
    assert pot["endpoint"]["published_port"] is None
    capacity = (await lab.client.get(f"/api/v1/hosts/{HOST}/capacity")).json()
    assert capacity["publication"] == {"enabled": True, "address": "127.0.0.1", "ports": [2222, 2323]}

    assert (await lab.client.post(f'/api/v1/honeypots/{pot["id"]}/publish', json={"port": 8080})).status_code == 422
    assert (await lab.client.post(f'/api/v1/honeypots/{pot["id"]}/publish', json={"port": 22})).status_code == 422
    asked = await lab.client.post(f'/api/v1/honeypots/{pot["id"]}/publish', json={"port": 2222})
    assert asked.status_code == 200, asked.text
    assert asked.json()["endpoint"]["published_port"] == 2222 and asked.json()["endpoint"]["published_observed"] is None
    taken = await lab.client.post(f'/api/v1/honeypots/{other["id"]}/publish', json={"port": 2222})
    assert taken.status_code == 409 and "published" in taken.json()["detail"]

    await lab.controller.cycle()
    decoy = lab.docker.role(pot["id"], "decoy")
    host, internal = decoy["spec"]["HostConfig"], f'{pot["endpoint"]["port"]}/tcp'
    assert host["NetworkMode"] == EXPOSED
    assert host["PortBindings"] == {internal: [{"HostIp": "127.0.0.1", "HostPort": "2222"}]}
    assert decoy["spec"]["ExposedPorts"] == {internal: {}}
    endpoints = decoy["spec"]["NetworkingConfig"]["EndpointsConfig"]
    assert set(endpoints) == {EXPOSED, "lab_decoy"} and endpoints["lab_decoy"]["Aliases"] == [pot["endpoint"]["alias"]]
    assert "lab_management" not in endpoints and decoy["state"] == "running"
    assert lab.docker.role(pot["id"], "agent") is agent_before
    assert "PortBindings" not in lab.docker.role(other["id"], "decoy")["spec"]["HostConfig"]
    view = (await lab.client.get("/api/v1/honeypots/" + pot["id"])).json()
    assert view["endpoint"]["published_observed"] == 2222 and view["endpoint"]["published_address"] == "127.0.0.1"
    codes = [row["code"] for row in (await lab.client.get(f'/api/v1/honeypots/{pot["id"]}/logs')).json()]
    assert "publication.requested" in codes and "runtime.decoy_republished" in codes
    actions = [row["action"] for row in (await lab.client.get("/api/v1/audit")).json()["items"]]
    assert "honeypot.publish" in actions and "runtime.recovered" not in actions

    await lab.controller.cycle()
    assert lab.docker.role(pot["id"], "decoy") is decoy

    assert (await lab.client.post(f'/api/v1/honeypots/{pot["id"]}/unpublish')).status_code == 200
    await lab.controller.cycle()
    closed = lab.docker.role(pot["id"], "decoy")
    assert closed["spec"]["HostConfig"]["NetworkMode"] == "lab_decoy" and "PortBindings" not in closed["spec"]["HostConfig"]
    view = (await lab.client.get("/api/v1/honeypots/" + pot["id"])).json()
    assert view["endpoint"]["published_port"] is None and view["endpoint"]["published_observed"] is None


async def test_publication_is_unavailable_until_the_host_itself_allows_it(client, controller_headers):
    await controller_online(client, controller_headers)
    pot, _ = await create_pot(client, "tcp-banner", "closed", deploy=True)
    refused = await client.post(f'/api/v1/honeypots/{pot["id"]}/publish', json={"port": 2222})
    assert refused.status_code == 409 and "PUBLISH_PORTS" in refused.json()["detail"]
    capacity = (await client.get(f"/api/v1/hosts/{HOST}/capacity")).json()
    assert capacity["publication"] == {"enabled": False, "address": None, "ports": []}
    desired = (await client.get("/api/v1/runtime/desired", headers=controller_headers)).json()["instances"]
    assert desired[0]["published_port"] is None


async def test_publication_requires_administrator(client, controller_headers):
    await controller_online(client, controller_headers, publication={"enabled": True, "address": "127.0.0.1", "ports": [2222]})
    pot, _ = await create_pot(client, "tcp-banner", "roles", deploy=True)
    created = await client.post("/api/v1/users", json={"username": "operator1", "password": "Operator-pass-12345", "role": "operator"})
    assert created.status_code == 201, created.text
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test",
                                 headers={"X-HoneyForge": "1", "Origin": "http://test"}) as operator:
        login = await operator.post("/api/v1/auth/login", json={"username": "operator1", "password": "Operator-pass-12345"})
        assert login.status_code == 200, login.text
        assert (await operator.post(f'/api/v1/honeypots/{pot["id"]}/publish', json={"port": 2222})).status_code == 403
        assert (await operator.post(f'/api/v1/honeypots/{pot["id"]}/unpublish')).status_code == 403


async def test_controller_disables_publication_on_an_unsafe_exposed_network(lab):
    lab.docker.exposed["Options"]["com.docker.network.bridge.enable_ip_masquerade"] = "true"
    await lab.controller.preflight()
    assert lab.controller.publication is False
    await lab.controller.cycle()
    pot, _ = await create_pot(lab.client, "tcp-banner", "unsafe", deploy=True)
    assert (await lab.client.post(f'/api/v1/honeypots/{pot["id"]}/publish', json={"port": 2222})).status_code == 409
    with pytest.raises(DockerError) as error:
        lab.controller.decoy_spec({"honeypot_id": "0" * 36, "emulator": "tcp", "alias": "hp-test", "memory_mb": 128,
                                   "cpu_limit": 0.5, "port": 8022, "published_port": 2222})
    assert error.value.code == "publication_rejected"


def published_spec(lab, **changes):
    spec = lab.controller.decoy_spec({"honeypot_id": "0" * 36, "emulator": "tcp", "alias": "hp-test", "memory_mb": 128,
                                      "cpu_limit": 0.5, "port": 8022, "published_port": 2222})
    return spec


@pytest.mark.parametrize("mutate", [
    lambda spec: spec["HostConfig"]["PortBindings"]["8022/tcp"][0].update(HostIp="0.0.0.0"),
    lambda spec: spec["HostConfig"]["PortBindings"]["8022/tcp"][0].update(HostPort="443"),
    lambda spec: spec["HostConfig"]["PortBindings"]["8022/tcp"][0].update(HostPort="2223"),
    lambda spec: spec["HostConfig"]["PortBindings"]["8022/tcp"].append({"HostIp": "127.0.0.1", "HostPort": "2323"}),
    lambda spec: spec["HostConfig"]["PortBindings"].update({"9000/tcp": [{"HostIp": "127.0.0.1", "HostPort": "2323"}]}),
    lambda spec: spec["HostConfig"]["PortBindings"].update({"8022/udp": spec["HostConfig"]["PortBindings"].pop("8022/tcp")}),
    lambda spec: spec["HostConfig"].update(PublishAllPorts=True),
    lambda spec: spec["HostConfig"].update(NetworkMode="lab_decoy"),
    lambda spec: spec["HostConfig"].update(NetworkMode="host"),
    lambda spec: spec["NetworkingConfig"]["EndpointsConfig"].update({"lab_management": {}}),
    lambda spec: spec["NetworkingConfig"]["EndpointsConfig"].update({"bridge": {}}),
    lambda spec: spec["HostConfig"].update(Privileged=True),
    lambda spec: spec["HostConfig"].update(CapAdd=["NET_ADMIN"]),
])
def test_policy_rejects_every_unsafe_publication(lab, mutate):
    spec = published_spec(lab)
    lab.policy.assert_safe(spec)
    mutate(spec)
    with pytest.raises(DockerError):
        lab.policy.assert_safe(spec)


def test_policy_without_a_port_list_publishes_nothing(lab):
    spec = published_spec(lab)
    closed = Policy(IMAGE, NETWORKS, "hf-lab-", exposed_network=EXPOSED, decoy_network="lab_decoy")
    with pytest.raises(DockerError) as error:
        closed.assert_safe(spec)
    assert error.value.code == "publication_rejected"
    plain = lab.controller.decoy_spec({"honeypot_id": "0" * 36, "emulator": "tcp", "alias": "hp-test", "memory_mb": 128, "cpu_limit": 0.5})
    plain["HostConfig"]["NetworkMode"] = EXPOSED
    with pytest.raises(DockerError):
        lab.policy.assert_safe(plain)


def test_port_list_parsing_refuses_management_ports():
    assert parse_ports("") == frozenset()
    assert parse_ports(" 23, 2222 ,8080-8082") == frozenset({23, 2222, 8080, 8081, 8082})
    for bad in ("22", "80", "443", "8440-8450", "9443", "0", "70000", "90-80", "ssh", "1-65535"):
        with pytest.raises(ValueError):
            parse_ports(bad)


async def test_catalog_offers_the_high_interaction_shell_as_an_ordinary_instance(client, controller_headers):
    types = {item["key"]: item for item in (await client.get("/api/v1/service-types")).json()}
    shell = types["telnet-shell"]
    assert shell["interaction_level"] == "medium" and shell["emulator"] == "tcp" and "max_commands" in shell["fields"]
    await controller_online(client, controller_headers)
    pot, _ = await create_pot(client, "telnet-shell", "shell-one", deploy=True, overrides={"hostname": "edge-07"})
    assert pot["interaction_level"] == "medium" and pot["service_type"] == "tcp"
    assert pot["configuration"]["hostname"] == "edge-07" and pot["configuration"]["connection_timeout"] == 180
    desired = (await client.get("/api/v1/runtime/desired", headers=controller_headers)).json()["instances"][0]
    assert desired["emulator"] == "tcp" and desired["service_key"] == "telnet-shell"
    assert (await client.get("/api/v1/events", params={"interaction_level": "high"})).status_code == 200
    bad = await client.patch("/api/v1/honeypots/" + pot["id"], json={"overrides": {"hostname": "Bad Host!"}})
    assert bad.status_code == 422
