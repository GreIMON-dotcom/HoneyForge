"""Deployment controller of one approved laboratory Docker host.

It has no listening socket. On every cycle it asks the control plane, over the
authenticated TLS management channel, which instances should exist on this
host, makes Docker match, and reports what it actually observes. Each instance
is a decoy container on the isolated decoy network plus a management sidecar on
the management network; the two share only a private spool volume.

Publication is opt-in twice. The host operator lists publishable ports in this
process's environment (``PUBLISH_PORTS``, empty by default), and an administrator
then publishes one instance on one of them. Such a decoy is additionally attached
to the "exposed" bridge, which forwards that single port and has no outbound NAT.
"""
import asyncio
import hashlib
import json
import logging
import os
import secrets
import ssl
import time
import ipaddress
from pathlib import Path
import httpx
from .docker_api import Docker, DockerError, Policy, LABEL, parse_ports

log = logging.getLogger("honeyforge.controller")
USER = "10001:10001"
SPOOL_CHECK = ("import time; from shared.buffer import DurableBuffer; "
               "h=DurableBuffer('/spool/events.db').get('{key}',{{}}); assert time.time()-h.get('at',0)<{age}")
SECOND = 1_000_000_000


class Settings:
    def __init__(self, env=os.environ):
        self.management_url = env["MANAGEMENT_URL"]
        if not self.management_url.startswith("https://"):
            raise RuntimeError("Для канала управления требуется HTTPS")
        self.host_id = env["HOST_ID"]
        self.token = env["CONTROLLER_TOKEN"]
        self.ca_pem = Path(env["CA_FILE"]).read_text(encoding="ascii")
        self.project = env.get("LAB_PROJECT", "honeyforge")
        self.image = env.get("RUNTIME_IMAGE", "honeyforge:local")
        self.decoy_network = env.get("DECOY_NETWORK", self.project + "_decoy")
        self.management_network = env.get("MANAGEMENT_NETWORK", self.project + "_management")
        self.socket = env.get("DOCKER_SOCKET", "/var/run/docker.sock")
        self.interval = float(env.get("RECONCILE_INTERVAL", "2"))
        self.orphan_policy = env.get("ORPHAN_POLICY", "remove")
        self.health_file = env.get("HEALTH_FILE", "/tmp/controller-health.json")
        self.volume_prefix = f"hf-{self.project}-"
        self.exposed_network = env.get("EXPOSED_NETWORK", self.project + "_exposed")
        self.publish_address = env.get("PUBLISH_ADDRESS", "127.0.0.1")
        self.publish_ports = parse_ports(env.get("PUBLISH_PORTS", ""))
        self.sandbox_node = env.get('NODE_ROLE', '') == 'sandbox'
        self.sandbox_image = env.get('SANDBOX_IMAGE', 'honeyforge-sandbox:local')
        self.center_vpn_ip = env.get('CENTER_VPN_IP', '')
        self.guard_file = env.get('SANDBOX_GUARD_FILE', '/guard/host.json')
        if self.sandbox_node:
            address = ipaddress.ip_address(self.center_vpn_ip)
            if address.version != 4 or not address.is_private or address.is_loopback or address.is_unspecified or address.is_link_local:
                raise RuntimeError('Для отдельного узла нужен частный IPv4 центра в VPN')
            if self.management_url != 'https://nginx:9443':
                raise RuntimeError('Отдельный узел использует VPN-адрес nginx и выделенный TLS-порт 9443')


class Controller:
    def __init__(self, settings, docker: Docker, api: httpx.AsyncClient):
        self.settings, self.docker, self.api = settings, docker, api
        self.scope = {"managed": "true", "project": settings.project, "host": settings.host_id}
        self.cycles = 0
        self.publication = False
        self.sandbox_ready = False


    def names(self, honeypot_id: str) -> tuple[str, str, str]:
        short = honeypot_id.replace("-", "")[:12]
        base = f"hf-{self.settings.project}-{short}"
        return base + "-decoy", base + "-agent", self.settings.volume_prefix + honeypot_id

    def labels(self, instance: dict, role: str) -> dict:
        values = {**self.scope, "honeypot": instance["honeypot_id"], "role": role,
                  "deployment": instance.get("deployment_id") or "", "profile": instance.get("profile_id") or "",
                  "emulator": instance["emulator"], "service": instance.get('service_key', ''), "agent": instance.get("agent_id") or ""}
        return {LABEL + key: value for key, value in values.items()}

    def container(self, instance, role, network, command, environment, memory_mb, cpus, health_key, health_age, aliases=()):
        return {
            "Image": self.settings.image, "Cmd": command, "User": USER,
            "Env": [f"{key}={value}" for key, value in environment.items()],
            "Labels": self.labels(instance, role),
            "Healthcheck": {"Test": ["CMD", "python", "-c", SPOOL_CHECK.format(key=health_key, age=health_age)],
                            "Interval": 10 * SECOND, "Timeout": 5 * SECOND, "Retries": 5},
            "HostConfig": {
                "NetworkMode": network, "ReadonlyRootfs": True, "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges:true"], "PidsLimit": 128, "Init": True, "Privileged": False,
                "Memory": memory_mb * 1024 ** 2, "MemorySwap": memory_mb * 1024 ** 2, "NanoCpus": round(cpus * SECOND),
                "Tmpfs": {"/tmp": "size=32m,mode=1777"},
                "Mounts": [{"Type": "volume", "Source": self.names(instance["honeypot_id"])[2], "Target": "/spool"}],
                "RestartPolicy": {"Name": "unless-stopped"}},
            "NetworkingConfig": {"EndpointsConfig": {network: {"Aliases": list(aliases)}}}}

    def decoy_spec(self, instance):
        spec = self.container(instance, "decoy", self.settings.decoy_network, ["python", "-m", "honeypots.service"],
                              {"SERVICE_TYPE": instance["emulator"]}, instance["memory_mb"], instance["cpu_limit"],
                              "service_health", 10, aliases=[instance["alias"]])
        published = instance.get("published_port")
        spec["Labels"][LABEL + "published"] = str(published or "")
        if instance.get('service_key') == 'linux-sandbox':
            spec['HostConfig']['Mounts'].append({'Type': 'volume', 'Source': self.names(instance['honeypot_id'])[2] + '-bridge', 'Target': '/bridge'})
        if published:
            if not self.publication or published not in self.settings.publish_ports:
                raise DockerError("publication_rejected")
            exposed, port = self.settings.exposed_network, f"{instance['port']}/tcp"
            spec["ExposedPorts"] = {port: {}}
            spec["HostConfig"]["NetworkMode"] = exposed
            spec["HostConfig"]["PortBindings"] = {port: [{"HostIp": self.settings.publish_address, "HostPort": str(published)}]}
            spec["NetworkingConfig"]["EndpointsConfig"][exposed] = {}
        return spec

    def agent_spec(self, instance, agent_id, token):
        environment = {"MANAGEMENT_URL": self.settings.management_url, "AGENT_ID": agent_id, "AGENT_TOKEN": token,
                       "CA_PEM": self.settings.ca_pem}
        spec = self.container(instance | {"agent_id": agent_id}, "agent", self.settings.management_network,
                              ["python", "-m", "agent.main"], environment, instance["agent_memory_mb"],
                              instance["agent_cpu"], "agent_health", 60)
        if getattr(self.settings, 'sandbox_node', False):
            spec['HostConfig']['ExtraHosts'] = ['nginx:' + self.settings.center_vpn_ip]
        return spec

    def sandbox_spec(self, instance, probe=False):
        """The worker never joins any Docker network and sees only a read-only socket volume."""
        return {'Image': getattr(self.settings, 'sandbox_image', 'honeyforge-sandbox:local'),
                'Cmd': ['python', '/opt/worker.py'] + (['--self-test'] if probe else []),
                'User': USER, 'Env': [], 'Labels': self.labels(instance, 'sandbox'),
                'HostConfig': {'Runtime': 'runsc', 'NetworkMode': 'none', 'ReadonlyRootfs': True,
                    'CapDrop': ['ALL'], 'SecurityOpt': ['no-new-privileges:true'], 'Privileged': False,
                    'Init': True, 'PidsLimit': 64, 'Memory': 256 * 1024 ** 2, 'MemorySwap': 256 * 1024 ** 2,
                    'NanoCpus': 500_000_000, 'RestartPolicy': {'Name': 'no'},
                    'Tmpfs': {'/tmp': 'size=64m,mode=1777', '/home/lab': 'size=64m,uid=10001,gid=10001,mode=700'},
                    'Mounts': [{'Type': 'volume', 'Source': self.names(instance['honeypot_id'])[2] + '-bridge',
                                'Target': '/bridge', 'ReadOnly': True}]}}

    async def ensure_sandbox(self, instance, current):
        worker = current.get('sandbox')
        reset = False
        if worker:
            from datetime import datetime, timezone
            details = await self.docker.inspect(worker['Id'])
            started = (details or {}).get('State', {}).get('StartedAt', '')
            try:
                age = (datetime.now(timezone.utc) - datetime.fromisoformat(started.replace('Z', '+00:00'))).total_seconds()
            except ValueError:
                age = 601
            reset = worker.get('State') != 'running' or age >= 600
            if reset:
                await self.docker.remove(worker['Id'])
                worker = None
        if not worker:
            name = self.names(instance['honeypot_id'])[0] + '-sandbox'
            identifier = await self.docker.create(name, self.sandbox_spec(instance))
            await self.docker.start(identifier)
            return ['sandbox_reset' if reset else 'sandbox_created']
        return []


    async def discover(self):
        """Managed containers and volumes of this host, grouped by instance. Names are never trusted."""
        groups, volumes = {}, {}
        for item in await self.docker.containers(self.scope):
            labels = item.get("Labels") or {}
            groups.setdefault(labels.get(LABEL + "honeypot", ""), {})[labels.get(LABEL + "role", "")] = item
        for item in await self.docker.volumes(self.scope):
            labels = item.get('Labels') or {}
            key = labels.get(LABEL + 'honeypot', '') + (':bridge' if labels.get(LABEL + 'volume') == 'bridge' else '')
            volumes[key] = item['Name']
        return groups, volumes

    async def provision_agent(self, instance, existing):
        """New sidecar with a fresh secret; the control plane only ever receives its hash."""
        if existing:
            await self.docker.remove(existing["Id"])
        token = secrets.token_urlsafe(48)
        try:
            response = await self.api.post(f"/api/v1/runtime/instances/{instance['honeypot_id']}/credential",
                                           json={"credential_sha256": hashlib.sha256(token.encode()).hexdigest()})
            response.raise_for_status()
            agent_id = response.json()["agent_id"]
        except (httpx.HTTPError, KeyError, ValueError):
            raise DockerError("credential_failed")
        _, name, _ = self.names(instance["honeypot_id"])
        identifier = await self.docker.create(name, self.agent_spec(instance, agent_id, token))
        await self.docker.start(identifier)

    async def ensure(self, instance, current, volumes) -> list[str]:
        actions = []
        sandbox = instance.get('service_key') == 'linux-sandbox'
        if sandbox and not self.sandbox_ready:
            raise DockerError('sandbox_unavailable')
        decoy_name, _, volume = self.names(instance["honeypot_id"])
        if sandbox and instance['honeypot_id'] + ':bridge' not in volumes:
            await self.docker.create_volume(volume + '-bridge', self.scope | {'honeypot': instance['honeypot_id'], 'volume': 'bridge'})
            actions.append('sandbox_volume_created')
        if instance["honeypot_id"] not in volumes:
            await self.docker.create_volume(volume, self.scope | {"honeypot": instance["honeypot_id"]})
            actions.append("volume_created")
        agent = current.get("agent")
        known = agent and (agent.get("Labels") or {}).get(LABEL + "agent")
        if not agent or not instance.get("agent_id") or known != instance["agent_id"]:
            await self.provision_agent(instance, agent)
            actions.append("agent_created")
        elif agent["State"] != "running":
            await self.docker.start(agent["Id"])
            actions.append("agent_started")
        decoy = current.get("decoy")
        republished = False
        if decoy and ((decoy.get("Labels") or {}).get(LABEL + "emulator") != instance["emulator"] or
                      sandbox != ((decoy.get('Labels') or {}).get(LABEL + 'service') == 'linux-sandbox')):
            await self.docker.remove(decoy["Id"])
            decoy = None
        if decoy and (decoy.get("Labels") or {}).get(LABEL + "published", "") != str(instance.get("published_port") or ""):
            self.decoy_spec(instance)
            await self.docker.remove(decoy["Id"])
            decoy, republished = None, True
        if not decoy:
            identifier = await self.docker.create(decoy_name, self.decoy_spec(instance))
            await self.docker.start(identifier)
            actions.append("decoy_republished" if republished else "decoy_created")
        else:
            if decoy["State"] != "running":
                await self.docker.start(decoy["Id"])
                actions.append("decoy_started")
            details = await self.docker.inspect(decoy["Id"])
            memory, cpus = instance["memory_mb"] * 1024 ** 2, round(instance["cpu_limit"] * SECOND)
            if details and (details["HostConfig"].get("Memory"), details["HostConfig"].get("NanoCpus")) != (memory, cpus):
                await self.docker.update_limits(decoy["Id"], memory, cpus)
                actions.append("limits_updated")
        if sandbox:
            actions.extend(await self.ensure_sandbox(instance, current))
        elif current.get('sandbox'):
            await self.docker.remove(current['sandbox']['Id'])
            actions.append('sandbox_removed')
            if instance['honeypot_id'] + ':bridge' in volumes:
                await self.docker.remove_volume(volumes[instance['honeypot_id'] + ':bridge'])
                actions.append('sandbox_volume_removed')
        return actions

    async def remove(self, honeypot_id, current, volumes) -> list[str]:
        actions = []
        for role in ("sandbox", "decoy", "agent"):
            if role in current:
                await self.docker.remove(current[role]["Id"])
                actions.append(role + "_removed")
        if honeypot_id in volumes:
            await self.docker.remove_volume(volumes[honeypot_id])
            actions.append("volume_removed")
        if honeypot_id + ':bridge' in volumes:
            await self.docker.remove_volume(volumes[honeypot_id + ':bridge'])
            actions.append('sandbox_volume_removed')
        return actions

    @staticmethod
    def observed(details) -> dict | None:
        if not details:
            return None
        state = details.get("State", {})
        return {"id": details["Id"][:64], "state": state.get("Status", "unknown"),
                "health": (state.get("Health") or {}).get("Status"),
                "memory_limit": details["HostConfig"].get("Memory") or 0,
                "nano_cpus": details["HostConfig"].get("NanoCpus") or 0,
                "restart_count": details.get("RestartCount") or 0, "started_at": (state.get("StartedAt") or "")[:40] or None,
                "published_port": Controller.host_port(details)}

    @staticmethod
    def host_port(details) -> int | None:
        """The host port Docker really bound for this container, not the one that was asked for."""
        for targets in ((details.get("HostConfig") or {}).get("PortBindings") or {}).values():
            for target in targets or []:
                if str(target.get("HostPort", "")).isdigit():
                    return int(target["HostPort"])
        return None

    async def cycle(self):
        response = await self.api.get("/api/v1/runtime/desired")
        response.raise_for_status()
        desired = response.json()["instances"]
        groups, volumes = await self.discover()
        report, removed = [], []
        for instance in desired:
            identifier = instance["honeypot_id"]
            current = groups.pop(identifier, {})
            entry = {"honeypot_id": identifier, "actions": []}
            try:
                if instance["desired"] == "absent":
                    await self.remove(identifier, current, volumes)
                    removed.append(identifier)
                    continue
                entry["actions"] = await self.ensure(instance, current, volumes)
            except DockerError as error:
                log.warning("Экземпляр %s: ошибка среды выполнения %s", identifier, error.code)
                entry["error"] = error.code
            report.append(entry)
        orphans = []
        known = {instance["honeypot_id"] for instance in desired}
        if self.settings.orphan_policy == "remove":
            for identifier in sorted((set(groups) | {key.split(':')[0] for key in volumes}) - known):
                try:
                    await self.remove(identifier, groups.get(identifier, {}), volumes)
                    orphans.append(identifier)
                except DockerError as error:
                    log.warning("Не удалось удалить осиротевшую среду %s: %s", identifier, error.code)
        fresh, _ = await self.discover()
        for entry in report:
            current = fresh.get(entry["honeypot_id"], {})
            for role in ("decoy", "agent", "sandbox"):
                entry[role] = self.observed(await self.docker.inspect(current[role]["Id"])) if role in current else None
        if self.cycles % 5 == 0:
            running = [entry for entry in report if entry["decoy"] and entry["decoy"]["state"] == "running"]
            samples = await asyncio.gather(*(self.docker.stats(entry["decoy"]["id"]) for entry in running), return_exceptions=True)
            for entry, sample in zip(running, samples):
                if isinstance(sample, dict):
                    entry["stats"] = sample
        info = await self.docker.info()
        payload = {"docker": {"version": info.get("ServerVersion", ""), "ncpu": info.get("NCPU", 0),
                              "memory_bytes": info.get("MemTotal", 0), "containers_running": info.get("ContainersRunning", 0),
                              "managed_containers": sum(len(group) for group in fresh.values())},
                   'sandbox': {'ready': self.sandbox_ready, 'runtime': 'runsc' if self.sandbox_ready else None},
                   "publication": {"enabled": self.publication, "address": self.settings.publish_address,
                                   "ports": sorted(self.settings.publish_ports) if self.publication else []},
                   "instances": report, "removed": removed, "orphans_removed": orphans}
        response = await self.api.post("/api/v1/runtime/report", json=payload)
        response.raise_for_status()
        self.cycles += 1

    async def preflight(self):
        """Refuse to manage anything unless the host matches the laboratory layout."""
        sandbox_node = getattr(self.settings, 'sandbox_node', False)
        for name in (self.settings.decoy_network, self.settings.management_network):
            network = await self.docker.network(name)
            remote_management = sandbox_node and name == self.settings.management_network and network and network.get('Driver') == 'bridge' \
                and (network.get('Options') or {}).get('com.docker.network.bridge.enable_icc') == 'false'
            if not network or (not network.get("Internal") and not remote_management):
                raise RuntimeError("Ожидалась внутренняя лабораторная сеть: " + name)
        if not await self.docker.image_exists(self.settings.image):
            raise RuntimeError("Образ сервиса не найден: " + self.settings.image)
        self.publication = bool(self.settings.publish_ports) and await self.exposed_ready()
        if sandbox_node:
            try:
                guard = json.loads(Path(self.settings.guard_file).read_text())
                if guard.get('center_vpn_ip') != self.settings.center_vpn_ip or guard.get('policy') != 'honeyforge-networkless-v1' \
                        or guard.get('boot_id') != Path('/proc/sys/kernel/random/boot_id').read_text().strip():
                    raise ValueError('Guard does not match this boot/node')
            except (OSError, ValueError):
                raise RuntimeError('Не подтверждены правила межсетевого экрана для текущей загрузки узла sandbox')
            if self.settings.host_id == 'lab-docker':
                raise RuntimeError('Sandbox должен находиться на отдельном узле')
            info = await self.docker.info()
            if 'runsc' not in (info.get('Runtimes') or {}):
                raise RuntimeError('На узле sandbox отсутствует runtime runsc')
            for item in await self.docker.containers({}):
                if (item.get('Labels') or {}).get('com.docker.compose.service') in {'backend', 'postgres', 'nginx', 'edge'}:
                    raise RuntimeError('На узле sandbox обнаружены компоненты центра HoneyForge')
            if not await self.docker.image_exists(self.settings.sandbox_image):
                raise RuntimeError('Образ Linux sandbox не собран на узле')
            await self.probe_sandbox()
            self.sandbox_ready = True

    async def probe_sandbox(self):
        probe = {'honeypot_id': '00000000-0000-0000-0000-000000000001', 'emulator': 'tcp', 'service_key': 'linux-sandbox'}
        volume = self.names(probe['honeypot_id'])[2] + '-bridge'
        identifier = gateway_id = None
        await self.docker.create_volume(volume, self.scope | {'honeypot': probe['honeypot_id'], 'volume': 'bridge'})
        try:
            gateway = self.container(probe, 'decoy', self.settings.decoy_network,
                ['python', '-m', 'honeypots.sandbox_probe'], {}, 128, .25, 'unused', 60)
            gateway.pop('Healthcheck', None)
            gateway['HostConfig']['Mounts'] = [{'Type': 'volume', 'Source': volume, 'Target': '/bridge'}]
            gateway['HostConfig']['RestartPolicy'] = {'Name': 'no'}
            gateway_id = await self.docker.create(self.names(probe['honeypot_id'])[0] + '-probe-gateway', gateway)
            await self.docker.start(gateway_id)
            identifier = await self.docker.create(self.names(probe['honeypot_id'])[0] + '-probe', self.sandbox_spec(probe, probe=True))
            await self.docker.start(identifier)
            codes = await asyncio.wait_for(asyncio.gather(self.docker.wait(identifier), self.docker.wait(gateway_id)), timeout=25)
            if any(codes):
                raise DockerError('sandbox_unavailable')
        except asyncio.TimeoutError:
            raise DockerError('sandbox_unavailable')
        finally:
            if identifier:
                await self.docker.remove(identifier)
            if gateway_id:
                await self.docker.remove(gateway_id)
            await self.docker.remove_volume(volume)

    async def exposed_ready(self) -> bool:
        """Publish only through a bridge that cannot be used to reach the Internet from a decoy."""
        network = await self.docker.network(self.settings.exposed_network)
        options = (network or {}).get("Options") or {}
        ready = bool(network) and not network.get("Internal") and network.get("Driver") == "bridge" \
            and options.get("com.docker.network.bridge.enable_ip_masquerade") == "false" \
            and options.get("com.docker.network.bridge.enable_icc") == "false"
        if not ready:
            log.warning("Публикация портов отключена: сеть %s отсутствует или настроена небезопасно", self.settings.exposed_network)
        return ready

    def heartbeat(self, healthy: bool, error: str | None = None):
        Path(self.settings.health_file).write_text(json.dumps({"at": time.time(), "healthy": healthy, "error": error}))

    async def run(self):
        failures, checked = 0, False
        while True:
            try:
                if not checked:
                    await self.preflight()
                    checked = True
                await self.cycle()
                failures = 0
                self.heartbeat(True)
            except (httpx.HTTPError, DockerError, RuntimeError, KeyError, ValueError) as error:
                failures += 1
                log.warning("Цикл согласования не выполнен (%s); повтор", type(error).__name__)
                self.heartbeat(False, type(error).__name__)
            await asyncio.sleep(min(self.settings.interval * (2 ** min(failures, 4)), 30))


async def main():
    settings = Settings()
    policy = Policy(settings.image, {settings.decoy_network, settings.management_network}, settings.volume_prefix,
                    exposed_network=settings.exposed_network, publish_address=settings.publish_address,
                    publish_ports=settings.publish_ports, decoy_network=settings.decoy_network,
                    sandbox_enabled=settings.sandbox_node, sandbox_image=settings.sandbox_image)
    context = ssl.create_default_context(cadata=settings.ca_pem)
    async with httpx.AsyncClient(base_url=settings.management_url, verify=context, timeout=15, headers={
            "X-Controller-ID": settings.host_id, "Authorization": "Bearer " + settings.token}) as api:
        await Controller(settings, Docker.over_socket(settings.socket, policy), api).run()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    asyncio.run(main())
