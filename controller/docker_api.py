"""Minimal Docker Engine API client restricted to what the controller is allowed to do.

Every container specification passes ``assert_safe`` before it is sent. The
controller therefore cannot be made to start a foreign image, mount host paths,
run privileged or join a network outside the laboratory, even by a bug upstream.
A host port is published only when the operator of the host listed it in the
controller's own environment; the control plane cannot widen that list.
"""
import json
import re
import httpx

LABEL = "io.honeyforge."
RESERVED_PORTS = frozenset({22, 80, 443, 2375, 2376, 8443, 9443})


def parse_ports(text: str, limit: int = 1024) -> frozenset[int]:
    """"23,2222,8080-8099" -> ports. Reserved and out-of-range numbers are a configuration error."""
    ports = set()
    for part in filter(None, (item.strip() for item in (text or "").split(","))):
        first, _, last = part.partition("-")
        try:
            start, end = int(first), int(last or first)
        except ValueError:
            raise ValueError("Некорректный список портов публикации: " + part)
        if not 1 <= start <= end <= 65535:
            raise ValueError("Некорректный диапазон портов публикации: " + part)
        ports.update(range(start, end + 1))
        if len(ports) > limit:
            raise ValueError("Слишком много портов публикации")
    if ports & RESERVED_PORTS:
        raise ValueError("Порты управления нельзя публиковать для ловушек: " + ", ".join(map(str, sorted(ports & RESERVED_PORTS))))
    return frozenset(ports)


class DockerError(Exception):
    def __init__(self, code: str, status: int = 0):
        super().__init__(code)
        self.code, self.status = code, status


class Policy:
    """Allowlist the controller enforces on everything it creates."""
    def __init__(self, image: str, networks: set[str], volume_prefix: str, exposed_network: str | None = None,
                 publish_address: str = "127.0.0.1", publish_ports: frozenset[int] = frozenset(), decoy_network: str | None = None,
                 sandbox_enabled: bool = False, sandbox_image: str = 'honeyforge-sandbox:local'):
        self.image, self.networks, self.volume_prefix = image, networks, volume_prefix
        self.exposed_network, self.publish_address, self.publish_ports = exposed_network, publish_address, publish_ports
        self.decoy_network = decoy_network
        self.sandbox_enabled, self.sandbox_image = sandbox_enabled, sandbox_image

    def assert_publication(self, spec: dict):
        """A published container: one TCP port from the host's own list, bound to the configured address."""
        host, bindings = spec["HostConfig"], spec["HostConfig"].get("PortBindings")
        attached = set((spec.get("NetworkingConfig") or {}).get("EndpointsConfig") or {})
        if not self.publish_ports or not self.exposed_network or host.get("NetworkMode") != self.exposed_network:
            raise DockerError("publication_rejected")
        if not attached <= {self.exposed_network, self.decoy_network} or host.get("PublishAllPorts"):
            raise DockerError("publication_rejected")
        if not isinstance(bindings, dict) or len(bindings) != 1:
            raise DockerError("publication_rejected")
        (container_port, targets), = bindings.items()
        if not re.fullmatch(r"[1-9][0-9]{3,4}/tcp", container_port) or not isinstance(targets, list) or len(targets) != 1:
            raise DockerError("publication_rejected")
        target = targets[0]
        if set(target) != {"HostIp", "HostPort"} or target["HostIp"] != self.publish_address:
            raise DockerError("publication_rejected")
        if not str(target["HostPort"]).isdigit() or int(target["HostPort"]) not in self.publish_ports:
            raise DockerError("publication_rejected")

    def assert_safe(self, spec: dict):
        host = spec.get("HostConfig", {})
        worker = (spec.get('Labels') or {}).get(LABEL + 'role') == 'sandbox'
        if worker:
            self.assert_sandbox(spec)
        elif spec.get("Image") != self.image:
            raise DockerError("image_rejected")
        if host.get("Privileged") or host.get("Binds") or host.get("CapAdd") or host.get("Devices"):
            raise DockerError("create_failed")
        if host.get("PidMode") or host.get("IpcMode") or host.get("UsernsMode"):
            raise DockerError("create_failed")
        if host.get("PortBindings") or host.get("PublishAllPorts") or host.get("NetworkMode") == self.exposed_network:
            self.assert_publication(spec)
        elif not worker and (host.get("NetworkMode") not in self.networks or set((spec.get("NetworkingConfig") or {}).get("EndpointsConfig") or {}) - self.networks):
            raise DockerError("create_failed")
        if host.get("CapDrop") != ["ALL"] or not host.get("ReadonlyRootfs") or "no-new-privileges:true" not in host.get("SecurityOpt", []):
            raise DockerError("create_failed")
        if not host.get("Memory") or not host.get("NanoCpus") or not host.get("PidsLimit"):
            raise DockerError("create_failed")
        for mount in host.get("Mounts", []):
            if mount.get("Type") != "volume" or not str(mount.get("Source", "")).startswith(self.volume_prefix):
                raise DockerError("create_failed")
        if spec.get("User") in (None, "", "0", "root", "0:0"):
            raise DockerError("create_failed")

    def assert_sandbox(self, spec):
        host = spec.get('HostConfig') or {}
        mounts = host.get('Mounts') or []
        if not self.sandbox_enabled or spec.get('Image') != self.sandbox_image or host.get('Runtime') != 'runsc':
            raise DockerError('sandbox_unavailable')
        if host.get('NetworkMode') != 'none' or spec.get('NetworkingConfig') or host.get('PortBindings') or spec.get('ExposedPorts'):
            raise DockerError('sandbox_unsafe')
        if spec.get('Cmd') not in (['python', '/opt/worker.py'], ['python', '/opt/worker.py', '--self-test']):
            raise DockerError('sandbox_unsafe')
        if spec.get('Env') or spec.get('Entrypoint') or spec.get('User') != '10001:10001':
            raise DockerError('sandbox_unsafe')
        if host.get('SecurityOpt') != ['no-new-privileges:true']:
            raise DockerError('sandbox_unsafe')
        if len(mounts) != 1 or mounts[0].get('Target') != '/bridge' or mounts[0].get('ReadOnly') is not True:
            raise DockerError('sandbox_unsafe')
        if not str(mounts[0].get('Source', '')).endswith('-bridge'):
            raise DockerError('sandbox_unsafe')
        if (host.get('Memory'), host.get('NanoCpus'), host.get('PidsLimit')) != (256 * 1024 ** 2, 500_000_000, 64):
            raise DockerError('sandbox_unsafe')
        if host.get('RestartPolicy') != {'Name': 'no'} or host.get('ReadonlyRootfs') is not True:
            raise DockerError('sandbox_unsafe')
        if host.get('Tmpfs') != {'/tmp': 'size=64m,mode=1777', '/home/lab': 'size=64m,uid=10001,gid=10001,mode=700'}:
            raise DockerError('sandbox_unsafe')
        if host.get('Devices') or host.get('DeviceRequests') or host.get('ExtraHosts') or host.get('Links') or host.get('VolumesFrom'):
            raise DockerError('sandbox_unsafe')


class Docker:
    def __init__(self, client: httpx.AsyncClient, policy: Policy):
        self.client, self.policy = client, policy

    @classmethod
    def over_socket(cls, path: str, policy: Policy):
        transport = httpx.AsyncHTTPTransport(uds=path)
        return cls(httpx.AsyncClient(transport=transport, base_url="http://docker", timeout=30), policy)

    async def call(self, method, path, expected=(200, 201, 204), error="docker_unavailable", **kwargs):
        try:
            response = await self.client.request(method, path, **kwargs)
        except httpx.HTTPError:
            raise DockerError("docker_unavailable")
        if response.status_code not in expected:
            raise DockerError(error, response.status_code)
        return response

    @staticmethod
    def filters(labels: dict) -> dict:
        return {"filters": json.dumps({"label": [f"{LABEL}{key}={value}" for key, value in labels.items()]})}

    async def info(self) -> dict:
        return (await self.call("GET", "/info")).json()

    async def containers(self, labels: dict) -> list[dict]:
        return (await self.call("GET", "/containers/json", params={"all": "true", **self.filters(labels)})).json()

    async def inspect(self, identifier: str) -> dict | None:
        response = await self.call("GET", f"/containers/{identifier}/json", expected=(200, 404))
        return response.json() if response.status_code == 200 else None

    async def image_exists(self, name: str) -> bool:
        return (await self.call("GET", f"/images/{name}/json", expected=(200, 404))).status_code == 200

    async def network(self, name: str) -> dict | None:
        response = await self.call("GET", f"/networks/{name}", expected=(200, 404))
        return response.json() if response.status_code == 200 else None

    async def create(self, name: str, spec: dict) -> str:
        self.policy.assert_safe(spec)
        response = await self.call("POST", "/containers/create", params={"name": name}, json=spec,
                                   expected=(201, 404, 409, 400, 500), error="create_failed")
        if response.status_code == 404:
            raise DockerError("image_missing", 404)
        if response.status_code != 201:
            raise DockerError("create_failed", response.status_code)
        return response.json()["Id"]

    async def start(self, identifier: str):
        await self.call("POST", f"/containers/{identifier}/start", expected=(204, 304), error="start_failed")

    async def wait(self, identifier: str):
        return (await self.call('POST', f'/containers/{identifier}/wait', params={'condition': 'not-running'}, error='sandbox_unavailable')).json()['StatusCode']

    async def update_limits(self, identifier: str, memory: int, nano_cpus: int):
        await self.call("POST", f"/containers/{identifier}/update", error="create_failed",
                        json={"Memory": memory, "MemorySwap": memory, "NanoCpus": nano_cpus})

    async def remove(self, identifier: str):
        await self.call("DELETE", f"/containers/{identifier}", params={"force": "true"},
                        expected=(204, 404), error="remove_failed")

    async def volumes(self, labels: dict) -> list[dict]:
        return (await self.call("GET", "/volumes", params=self.filters(labels))).json().get("Volumes") or []

    async def create_volume(self, name: str, labels: dict):
        if not name.startswith(self.policy.volume_prefix):
            raise DockerError("create_failed")
        await self.call("POST", "/volumes/create", error="create_failed",
                        json={"Name": name, "Labels": {LABEL + key: value for key, value in labels.items()}})

    async def remove_volume(self, name: str):
        await self.call("DELETE", f"/volumes/{name}", expected=(204, 404), error="remove_failed")

    async def stats(self, identifier: str) -> dict | None:
        """Memory in use and CPU share since the previous sample, as Docker itself computes them."""
        response = await self.call("GET", f"/containers/{identifier}/stats", params={"stream": "false"}, expected=(200, 404, 409))
        if response.status_code != 200:
            return None
        data = response.json()
        memory = data.get("memory_stats", {})
        usage = max(memory.get("usage", 0) - memory.get("stats", {}).get("inactive_file", 0), 0)
        cpu, previous = data.get("cpu_stats", {}), data.get("precpu_stats", {})
        delta = cpu.get("cpu_usage", {}).get("total_usage", 0) - previous.get("cpu_usage", {}).get("total_usage", 0)
        system = cpu.get("system_cpu_usage", 0) - previous.get("system_cpu_usage", 0)
        percent = delta / system * cpu.get("online_cpus", 1) * 100 if system > 0 and delta > 0 else 0.0
        return {"memory_bytes": float(usage), "cpu_percent": round(percent, 2)}
