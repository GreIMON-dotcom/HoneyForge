"""Runtime plane API: service catalog, hosts, endpoints and the deployment controller channel.

The ``/runtime/*`` endpoints are the only way container state enters the
database. They accept nothing but an authenticated controller's observations;
images, commands, mounts and networks are never taken from any request.
"""
import ipaddress
from typing import Literal
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select
from .db import database
from .models import *
from datetime import datetime, timezone
from .security import current_user, current_controller, current_notifier, roles
from .services import audit, required, hub, serialize
from .lifecycle import (CONTROLLER_ERRORS, SETTLED, AGENT_MEMORY_MB, AGENT_CPU, host_public, host_capacity, locked_host,
                        choose_port, set_status, record, complete_commands, finalize_delete)
from shared.catalog import PLUGINS
from shared.contracts import ProfileSpec

router = APIRouter(prefix="/api/v1")
admin = roles("administrator")



@router.get("/service-types", summary="Каталог поддерживаемых сервисов")
async def service_types(user=Depends(current_user)):
    return [plugin.view() for plugin in PLUGINS.values()]


def plugin_or_404(key):
    if key not in PLUGINS:
        raise HTTPException(404, "Тип сервиса не поддерживается")
    return PLUGINS[key]


@router.get("/service-types/{key}", summary="Описание сервиса и конфигурация по умолчанию")
async def service_type(key: str, user=Depends(current_user)):
    plugin = plugin_or_404(key)
    return {**plugin.view(), "defaults": plugin.default_spec()}


@router.get("/service-types/{key}/schema", summary="Схема конфигурации сервиса")
async def service_schema(key: str, user=Depends(current_user)):
    plugin = plugin_or_404(key)
    return {"key": key, "config_schema_version": plugin.schema_version, "fields": list(plugin.fields),
            "schema": ProfileSpec.model_json_schema()}



@router.get("/hosts", summary="Одобренные узлы лаборатории")
async def hosts(user=Depends(current_user), db=Depends(database)):
    return [{**host_public(host), "capacity": await host_capacity(db, host)}
            for host in (await db.scalars(select(Host).order_by(Host.name))).all()]


@router.get("/hosts/{identifier}", summary="Сведения об узле лаборатории")
async def host_detail(identifier: str, user=Depends(current_user), db=Depends(database)):
    host = await required(db, Host, identifier)
    return {**host_public(host), "capacity": await host_capacity(db, host)}


@router.get("/hosts/{identifier}/capacity", summary="Ёмкость и занятые ресурсы узла")
async def capacity(identifier: str, user=Depends(current_user), db=Depends(database)):
    return await host_capacity(db, await required(db, Host, identifier))


class HostPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str | None = Field(default=None, min_length=1, max_length=80)
    approved: bool | None = None
    max_instances: int | None = Field(default=None, ge=0, le=200)
    cpu_budget: float | None = Field(default=None, ge=0, le=256)
    memory_budget_mb: int | None = Field(default=None, ge=0, le=1048576)
    port_range_start: int | None = Field(default=None, ge=1024, le=65535)
    port_range_end: int | None = Field(default=None, ge=1024, le=65535)


@router.patch("/hosts/{identifier}", summary="Изменение политики ёмкости узла")
async def change_host(identifier: str, body: HostPolicy, user=Depends(admin), db=Depends(database)):
    host = await required(db, Host, identifier, lock=True)
    changes = body.model_dump(exclude_none=True)
    start, end = changes.get("port_range_start", host.port_range_start), changes.get("port_range_end", host.port_range_end)
    if start > end:
        raise HTTPException(422, "Начало диапазона портов должно быть не больше его конца")
    outside = await db.scalar(select(NetworkEndpoint.internal_port).where(
        NetworkEndpoint.host_id == host.id, (NetworkEndpoint.internal_port < start) | (NetworkEndpoint.internal_port > end)))
    if outside:
        raise HTTPException(409, f"Порт {outside} уже выделен ловушке и не входит в новый диапазон")
    for key, value in changes.items():
        setattr(host, key, value)
    audit(db, user.id, "host.update", host.id, changes)
    await db.commit()
    hub.publish({"type": "status"})
    return {**host_public(host), "capacity": await host_capacity(db, host)}


class HostRegistration(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(pattern=r"^[a-z][a-z0-9-]{2,39}$")
    name: str = Field(min_length=1, max_length=80)
    credential_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    max_instances: int = Field(default=12, ge=0, le=200)
    cpu_budget: float = Field(default=8.0, ge=0, le=256)
    memory_budget_mb: int = Field(default=4096, ge=0, le=1048576)


@router.post("/hosts", status_code=201, summary="Добавление узла с контроллером в список разрешённых")
async def register_host(body: HostRegistration, user=Depends(admin), db=Depends(database)):
    if await db.get(Host, body.id):
        raise HTTPException(409, "Идентификатор узла уже существует")
    values = body.model_dump()
    host = Host(controller_token_hash=values.pop("credential_sha256"), approved=True, provisioning="controller",
                management_address="controller", **values)
    db.add(host)
    audit(db, user.id, "host.allowlist", host.id)
    await db.commit()
    return host_public(host)


@router.delete("/hosts/{identifier}", summary="Удаление свободного узла")
async def remove_host(identifier: str, user=Depends(admin), db=Depends(database)):
    host = await required(db, Host, identifier, lock=True)
    if await db.scalar(select(Honeypot.id).where(Honeypot.host_id == identifier)):
        raise HTTPException(409, "Сначала удалите ловушки, размещённые на этом узле")
    if await db.scalar(select(Deployment.id).where(Deployment.host_id == identifier)):
        raise HTTPException(409, "У узла есть история развёртываний; отключите его вместо удаления")
    await db.delete(host)
    audit(db, user.id, "host.remove", identifier)
    await db.commit()
    return {"ok": True}



@router.get("/network-endpoints", summary="Выделенные точки подключения")
async def endpoints(host_id: str | None = None, user=Depends(current_user), db=Depends(database)):
    query = select(NetworkEndpoint, Honeypot.name).join(Honeypot, Honeypot.id == NetworkEndpoint.honeypot_id)
    if host_id:
        query = query.where(NetworkEndpoint.host_id == host_id)
    return [{**serialize(endpoint), "honeypot_name": name, "address": f"{endpoint.alias}:{endpoint.internal_port}"}
            for endpoint, name in (await db.execute(query.order_by(NetworkEndpoint.internal_port))).all()]


class EndpointCheck(BaseModel):
    model_config = ConfigDict(extra="forbid")
    host_id: str
    mode: Literal["auto", "manual"] = "auto"
    port: int | None = Field(default=None, ge=1, le=65535)
    preferred_port: int | None = Field(default=None, ge=1, le=65535)
    honeypot_id: str | None = None


@router.post("/network-endpoints/validate", summary="Проверка доступности точки подключения")
async def validate_endpoint(body: EndpointCheck, user=Depends(current_user), db=Depends(database)):
    """Dry run of the allocation; the reservation itself happens when the instance is created."""
    host = await required(db, Host, body.host_id)
    try:
        port = await choose_port(db, host, body.preferred_port or host.port_range_start, body.mode, body.port, body.honeypot_id)
    except HTTPException as error:
        return {"available": False, "port": body.port, "reason": error.detail,
                "range": [host.port_range_start, host.port_range_end], "network": host.network}
    return {"available": True, "port": port, "reason": None, "range": [host.port_range_start, host.port_range_end],
            "network": host.network, "scope": "laboratory-network", "published": False}



@router.get("/runtime/desired", summary="Требуемое состояние среды выполнения узла")
async def desired_runtime(host=Depends(current_controller), db=Depends(database)):
    """Everything the controller may create: fixed service families and numeric limits only."""
    rows = (await db.execute(select(Honeypot, NetworkEndpoint).join(
        NetworkEndpoint, NetworkEndpoint.honeypot_id == Honeypot.id).where(
            Honeypot.host_id == host.id, Honeypot.status != "draft"))).all()
    agents = {a.honeypot_id: a.id for a in (await db.scalars(select(Agent).where(
        Agent.honeypot_id.in_([pot.id for pot, _ in rows]), Agent.retired.is_(False)))).all()}
    deployments = {}
    for item in (await db.scalars(select(Deployment).where(Deployment.host_id == host.id).order_by(Deployment.started_at))).all():
        deployments[item.honeypot_id] = item.id
    return {"host_id": host.id, "network": host.network, "instances": [{
        "honeypot_id": pot.id, "desired": "absent" if pot.status == "deleting" else "present",
        "emulator": pot.configuration["service_type"], "service_key": pot.configuration["service_key"],
        "profile_id": pot.profile_id, "deployment_id": deployments.get(pot.id), "alias": endpoint.alias,
        "port": endpoint.internal_port, "published_port": endpoint.published_port,
        "memory_mb": pot.configuration["memory_mb"],
        "cpu_limit": pot.configuration["cpu_limit"], "agent_memory_mb": AGENT_MEMORY_MB, "agent_cpu": AGENT_CPU,
        "agent_id": agents.get(pot.id), "generation": pot.generation} for pot, endpoint in rows]}


FAILURE_CODES = {"instance.offline": "honeypot_offline", "runtime.error": "honeypot_failed", "operation.timeout": "honeypot_failed"}


@router.get("/runtime/notifications", summary="Новые оповещения и сбои ловушек для службы уведомлений")
async def notifications(since: datetime, caller=Depends(current_notifier), db=Depends(database)):
    """Names and counts only: no source addresses, usernames or visitor input leave through this endpoint."""
    if since.tzinfo is None:
        raise HTTPException(422, "Время должно содержать часовой пояс")
    since = since.astimezone(timezone.utc)
    alerts = (await db.execute(select(Alert, Honeypot.name).join(Honeypot, Honeypot.id == Alert.honeypot_id)
                               .where(Alert.triggered_at > since, Alert.details['system'].as_boolean().is_not(True))
                               .order_by(Alert.triggered_at).limit(50))).all()
    failures = (await db.execute(select(DeploymentLog, Honeypot.name).join(Honeypot, Honeypot.id == DeploymentLog.honeypot_id)
                                 .where(DeploymentLog.timestamp > since, DeploymentLog.code.in_(FAILURE_CODES))
                                 .order_by(DeploymentLog.timestamp).limit(50))).all()
    aware = lambda value: value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    items = [{"kind": "alert", "at": aware(alert.triggered_at), "honeypot_name": name, "severity": alert.severity,
              "rule": alert.details.get("rule"), "count": alert.details.get("count"),
              "window_seconds": alert.details.get("window_seconds")} for alert, name in alerts]
    items += [{"kind": FAILURE_CODES[entry.code], "at": aware(entry.timestamp), "honeypot_name": name} for entry, name in failures]
    return {"now": now(), "items": sorted(items, key=lambda item: item["at"])[:50]}


class Credential(BaseModel):
    model_config = ConfigDict(extra="forbid")
    credential_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


@router.post("/runtime/instances/{identifier}/credential", summary="Привязка удостоверения агента к ловушке")
async def provision_agent(identifier: str, body: Credential, host=Depends(current_controller), db=Depends(database)):
    """The controller generates the agent secret on the host and registers only its hash."""
    pot = await db.scalar(select(Honeypot).where(Honeypot.id == identifier, Honeypot.host_id == host.id).with_for_update())
    if not pot or pot.status in {"draft", "deleting"}:
        raise HTTPException(404, "Ловушка не размещена на этом узле")
    agent = await db.scalar(select(Agent).where(Agent.honeypot_id == pot.id, Agent.retired.is_(False)))
    if agent:
        agent.token_hash = body.credential_sha256
    else:
        agent = Agent(id="ag-" + uid().replace("-", "")[:16], honeypot_id=pot.id, host_id=host.id,
                      token_hash=body.credential_sha256, approved=True)
        db.add(agent)
    audit(db, "controller:" + host.id, "agent.provisioned", agent.id, {"honeypot_id": pot.id})
    record(db, pot, "agent.provisioned", details={"agent_id": agent.id})
    await db.commit()
    return {"agent_id": agent.id}


class ContainerState(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(max_length=80)
    state: str = Field(max_length=20)
    health: str | None = Field(default=None, max_length=20)
    memory_limit: int = Field(default=0, ge=0)
    nano_cpus: int = Field(default=0, ge=0)
    restart_count: int = Field(default=0, ge=0)
    started_at: str | None = Field(default=None, max_length=40)
    published_port: int | None = Field(default=None, ge=1, le=65535)


class InstanceReport(BaseModel):
    model_config = ConfigDict(extra="forbid")
    honeypot_id: str = Field(max_length=40)
    decoy: ContainerState | None = None
    agent: ContainerState | None = None
    sandbox: ContainerState | None = None
    actions: list[str] = Field(default_factory=list, max_length=20)
    error: str | None = Field(default=None, max_length=40)
    stats: dict[str, float] | None = None


class Publication(BaseModel):
    """The controller's own publication policy, taken from its environment on the host."""
    model_config = ConfigDict(extra="forbid")
    enabled: bool = False
    address: str = Field(default="127.0.0.1", max_length=45)
    ports: list[int] = Field(default_factory=list, max_length=1024)

    @field_validator("address")
    @classmethod
    def literal_address(cls, value):
        ipaddress.ip_address(value)
        return value


class SandboxCapability(BaseModel):
    model_config = ConfigDict(extra='forbid')
    ready: bool = False
    runtime: Literal['runsc'] | None = None


class RuntimeReport(BaseModel):
    model_config = ConfigDict(extra="forbid")
    docker: dict[str, str | int | float] = Field(default_factory=dict, max_length=12)
    publication: Publication = Field(default_factory=Publication)
    sandbox: SandboxCapability = Field(default_factory=SandboxCapability)
    instances: list[InstanceReport] = Field(default_factory=list, max_length=500)
    removed: list[str] = Field(default_factory=list, max_length=500)
    orphans_removed: list[str] = Field(default_factory=list, max_length=500)


ACTIONS = frozenset({"volume_created", "agent_created", "agent_started", "decoy_created", "decoy_started", "decoy_republished",
                     "limits_updated", "decoy_removed", "agent_removed", "volume_removed", 'sandbox_created', 'sandbox_reset',
                     'sandbox_removed', 'sandbox_volume_created', 'sandbox_volume_removed'})


@router.post("/runtime/report", summary="Приём фактического состояния контейнеров узла")
async def runtime_report(body: RuntimeReport, host=Depends(current_controller), db=Depends(database)):
    host.last_seen = now()
    host.metrics = body.docker | {"reported_at": now().isoformat(), "publication": body.publication.model_dump(),
                                  'sandbox': body.sandbox.model_dump()}
    pots = {p.id: p for p in (await db.scalars(select(Honeypot).where(Honeypot.host_id == host.id).with_for_update())).all()}
    source = "controller:" + host.id
    before = {p.id: p.status for p in pots.values()}
    changed = bool(body.removed or body.orphans_removed) or any(item.actions for item in body.instances)
    for item in body.instances:
        pot = pots.get(item.honeypot_id)
        if not pot:
            continue
        previous = pot.runtime or {}
        pot.runtime = {"decoy": item.decoy and item.decoy.model_dump(), "agent": item.agent and item.agent.model_dump(),
                       'sandbox': item.sandbox and item.sandbox.model_dump(),
                       "stats": item.stats or previous.get("stats"), "reported_at": now().isoformat()}
        for action in item.actions:
            if action in ACTIONS:
                record(db, pot, "runtime." + action)
        if pot.status in SETTLED | {"offline", "failed"} and {"decoy_created", "agent_created"} & set(item.actions):
            audit(db, source, "runtime.recovered", pot.id, {"actions": item.actions})
        if pot.status == "deleting":
            continue
        if item.error:
            message = CONTROLLER_ERRORS.get(item.error, "Ошибка среды выполнения на узле")
            if pot.status != "failed" or pot.error != message:
                record(db, pot, "runtime.error", "error", {"error": message})
                set_status(pot, "failed", message)
                await complete_commands(db, pot, "failed", message, actor=source)
        elif pot.status == "deploying" and item.decoy and item.agent and item.decoy.state == item.agent.state == "running":
            set_status(pot, "starting")
            record(db, pot, "runtime.ready")
    for identifier in body.removed:
        pot = pots.get(identifier)
        if pot and pot.status == "deleting":
            await finalize_delete(db, pot, source)
    for identifier in body.orphans_removed:
        audit(db, source, "runtime.orphan_removed", identifier[:40])
    changed = changed or any(before[p.id] != p.status for p in pots.values() if p.id not in body.removed)
    await db.commit()
    if changed:
        hub.publish({"type": "status"})
    return {"ok": True}
