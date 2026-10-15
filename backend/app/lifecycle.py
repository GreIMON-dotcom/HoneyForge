"""Honeypot instance lifecycle: configuration, endpoints, capacity and state transitions.

The database holds the desired state. Actual state is only ever written from
authenticated reports of the host controller and of the instance's own agent.
"""
from fastapi import HTTPException
from sqlalchemy import select, func, delete
from sqlalchemy.exc import IntegrityError
from pydantic import ValidationError
from .models import *
from .config import settings
from .services import serialize, audit, required, as_utc
from shared.contracts import ProfileSpec, effective_configuration

TRANSITIONAL = frozenset({"deploying", "starting", "stopping", "restarting", "updating", "deleting"})
SETTLED = frozenset({"running", "stopped"})
REMOVABLE = frozenset({"stopped", "failed", "offline"})
AGENT_MEMORY_MB = 96
AGENT_CPU = 0.25
CONTROLLER_ERRORS = {
    'sandbox_unavailable': 'Для реальной оболочки нужен отдельный подготовленный узел с gVisor (runsc)',
    'sandbox_unsafe': 'Проверка изоляции Linux sandbox не пройдена; запуск заблокирован',
    "image_missing": "Образ сервиса не найден на узле. Соберите образ HoneyForge и повторите развёртывание",
    "image_rejected": "Образ не входит в список разрешённых",
    "network_missing": "Лабораторная сеть ловушек не найдена на узле",
    "create_failed": "Не удалось создать контейнер ловушки",
    "start_failed": "Не удалось запустить контейнер ловушки",
    "credential_failed": "Не удалось подготовить удостоверение агента",
    "remove_failed": "Не удалось удалить контейнеры или том экземпляра",
    "docker_unavailable": "Служба Docker на узле недоступна",
    "publication_rejected": "Контроллер узла отклонил публикацию порта: порт не входит в список, разрешённый на узле",
}


def normalized_spec(profile) -> dict:
    """Stored specs predate newer fields; reading always yields the current complete shape."""
    return ProfileSpec.model_validate(profile.spec).model_dump()


def profile_view(profile, instances=0) -> dict:
    spec = normalized_spec(profile)
    return {**serialize(profile), "spec": spec, "description": spec["description"],
            "service_key": spec["service_key"], "service_type_id": spec["service_key"],
            "interaction_level": spec["interaction_level"], "configuration": spec, "instances": instances}


def set_status(pot, status, error=None):
    pot.status = status
    pot.transition_at = now() if status in TRANSITIONAL else None
    pot.error = error


def record(db, pot, code, level="info", details=None, deployment_id=None):
    db.add(DeploymentLog(honeypot_id=pot.id, deployment_id=deployment_id, level=level, code=code, details=details or {}))


def displayed_status(pot) -> str:
    stale = not pot.last_seen or (now() - as_utc(pot.last_seen)).total_seconds() > settings().heartbeat_timeout
    return "offline" if pot.status in SETTLED and stale else pot.status


def controller_connected(host) -> bool:
    return bool(host.last_seen and (now() - as_utc(host.last_seen)).total_seconds() <= settings().heartbeat_timeout)


def host_public(host) -> dict:
    """Host record for operators; the controller credential hash never leaves the server."""
    data = serialize(host)
    data.pop("controller_token_hash")
    data["controller_connected"] = controller_connected(host)
    return data


async def host_capacity(db, host) -> dict:
    usage = await host_usage(db, host)
    policy = {"max_instances": host.max_instances, "cpu_budget": host.cpu_budget, "memory_budget_mb": host.memory_budget_mb,
              "port_range_start": host.port_range_start, "port_range_end": host.port_range_end}
    ports = host.port_range_end - host.port_range_start + 1
    return {"host_id": host.id, "policy": policy, "allocated": usage,
            "available": {"instances": max(host.max_instances - usage["instances"], 0),
                          "cpu": round(max(host.cpu_budget - usage["cpu"], 0), 2),
                          "memory_mb": max(host.memory_budget_mb - usage["memory_mb"], 0),
                          "endpoints": max(ports - usage["endpoints"], 0)},
            "per_instance_overhead": {"memory_mb": AGENT_MEMORY_MB, "cpu": AGENT_CPU},
            "observed": host.metrics or {}, "controller_connected": controller_connected(host), "last_seen": host.last_seen,
            "publication": publication_policy(host)}


def publication_policy(host) -> dict:
    """What the host controller itself reported it may publish; nothing until it says so."""
    reported = (host.metrics or {}).get("publication") or {}
    enabled = bool(reported.get("enabled")) and controller_known(host)
    return {"enabled": enabled, "address": reported.get("address") if enabled else None,
            "ports": list(reported.get("ports") or []) if enabled else []}


def controller_known(host) -> bool:
    return host.last_seen is not None


async def set_publication(db, pot, actor, port: int | None):
    """Ask for one host port to be forwarded to the instance, or withdraw it (port=None)."""
    host = await locked_host(db, pot.host_id)
    endpoint = await db.scalar(select(NetworkEndpoint).where(NetworkEndpoint.honeypot_id == pot.id))
    if pot.status == "deleting":
        raise HTTPException(409, "Ловушка удаляется; другие операции недоступны")
    if port is not None:
        policy = publication_policy(host)
        if not policy["enabled"]:
            raise HTTPException(409, "Публикация портов на этом узле не разрешена. Её включает владелец узла параметром PUBLISH_PORTS контроллера")
        if port not in policy["ports"]:
            raise HTTPException(422, "Порт не входит в список портов, разрешённых для публикации на узле")
        owner = await db.scalar(select(Honeypot).join(NetworkEndpoint, NetworkEndpoint.honeypot_id == Honeypot.id).where(
            NetworkEndpoint.host_id == host.id, NetworkEndpoint.published_port == port, Honeypot.id != pot.id))
        if owner:
            raise HTTPException(409, f"Конфликт портов: порт {port} уже опубликован для ловушки «{owner.name}»")
    if endpoint.published_port == port:
        return False
    previous, endpoint.published_port = endpoint.published_port, port
    record(db, pot, "publication.requested" if port else "publication.withdrawn", "warning" if port else "info",
           {"port": port or previous})
    audit(db, actor.id, "honeypot.publish" if port else "honeypot.unpublish", pot.id, {"port": port or previous})
    await db.flush()
    return True


async def locked_host(db, host_id):
    """Serializes admission and endpoint reservation for one host."""
    host = await required(db, Host, host_id, lock=True)
    if not host.approved or host.provisioning != "controller":
        raise HTTPException(422, "Развёртывание разрешено только на одобренных узлах с контроллером")
    return host


async def host_usage(db, host, exclude=None) -> dict:
    pots = (await db.scalars(select(Honeypot).where(Honeypot.host_id == host.id, Honeypot.status != "draft"))).all()
    pots = [p for p in pots if p.id != exclude]
    ports = (await db.scalars(select(NetworkEndpoint.internal_port).where(NetworkEndpoint.host_id == host.id))).all()
    return {"instances": len(pots),
            "running": sum(p.status == "running" for p in pots),
            "failed": sum(p.status == "failed" for p in pots),
            "cpu": round(sum(p.configuration.get("cpu_limit", 0.5) + AGENT_CPU + (0.5 if p.configuration.get('service_key') == 'linux-sandbox' else 0) for p in pots), 2),
            "memory_mb": sum(p.configuration.get("memory_mb", 128) + AGENT_MEMORY_MB + (256 if p.configuration.get('service_key') == 'linux-sandbox' else 0) for p in pots),
            "endpoints": len(ports)}


async def admit(db, host, configuration, pot_id=None):
    """Admission control: refuse instead of overcommitting the approved host."""
    usage = await host_usage(db, host, exclude=pot_id)
    high = configuration.get('service_key') == 'linux-sandbox'
    capability = (host.metrics or {}).get('sandbox') or {}
    if high and (host.id == 'lab-docker' or not controller_connected(host) or not capability.get('ready') or capability.get('runtime') != 'runsc'):
        raise HTTPException(409, 'Для Linux sandbox нужен отдельный узел VM/VPS с проверенным runtime runsc. Центр и локальный узел не подходят')
    if usage["instances"] + 1 > host.max_instances:
        raise HTTPException(409, f"На узле достигнут предел числа ловушек ({host.max_instances}). Удалите ненужные экземпляры или измените политику узла")
    if usage["memory_mb"] + configuration["memory_mb"] + AGENT_MEMORY_MB + (256 if high else 0) > host.memory_budget_mb:
        raise HTTPException(409, "Недостаточно оперативной памяти для запуска новой ловушки")
    if usage["cpu"] + configuration["cpu_limit"] + AGENT_CPU + (0.5 if high else 0) > host.cpu_budget + 1e-9:
        raise HTTPException(409, "Недостаточно ресурсов процессора для запуска новой ловушки")


async def choose_port(db, host, preferred, mode="auto", port=None, pot_id=None) -> int:
    """Reserve-ready port on the host's laboratory network. Call with the host row locked."""
    rows = (await db.execute(select(NetworkEndpoint.internal_port, NetworkEndpoint.honeypot_id).where(
        NetworkEndpoint.host_id == host.id, NetworkEndpoint.network == host.network))).all()
    used = {number: owner for number, owner in rows if owner != pot_id}
    allowed = range(host.port_range_start, host.port_range_end + 1)
    if mode == "manual":
        if port is None:
            raise HTTPException(422, "Укажите порт или выберите автоматическое выделение")
        if port not in allowed:
            raise HTTPException(422, f"Порт должен входить в разрешённый диапазон узла: {host.port_range_start}–{host.port_range_end}")
        if port in used:
            owner = await db.get(Honeypot, used[port])
            raise HTTPException(409, f"Конфликт портов: порт {port} уже выделен ловушке «{owner.name if owner else used[port]}»")
        return port
    start = preferred if preferred in allowed else host.port_range_start
    for candidate in [*range(start, host.port_range_end + 1), *range(host.port_range_start, start)]:
        if candidate not in used:
            return candidate
    raise HTTPException(409, "В разрешённом диапазоне узла не осталось свободных портов")


def own_settings(profile, overrides) -> dict:
    """Only what really differs from the profile is an instance's own setting."""
    spec = normalized_spec(profile)
    return {key: value for key, value in (overrides or {}).items() if key not in spec or spec[key] != value}


def build_configuration(profile, overrides, port) -> dict:
    try:
        return effective_configuration(normalized_spec(profile), overrides, port)
    except ValidationError as error:
        detail = "; ".join(str(item.get("ctx", {}).get("error", item["msg"])) for item in error.errors()[:3])
        raise HTTPException(422, "Ошибка проверки конфигурации: " + detail)
    except ValueError as error:
        raise HTTPException(422, str(error))


async def dry_run(db, name, spec, overrides, host_id, port_mode, port, deploy, profile_name=None) -> dict:
    """Every check a real creation performs, without writing anything."""
    errors, configuration, reserved = [], None, None
    host = await db.get(Host, host_id)
    if not host or not host.approved or host.provisioning != "controller":
        return {"valid": False, "errors": ["Развёртывание разрешено только на одобренных узлах с контроллером"]}
    if await db.scalar(select(Honeypot.id).where(Honeypot.name == name)):
        errors.append("Ловушка с таким названием уже существует")
    if profile_name and await db.scalar(select(Profile.id).where(Profile.name == profile_name)):
        errors.append("Профиль с таким названием уже существует")
    try:
        reserved = await choose_port(db, host, spec["port"], port_mode, port)
        try:
            configuration = effective_configuration(spec, overrides, reserved)
        except ValidationError as error:
            raise HTTPException(422, "; ".join(str(item.get("ctx", {}).get("error", item["msg"])) for item in error.errors()[:3]))
        except ValueError as error:
            raise HTTPException(422, str(error))
        if not configuration["enabled"] and deploy:
            raise HTTPException(422, "Профиль отключён")
        if deploy:
            if not controller_connected(host):
                raise HTTPException(409, "Контроллер узла недоступен. Проверьте сервис controller и повторите развёртывание")
            await admit(db, host, configuration)
    except HTTPException as error:
        errors.append(error.detail)
    return {"valid": not errors, "errors": errors, "configuration": configuration,
            "endpoint": reserved and {"port": reserved, "network": host.network, "mode": port_mode, "published": False},
            "capacity": await host_capacity(db, host),
            "runtime": {"image": "honeyforge:local", "containers": 3 if configuration and configuration['service_key'] == 'linux-sandbox' else 2, "user": "10001:10001",
                        "memory_mb": configuration and configuration["memory_mb"] + AGENT_MEMORY_MB + (256 if configuration['service_key'] == 'linux-sandbox' else 0),
                        "cpu": configuration and round(configuration["cpu_limit"] + AGENT_CPU + (0.5 if configuration['service_key'] == 'linux-sandbox' else 0), 2)}}


async def create_instance(db, actor, name, profile_id, host_id, description="", tags=(), overrides=None,
                          port_mode="auto", port=None, update_policy="manual", deploy=False):
    host = await locked_host(db, host_id)
    profile = await required(db, Profile, profile_id)
    spec = normalized_spec(profile)
    if await db.scalar(select(Honeypot.id).where(Honeypot.name == name)):
        raise HTTPException(409, "Ловушка с таким названием уже существует")
    reserved = await choose_port(db, host, spec["port"], port_mode, port)
    overrides = own_settings(profile, overrides)
    configuration = build_configuration(profile, overrides, reserved)
    pot = Honeypot(id=uid(), name=name, description=description, tags=list(tags), profile_id=profile.id,
                   profile_version=profile.version, overrides=overrides, configuration=configuration,
                   update_policy=update_policy, host_id=host.id, status="draft", desired_state="stopped")
    db.add(pot)
    try:
        await db.flush()
        db.add(NetworkEndpoint(host_id=host.id, network=host.network, alias="hp-" + pot.id[:8],
                               internal_port=reserved, mode=port_mode, honeypot_id=pot.id))
        await db.flush()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(409, "Конфликт портов: точка подключения уже занята. Повторите создание")
    audit(db, actor.id, "honeypot.register", pot.id, {"profile_id": profile.id, "host_id": host.id, "port": reserved})
    record(db, pot, "instance.created", details={"port": reserved, "mode": port_mode})
    if deploy:
        await request_deploy(db, pot, actor, host=host)
    return pot


async def request_deploy(db, pot, actor, host=None):
    """First start of a draft, or a retry after a failure. Admission happens here."""
    host = host or await locked_host(db, pot.host_id)
    if pot.status in TRANSITIONAL:
        raise HTTPException(409, "Дождитесь завершения текущей операции с этой ловушкой")
    if pot.status == "running":
        return None
    if not pot.configuration.get("enabled", True):
        raise HTTPException(422, "Профиль отключён")
    if not controller_connected(host):
        raise HTTPException(409, "Контроллер узла недоступен. Проверьте сервис controller и повторите развёртывание")
    await admit(db, host, pot.configuration, pot.id)
    first = pot.status == "draft"
    pot.generation += 1
    pot.desired_state = "running"
    set_status(pot, "deploying" if first or not pot.runtime.get("decoy") else "starting")
    db.add(Command(honeypot_id=pot.id, command_type="deploy", generation=pot.generation))
    deployment = Deployment(honeypot_id=pot.id, host_id=pot.host_id, profile_id=pot.profile_id,
                            initiated_by=actor.id, generation=pot.generation, operation="deploy")
    db.add(deployment)
    await db.flush()
    record(db, pot, "deployment.requested", deployment_id=deployment.id, details={"generation": pot.generation})
    audit(db, actor.id, "deployment.create", pot.id, {"deployment_id": deployment.id})
    return deployment


async def operate(db, pot, operation, actor):
    await db.refresh(pot, with_for_update=True)
    if pot.status == "draft":
        raise HTTPException(409, "Экземпляр ещё не развёрнут. Сначала выполните развёртывание")
    if pot.status == "deleting":
        raise HTTPException(409, "Ловушка удаляется; другие операции недоступны")
    if operation == "start" and pot.desired_state == "running" and pot.status in {"running", "deploying", "starting", "restarting", "updating"}:
        return
    if operation == "stop" and pot.desired_state == "stopped" and pot.status in {"stopped", "stopping"}:
        return
    if operation != "stop" and not pot.configuration.get("enabled", True):
        raise HTTPException(422, "Профиль отключён")
    pot.generation += 1
    pot.desired_state = "stopped" if operation == "stop" else "running"
    set_status(pot, {"start": "starting", "stop": "stopping", "restart": "restarting"}[operation])
    db.add(Command(honeypot_id=pot.id, command_type=operation, generation=pot.generation))
    record(db, pot, "operation." + operation, details={"generation": pot.generation})
    audit(db, actor, f"honeypot.{operation}", pot.id)
    await db.flush()


async def reconfigure(db, pot, actor_id, profile=None, overrides=None, port=None, reason="honeypot.configure"):
    """Rebuild the desired configuration and, for a deployed instance, request its application."""
    profile = profile or await required(db, Profile, pot.profile_id)
    endpoint = await db.scalar(select(NetworkEndpoint).where(NetworkEndpoint.honeypot_id == pot.id))
    if port is not None and port != endpoint.internal_port:
        host = await locked_host(db, pot.host_id)
        endpoint.internal_port = await choose_port(db, host, port, "manual", port, pot.id)
        endpoint.mode = "manual"
    overrides = own_settings(profile, pot.overrides if overrides is None else overrides)
    configuration = build_configuration(profile, overrides, endpoint.internal_port)
    changed = configuration != pot.configuration
    if changed and pot.status != "draft":
        if pot.status == "deleting":
            raise HTTPException(409, "Ловушка удаляется; другие операции недоступны")
        if (configuration["memory_mb"], configuration["cpu_limit"], configuration.get('service_key')) != (pot.configuration.get("memory_mb"), pot.configuration.get("cpu_limit"), pot.configuration.get('service_key')):
            await admit(db, await locked_host(db, pot.host_id), configuration, pot.id)
    pot.profile_id, pot.profile_version = profile.id, profile.version
    pot.overrides = overrides
    if not changed:
        return False
    pot.configuration = configuration
    if pot.status != "draft":
        pot.generation += 1
        set_status(pot, "updating")
        db.add(Command(honeypot_id=pot.id, command_type="configure", generation=pot.generation))
        record(db, pot, "operation.configure", details={"generation": pot.generation, "profile_version": profile.version})
    audit(db, actor_id, reason, pot.id, {"profile_version": profile.version})
    return True


async def finalize_delete(db, pot, actor="system"):
    """Remove the instance and everything that only exists because of it."""
    identifier = pot.id
    for model in (Event, InteractionSession, Command, DeploymentLog, Deployment, Alert, AlertRule, NetworkEndpoint):
        await db.execute(delete(model).where(model.honeypot_id == identifier))
    await db.execute(delete(Agent).where(Agent.honeypot_id == identifier))
    await db.delete(pot)
    audit(db, actor, "honeypot.delete", identifier, {"name": pot.name})
    await db.flush()


async def request_delete(db, pot, actor, force=False):
    if pot.status == "draft" or force:
        await finalize_delete(db, pot, actor.id)
        return True
    if displayed_status(pot) == "deleting":
        return False
    if displayed_status(pot) not in REMOVABLE:
        raise HTTPException(409, "Перед удалением остановите ловушку и дождитесь подтверждения остановки")
    pot.desired_state = "deleted"
    pot.generation += 1
    set_status(pot, "deleting")
    db.add(Command(honeypot_id=pot.id, command_type="delete", generation=pot.generation))
    record(db, pot, "operation.delete")
    audit(db, actor.id, "honeypot.delete_requested", pot.id)
    return False


async def complete_commands(db, pot, outcome, error=None, actor="system"):
    """Close pending commands and deployments once their generation was confirmed or failed."""
    commands = (await db.scalars(select(Command).where(Command.honeypot_id == pot.id, Command.status == "pending"))).all()
    for item in commands:
        item.status = "superseded" if item.generation < pot.generation else outcome
        item.completed_at, item.error = now(), error
        audit(db, actor, "command." + item.status, item.id)
    deployments = (await db.scalars(select(Deployment).where(Deployment.honeypot_id == pot.id, Deployment.status == "pending"))).all()
    for item in deployments:
        item.status = "failed" if outcome == "failed" else "running" if pot.status == "running" else "cancelled"
        item.completed_at, item.error_message = now(), error
        item.runtime_identifier = (pot.runtime.get("decoy") or {}).get("id")
        record(db, pot, "deployment." + item.status, "error" if item.status == "failed" else "info",
               {"error": error} if error else {}, item.id)


async def pot_views(db, pots) -> list[dict]:
    """Inventory rows with the related endpoint, agent, profile and telemetry volume."""
    ids = [p.id for p in pots]
    if not ids:
        return []
    endpoints = {e.honeypot_id: e for e in (await db.scalars(select(NetworkEndpoint).where(NetworkEndpoint.honeypot_id.in_(ids)))).all()}
    agents = {a.honeypot_id: a for a in (await db.scalars(select(Agent).where(
        Agent.honeypot_id.in_(ids), Agent.retired.is_(False)))).all()}
    profiles = {p.id: p for p in (await db.scalars(select(Profile).where(Profile.id.in_({p.profile_id for p in pots})))).all()}
    hosts = {h.id: h for h in (await db.scalars(select(Host).where(Host.id.in_({p.host_id for p in pots})))).all()}
    counts = dict((await db.execute(select(Event.honeypot_id, func.count()).where(Event.honeypot_id.in_(ids)).group_by(Event.honeypot_id))).all())
    timeout = settings().heartbeat_timeout
    result = []
    for pot in pots:
        data = serialize(pot)
        endpoint, agent, profile = endpoints.get(pot.id), agents.get(pot.id), profiles[pot.profile_id]
        data["status"] = displayed_status(pot)
        data["actual_state"] = data["status"]
        data["synchronized"] = pot.generation == pot.applied_generation and pot.status in SETTLED
        data["deployed"] = pot.status != "draft"
        data["service_key"] = pot.configuration.get("service_key")
        data["service_type"] = pot.configuration.get("service_type")
        data["interaction_level"] = pot.configuration.get("interaction_level")
        data["profile_name"] = profile.name
        data["profile_latest_version"] = profile.version
        data["update_available"] = profile.version > pot.profile_version
        data["host_name"] = hosts[pot.host_id].name
        data["event_count"] = counts.get(pot.id, 0)
        data["runtime_identifier"] = (pot.runtime.get("decoy") or {}).get("id")
        data["endpoint"] = endpoint and {"id": endpoint.id, "alias": endpoint.alias, "port": endpoint.internal_port,
            "network": endpoint.network, "protocol": pot.configuration.get("service_type"), "mode": endpoint.mode,
            "published_port": endpoint.published_port, "address": f"{endpoint.alias}:{endpoint.internal_port}",
            "ip_address": pot.ip_address,
            "published_observed": (pot.runtime.get("decoy") or {}).get("published_port"),
            "published_address": publication_policy(hosts[pot.host_id])["address"] if endpoint.published_port else None}
        data["agent"] = agent and {"id": agent.id, "approved": agent.approved, "version": agent.version,
            "last_seen": agent.last_seen, "connected": bool(agent.approved and agent.last_seen and
                (now() - as_utc(agent.last_seen)).total_seconds() <= timeout)}
        result.append(data)
    return result


async def pot_view(db, pot) -> dict:
    return (await pot_views(db, [pot]))[0]
