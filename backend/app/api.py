import asyncio
from datetime import timedelta
from typing import Annotated, Literal
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field, ConfigDict, IPvAnyAddress
from sqlalchemy import select, delete, func
from .db import database, Session
from .models import *
from .security import current_user, current_agent, identified_agent, roles, password_hash, password_matches, digest, issue_session, resolve_session
from .services import required, serialize, audit, ingest, hub, evaluate_rules
from .lifecycle import (SETTLED, normalized_spec, profile_view, host_public, pot_view, pot_views, set_status, record,
                        create_instance, request_deploy, request_delete, operate, reconfigure, complete_commands, dry_run, set_publication)
from .config import settings
from shared.contracts import ProfileSpec, EventBatch

router = APIRouter(prefix="/api/v1")
admin = roles("administrator")
operator = roles("administrator", "operator")


class Login(BaseModel):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=256)


@router.post("/auth/login", summary="Вход в систему")
async def login(body: Login, request: Request, response: Response, db=Depends(database)):
    if request.headers.get("origin") and request.headers["origin"] != settings().allowed_origin:
        raise HTTPException(403, "Источник запроса не разрешён")
    recent = await db.scalar(select(func.count()).select_from(Audit).where(
        Audit.action == "login.failed", Audit.actor == body.username, Audit.timestamp > now() - timedelta(minutes=5)))
    if recent >= 10:
        raise HTTPException(429, "Слишком много попыток. Повторите через пять минут")
    user = await db.scalar(select(User).where(User.username == body.username, User.is_active.is_(True)))
    if not user or not await asyncio.to_thread(password_matches, body.password, user.password_hash):
        audit(db, body.username, "login.failed", "session", result="denied")
        await db.commit()
        raise HTTPException(401, "Неверное имя пользователя или пароль")
    await issue_session(db, user, response)
    audit(db, user.id, "login", "session")
    await db.commit()
    return {"id": user.id, "username": user.username, "role": user.role}


@router.get("/auth/me", summary="Текущая учётная запись")
async def me(user=Depends(current_user)):
    return {"id": user.id, "username": user.username, "role": user.role}


@router.post("/auth/logout", summary="Выход из системы")
async def logout(request: Request, response: Response, user=Depends(current_user), db=Depends(database)):
    await db.execute(delete(LoginSession).where(LoginSession.token_hash == digest(request.cookies["hf_session"])))
    response.delete_cookie("hf_session", path="/")
    audit(db, user.id, "logout", "session")
    await db.commit()
    return {"ok": True}


@router.post("/auth/refresh", summary="Продление сеанса")
async def refresh(request: Request, response: Response, user=Depends(current_user), db=Depends(database)):
    await db.execute(delete(LoginSession).where(LoginSession.token_hash == digest(request.cookies["hf_session"])))
    await issue_session(db, user, response)
    await db.commit()
    return {"ok": True}


class UserCreate(Login):
    password: str = Field(min_length=12, max_length=256)
    role: Literal["administrator", "operator", "viewer"]


class UserPatch(BaseModel):
    role: Literal["administrator", "operator", "viewer"] | None = None
    is_active: bool | None = None


@router.get("/users", summary="Список пользователей")
async def users(user=Depends(admin), db=Depends(database)):
    return [{"id": u.id, "username": u.username, "role": u.role, "is_active": u.is_active}
            for u in (await db.scalars(select(User))).all()]


@router.post("/users", status_code=201, summary="Создание пользователя")
async def create_user(body: UserCreate, user=Depends(admin), db=Depends(database)):
    obj = User(username=body.username, password_hash=await asyncio.to_thread(password_hash, body.password), role=body.role)
    db.add(obj)
    await db.flush()
    audit(db, user.id, "user.create", obj.id)
    await db.commit()
    return {"id": obj.id}


@router.patch("/users/{identifier}", summary="Изменение доступа пользователя")
async def change_user(identifier: str, body: UserPatch, user=Depends(admin), db=Depends(database)):
    if identifier == user.id:
        raise HTTPException(409, "Нельзя изменить собственную роль или отключить текущую учётную запись")
    obj = await required(db, User, identifier)
    for key, value in body.model_dump(exclude_none=True).items():
        setattr(obj, key, value)
    await db.execute(delete(LoginSession).where(LoginSession.user_id == identifier))
    audit(db, user.id, "user.update", identifier)
    await db.commit()
    return {"ok": True}


class PasswordChange(BaseModel):
    current_password: str = Field(max_length=256)
    new_password: str = Field(min_length=12, max_length=256)


@router.post("/auth/password", summary="Изменение пароля")
async def change_password(body: PasswordChange, user=Depends(current_user), db=Depends(database)):
    if not await asyncio.to_thread(password_matches, body.current_password, user.password_hash):
        raise HTTPException(403, "Текущий пароль неверен")
    user.password_hash = await asyncio.to_thread(password_hash, body.new_password)
    await db.execute(delete(LoginSession).where(LoginSession.user_id == user.id))
    audit(db, user.id, "user.password", user.id)
    await db.commit()
    return {"ok": True, "message": "Пароль изменён. Войдите снова."}


@router.get("/profiles", summary="Библиотека профилей")
async def profiles(user=Depends(current_user), db=Depends(database)):
    counts = dict((await db.execute(select(Honeypot.profile_id, func.count()).group_by(Honeypot.profile_id))).all())
    return [profile_view(p, counts.get(p.id, 0)) for p in (await db.scalars(select(Profile).order_by(Profile.name))).all()]


@router.get("/profiles/{identifier}", summary="Получение профиля")
async def profile(identifier: str, user=Depends(current_user), db=Depends(database)):
    obj = await required(db, Profile, identifier)
    return profile_view(obj, await db.scalar(select(func.count()).select_from(Honeypot).where(Honeypot.profile_id == identifier)))


@router.post("/profiles", status_code=201, summary="Создание профиля")
async def create_profile(body: ProfileSpec, user=Depends(admin), db=Depends(database)):
    obj = Profile(name=body.name, spec=body.model_dump())
    db.add(obj)
    await db.flush()
    audit(db, user.id, "profile.create", obj.id)
    await db.commit()
    return profile_view(obj)


@router.patch("/profiles/{identifier}", summary="Изменение профиля")
async def change_profile(identifier: str, body: ProfileSpec, user=Depends(admin), db=Depends(database)):
    obj = await required(db, Profile, identifier, lock=True)
    pots = (await db.scalars(select(Honeypot).where(Honeypot.profile_id == identifier).order_by(Honeypot.id).with_for_update())).all()
    if pots and body.service_type != normalized_spec(obj)["service_type"]:
        raise HTTPException(409, "Нельзя изменить тип сервиса у профиля, по которому созданы ловушки")
    obj.name, obj.spec = body.name, body.model_dump()
    obj.version += 1
    updated = 0
    for pot in pots:
        if pot.update_policy == "auto" and pot.status != "deleting":
            updated += await reconfigure(db, pot, user.id, profile=obj, reason="honeypot.auto_update")
    audit(db, user.id, "profile.update", obj.id, {"version": obj.version, "instances": len(pots), "auto_updated": updated})
    await db.commit()
    hub.publish({"type": "status"})
    return profile_view(obj, len(pots))


@router.post("/profiles/{identifier}/duplicate", status_code=201, summary="Дублирование профиля")
async def duplicate_profile(identifier: str, user=Depends(admin), db=Depends(database)):
    original = await required(db, Profile, identifier)
    spec = normalized_spec(original)
    spec["name"] = original.name[:60] + " — копия " + uid()[:6]
    return await create_profile(ProfileSpec(**spec), user, db)


@router.delete("/profiles/{identifier}", summary="Удаление профиля")
async def delete_profile(identifier: str, user=Depends(admin), db=Depends(database)):
    obj = await required(db, Profile, identifier)
    if await db.scalar(select(Honeypot.id).where(Honeypot.profile_id == identifier)):
        raise HTTPException(409, "По профилю созданы ловушки. Сначала удалите их или назначьте им другой профиль")
    await db.delete(obj)
    audit(db, user.id, "profile.delete", identifier)
    await db.commit()
    return {"ok": True}


Tag = Annotated[str, Field(min_length=1, max_length=30, pattern=r"^[\w .-]+$")]


class InstanceCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=80)
    description: str = Field(default="", max_length=1000)
    tags: list[Tag] = Field(default_factory=list, max_length=10)
    profile_id: str
    host_id: str
    overrides: dict = Field(default_factory=dict)
    port_mode: Literal["auto", "manual"] = "auto"
    port: int | None = Field(default=None, ge=1024, le=65535)
    update_policy: Literal["manual", "auto"] = "manual"
    deploy: bool = False


class InstancePatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str | None = Field(default=None, min_length=1, max_length=80)
    description: str | None = Field(default=None, max_length=1000)
    tags: list[Tag] | None = Field(default=None, max_length=10)
    profile_id: str | None = None
    overrides: dict | None = None
    port: int | None = Field(default=None, ge=1024, le=65535)
    update_policy: Literal["manual", "auto"] | None = None


class CloneRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=80)
    host_id: str | None = None
    deploy: bool = False


@router.get("/honeypots", summary="Все ловушки")
async def pots(q: str | None = Query(default=None, max_length=80), status: str | None = None,
               service_key: str | None = None, host_id: str | None = None, profile_id: str | None = None,
               user=Depends(current_user), db=Depends(database)):
    query = select(Honeypot).order_by(Honeypot.name)
    if host_id:
        query = query.where(Honeypot.host_id == host_id)
    if profile_id:
        query = query.where(Honeypot.profile_id == profile_id)
    if q:
        query = query.where(Honeypot.name.icontains(q, autoescape=True))
    items = await pot_views(db, (await db.scalars(query)).all())
    return [item for item in items if (not status or item["status"] == status)
            and (not service_key or item["service_key"] == service_key)]


@router.post("/honeypots", status_code=201, summary="Создание ловушки")
async def create_pot(body: InstanceCreate, user=Depends(admin), db=Depends(database)):
    obj = await create_instance(db, user, **body.model_dump())
    await db.commit()
    hub.publish({"type": "status"})
    return await pot_view(db, obj)


class InstanceDraft(InstanceCreate):
    profile_id: str | None = None
    profile: ProfileSpec | None = None


@router.post("/honeypots/validate", summary="Проверка конфигурации ловушки без создания")
async def validate_pot(body: InstanceDraft, user=Depends(admin), db=Depends(database)):
    if body.profile:
        spec, new_profile = body.profile.model_dump(), body.profile.name
    elif body.profile_id:
        spec, new_profile = normalized_spec(await required(db, Profile, body.profile_id)), None
    else:
        raise HTTPException(422, "Укажите существующий профиль или конфигурацию нового профиля")
    return await dry_run(db, body.name, spec, body.overrides, body.host_id, body.port_mode, body.port, body.deploy, new_profile)


@router.get("/honeypots/{identifier}", summary="Сведения о ловушке и её состоянии")
@router.get("/honeypots/{identifier}/health", summary="Сведения о ловушке и её состоянии")
async def pot_detail(identifier: str, user=Depends(current_user), db=Depends(database)):
    obj = await required(db, Honeypot, identifier)
    commands = (await db.scalars(select(Command).where(Command.honeypot_id == identifier).order_by(Command.created_at.desc()).limit(30))).all()
    history = (await db.scalars(select(Deployment).where(Deployment.honeypot_id == identifier).order_by(Deployment.started_at.desc()).limit(20))).all()
    return {**await pot_view(db, obj), "profile": profile_view(await required(db, Profile, obj.profile_id)),
            "host": host_public(await required(db, Host, obj.host_id)),
            "commands": [serialize(c) for c in commands], "deployments": [serialize(d) for d in history]}


@router.get("/honeypots/{identifier}/configuration", summary="Требуемая и применённая конфигурация ловушки")
async def pot_configuration(identifier: str, user=Depends(current_user), db=Depends(database)):
    obj = await required(db, Honeypot, identifier)
    latest = await required(db, Profile, obj.profile_id)
    return {"honeypot_id": obj.id, "profile_id": obj.profile_id, "profile_version": obj.profile_version,
            "profile_latest_version": latest.version, "update_available": latest.version > obj.profile_version,
            "update_policy": obj.update_policy, "overrides": obj.overrides, "configuration": obj.configuration,
            "generation": obj.generation, "applied_generation": obj.applied_generation,
            "applied_profile_version": obj.applied_profile_version,
            "synchronized": obj.generation == obj.applied_generation and obj.status in SETTLED}


@router.get("/honeypots/{identifier}/logs", summary="Журнал операций ловушки")
async def pot_logs(identifier: str, user=Depends(current_user), db=Depends(database)):
    await required(db, Honeypot, identifier)
    rows = (await db.scalars(select(DeploymentLog).where(DeploymentLog.honeypot_id == identifier).order_by(DeploymentLog.id.desc()).limit(200))).all()
    return [serialize(row) for row in rows]


@router.patch("/honeypots/{identifier}", summary="Изменение ловушки, профиля и её собственных настроек")
async def change_pot(identifier: str, body: InstancePatch, user=Depends(operator), db=Depends(database)):
    obj = await required(db, Honeypot, identifier, lock=True)
    profile = None
    if body.profile_id and body.profile_id != obj.profile_id:
        profile = await required(db, Profile, body.profile_id)
        if normalized_spec(profile)["service_type"] != obj.configuration.get("service_type"):
            raise HTTPException(422, "Профиль другого типа сервиса нельзя назначить существующей ловушке. Создайте новую ловушку")
    for key in ("name", "description", "tags", "update_policy"):
        if getattr(body, key) is not None:
            setattr(obj, key, getattr(body, key))
    if profile or body.overrides is not None or body.port is not None:
        await reconfigure(db, obj, user.id, profile=profile, overrides=body.overrides, port=body.port)
    audit(db, user.id, "honeypot.update", obj.id)
    await db.commit()
    hub.publish({"type": "status"})
    return await pot_view(db, obj)


@router.delete("/honeypots/{identifier}", summary="Удаление ловушки и её среды выполнения")
async def delete_pot(identifier: str, force: bool = False, user=Depends(admin), db=Depends(database)):
    obj = await required(db, Honeypot, identifier, lock=True)
    removed = await request_delete(db, obj, user, force)
    await db.commit()
    hub.publish({"type": "status"})
    return {"ok": True, "deleted": removed, "status": "deleted" if removed else "deleting"}


@router.post("/honeypots/{identifier}/deploy", summary="Развёртывание ловушки на её узле")
async def deploy_pot(identifier: str, user=Depends(admin), db=Depends(database)):
    obj = await required(db, Honeypot, identifier, lock=True)
    await request_deploy(db, obj, user)
    await db.commit()
    hub.publish({"type": "status"})
    return await pot_view(db, obj)


@router.post("/honeypots/{identifier}/clone", status_code=201, summary="Создание независимой копии ловушки")
async def clone_pot(identifier: str, body: CloneRequest, user=Depends(admin), db=Depends(database)):
    source = await required(db, Honeypot, identifier)
    obj = await create_instance(db, user, name=body.name, profile_id=source.profile_id,
                                host_id=body.host_id or source.host_id, description=source.description,
                                tags=source.tags, overrides=source.overrides, update_policy=source.update_policy,
                                deploy=body.deploy)
    audit(db, user.id, "honeypot.clone", obj.id, {"source": source.id})
    await db.commit()
    hub.publish({"type": "status"})
    return await pot_view(db, obj)


@router.post("/honeypots/{identifier}/apply-updates", summary="Применение новой версии профиля к ловушке")
async def apply_updates(identifier: str, user=Depends(operator), db=Depends(database)):
    obj = await required(db, Honeypot, identifier, lock=True)
    await reconfigure(db, obj, user.id, reason="honeypot.apply_updates")
    await db.commit()
    hub.publish({"type": "status"})
    return await pot_view(db, obj)


class PublishRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    port: int = Field(ge=1, le=65535)


@router.post("/honeypots/{identifier}/publish", summary="Публикация порта ловушки на интерфейсе узла")
async def publish_pot(identifier: str, body: PublishRequest, user=Depends(admin), db=Depends(database)):
    """The port must be one the host controller itself reports as publishable."""
    obj = await required(db, Honeypot, identifier, lock=True)
    await set_publication(db, obj, user, body.port)
    await db.commit()
    hub.publish({"type": "status"})
    return await pot_view(db, obj)


@router.post("/honeypots/{identifier}/unpublish", summary="Снятие публикации порта ловушки")
async def unpublish_pot(identifier: str, user=Depends(admin), db=Depends(database)):
    obj = await required(db, Honeypot, identifier, lock=True)
    await set_publication(db, obj, user, None)
    await db.commit()
    hub.publish({"type": "status"})
    return await pot_view(db, obj)


@router.post("/honeypots/{identifier}/{operation}", summary="Запуск, остановка или перезапуск ловушки")
async def operate_pot(identifier: str, operation: Literal["start", "stop", "restart"], user=Depends(operator), db=Depends(database)):
    obj = await required(db, Honeypot, identifier)
    await operate(db, obj, operation, user.id)
    await db.commit()
    hub.publish({"type": "status"})
    return await pot_view(db, obj)


@router.get("/deployments", summary="История развёртываний")
async def deployments(user=Depends(current_user), db=Depends(database)):
    return [serialize(d) for d in (await db.scalars(select(Deployment).order_by(Deployment.started_at.desc()).limit(200))).all()]


@router.post("/deployments", status_code=201, summary="Создание и развёртывание ловушки на одобренном узле")
async def create_deployment(body: InstanceCreate, user=Depends(admin), db=Depends(database)):
    obj = await create_instance(db, user, **(body.model_dump() | {"deploy": True}))
    deployment = await db.scalar(select(Deployment).where(Deployment.honeypot_id == obj.id))
    await db.commit()
    hub.publish({"type": "status"})
    return serialize(deployment)


@router.get("/deployments/{identifier}", summary="Сведения о развёртывании")
async def deployment_detail(identifier: str, user=Depends(current_user), db=Depends(database)):
    return serialize(await required(db, Deployment, identifier))


@router.get("/deployments/{identifier}/logs", summary="Журнал шагов развёртывания")
async def deployment_logs(identifier: str, user=Depends(current_user), db=Depends(database)):
    obj = await required(db, Deployment, identifier)
    query = select(DeploymentLog).where(DeploymentLog.honeypot_id == obj.honeypot_id, DeploymentLog.timestamp >= obj.started_at)
    if obj.completed_at:
        query = query.where(DeploymentLog.timestamp <= obj.completed_at + timedelta(seconds=5))
    return [serialize(row) for row in (await db.scalars(query.order_by(DeploymentLog.id).limit(500))).all()]


@router.post("/deployments/{identifier}/cancel", summary="Остановка развёртывания")
async def cancel_deployment(identifier: str, user=Depends(admin), db=Depends(database)):
    obj = await required(db, Deployment, identifier)
    pot = await required(db, Honeypot, obj.honeypot_id)
    await operate(db, pot, "stop", user.id)
    if obj.status == "pending":
        obj.status, obj.completed_at = "cancelled", now()
    audit(db, user.id, "deployment.cancel", identifier)
    await db.commit()
    hub.publish({"type": "status"})
    return serialize(obj)


@router.post("/agents/register", summary="Регистрация агента с аутентификацией")
async def register_agent(agent=Depends(identified_agent), db=Depends(database)):
    if agent.last_seen is None:
        audit(db, 'agent:' + agent.id, 'agent.registration_requested', agent.id)
    agent.last_seen = now()
    await db.commit()
    return {"id": agent.id, "approved": agent.approved and not agent.retired}


class Heartbeat(BaseModel):
    model_config = ConfigDict(extra="forbid")
    honeypot_id: UUID | None = None
    ip_address: IPvAnyAddress | None = None
    profile_version: int = Field(default=0, ge=0)
    agent_version: str = Field(default="1.0", min_length=1, max_length=40)
    generation: int = Field(ge=0)
    attempted_generation: int = Field(default=0, ge=0)
    status: Literal["running", "stopped", "error", "pending"]
    queue_size: int = Field(ge=0)
    error: str | None = Field(default=None, max_length=1000)
    last_delivery: str | None = Field(default=None, max_length=100)


@router.post("/agents/heartbeat", summary="Приём сообщения о состоянии агента")
async def heartbeat(body: Heartbeat, agent=Depends(current_agent), db=Depends(database)):
    agent.last_seen = now()
    agent.version = body.agent_version
    pot = await db.scalar(select(Honeypot).where(Honeypot.id == agent.honeypot_id).with_for_update())
    if not pot or (str(body.honeypot_id) if body.honeypot_id else None) != pot.id:
        raise HTTPException(409, "В сообщении состояния указана другая ловушка. Синхронизируйте конфигурацию агента")
    if body.generation > pot.generation or body.attempted_generation > pot.generation:
        raise HTTPException(409, "Сообщение состояния содержит ещё не назначенное поколение конфигурации")
    settled = body.generation == pot.generation and body.status in SETTLED
    if settled and body.profile_version != pot.profile_version:
        raise HTTPException(409, "Применённая версия профиля не соответствует назначенной конфигурации")
    before = (pot.status, pot.queue_size, pot.error, pot.applied_generation, pot.last_seen is None)
    pot.last_seen = now()
    pot.ip_address = str(body.ip_address) if body.ip_address else None
    pot.queue_size, pot.last_delivery = body.queue_size, body.last_delivery
    pot.applied_generation, pot.applied_profile_version = body.generation, body.profile_version
    failed = body.status == "error" and body.attempted_generation == pot.generation
    if pot.status != "deleting":
        source = "agent:" + agent.id
        if settled:
            if pot.status != body.status:
                record(db, pot, "instance." + body.status)
            set_status(pot, body.status, body.error)
            await complete_commands(db, pot, "completed", actor=source)
        elif failed:
            if pot.status != "failed":
                record(db, pot, "instance.failed", "error", {"error": body.error})
            set_status(pot, "failed", body.error)
            await complete_commands(db, pot, "failed", body.error, actor=source)
    fired = await evaluate_rules(db, pot, "queue_backlog")
    changed = before != (pot.status, pot.queue_size, pot.error, pot.applied_generation, False)
    await db.commit()
    if changed:
        hub.publish({"type": "status"})
    if fired:
        hub.publish({"type": "alert", "honeypot_id": agent.honeypot_id})
    return {"ok": True}


def check_agent(identifier, agent):
    if identifier != agent.id:
        raise HTTPException(403, "Доступ к другому агенту запрещён")


@router.get("/agents/{identifier}/configuration", summary="Получение назначенной конфигурации")
async def configuration(identifier: str, agent=Depends(current_agent), db=Depends(database)):
    check_agent(identifier, agent)
    pot = await db.get(Honeypot, agent.honeypot_id)
    if not pot:
        return {"schema_version": 1, "assigned": False}
    return {"schema_version": 1, "assigned": True, "honeypot_id": pot.id, "generation": pot.generation,
            "profile_version": pot.profile_version,
            "desired_state": "running" if pot.desired_state == "running" else "stopped",
            "spec": pot.configuration}


@router.get("/agents/{identifier}/commands", summary="Команды для агента")
async def agent_commands(identifier: str, agent=Depends(current_agent), db=Depends(database)):
    check_agent(identifier, agent)
    return [serialize(c) for c in (await db.scalars(select(Command).where(
        Command.honeypot_id == agent.honeypot_id, Command.status == "pending"))).all()]


@router.post("/agents/{identifier}/telemetry", summary="Приём пакета телеметрии")
async def telemetry(identifier: str, body: EventBatch, agent=Depends(current_agent), db=Depends(database)):
    check_agent(identifier, agent)
    return await ingest(db, agent, body)


@router.websocket("/ws")
async def websocket(socket: WebSocket):
    if socket.headers.get("origin") != settings().allowed_origin:
        await socket.close(code=1008)
        return
    token = socket.cookies.get("hf_session")
    async with Session() as db:
        if not await resolve_session(db, token):
            await socket.close(code=1008)
            return
    await socket.accept()
    queue = asyncio.Queue(maxsize=100)
    hub.clients.add(queue)
    incoming = asyncio.create_task(socket.receive())
    pending = None
    try:
        await socket.send_json({"type": "connected"})
        while True:
            pending = asyncio.create_task(queue.get())
            done, _ = await asyncio.wait({pending, incoming}, timeout=15, return_when=asyncio.FIRST_COMPLETED)
            if incoming in done:
                received = incoming.result()
                if received["type"] == "websocket.disconnect":
                    break
                incoming = asyncio.create_task(socket.receive())
            message = pending.result() if pending in done else {"type": "heartbeat"}
            if not pending.done():
                pending.cancel()
                await asyncio.gather(pending, return_exceptions=True)
            async with Session() as db:
                if not await resolve_session(db, token):
                    await socket.close(code=1008)
                    break
            await socket.send_json(message)
    except (WebSocketDisconnect, RuntimeError, OSError):
        pass
    finally:
        hub.clients.discard(queue)
        for task in (incoming, pending):
            if task and not task.done():
                task.cancel()
        await asyncio.gather(*(t for t in (incoming, pending) if t), return_exceptions=True)
