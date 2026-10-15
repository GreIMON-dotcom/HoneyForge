"""Shared transactional helpers, telemetry ingestion, alert rules and background maintenance."""
from datetime import timezone, timedelta
from fastapi import HTTPException
from sqlalchemy import select, func, delete, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from .models import *
from .config import settings
from .security import digest, password_hash
from shared.contracts import ProfileSpec


def serialize(obj):
    return {c.name: getattr(obj, c.name) for c in obj.__table__.columns}


def audit(db, actor, action, resource, details=None, result="success"):
    db.add(Audit(actor=actor, action=action, resource=str(resource), details=details or {}, result=result))


async def required(db, model, identifier, lock=False):
    obj = await db.scalar(select(model).where(model.id == identifier).with_for_update()) if lock else await db.get(model, identifier)
    if not obj:
        raise HTTPException(404, "Ресурс не найден")
    return obj


def as_utc(value):
    return value.replace(tzinfo=timezone.utc) if value and value.tzinfo is None else value


async def bootstrap(db):
    """First-start records: the administrator, the laboratory host and template profiles."""
    from shared.catalog import PLUGINS
    cfg = settings()
    if not await db.scalar(select(User).limit(1)):
        if len(cfg.admin_password) < 12:
            raise RuntimeError("При первом запуске ADMIN_PASSWORD должен содержать не менее 12 символов")
        db.add(User(username=cfg.admin_username, password_hash=password_hash(cfg.admin_password), role="administrator"))
    if cfg.bootstrap_lab:
        if cfg.controller_token:
            if len(cfg.controller_token) < 32:
                raise RuntimeError("CONTROLLER_TOKEN должен содержать не менее 32 символов")
            host = await db.get(Host, cfg.controller_host_id)
            if not host:
                host = Host(id=cfg.controller_host_id, name="Локальный узел лаборатории", approved=True,
                            management_address="controller", provisioning="controller")
                db.add(host)
            host.controller_token_hash = digest(cfg.controller_token)
        if not await db.scalar(select(Profile.id).limit(1)):
            names = {"linux-sandbox": "Реальная оболочка на отдельном узле", "tcp-banner": "Лабораторный профиль TCP", "http-admin": "Лабораторный профиль HTTP",
                     "http-site": "Шаблон HTTP-сайта", "http-api": "Шаблон HTTP API",
                     "telnet-shell": "Шаблон Telnet-оболочки", "http-store": "Шаблон интернет-магазина",
                     "http-portal": "Шаблон портала сотрудников"}
            for key, plugin in PLUGINS.items():
                spec = plugin.default_spec(names[key])
                db.add(Profile(name=spec["name"], spec=spec))
    for pot in (await db.scalars(select(Honeypot))).all():
        complete = ProfileSpec.model_validate(pot.configuration).model_dump()
        if complete != pot.configuration:
            pot.configuration = complete
    await db.commit()


class Hub:
    """Bounded per-client queues. Persisted history is the source of truth."""
    def __init__(self):
        self.clients = set()

    def publish(self, message):
        for queue in tuple(self.clients):
            if queue.full():
                queue.get_nowait()
            queue.put_nowait(message)


hub = Hub()

HEALTH_RULES = {
    'offline': ('e4bd219e-02db-4c81-9e43-98cc829aaa01', 'Ловушка потеряла связь', 'high'),
    'failed': ('e4bd219e-02db-4c81-9e43-98cc829aaa02', 'Ловушка остановилась с ошибкой', 'critical'),
}


async def sync_health_alerts(db):
    """Persist one availability incident per honeypot; automatically resolve it on recovery.

    These are state conditions, not a stream of repeated events. Acknowledgment does not
    resolve a fault, and an unresolved fault must not create a fresh alert every minute.
    """
    from .lifecycle import displayed_status
    changed, fired = False, 0
    for status, (identifier, name, severity) in HEALTH_RULES.items():
        rule = await db.get(AlertRule, identifier)
        if not rule:
            rule = AlertRule(id=identifier, name=name, event_type='offline' if status == 'offline' else 'instance_error',
                             threshold=1, window_seconds=60, severity=severity, enabled=True)
            db.add(rule)
            await db.flush()
        pots = (await db.scalars(select(Honeypot))).all()
        active = (await db.scalars(select(Alert).where(Alert.rule_id == identifier, Alert.status != 'resolved'))).all()
        by_pot = {alert.honeypot_id: alert for alert in active}
        for pot in pots:
            condition = displayed_status(pot) == status
            previous = by_pot.get(pot.id)
            if not condition and not previous:
                last = await db.scalar(select(Alert).where(Alert.rule_id == identifier, Alert.honeypot_id == pot.id)
                                       .order_by(Alert.triggered_at.desc()).limit(1))
                if last and not last.details.get('recovered_at'):
                    last.details = {**last.details, 'recovered_at': now().isoformat()}
            if previous and not condition:
                previous.status = 'resolved'
                previous.details = {**previous.details, 'recovered_at': now().isoformat()}
                changed = True
            elif condition and rule.enabled and (not rule.honeypot_id or rule.honeypot_id == pot.id) and not previous:
                last = await db.scalar(select(Alert).where(Alert.rule_id == identifier, Alert.honeypot_id == pot.id)
                                       .order_by(Alert.triggered_at.desc()).limit(1))
                fingerprint = f'{status}:{pot.generation}:{pot.error or ""}'
                if last and last.details.get('fingerprint') == fingerprint and not last.details.get('recovered_at'):
                    continue
                db.add(Alert(rule_id=identifier, honeypot_id=pot.id, severity=rule.severity,
                             details={'rule': rule.name, 'count': 1, 'window_seconds': rule.window_seconds,
                                      'event_ids': [], 'system': True, 'condition': status,
                                      'fingerprint': fingerprint, 'error': pot.error}))
                changed, fired = True, fired + 1
    return changed, fired


async def evaluate_rules(db, pot, event_type, event_ids=None):
    """Create deduplicated alerts for matching rules; returns how many fired."""
    rules = (await db.scalars(select(AlertRule).where(AlertRule.enabled.is_(True),
                                                   AlertRule.event_type == event_type).with_for_update())).all()
    fired = 0
    for rule in rules:
        if rule.id in {item[0] for item in HEALTH_RULES.values()}:
            continue
        if rule.honeypot_id and rule.honeypot_id != pot.id:
            continue
        cutoff = now() - timedelta(seconds=rule.window_seconds)
        if event_type == "offline":
            count = 1
        elif event_type == "queue_backlog":
            count = pot.queue_size
        else:
            count = await db.scalar(select(func.count()).select_from(Event).where(
                Event.honeypot_id == pot.id, Event.event_type == event_type, Event.received_at >= cutoff))
        existing = await db.scalar(select(Alert).where(Alert.rule_id == rule.id, Alert.honeypot_id == pot.id,
                                                      Alert.triggered_at >= cutoff))
        if count >= rule.threshold and not existing:
            db.add(Alert(rule_id=rule.id, honeypot_id=pot.id, severity=rule.severity,
                         details={"rule": rule.name, "count": count, "window_seconds": rule.window_seconds,
                                  "event_ids": (event_ids or [])[-20:]}))
            fired += 1
    return fired


async def ingest(db, agent, batch):
    await db.execute(select(Agent).where(Agent.id == agent.id).with_for_update())
    pot = await db.scalar(select(Honeypot).where(Honeypot.id == agent.honeypot_id).with_for_update())
    if not pot:
        raise HTTPException(409, "Агенту не назначена ловушка")
    if any(str(event.honeypot_id) != pot.id for event in batch.events):
        raise HTTPException(409, "Пакет содержит события, записанные для другой назначенной ловушки")
    insert = pg_insert if db.bind.dialect.name == "postgresql" else sqlite_insert
    accepted, added, live = [], [], []
    for event in batch.events:
        values = event.model_dump(mode="json")
        values["timestamp"] = event.timestamp
        values.update(honeypot_id=pot.id, agent_id=agent.id)
        result = await db.execute(insert(Event).values(**values).on_conflict_do_nothing(
            index_elements=["agent_id", "event_uid"]).returning(Event.id))
        event_id = result.scalar_one_or_none()
        accepted.append(str(event.event_uid))
        if event_id is None:
            continue
        added.append(event_id)
        live.append({"id": event_id, "timestamp": event.timestamp.isoformat(), "honeypot_id": pot.id,
                     "event_type": event.event_type, "protocol": event.protocol, "severity": event.severity,
                     "source_ip": event.source_ip, "source_port": event.source_port,
                     "destination_port": event.destination_port, "summary": str(event.payload.get("summary", ""))[:200]})
        await db.execute(insert(InteractionSession).values(honeypot_id=pot.id, session_uid=str(event.session_id),
            source_ip=event.source_ip, started_at=event.timestamp, ended_at=event.timestamp, event_count=0
        ).on_conflict_do_nothing(index_elements=["honeypot_id", "session_uid"]))
        await db.execute(update(InteractionSession).where(InteractionSession.honeypot_id == pot.id,
            InteractionSession.session_uid == str(event.session_id)).values(
                event_count=InteractionSession.event_count + 1, ended_at=event.timestamp))
    await db.flush()
    fired = 0
    if added:
        from .geo import enrich
        await enrich(db, [item["source_ip"] for item in live])
        for event_type in {e.event_type for e in batch.events}:
            fired += await evaluate_rules(db, pot, event_type, added)
    name = pot.name
    await db.commit()
    if added:
        hub.publish({"type": "events", "ids": added, "honeypot_id": agent.honeypot_id, "events": live[-50:]})
    if fired:
        hub.publish({"type": "alert", "honeypot_id": agent.honeypot_id, "name": name})
    return {"accepted": accepted, "inserted": len(added)}


async def maintenance_once(db):
    from .lifecycle import TRANSITIONAL, SETTLED, set_status, complete_commands, record
    changed, fired = False, 0
    cutoff = now() - timedelta(seconds=settings().heartbeat_timeout)
    pots = (await db.scalars(select(Honeypot).where(Honeypot.last_seen < cutoff, Honeypot.status.in_(SETTLED)))).all()
    for pot in pots:
        pot.status = "offline"
        audit(db, "system", "honeypot.offline", pot.id)
        record(db, pot, "instance.offline", "warning")
        fired += await evaluate_rules(db, pot, "offline")
        changed = True
    deadline = now() - timedelta(seconds=settings().operation_timeout)
    stuck = (await db.scalars(select(Honeypot).where(Honeypot.status.in_(TRANSITIONAL), Honeypot.transition_at < deadline))).all()
    for pot in stuck:
        message = "Операция не подтверждена за отведённое время. Проверьте контроллер узла и агента ловушки"
        record(db, pot, "operation.timeout", "error", {"state": pot.status})
        set_status(pot, "failed", message)
        await complete_commands(db, pot, "failed", message)
        audit(db, "system", "honeypot.operation_timeout", pot.id, result="failed")
        changed = True
    health_changed, health_fired = await sync_health_alerts(db)
    changed, fired = changed or health_changed, fired + health_fired
    retention = now() - timedelta(days=settings().retention_days)
    await db.execute(delete(Event).where(Event.received_at < retention))
    await db.execute(delete(InteractionSession).where(InteractionSession.ended_at < retention))
    await db.execute(delete(DeploymentLog).where(DeploymentLog.timestamp < retention))
    await db.execute(delete(LoginSession).where(LoginSession.expires_at < now()))
    await db.commit()
    if changed:
        hub.publish({"type": "status"})
    if fired:
        hub.publish({"type": "alert"})
