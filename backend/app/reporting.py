import csv
import io
from datetime import datetime, timedelta
from ipaddress import ip_address
from pathlib import Path
from cryptography import x509
from typing import Literal
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select, func
from .db import database
from .models import *
from .security import current_user, roles
from .services import serialize, required, audit, as_utc, HEALTH_RULES, hub
from .lifecycle import displayed_status
from .geo import provider_status
from shared.contracts import EVENT_TYPES
from .config import settings

router = APIRouter(prefix="/api/v1")
admin = roles("administrator")
operator = roles("administrator", "operator")


class Filters(BaseModel):
    format: Literal["csv", "ioc"] = "csv"
    honeypot_id: str | None = None
    interaction_level: Literal["low", "medium", "high"] | None = None
    protocol: Literal["TCP", "HTTP"] | None = None
    event_type: str | None = None
    source_ip: str | None = None
    severity: Literal["info", "low", "medium", "high", "critical"] | None = None
    start: datetime | None = None
    end: datetime | None = None
    q: str | None = Field(default=None, max_length=100)
    order: Literal["asc", "desc"] = "desc"
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=50, ge=1, le=200)

    @field_validator("source_ip")
    @classmethod
    def ip_filter(cls, value):
        return str(ip_address(value)) if value else value

    @field_validator("start", "end")
    @classmethod
    def aware(cls, value):
        if value and value.tzinfo is None:
            raise ValueError("Фильтры времени должны содержать часовой пояс")
        return value


def event_query(filters):
    query = select(Event).join(Honeypot)
    for key in ["honeypot_id", "protocol", "event_type", "source_ip", "severity"]:
        value = getattr(filters, key)
        if value:
            query = query.where(getattr(Event, key) == value)
    if filters.interaction_level:
        query = query.where(Honeypot.configuration["interaction_level"].as_string() == filters.interaction_level)
    if filters.start:
        query = query.where(Event.timestamp >= filters.start)
    if filters.end:
        query = query.where(Event.timestamp <= filters.end)
    if filters.start and filters.end and filters.start > filters.end:
        raise HTTPException(422, "Начало периода должно предшествовать концу")
    if filters.q:
        query = query.where(Event.payload["summary"].as_string().icontains(filters.q, autoescape=True))
    return query


def event_view(event, user):
    data = serialize(event)
    if user.role == "viewer":
        data["payload"] = {k: v for k, v in event.payload.items() if k in {"summary", "method", "result", "status", "bytes_received"}}
    return data


@router.get("/events/export", summary="Экспорт событий")
async def export_events(filters: Filters = Query(),
                        user=Depends(operator), db=Depends(database)):
    rows = (await db.scalars(event_query(filters).order_by(Event.id.desc()).limit(10000))).all()
    format = filters.format
    audit(db, user.id, "events.export", format, {"rows": len(rows)})
    await db.commit()
    if format == "ioc":
        return {"type": "source_ip_observations", "note": "Наблюдения лаборатории; вредоносность этих индикаторов не подтверждена",
                "values": sorted({e.source_ip for e in rows}), "limit": 10000}
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    fields = ["id", "event_uid", "timestamp", "honeypot_id", "source_ip", "source_port", "destination_port", "protocol", "event_type", "severity"]
    writer.writerow(fields)
    for event in rows:
        values = [str(getattr(event, key)) for key in fields]
        writer.writerow(["'" + v if v.startswith(("=", "+", "-", "@")) else v for v in values])
    return Response(output.getvalue(), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=honeyforge-events.csv"})


@router.get("/events", summary="Поиск и фильтрация событий")
async def events(filters: Filters = Query(), user=Depends(current_user), db=Depends(database)):
    query = event_query(filters)
    total = await db.scalar(select(func.count()).select_from(query.subquery()))
    ordering = Event.id.asc() if filters.order == "asc" else Event.id.desc()
    rows = (await db.scalars(query.order_by(ordering).offset((filters.page - 1) * filters.page_size).limit(filters.page_size))).all()
    return {"items": [event_view(e, user) for e in rows], "total": total, "page": filters.page, "page_size": filters.page_size}


@router.get("/honeypots/{identifier}/events", summary="Последние события ловушки")
async def pot_events(identifier: str, user=Depends(current_user), db=Depends(database)):
    await required(db, Honeypot, identifier)
    return await events(Filters(honeypot_id=identifier), user, db)


@router.get("/events/{identifier}", summary="Подробные сведения о событии")
async def event_detail(identifier: int, user=Depends(current_user), db=Depends(database)):
    return event_view(await required(db, Event, identifier), user)


async def grouped(db, column, limit=20):
    rows = (await db.execute(select(column, func.count()).select_from(Event).group_by(column).order_by(func.count().desc()).limit(limit))).all()
    return [{"label": label, "count": count} for label, count in rows]


@router.get("/analytics/overview", summary="Сводные показатели лаборатории")
async def overview(user=Depends(current_user), db=Depends(database)):
    rows = (await db.scalars(select(Honeypot))).all()
    pots = [{"status": displayed_status(p), "queue_size": p.queue_size} for p in rows]
    total = await db.scalar(select(func.count()).select_from(Event))
    recent = await db.scalar(select(func.count()).select_from(Event).where(Event.received_at >= now() - timedelta(days=1)))
    return {"honeypots": len(pots), "active": sum(p["status"] == "running" for p in pots),
            "offline": sum(p["status"] == "offline" for p in pots),
            "failed": sum(p["status"] == "failed" for p in pots), "drafts": sum(p["status"] == "draft" for p in pots),
            "events": total, "events_24h": recent,
            "unique_sources": await db.scalar(select(func.count(func.distinct(Event.source_ip)))),
            "authentication_attempts": await db.scalar(select(func.count()).select_from(Event).where(Event.event_type == "authentication_attempt")),
            "active_alerts": await db.scalar(select(func.count()).select_from(Alert).where(Alert.status != "resolved")),
            "queue_size": sum(p["queue_size"] for p in pots),
            "connected_agents": await db.scalar(select(func.count()).select_from(Agent).where(Agent.approved.is_(True), Agent.last_seen > now() - timedelta(seconds=settings().heartbeat_timeout))),
            "by_honeypot": await grouped(db, Event.honeypot_id), "by_type": await grouped(db, Event.event_type)}


@router.get("/analytics/protocols", summary="Распределение событий по протоколам")
async def protocols(user=Depends(current_user), db=Depends(database)):
    return await grouped(db, Event.protocol)


@router.get("/analytics/sources", summary="Наиболее активные IP-адреса источников")
async def sources(user=Depends(current_user), db=Depends(database)):
    return await grouped(db, Event.source_ip)


@router.get("/analytics/timeline", summary="Динамика событий по часам или дням")
async def timeline(bucket: Literal["hour", "day"] = "hour",
                   event_type: Literal[EVENT_TYPES] | None = None,
                   user=Depends(current_user), db=Depends(database)):
    end = now().replace(minute=0, second=0, microsecond=0)
    step = timedelta(hours=1) if bucket == "hour" else timedelta(days=1)
    if bucket == "day":
        end = end.replace(hour=0)
    start = end - step * (23 if bucket == "hour" else 29)
    if db.bind.dialect.name == "postgresql":
        key = func.date_trunc(bucket, Event.received_at)
    else:
        key = func.strftime("%Y-%m-%dT%H:00:00" if bucket == "hour" else "%Y-%m-%dT00:00:00", Event.received_at)
    query = select(key, func.count()).where(Event.received_at >= start)
    if event_type:
        query = query.where(Event.event_type == event_type)
    rows = (await db.execute(query.group_by(key))).all()
    values = {as_utc(k if isinstance(k, datetime) else datetime.fromisoformat(k)).isoformat(): n for k, n in rows}
    result = []
    current = start
    while current <= end:
        result.append({"timestamp": current.isoformat(), "count": values.get(current.isoformat(), 0)})
        current += step
    return result


class RuleSpec(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    enabled: bool = True
    honeypot_id: str | None = None
    event_type: Literal[EVENT_TYPES + ("offline", "queue_backlog", "instance_error")]
    threshold: int = Field(ge=1, le=100000)
    window_seconds: int = Field(ge=10, le=86400)
    severity: Literal["info", "low", "medium", "high", "critical"] = "medium"


@router.get("/alerts/rules", summary="Правила оповещений")
async def rules(user=Depends(current_user), db=Depends(database)):
    system_ids = {item[0] for item in HEALTH_RULES.values()}
    return [{**serialize(r), 'system': r.id in system_ids} for r in (await db.scalars(select(AlertRule))).all()]


@router.post("/alerts/rules", status_code=201, summary="Создание правила оповещения")
async def create_rule(body: RuleSpec, user=Depends(admin), db=Depends(database)):
    if body.honeypot_id:
        await required(db, Honeypot, body.honeypot_id)
    obj = AlertRule(**body.model_dump())
    db.add(obj)
    await db.flush()
    audit(db, user.id, "rule.create", obj.id)
    await db.commit()
    return serialize(obj)


@router.patch("/alerts/rules/{identifier}", summary="Изменение правила оповещения")
async def update_rule(identifier: str, body: RuleSpec, user=Depends(admin), db=Depends(database)):
    obj = await required(db, AlertRule, identifier)
    if identifier in {item[0] for item in HEALTH_RULES.values()} and (
            body.event_type != obj.event_type or body.threshold != 1 or body.window_seconds != 60 or body.honeypot_id is not None):
        raise HTTPException(422, 'У системного правила можно менять название, критичность и включение. Условие фиксировано')
    if body.honeypot_id:
        await required(db, Honeypot, body.honeypot_id)
    for key, value in body.model_dump().items():
        setattr(obj, key, value)
    audit(db, user.id, "rule.update", obj.id)
    await db.commit()
    return serialize(obj)


@router.delete("/alerts/rules/{identifier}", summary="Удаление или отключение правила оповещения")
async def delete_rule(identifier: str, user=Depends(admin), db=Depends(database)):
    obj = await required(db, AlertRule, identifier)
    if identifier in {item[0] for item in HEALTH_RULES.values()} or await db.scalar(select(Alert).where(Alert.rule_id == identifier)):
        obj.enabled = False
    else:
        await db.delete(obj)
    audit(db, user.id, "rule.delete_or_disable", identifier)
    await db.commit()
    return {"ok": True}


@router.get("/alerts", summary="История оповещений")
async def alerts(user=Depends(current_user), db=Depends(database)):
    return [serialize(a) for a in (await db.scalars(select(Alert).order_by(Alert.triggered_at.desc()).limit(200))).all()]


@router.get('/alerts/summary', summary='Счётчики по всей истории оповещений')
async def alert_summary(user=Depends(current_user), db=Depends(database)):
    counts = {'open': 0, 'acknowledged': 0, 'resolved': 0}
    for status, count in (await db.execute(select(Alert.status, func.count()).group_by(Alert.status))).all():
        counts[status] = count
    return {**counts, 'total': sum(counts.values()),
            'enabled_rules': await db.scalar(select(func.count()).select_from(AlertRule).where(AlertRule.enabled.is_(True)))}


@router.post("/alerts/{identifier}/{operation}", summary="Подтверждение или решение оповещения")
async def alert_action(identifier: str, operation: Literal["acknowledge", "resolve"], user=Depends(operator), db=Depends(database)):
    obj = await required(db, Alert, identifier)
    obj.status = "acknowledged" if operation == "acknowledge" else "resolved"
    obj.acknowledged_at = now()
    audit(db, user.id, f"alert.{operation}", identifier)
    await db.commit()
    hub.publish({'type': 'status'})
    return serialize(obj)


@router.get("/audit", summary="Журнал аудита")
async def audits(page: int = Query(default=1, ge=1), user=Depends(admin), db=Depends(database)):
    return {"items": [serialize(a) for a in (await db.scalars(select(Audit).order_by(Audit.id.desc()).offset((page-1)*50).limit(50))).all()],
            "total": await db.scalar(select(func.count()).select_from(Audit))}


@router.get("/settings", summary="Настройки и состояние сертификата")
async def system_settings(user=Depends(current_user)):
    cfg = settings()
    certificate = {'certificate_validity': 'not configured'}
    if cfg.tls_certificate_file:
        try:
            public = x509.load_pem_x509_certificate(Path(cfg.tls_certificate_file).read_bytes())
            certificate = {'certificate_validity': 'within validity period' if public.not_valid_before_utc <= now() < public.not_valid_after_utc else 'outside validity period',
                           'certificate_expires_at': public.not_valid_after_utc.isoformat(),
                           'certificate_issuer': public.issuer.rfc4514_string()}
        except (OSError, ValueError):
            certificate = {'certificate_validity': 'unavailable'}
    return {"version": "2.1.0", "retention_days": cfg.retention_days, "heartbeat_timeout": cfg.heartbeat_timeout,
            **certificate,
            "mode": "development-preview" if cfg.database_url.startswith("sqlite") else "postgresql-laboratory",
            "session_hours": cfg.session_hours, "management_origin": cfg.allowed_origin,
            "secure_cookies": cfg.cookie_secure, "operation_timeout": cfg.operation_timeout,
            "geolocation": provider_status()["name"],
            "deployment_mode": "Контроллер узла создаёт изолированные контейнеры ловушек по требуемому состоянию",
            "configuration": "Настраивается через окружение. Для изменения сроков хранения и тайм-аутов перезапустите сервер"}
