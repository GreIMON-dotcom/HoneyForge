"""Interpretation of recorded telemetry: period summaries, findings, sessions and source profiles.

Nothing here is inferred beyond what the stored events say. A "finding" is a
named pattern together with its numbers (who, where, how many, when); the
interface turns these fields into a sentence. Usernames, commands and request
paths are details of the events, so observers (the viewer role) do not receive
them here either.
"""
import csv
import io
from datetime import timedelta
from ipaddress import ip_address
from typing import Literal
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import case, func, select
from .db import database
from .geo import classify, enrich
from .lifecycle import displayed_status
from .models import Event, Honeypot, InteractionSession, now
from .reporting import event_view
from .security import current_user, roles
from .services import as_utc, audit

router = APIRouter(prefix="/api/v1")
operator = roles("administrator", "operator")

PERIODS = {"1h": 3600, "24h": 86400, "7d": 604800, "30d": 2592000}
Period = Literal["1h", "24h", "7d", "30d"]
ACCEPTED = ("accepted", "simulated_success")
SHELL_COMMAND = "Shell command"
BRUTE_FORCE_ATTEMPTS = 5
PATH_SCAN_PATHS = 8
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

username = Event.payload["username"].as_string()
outcome = Event.payload["result"].as_string()
path = Event.payload["path"].as_string()
command = Event.payload["input_preview"].as_string()
summary_text = Event.payload["summary"].as_string()


def detailed(user) -> bool:
    return user.role != "viewer"


def valid_address(value: str) -> str:
    try:
        return str(ip_address(value))
    except ValueError:
        raise HTTPException(422, "Некорректный IP-адрес")


def within(query, since=None, until=None, honeypot_id=None, source_ip=None):
    if since is not None:
        query = query.where(Event.timestamp >= since)
    if until is not None:
        query = query.where(Event.timestamp < until)
    if honeypot_id:
        query = query.where(Event.honeypot_id == honeypot_id)
    if source_ip:
        query = query.where(Event.source_ip == source_ip)
    return query


async def counts(db, since, until=None, honeypot_id=None) -> dict:
    """What happened in one period, by kind. Every figure is a count of stored records."""
    scope = dict(since=since, until=until, honeypot_id=honeypot_id)
    types = dict((await db.execute(within(select(Event.event_type, func.count()), **scope).group_by(Event.event_type))).all())
    sessions = select(func.count()).select_from(InteractionSession).where(InteractionSession.started_at >= since)
    if until is not None:
        sessions = sessions.where(InteractionSession.started_at < until)
    if honeypot_id:
        sessions = sessions.where(InteractionSession.honeypot_id == honeypot_id)
    return {"events": sum(types.values()), "connections": types.get("connection", 0),
            "authentication_attempts": types.get("authentication_attempt", 0), "http_requests": types.get("http_request", 0),
            "commands": await db.scalar(within(select(func.count()).select_from(Event).where(
                Event.event_type == "data_received", summary_text == SHELL_COMMAND), **scope)),
            "unique_sources": await db.scalar(within(select(func.count(func.distinct(Event.source_ip))), **scope)),
            "sessions": await db.scalar(sessions)}


async def pot_index(db, identifiers) -> dict:
    rows = (await db.scalars(select(Honeypot).where(Honeypot.id.in_(set(identifiers))))).all() if identifiers else []
    return {pot.id: pot for pot in rows}


async def findings(db, user, since=None, until=None, honeypot_id=None, source_ip=None, limit=20) -> list[dict]:
    """Named patterns found in the events of a period, most serious first."""
    scope = dict(since=since, until=until, honeypot_id=honeypot_id, source_ip=source_ip)
    span = (func.min(Event.timestamp), func.max(Event.timestamp))
    group = (Event.source_ip, Event.honeypot_id)
    found = []

    def add(kind, severity, source, pot, count, first, last, **details):
        first, last = as_utc(first), as_utc(last)
        found.append({"kind": kind, "severity": severity, "source_ip": source, "honeypot_id": pot, "count": count,
                      "first_seen": first, "last_seen": last,
                      "details": {**details, "duration_seconds": int((last - first).total_seconds())}})

    logins = (await db.execute(within(select(*group, func.count(), func.sum(case((outcome.in_(ACCEPTED), 1), else_=0)), *span,
                                             func.count(func.distinct(username)), func.min(username))
                                      .where(Event.event_type == "authentication_attempt"), **scope)
                               .group_by(*group).order_by(func.count().desc()).limit(50))).all()
    for source, pot, attempts, accepted, first, last, names, name in logins:
        accepted = int(accepted or 0)
        if attempts >= BRUTE_FORCE_ATTEMPTS:
            add("brute_force", "high" if accepted or attempts >= 20 else "medium", source, pot, attempts, first, last,
                attempts=attempts, usernames=names, accepted=accepted)
        elif accepted:
            add("login_success", "high", source, pot, accepted, first, last, attempts=attempts,
                username=name if detailed(user) else None)
    risky = (await db.execute(within(select(*group, func.count(), *span).where(
        Event.event_type == "data_received", Event.severity == "high"), **scope)
        .group_by(*group).order_by(func.count().desc()).limit(50))).all()
    for source, pot, number, first, last in risky:
        add("payload_attempt", "high", source, pot, number, first, last, commands=number)
    distinct_paths = func.count(func.distinct(path))
    scans = (await db.execute(within(select(*group, func.count(), distinct_paths, *span).where(
        Event.event_type == "http_request"), **scope)
        .group_by(*group).having(distinct_paths >= PATH_SCAN_PATHS).order_by(distinct_paths.desc()).limit(50))).all()
    for source, pot, requests, paths, first, last in scans:
        add("path_scan", "medium", source, pot, paths, first, last, requests=requests, paths=paths)
    if not honeypot_id:
        targets = func.count(func.distinct(Event.honeypot_id))
        several = (await db.execute(within(select(Event.source_ip, targets, func.count(), *span), **scope)
                                    .group_by(Event.source_ip).having(targets >= 2).order_by(targets.desc()).limit(50))).all()
        for source, pots, events, first, last in several:
            add("multi_target", "low", source, None, pots, first, last, honeypots=pots, events=events)
    found.sort(key=lambda item: (SEVERITY_ORDER[item["severity"]], -item["last_seen"].timestamp()))
    found = found[:limit]
    pots = await pot_index(db, [item["honeypot_id"] for item in found if item["honeypot_id"]])
    places = await enrich(db, [item["source_ip"] for item in found])
    for item in found:
        pot, place = pots.get(item["honeypot_id"]), places[item["source_ip"]]
        item.update(honeypot_name=pot.name if pot else None, service_key=pot.configuration.get("service_key") if pot else None,
                    scope=place.scope, country=place.country_name, country_code=place.country_code)
    return found


async def frequent(db, column, condition, limit=15, **scope) -> list[dict]:
    rows = (await db.execute(within(select(column, func.count()).where(condition, column.is_not(None), column != ""), **scope)
                             .group_by(column).order_by(func.count().desc()).limit(limit))).all()
    return [{"label": label, "count": count} for label, count in rows]


async def frequent_values(db, user, **scope) -> dict:
    """Most frequent usernames, shell commands and request paths. Observers get none of them."""
    if not detailed(user):
        return {"restricted": True, "usernames": [], "commands": [], "paths": []}
    return {"restricted": False,
            "usernames": await frequent(db, username, Event.event_type == "authentication_attempt", **scope),
            "commands": await frequent(db, command, (Event.event_type == "data_received") & (summary_text == SHELL_COMMAND), **scope),
            "paths": await frequent(db, path, Event.event_type == "http_request", **scope)}


@router.get("/analytics/summary", summary="Сводка за период со сравнением с предыдущим и выводами")
async def summary(range: Period = "24h", honeypot_id: str | None = None, user=Depends(current_user), db=Depends(database)):
    length, moment = timedelta(seconds=PERIODS[range]), now()
    since, before = moment - length, moment - 2 * length
    oldest = await db.scalar(select(func.min(Event.timestamp)))
    pots = (await db.scalars(select(Honeypot))).all()
    states = [(pot, displayed_status(pot)) for pot in pots]
    down = [{"id": pot.id, "name": pot.name, "status": status, "since": pot.transition_at or pot.last_seen, "error": pot.error}
            for pot, status in states if status in {"failed", "offline"}]
    sources = (await db.execute(within(select(Event.source_ip, func.count()), since=since, honeypot_id=honeypot_id)
                                .group_by(Event.source_ip).order_by(func.count().desc()).limit(5000))).all()
    places, countries = await enrich(db, [address for address, _ in sources]), {}
    for address, events in sources:
        place = places[address]
        if place.scope == "public" and place.country_code:
            country = countries.setdefault(place.country_code, {"code": place.country_code, "name": place.country_name, "events": 0, "unique_ips": 0})
            country["events"] += events
            country["unique_ips"] += 1
    result = {"range": range, "from": since, "to": moment, "generated_at": moment,
              "current": await counts(db, since, None, honeypot_id), "previous": await counts(db, before, since, honeypot_id),
              "comparable": bool(oldest and as_utc(oldest) <= before),
              "honeypots": {"total": len(pots), "running": sum(status == "running" for _, status in states), "down": down},
              "findings": await findings(db, user, since, None, honeypot_id),
              "countries": sorted(countries.values(), key=lambda item: -item["events"])[:10]}
    await db.commit()
    return result


@router.get("/analytics/top", summary="Самые частые имена пользователей, команды и адреса страниц")
async def top(range: Period = "24h", honeypot_id: str | None = None, user=Depends(current_user), db=Depends(database)):
    since = now() - timedelta(seconds=PERIODS[range])
    return {"range": range, "from": since, **await frequent_values(db, user, since=since, honeypot_id=honeypot_id)}


def session_view(row, pot) -> dict:
    started, ended = as_utc(row.started_at), as_utc(row.ended_at)
    return {"honeypot_id": row.honeypot_id, "session_uid": row.session_uid, "source_ip": row.source_ip,
            "honeypot_name": pot.name if pot else None, "service_key": pot.configuration.get("service_key") if pot else None,
            "started_at": started, "ended_at": ended, "duration_seconds": max(int((ended - started).total_seconds()), 0),
            "event_count": row.event_count}


@router.get("/sessions", summary="Последние сеансы взаимодействия с ловушками")
async def sessions(source_ip: str | None = None, honeypot_id: str | None = None, limit: int = Query(default=30, ge=1, le=100),
                   user=Depends(current_user), db=Depends(database)):
    query = select(InteractionSession)
    if source_ip:
        query = query.where(InteractionSession.source_ip == valid_address(source_ip))
    if honeypot_id:
        query = query.where(InteractionSession.honeypot_id == honeypot_id)
    rows = (await db.scalars(query.order_by(InteractionSession.ended_at.desc()).limit(limit))).all()
    pots = await pot_index(db, [row.honeypot_id for row in rows])
    return [session_view(row, pots.get(row.honeypot_id)) for row in rows]


@router.get("/sessions/{honeypot_id}/{session_uid}", summary="Сеанс: все действия одного подключения по порядку")
async def session_detail(honeypot_id: str, session_uid: str, user=Depends(current_user), db=Depends(database)):
    row = await db.scalar(select(InteractionSession).where(InteractionSession.honeypot_id == honeypot_id,
                                                           InteractionSession.session_uid == session_uid))
    if not row:
        raise HTTPException(404, "Сеанс не найден")
    events = (await db.scalars(select(Event).where(Event.honeypot_id == honeypot_id, Event.session_id == session_uid)
                               .order_by(Event.timestamp, Event.id).limit(500))).all()
    place = (await enrich(db, [row.source_ip]))[row.source_ip]
    await db.commit()
    attempts = [event for event in events if event.event_type == "authentication_attempt"]
    return {**session_view(row, (await pot_index(db, [honeypot_id])).get(honeypot_id)),
            "scope": place.scope, "country": place.country_name, "truncated": len(events) >= 500,
            "outcome": {"login_attempts": len(attempts),
                        "logged_in": any(event.payload.get("result") in ACCEPTED for event in attempts),
                        "commands": sum(event.event_type == "data_received" and event.payload.get("summary") == SHELL_COMMAND for event in events),
                        "requests": sum(event.event_type == "http_request" for event in events),
                        "risky": sum(event.severity in {"high", "critical"} for event in events)},
            "events": [event_view(event, user) for event in events]}


@router.get("/sources/{address}", summary="Карточка адреса источника")
async def source_profile(address: str, user=Depends(current_user), db=Depends(database)):
    address = valid_address(address)
    total, first, last = (await db.execute(select(func.count(), func.min(Event.timestamp), func.max(Event.timestamp))
                                           .where(Event.source_ip == address))).one()
    if not total:
        raise HTTPException(404, "От этого адреса нет записанных событий")
    types = (await db.execute(select(Event.event_type, func.count()).where(Event.source_ip == address)
                              .group_by(Event.event_type).order_by(func.count().desc()))).all()
    touched = (await db.execute(select(Event.honeypot_id, func.count(), func.max(Event.timestamp)).where(Event.source_ip == address)
                                .group_by(Event.honeypot_id).order_by(func.count().desc()))).all()
    pots = await pot_index(db, [pot for pot, _, _ in touched])
    recent = (await db.scalars(select(InteractionSession).where(InteractionSession.source_ip == address)
                               .order_by(InteractionSession.ended_at.desc()).limit(20))).all()
    place = (await enrich(db, [address]))[address]
    result = {"source_ip": address, "scope": place.scope, "country_code": place.country_code, "country": place.country_name,
              "city": place.city, "first_seen": as_utc(first), "last_seen": as_utc(last), "events": total,
              "sessions": await db.scalar(select(func.count()).select_from(InteractionSession).where(InteractionSession.source_ip == address)),
              "event_types": [{"label": label, "count": count} for label, count in types],
              "honeypots": [{"id": pot, "name": pots[pot].name if pot in pots else None,
                             "service_key": pots[pot].configuration.get("service_key") if pot in pots else None,
                             "events": events, "last_seen": as_utc(seen)} for pot, events, seen in touched],
              "findings": await findings(db, user, source_ip=address),
              "recent_sessions": [session_view(row, pots.get(row.honeypot_id)) for row in recent],
              **await frequent_values(db, user, source_ip=address, limit=10)}
    await db.commit()
    return result


@router.get("/export/sources", summary="Экспорт адресов источников для списков блокировки")
async def export_sources(range: Period = "7d", format: Literal["txt", "csv"] = "txt", honeypot_id: str | None = None,
                         user=Depends(operator), db=Depends(database)):
    """Public addresses only: private, loopback and reserved ranges never belong in a block list."""
    since = now() - timedelta(seconds=PERIODS[range])
    rows = (await db.execute(within(select(Event.source_ip, func.count(), func.min(Event.timestamp), func.max(Event.timestamp),
                                           func.count(func.distinct(Event.honeypot_id))), since=since, honeypot_id=honeypot_id)
                             .group_by(Event.source_ip).order_by(func.count().desc()).limit(10000))).all()
    rows = [row for row in rows if classify(row[0]) == "public"]
    places = await enrich(db, [row[0] for row in rows])
    audit(db, user.id, "sources.export", format, {"rows": len(rows), "range": range})
    await db.commit()
    name = f"honeyforge-sources-{range}.{format}"
    if format == "csv":
        output = io.StringIO(newline="")
        writer = csv.writer(output)
        writer.writerow(["source_ip", "events", "first_seen", "last_seen", "honeypots", "country_code"])
        for address, events, first, last, pots in rows:
            writer.writerow([address, events, as_utc(first).isoformat(), as_utc(last).isoformat(), pots, places[address].country_code or ""])
        body, media = output.getvalue(), "text/csv"
    else:
        head = [f"# HoneyForge: адреса, обращавшиеся к ловушкам за период {range}. Сформировано {now().isoformat(timespec='seconds')}",
                "# Это наблюдения ловушек: вредоносность адресов не подтверждена. Проверьте список перед блокировкой.",
                f"# Адресов: {len(rows)}"]
        body, media = "\n".join(head + [row[0] for row in rows]) + "\n", "text/plain; charset=utf-8"
    return Response(body, media_type=media, headers={"Content-Disposition": f"attachment; filename={name}"})
