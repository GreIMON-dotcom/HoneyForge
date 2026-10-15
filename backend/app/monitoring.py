"""Aggregated views of recorded honeypot events: activity over time and source geography.

Everything is computed in the database from stored telemetry. These figures
describe interactions with the decoys only; they are not host or network
traffic measurements, and they contain no byte or packet counts.
"""
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from typing import Literal
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, field_validator
from sqlalchemy import select, func, BigInteger
from .db import database
from .geo import classify, enrich, provider_status
from .models import Event, Honeypot, InteractionSession, now
from .security import current_user
from .services import as_utc
from shared.contracts import EVENT_TYPES

router = APIRouter(prefix="/api/v1")

RANGES = {"15m": (900, 60), "1h": (3600, 60), "6h": (21600, 300), "24h": (86400, 900), "7d": (604800, 3600)}
GEO_RANGES = {"24h": 86400, "7d": 604800, "30d": 2592000, "all": None}
SERIES = ("connection", "authentication_attempt", "http_request")
RATE_WINDOW = 300
SOURCE_LIMIT = 20000


class ActivityFilters(BaseModel):
    range: Literal["15m", "1h", "6h", "24h", "7d"] = "1h"
    honeypot_id: str | None = None
    event_type: Literal[EVENT_TYPES] | None = None
    protocol: Literal["TCP", "HTTP"] | None = None
    source_ip: str | None = None

    @field_validator("source_ip")
    @classmethod
    def valid_ip(cls, value):
        return str(ip_address(value)) if value else None


def filtered(query, filters):
    for key in ("honeypot_id", "event_type", "protocol", "source_ip"):
        value = getattr(filters, key, None)
        if value:
            query = query.where(getattr(Event, key) == value)
    return query


@router.get("/analytics/network-activity", summary="Сетевая активность ловушек по времени")
async def network_activity(filters: ActivityFilters = Query(), user=Depends(current_user), db=Depends(database)):
    length, bucket = RANGES[filters.range]
    moment = now()
    end = int(moment.timestamp()) // bucket * bucket + bucket
    start = end - length
    since = datetime.fromtimestamp(start, timezone.utc)
    seconds = func.extract("epoch", Event.timestamp)
    if db.bind.dialect.name == "postgresql":
        seconds = func.floor(seconds)
    index = (func.cast(seconds, BigInteger) - start) // bucket
    rows = (await db.execute(filtered(select(index, Event.event_type, func.count()).where(Event.timestamp >= since), filters)
                             .group_by(index, Event.event_type))).all()
    buckets = [{"timestamp": datetime.fromtimestamp(start + number * bucket, timezone.utc), "total": 0,
                **dict.fromkeys(SERIES, 0)} for number in range(length // bucket)]
    for number, event_type, count in rows:
        if 0 <= number < len(buckets):
            buckets[number]["total"] += count
            if event_type in SERIES:
                buckets[number][event_type] += count
    scoped = lambda *columns: filtered(select(*columns).where(Event.timestamp >= since), filters)
    unique = await db.scalar(scoped(func.count(func.distinct(Event.source_ip))))
    protocols = (await db.execute(scoped(Event.protocol, func.count()).group_by(Event.protocol).order_by(func.count().desc()))).all()
    types = (await db.execute(scoped(Event.event_type, func.count()).group_by(Event.event_type).order_by(func.count().desc()))).all()
    sources = (await db.execute(scoped(Event.source_ip, func.count(), func.min(Event.timestamp), func.max(Event.timestamp),
                                       func.count(func.distinct(Event.honeypot_id)))
                                .group_by(Event.source_ip).order_by(func.count().desc()).limit(20))).all()
    window = moment - timedelta(seconds=RATE_WINDOW)
    recent = await db.scalar(filtered(select(func.count()).select_from(Event).where(Event.timestamp >= window), filters))
    sessions = select(func.count()).select_from(InteractionSession).where(InteractionSession.ended_at >= window)
    if filters.honeypot_id:
        sessions = sessions.where(InteractionSession.honeypot_id == filters.honeypot_id)
    if filters.source_ip:
        sessions = sessions.where(InteractionSession.source_ip == filters.source_ip)
    totals = {"events": sum(item["total"] for item in buckets), "unique_sources": unique,
              **{key: sum(item[key] for item in buckets) for key in SERIES}}
    return {"range": filters.range, "bucket_seconds": bucket, "from": since, "to": datetime.fromtimestamp(end, timezone.utc),
            "generated_at": moment, "buckets": buckets, "totals": totals,
            "events_per_minute": {"value": round(recent / (RATE_WINDOW / 60), 1), "window_seconds": RATE_WINDOW},
            "active_sessions": {"value": await db.scalar(sessions), "window_seconds": RATE_WINDOW},
            "protocols": [{"label": label, "count": count} for label, count in protocols],
            "event_types": [{"label": label, "count": count} for label, count in types],
            "top_sources": [{"source_ip": source, "count": count, "first_seen": as_utc(first), "last_seen": as_utc(last),
                             "honeypots": pots, "scope": classify(source)} for source, count, first, last, pots in sources]}


@router.get("/analytics/geography", summary="География публичных источников событий")
async def geography(range: Literal["24h", "7d", "30d", "all"] = "7d", honeypot_id: str | None = None,
                    user=Depends(current_user), db=Depends(database)):
    """Country and marker aggregates. Individual addresses are not returned: aggregates are enough for a map."""
    query = select(Event.source_ip, Event.honeypot_id, func.count(), func.max(Event.timestamp)).group_by(Event.source_ip, Event.honeypot_id)
    if GEO_RANGES[range]:
        query = query.where(Event.timestamp >= now() - timedelta(seconds=GEO_RANGES[range]))
    if honeypot_id:
        query = query.where(Event.honeypot_id == honeypot_id)
    rows = (await db.execute(query.order_by(func.count().desc()).limit(SOURCE_LIMIT))).all()
    cache = await enrich(db, [row[0] for row in rows])
    await db.commit()

    def group():
        return {"events": 0, "ips": set(), "honeypots": set(), "last_seen": None}

    def add(target, address, pot, count, last):
        target["events"] += count
        target["ips"].add(address)
        target["honeypots"].add(pot)
        last = as_utc(last)
        if target["last_seen"] is None or last > target["last_seen"]:
            target["last_seen"] = last

    def summary(target):
        return {"events": target["events"], "unique_ips": len(target["ips"]), "honeypots": len(target["honeypots"]),
                "last_seen": target["last_seen"]}

    scopes = {scope: group() for scope in ("public", "private", "loopback", "reserved")}
    located, countries, markers = group(), {}, {}
    for address, pot, count, last in rows:
        info = cache[address]
        add(scopes[info.scope], address, pot, count, last)
        if info.scope != "public" or not info.country_code:
            continue
        add(located, address, pot, count, last)
        country = countries.setdefault(info.country_code, {**group(), "code": info.country_code, "name": info.country_name})
        add(country, address, pot, count, last)
        if info.latitude is None:
            continue
        key = (info.country_code, info.city or "", round(info.latitude, 1), round(info.longitude, 1))
        marker = markers.setdefault(key, {**group(), "country_code": info.country_code, "country": info.country_name,
                                          "city": info.city, "latitude": info.latitude, "longitude": info.longitude})
        add(marker, address, pot, count, last)
    public, known = len(scopes["public"]["ips"]), len(located["ips"])
    newest = max((as_utc(cache[address].enriched_at) for address in cache), default=None)

    def rows_of(items, fields):
        return [{**{field: item[field] for field in fields}, **summary(item)} for item in sorted(items, key=lambda value: -value["events"])]

    return {"range": range, "provider": provider_status(), "enriched_at": newest, "truncated": len(rows) >= SOURCE_LIMIT,
            "sources": {"total": sum(len(item["ips"]) for item in scopes.values()), "public": public, "geolocated": known,
                        "unknown": public - known, "local": len(scopes["private"]["ips"]),
                        "other": len(scopes["loopback"]["ips"]) + len(scopes["reserved"]["ips"])},
            "coverage_percent": round(known / public * 100) if public else None,
            "public": summary(scopes["public"]), "local": summary(scopes["private"]),
            "countries": rows_of(countries.values(), ("code", "name")),
            "markers": rows_of(markers.values(), ("country_code", "country", "city", "latitude", "longitude"))[:300]}
