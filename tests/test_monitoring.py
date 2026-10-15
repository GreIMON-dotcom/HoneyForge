"""Network activity and source geography are aggregates of stored telemetry, never invented data."""
import asyncio
from datetime import datetime, timedelta, timezone
import pytest
from sqlalchemy import select, func
from backend.app.config import settings
from backend.app.geo import classify, CsvDatabase
from backend.app.models import SourceGeo
from backend.app.services import hub
from conftest import running_pot
from test_backend import event

ACTIVITY = "/api/v1/analytics/network-activity"
GEOGRAPHY = "/api/v1/analytics/geography"


def at(**ago):
    return (datetime.now(timezone.utc) - timedelta(**ago)).isoformat()


async def send(client, agent, events):
    response = await client.post(f'/api/v1/agents/{agent["X-Agent-ID"]}/telemetry', headers=agent, json={"events": events})
    assert response.status_code == 200, response.text
    return response.json()


@pytest.mark.parametrize("address,scope", [
    ("172.18.0.5", "private"), ("10.1.2.3", "private"), ("192.168.1.1", "private"), ("fd00::1", "private"),
    ("::ffff:10.0.0.1", "private"), ("127.0.0.1", "loopback"), ("::1", "loopback"),
    ("8.8.8.8", "public"), ("2a00:1450:4010::1", "public"),
    ("192.0.2.10", "reserved"), ("198.51.100.7", "reserved"), ("203.0.113.9", "reserved"), ("2001:db8::1", "reserved"),
    ("198.18.0.1", "reserved"), ("100.64.1.1", "reserved"), ("169.254.1.1", "reserved"), ("224.0.0.1", "reserved"),
    ("0.0.0.0", "reserved"), ("240.0.0.1", "reserved"),
])
def test_source_address_classification(address, scope):
    assert classify(address) == scope


async def test_network_activity_buckets_filters_and_definitions(client, controller_headers):
    tcp, _, tcp_agent = await running_pot(client, controller_headers, "tcp-banner", "tcp-sensor")
    web, _, web_agent = await running_pot(client, controller_headers, "http-admin", "web-sensor")
    empty = (await client.get(ACTIVITY)).json()
    assert empty["totals"]["events"] == 0 and len(empty["buckets"]) == 60 and empty["top_sources"] == []
    assert empty["events_per_minute"] == {"value": 0.0, "window_seconds": 300}
    await send(client, tcp_agent, [
        event(honeypot_id=tcp["id"], source_ip="8.8.8.8"),
        event(honeypot_id=tcp["id"], source_ip="8.8.8.8", timestamp=at(minutes=30)),
        event(honeypot_id=tcp["id"], source_ip="172.18.0.9", timestamp=at(hours=3)),
        event(honeypot_id=tcp["id"], source_ip="172.18.0.9", timestamp=at(days=3))])
    web_events = [
        event(honeypot_id=web["id"], protocol="HTTP", destination_port=8080, source_ip="8.8.8.8", event_type="http_request"),
        event(honeypot_id=web["id"], protocol="HTTP", destination_port=8080, source_ip="1.1.1.1", event_type="authentication_attempt"),
        event(honeypot_id=web["id"], protocol="HTTP", destination_port=8080, source_ip="1.1.1.1", event_type="navigation")]
    await send(client, web_agent, web_events)
    assert (await send(client, web_agent, web_events))["inserted"] == 0

    quarter = (await client.get(ACTIVITY, params={"range": "15m"})).json()
    assert quarter["bucket_seconds"] == 60 and len(quarter["buckets"]) == 15
    assert quarter["totals"] == {"events": 4, "unique_sources": 2, "connection": 1, "authentication_attempt": 1, "http_request": 1}
    assert sum(bucket["total"] for bucket in quarter["buckets"][-2:]) == 4
    assert quarter["events_per_minute"]["value"] == 0.8 and quarter["active_sessions"]["value"] == 4
    assert {row["label"]: row["count"] for row in quarter["protocols"]} == {"TCP": 1, "HTTP": 3}
    assert {row["label"]: row["count"] for row in quarter["event_types"]} == {
        "connection": 1, "http_request": 1, "authentication_attempt": 1, "navigation": 1}
    top = {row["source_ip"]: row for row in quarter["top_sources"]}
    assert top["8.8.8.8"]["count"] == 2 and top["8.8.8.8"]["honeypots"] == 2 and top["8.8.8.8"]["scope"] == "public"
    assert top["1.1.1.1"]["count"] == 2 and top["1.1.1.1"]["honeypots"] == 1

    hour = (await client.get(ACTIVITY, params={"range": "1h"})).json()
    assert hour["totals"]["events"] == 5 and hour["totals"]["connection"] == 2
    assert (await client.get(ACTIVITY, params={"range": "6h"})).json()["totals"]["events"] == 6
    day = (await client.get(ACTIVITY, params={"range": "24h"})).json()
    assert day["totals"]["events"] == 6 and day["bucket_seconds"] == 900 and len(day["buckets"]) == 96
    week = (await client.get(ACTIVITY, params={"range": "7d"})).json()
    assert week["totals"]["events"] == 7 and week["totals"]["unique_sources"] == 3 and len(week["buckets"]) == 168
    assert {row["source_ip"]: row["scope"] for row in week["top_sources"]}["172.18.0.9"] == "private"

    only = lambda **params: client.get(ACTIVITY, params={"range": "7d", **params})
    assert (await only(honeypot_id=web["id"])).json()["totals"]["events"] == 3
    assert (await only(protocol="TCP")).json()["totals"]["events"] == 4
    assert (await only(event_type="authentication_attempt")).json()["totals"] == {
        "events": 1, "unique_sources": 1, "connection": 0, "authentication_attempt": 1, "http_request": 0}
    by_source = (await only(source_ip="8.8.8.8")).json()
    assert by_source["totals"]["events"] == 3 and [row["source_ip"] for row in by_source["top_sources"]] == ["8.8.8.8"]
    for invalid in ({"range": "1y"}, {"source_ip": "not-an-ip"}, {"protocol": "UDP"}, {"event_type": "packets"}):
        assert (await client.get(ACTIVITY, params=invalid)).status_code == 422
    assert not {"bytes", "packets", "bandwidth"} & set(str(week).lower().replace("'", " ").replace(":", " ").split())


async def test_live_channel_carries_event_summaries_once(client, controller_headers):
    pot, _, agent = await running_pot(client, controller_headers)
    queue = asyncio.Queue()
    hub.clients.add(queue)
    try:
        batch = [event(honeypot_id=pot["id"], source_ip="172.18.0.4", payload={"summary": "Laboratory client connected", "username": "hidden"})]
        await send(client, agent, batch)
        message = await queue.get()
        assert message["type"] == "events" and len(message["events"]) == 1 and message["ids"] == [message["events"][0]["id"]]
        live = message["events"][0]
        assert live["honeypot_id"] == pot["id"] and live["event_type"] == "connection" and live["source_ip"] == "172.18.0.4"
        assert live["summary"] == "Laboratory client connected" and "username" not in live and "payload" not in live
        await send(client, agent, batch)
        assert queue.empty()
    finally:
        hub.clients.discard(queue)


async def test_geography_without_provider_never_invents_locations(client, controller_headers, factory):
    pot, _, agent = await running_pot(client, controller_headers)
    nothing = (await client.get(GEOGRAPHY)).json()
    assert nothing["sources"]["total"] == 0 and nothing["coverage_percent"] is None and nothing["markers"] == []
    assert nothing["provider"] == {"name": "none", "ready": False, "error": None, "records": 0,
                                   "database_updated_at": None, "attribution": "", "attribution_url": "", "external_requests": False}
    await send(client, agent, [event(honeypot_id=pot["id"], source_ip=address) for address in
                               ("172.18.0.5", "172.18.0.5", "172.18.0.6", "127.0.0.1", "192.0.2.10", "8.8.8.8")])
    data = (await client.get(GEOGRAPHY)).json()
    assert data["sources"] == {"total": 5, "public": 1, "geolocated": 0, "unknown": 1, "local": 2, "other": 2}
    assert data["local"]["events"] == 3 and data["local"]["unique_ips"] == 2 and data["public"]["events"] == 1
    assert data["markers"] == [] and data["countries"] == [] and data["coverage_percent"] == 0
    for address in ("172.18.0.5", "8.8.8.8", "127.0.0.1"):
        assert address not in str(data)
    async with factory() as db:
        stored = {row.ip_address: row for row in (await db.scalars(select(SourceGeo))).all()}
    assert {address: row.scope for address, row in stored.items()} == {
        "172.18.0.5": "private", "172.18.0.6": "private", "127.0.0.1": "loopback", "192.0.2.10": "reserved", "8.8.8.8": "public"}
    assert all(row.country_code is None and row.latitude is None for row in stored.values())
    assert (await client.get(GEOGRAPHY, params={"range": "1y"})).status_code == 422


@pytest.fixture
def local_database(tmp_path, monkeypatch):
    """A tiny local range file in the supported layout, including rows that must be ignored."""
    path = tmp_path / "ranges.csv"
    path.write_text("\n".join([
        "ip_start,ip_end,country",
        "8.8.8.0,8.8.8.255,NA,US,California,Mountain View,37.4,-122.1",
        "1.1.1.0,1.1.1.255,AU",
        "5.255.255.0,5.255.255.255,RU",
        "9.9.9.0,9.9.9.255,ZZ",
        "192.0.2.0,192.0.2.255,FR",
        "172.16.0.0,172.31.255.255,DE",
        "2a00:1450:4010::,2a00:1450:4010:ffff:ffff:ffff:ffff:ffff,IE",
        "broken line",
    ]), encoding="utf-8")
    monkeypatch.setenv("GEOIP_PROVIDER", "csv")
    monkeypatch.setenv("GEOIP_DATABASE", str(path))
    settings.cache_clear()
    yield path
    monkeypatch.undo()
    settings.cache_clear()


async def test_geography_with_local_database(client, controller_headers, factory, local_database):
    database = CsvDatabase(str(local_database), 1000)
    assert database.rows == 7 and database.lookup("8.8.8.8") == ("US", "Mountain View", 37.4, -122.1)
    assert database.lookup("1.1.1.1") == ("AU", None, None, None) and database.lookup("4.4.4.4") is None
    first, _, first_agent = await running_pot(client, controller_headers, name="north")
    second, _, second_agent = await running_pot(client, controller_headers, name="south")
    await send(client, first_agent, [event(honeypot_id=first["id"], source_ip=address) for address in
                                     ("8.8.8.8", "8.8.8.9", "8.8.8.8", "1.1.1.1", "4.4.4.4", "9.9.9.9",
                                      "172.18.0.5", "192.0.2.10", "2a00:1450:4010::5")])
    await send(client, second_agent, [event(honeypot_id=second["id"], source_ip="8.8.8.8"),
                                      event(honeypot_id=second["id"], source_ip="5.255.255.70", timestamp=at(days=10))])
    data = (await client.get(GEOGRAPHY, params={"range": "7d"})).json()
    assert data["provider"]["name"] == "csv" and data["provider"]["ready"] and data["provider"]["records"] == 7
    assert data["provider"]["external_requests"] is False
    assert data["sources"] == {"total": 8, "public": 6, "geolocated": 5, "unknown": 1, "local": 1, "other": 1}
    assert data["coverage_percent"] == 83
    countries = {row["code"]: row for row in data["countries"]}
    assert [row["code"] for row in data["countries"]][0] == "US"
    assert countries["US"]["name"] == "США" and countries["US"]["events"] == 4 and countries["US"]["unique_ips"] == 2
    assert countries["US"]["honeypots"] == 2 and countries["AU"]["name"] == "Австралия" and countries["IE"]["events"] == 1
    assert countries["ZZ"]["name"] == "ZZ" and "FR" not in countries and "DE" not in countries and "RU" not in countries
    markers = {marker["country_code"]: marker for marker in data["markers"]}
    assert markers["US"]["city"] == "Mountain View" and (markers["US"]["latitude"], markers["US"]["longitude"]) == (37.4, -122.1)
    assert markers["US"]["events"] == 4 and markers["US"]["unique_ips"] == 2
    assert (markers["AU"]["latitude"], markers["AU"]["longitude"]) == (-25.3, 133.8) and "ZZ" not in markers
    assert "8.8.8.8" not in str(data) and "172.18.0.5" not in str(data)
    assert (await client.get(GEOGRAPHY, params={"range": "all"})).json()["sources"]["geolocated"] == 6
    only_second = (await client.get(GEOGRAPHY, params={"range": "all", "honeypot_id": second["id"]})).json()
    assert {row["code"]: row["events"] for row in only_second["countries"]} == {"US": 1, "RU": 1}
    async with factory() as db:
        assert await db.scalar(select(func.count()).select_from(SourceGeo).where(SourceGeo.provider == "csv")) == 7
        special = await db.get(SourceGeo, "192.0.2.10")
        assert special.scope == "reserved" and special.country_code is None and special.provider == "none"


async def test_enabling_the_database_later_resolves_earlier_sources(client, controller_headers, tmp_path, monkeypatch):
    pot, _, agent = await running_pot(client, controller_headers)
    await send(client, agent, [event(honeypot_id=pot["id"], source_ip="8.8.8.8")])
    assert (await client.get(GEOGRAPHY)).json()["sources"]["geolocated"] == 0
    path = tmp_path / "ranges.csv"
    path.write_text("8.8.8.0,8.8.8.255,US\n", encoding="utf-8")
    monkeypatch.setenv("GEOIP_PROVIDER", "csv")
    monkeypatch.setenv("GEOIP_DATABASE", str(path))
    settings.cache_clear()
    try:
        assert (await client.get(GEOGRAPHY)).json()["sources"]["geolocated"] == 1
        monkeypatch.setenv("GEOIP_DATABASE", str(tmp_path / "absent.csv"))
        settings.cache_clear()
        broken = (await client.get(GEOGRAPHY)).json()
        assert broken["provider"]["ready"] is False and broken["provider"]["error"] == "unreadable"
        assert broken["sources"]["geolocated"] == 0 and broken["sources"]["unknown"] == 1
    finally:
        monkeypatch.undo()
        settings.cache_clear()


async def test_viewer_sees_aggregates_only(client, controller_headers):
    pot, _, agent = await running_pot(client, controller_headers)
    await send(client, agent, [event(honeypot_id=pot["id"], source_ip="172.18.0.5")])
    await client.post("/api/v1/users", json={"username": "watcher", "password": "watcher-test-only", "role": "viewer"})
    await client.post("/api/v1/auth/login", json={"username": "watcher", "password": "watcher-test-only"})
    assert (await client.get(ACTIVITY)).json()["totals"]["events"] == 1
    assert (await client.get(GEOGRAPHY)).json()["sources"]["local"] == 1
    await client.post("/api/v1/auth/logout")
    assert (await client.get(ACTIVITY)).status_code == 401 and (await client.get(GEOGRAPHY)).status_code == 401


async def test_events_late_in_a_bucket_stay_in_that_bucket(client, controller_headers):
    """Bucket boundaries are exact: the last seconds of an interval must not leak into the next one."""
    pot, _, agent = await running_pot(client, controller_headers)
    minute = int(datetime.now(timezone.utc).timestamp()) // 60 * 60
    stamp = lambda offset: datetime.fromtimestamp(minute + offset, timezone.utc).isoformat()
    await send(client, agent, [event(honeypot_id=pot["id"], timestamp=stamp(-0.1)),
                               event(honeypot_id=pot["id"], timestamp=stamp(-120))])
    data = (await client.get(ACTIVITY, params={"range": "15m"})).json()
    counts = {bucket["timestamp"][:19]: bucket["total"] for bucket in data["buckets"] if bucket["total"]}
    expected = lambda offset: datetime.fromtimestamp(minute + offset, timezone.utc).isoformat()[:19]
    assert counts == {expected(-60): 1, expected(-120): 1} and data["totals"]["events"] == 2
    assert (await client.get(ACTIVITY, params={"range": "7d"})).json()["totals"]["events"] == 2
