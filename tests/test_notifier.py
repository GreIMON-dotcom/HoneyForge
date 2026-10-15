"""The notifier forwards alerts and honeypot failures, once each, without visitor data."""
import json
import os
from datetime import datetime, timedelta, timezone
import httpx
import pytest
from sqlalchemy import update
from backend.app.config import settings
from backend.app.main import app
from backend.app.models import Honeypot
from backend.app.services import maintenance_once
from conftest import running_pot
from notifier.main import Notifier, message
from test_backend import event

TOKEN = "notifier-test-token"
ENDPOINT = "/api/v1/runtime/notifications"


@pytest.fixture
def notifier_token(monkeypatch):
    monkeypatch.setenv("NOTIFIER_TOKEN", TOKEN)
    settings.cache_clear()
    yield {"Authorization": "Bearer " + TOKEN}
    monkeypatch.delenv("NOTIFIER_TOKEN")
    settings.cache_clear()


class FakeTelegram:
    def __init__(self):
        self.messages, self.status = [], 200

    def handle(self, request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/bot123:test/sendMessage"
        if self.status == 200:
            self.messages.append(json.loads(request.content))
        return httpx.Response(self.status, json={"ok": self.status == 200})


async def test_notification_endpoint_is_closed_without_its_own_secret(client, controller_headers):
    since = {"since": datetime.now(timezone.utc).isoformat()}
    assert (await client.get(ENDPOINT, params=since)).status_code == 401
    assert (await client.get(ENDPOINT, params=since, headers=controller_headers)).status_code == 401
    assert (await client.get(ENDPOINT, params=since, headers={"Authorization": "Bearer "})).status_code == 401


async def test_notifier_sends_each_alert_and_failure_once(client, controller_headers, factory, notifier_token):
    pot, _, agent = await running_pot(client, controller_headers, "tcp-banner", "edge")
    rule = await client.post("/api/v1/alerts/rules", json={"name": "Много входов", "event_type": "authentication_attempt",
                                                           "threshold": 2, "window_seconds": 300, "severity": "high"})
    assert rule.status_code == 201, rule.text
    assert (await client.get(ENDPOINT, params={"since": "2026-01-01T00:00:00"}, headers=notifier_token)).status_code == 422
    assert (await client.get(ENDPOINT, params={"since": datetime.now(timezone.utc).isoformat()},
                             headers={"Authorization": "Bearer wrong"})).status_code == 401

    telegram = FakeTelegram()
    started = datetime.now(timezone.utc) - timedelta(seconds=1)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test", headers=notifier_token) as api, \
            httpx.AsyncClient(transport=httpx.MockTransport(telegram.handle), base_url="https://api.telegram.org") as bot:
        worker = Notifier(api, bot, "123:test", "42", started)
        assert await worker.cycle() == 0 and telegram.messages == []

        attempts = [event(honeypot_id=pot["id"], source_ip="8.8.8.8", event_type="authentication_attempt", severity="medium",
                          payload={"username": "secret-user", "result": "rejected", "summary": "login"}) for _ in range(3)]
        sent = await client.post(f'/api/v1/agents/{agent["X-Agent-ID"]}/telemetry', headers=agent, json={"events": attempts})
        assert sent.status_code == 200
        assert await worker.cycle() == 1
        text = telegram.messages[0]["text"]
        assert telegram.messages[0]["chat_id"] == "42" and "Много входов" in text and "«edge»" in text and "высокая" in text
        assert "8.8.8.8" not in text and "secret-user" not in text

        async with factory() as db:
            await db.execute(update(Honeypot).where(Honeypot.id == pot["id"]).values(last_seen=datetime.now(timezone.utc) - timedelta(hours=1)))
            await db.commit()
            await maintenance_once(db)
        telegram.status = 500
        assert await worker.cycle() == 0
        telegram.status = 200
        assert await worker.cycle() == 1 and await worker.cycle() == 0
        assert "ОПАСНОСТЬ" in telegram.messages[1]["text"] and "не выходит на связь" in telegram.messages[1]["text"]
        assert len(telegram.messages) == 2 and worker.sent == 2


def test_messages_are_plain_russian_sentences():
    assert "остановилась с ошибкой" in message({"kind": "honeypot_failed", "honeypot_name": "web"})
    text = message({"kind": "alert", "honeypot_name": "web", "rule": "Правило", "count": 7, "window_seconds": 60, "severity": "medium"})
    assert text.endswith("Критичность: средняя.") and "Событий: 7 за 60 с." in text
