import asyncio
import logging
import os
import random
import ssl
import time
from datetime import datetime, timezone
import httpx
from shared.buffer import DurableBuffer
from shared.contracts import EventBatch, validate_configuration

log = logging.getLogger("honeyforge.agent")


class AgentClient:
    def __init__(self, buffer, client, agent_id):
        self.buffer, self.client, self.agent_id = buffer, client, agent_id

    async def register(self):
        response = await self.client.post('/api/v1/agents/register')
        response.raise_for_status()

    async def sync(self):
        response = await self.client.get(f"/api/v1/agents/{self.agent_id}/configuration")
        response.raise_for_status()
        config = validate_configuration(response.json())
        previous = self.buffer.get("configuration", {})
        if previous != config:
            self.buffer.set("configuration", config)

    async def transmit(self):
        batch = self.buffer.batch()
        if not batch:
            return
        EventBatch.model_validate({"events": batch})
        response = await self.client.post(f"/api/v1/agents/{self.agent_id}/telemetry", json={"events": batch})
        response.raise_for_status()
        accepted = response.json()["accepted"]
        if not isinstance(accepted, list) or not set(accepted).issubset({e["event_uid"] for e in batch}):
            raise ValueError("Недопустимое подтверждение приёма")
        self.buffer.acknowledge(accepted)
        self.buffer.set("last_delivery", datetime.now(timezone.utc).isoformat())

    async def heartbeat(self):
        service = self.buffer.get("service_health", {})
        stale = time.time() - service.get("at", 0) > 10
        assignment = service.get("attempted_honeypot_id") if service.get("status") == "error" else service.get("honeypot_id")
        applied_to_assignment = assignment == service.get("honeypot_id")
        report = {"generation": service.get("generation", 0) if applied_to_assignment else 0,
                  "ip_address": service.get('ip_address'),
                  "honeypot_id": assignment,
                  "profile_version": service.get("profile_version", 0) if applied_to_assignment else 0,
                  "agent_version": "1.0",
                  "attempted_generation": service.get("attempted_generation", 0),
                  "status": "error" if stale else service.get("status", "pending"),
                  "queue_size": self.buffer.size(),
                  "error": "Нет сообщений о состоянии от процесса управления ловушкой" if stale else service.get("error"),
                  "last_delivery": self.buffer.get("last_delivery")}
        config = self.buffer.get('configuration', {})
        if config.get('assigned') and not service:
            report.update(honeypot_id=config['honeypot_id'], attempted_generation=config['generation'],
                          status='pending', error='Ожидание процесса управления ловушкой')
        response = await self.client.post("/api/v1/agents/heartbeat", json=report)
        response.raise_for_status()

    async def run(self):
        failures = {"register": 0, "sync": 0, "transmit": 0, "heartbeat": 0}
        deadlines = dict.fromkeys(failures, 0.0)
        while True:
            config = self.buffer.get("configuration", {}).get("spec", {})
            for name in failures:
                if time.monotonic() < deadlines[name]:
                    continue
                try:
                    await getattr(self, name)()
                    failures[name] = 0
                except (httpx.HTTPError, ValueError, OSError) as exc:
                    failures[name] += 1
                    log.warning("Ошибка операции управления %s (%s); события остаются в очереди", name, type(exc).__name__)
                interval = config.get("batch_interval", 3) if name == "transmit" else config.get("health_interval", 5)
                delay = interval if not failures[name] else min(config.get("retry_max_seconds", 30), 2 ** min(failures[name], 7)) + random.random()
                deadlines[name] = time.monotonic() + delay
            self.buffer.set("agent_health", {"at": time.time(), "connected": not any(failures.values()),
                                             "failed_operations": [k for k, v in failures.items() if v]})
            await asyncio.sleep(0.5)


async def main():
    base = os.environ["MANAGEMENT_URL"]
    if not base.startswith("https://"):
        raise RuntimeError("Для канала управления требуется HTTPS")
    agent_id, token = os.environ["AGENT_ID"], os.environ["AGENT_TOKEN"]
    if os.getenv("CA_PEM"):
        context = ssl.create_default_context(cadata=os.environ["CA_PEM"])
    else:
        context = ssl.create_default_context(cafile=os.environ["CA_FILE"])
    buffer = DurableBuffer(os.getenv("SPOOL_PATH", "/spool/events.db"))
    async with httpx.AsyncClient(base_url=base, verify=context, timeout=10,
                                 headers={"X-Agent-ID": agent_id, "Authorization": f"Bearer {token}"}) as client:
        await AgentClient(buffer, client, agent_id).run()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
