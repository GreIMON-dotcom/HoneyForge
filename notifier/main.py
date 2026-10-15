"""Optional Telegram notifier.

The application server has no route to the Internet by design. This separate
process is the only component that does: it asks the server, over the same
authenticated TLS management channel the agents use, for alerts and honeypot
failures that appeared since its last question, and forwards each as one short
message. A message names the honeypot and the rule and gives counts; it never
contains source addresses, usernames or anything a visitor typed.
"""
import asyncio
import logging
import os
import ssl
from datetime import datetime, timezone
import httpx

log = logging.getLogger("honeyforge.notifier")
SEVERITIES = {"info": "информационная", "low": "низкая", "medium": "средняя", "high": "высокая", "critical": "критическая"}


def message(item: dict) -> str:
    """One notification as plain Russian text."""
    pot = item.get("honeypot_name") or "—"
    if item["kind"] == "alert":
        return (f"⚠️ HoneyForge: сработало правило «{item.get('rule') or '—'}» на ловушке «{pot}». "
                f"Событий: {item.get('count', 0)} за {item.get('window_seconds', 0)} с. "
                f"Критичность: {SEVERITIES.get(item.get('severity'), '—')}.")
    if item["kind"] == "honeypot_offline":
        return f"🔴 HoneyForge: ОПАСНОСТЬ. Ловушка «{pot}» не выходит на связь."
    return f"🔴 HoneyForge: ОПАСНОСТЬ. Ловушка «{pot}» остановилась с ошибкой."


class Notifier:
    def __init__(self, api: httpx.AsyncClient, telegram: httpx.AsyncClient, token: str, chat: str, started: datetime | None = None):
        self.api, self.telegram, self.token, self.chat = api, telegram, token, chat
        self.cursor = started or datetime.now(timezone.utc)
        self.sent = 0

    async def cycle(self) -> int:
        response = await self.api.get("/api/v1/runtime/notifications", params={"since": self.cursor.isoformat()})
        response.raise_for_status()
        delivered = 0
        for item in response.json()["items"]:
            reply = await self.telegram.post(f"/bot{self.token}/sendMessage",
                                             json={"chat_id": self.chat, "text": message(item), "disable_web_page_preview": True})
            if reply.status_code != 200:
                log.warning("Telegram отклонил сообщение: код %s", reply.status_code)
                break
            self.cursor = datetime.fromisoformat(item["at"])
            delivered += 1
        self.sent += delivered
        return delivered

    async def run(self, interval: float):
        while True:
            try:
                await self.cycle()
            except (httpx.HTTPError, KeyError, ValueError) as error:
                log.warning("Цикл уведомлений не выполнен (%s); повтор", type(error).__name__)
            await asyncio.sleep(interval)


async def main(env=os.environ):
    token, chat = env.get("TELEGRAM_BOT_TOKEN", ""), env.get("TELEGRAM_CHAT_ID", "")
    if not token or not chat or not env.get("NOTIFIER_TOKEN"):
        log.warning("Уведомления выключены: не заданы TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID или NOTIFIER_TOKEN")
        while True:
            await asyncio.sleep(3600)
    url = env["MANAGEMENT_URL"]
    if not url.startswith("https://"):
        raise RuntimeError("Для канала управления требуется HTTPS")
    context = ssl.create_default_context(cafile=env["CA_FILE"])
    async with httpx.AsyncClient(base_url=url, verify=context, timeout=15,
                                 headers={"Authorization": "Bearer " + env["NOTIFIER_TOKEN"]}) as api, \
            httpx.AsyncClient(base_url="https://api.telegram.org", timeout=15) as telegram:
        log.info("Уведомления в Telegram включены")
        await Notifier(api, telegram, token, chat).run(float(env.get("NOTIFY_INTERVAL", "15")))


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    asyncio.run(main())
