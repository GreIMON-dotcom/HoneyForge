"""Safe TCP/HTTP emulators. No real shell, forwarding, filesystem access, or real accounts.

The Telnet shell is an emulation: every answer comes from a fixed table in
``honeypots.shell`` and no input is ever executed.

One process serves exactly one honeypot instance. Its port, banner, pages and
routes come from the validated configuration its paired agent stored in the
shared spool; nothing instance-specific is compiled into this module.
"""
import asyncio
import contextlib
import json
import os
import socket
import time
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlsplit
from uuid import UUID, uuid4
from shared.buffer import DurableBuffer
from shared.catalog import site_definition
from shared.contracts import ProfileSpec, EventInput, Page, validate_configuration, printable_preview
from .rendering import STYLESHEET, render_page
from .shell import Shell, severity as command_severity

REASONS = {200: "OK", 201: "Created", 302: "Found", 400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
           404: "Not Found", 500: "Internal Server Error", 503: "Service Unavailable"}
USERNAME_FIELDS = ("username", "login", "user", "email")
MAX_SESSIONS = 1024
MAX_PER_SOURCE = 8
IAC, SE, SB, WILL, DO = 255, 240, 250, 251, 253
TELNET_GREETING = bytes([IAC, WILL, 1, IAC, WILL, 3])
MAX_SHELL_BYTES = 65536


class TelnetLine:
    """Bounded line reader that removes Telnet negotiation and echoes what the visitor types."""
    def __init__(self, reader, writer):
        self.reader, self.writer, self.received, self.after_return = reader, writer, 0, False

    async def byte(self) -> int | None:
        data = await self.reader.read(1)
        self.received += len(data)
        if not data or self.received > MAX_SHELL_BYTES:
            return None
        return data[0]

    async def read(self, limit: int, echo: bool = True) -> bytes | None:
        line = bytearray()
        while True:
            value = await self.byte()
            if value is None:
                return None
            if value == IAC:
                command = await self.byte()
                if command is None:
                    return None
                if command == SB:
                    previous = 0
                    while not (previous == IAC and command == SE):
                        previous, command = command, await self.byte()
                        if command is None:
                            return None
                elif WILL <= command <= 254 and await self.byte() is None:
                    return None
                continue
            if value in (10, 0) and self.after_return:
                self.after_return = False
                continue
            self.after_return = value == 13
            if value in (10, 13):
                self.writer.write(b"\r\n")
                return bytes(line)
            if value in (8, 127):
                if line:
                    del line[-1]
                    if echo:
                        self.writer.write(b"\b \b")
            elif 32 <= value < 127 and len(line) < limit:
                line.append(value)
                if echo:
                    self.writer.write(bytes([value]))
            await self.writer.drain()


class Decoy:
    def __init__(self, buffer, spec, honeypot_id):
        self.buffer, self.spec = buffer, spec
        self.honeypot_id = honeypot_id
        self.active = set()
        self.per_source = {}
        self.sessions = {}
        self.broker = None
        if spec.service_type == "http":
            self.pages, routes = site_definition(spec)
            self.routes = {(route.method, route.path): route for route in routes}

    def record(self, peer, session, kind, payload, severity="info"):
        flags = {"connection": self.spec.connection_logging, "data_received": self.spec.connection_logging,
                 "authentication_attempt": self.spec.authentication_logging,
                 "http_request": self.spec.request_logging, "navigation": self.spec.request_logging}
        if not self.spec.telemetry_enabled or not flags[kind]:
            return
        if self.spec.logging_verbosity == 'metadata':
            payload = {'summary': payload.get('summary', kind)}
        event = EventInput(event_uid=uuid4(), honeypot_id=self.honeypot_id, session_id=session, timestamp=datetime.now(timezone.utc),
                           source_ip=peer[0], source_port=peer[1], destination_port=self.spec.port,
                           protocol=self.spec.service_type.upper(), event_type=kind, severity=severity, payload=payload)
        self.buffer.put(event.model_dump(mode="json"), self.spec.buffer_limit)

    async def handle(self, reader, writer):
        task = asyncio.current_task()
        peer = writer.get_extra_info("peername")
        source = peer[0] if peer else ""
        if len(self.active) >= self.spec.max_connections or                 self.per_source.get(source, 0) >= min(MAX_PER_SOURCE, self.spec.max_connections):
            writer.close()
            return
        self.active.add(task)
        self.per_source[source] = self.per_source.get(source, 0) + 1
        try:
            async with asyncio.timeout(self.spec.connection_timeout):
                session = uuid4()
                self.record(peer, session, "connection", {"summary": "Laboratory client connected"})
                await asyncio.sleep(self.spec.response_delay_ms / 1000)
                if self.spec.service_type == "tcp":
                    await self.tcp(reader, writer, peer, session)
                else:
                    await self.http(reader, writer, peer, session)
        except (BufferError, OSError, ValueError, asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError) as exc:
            if not isinstance(exc, (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError)):
                self.buffer.set("capture_error", {"error": type(exc).__name__, "at": time.time()})
        finally:
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()
            self.active.discard(task)
            remaining = self.per_source.get(source, 1) - 1
            if remaining > 0:
                self.per_source[source] = remaining
            else:
                self.per_source.pop(source, None)

    async def shell(self, reader, writer, peer, session):
        """Login dialogue and emulated shell. Input is recorded and answered from a table, never run."""
        spec, lines = self.spec, TelnetLine(reader, writer)
        limit = spec.max_input_bytes or 256

        def send(text):
            writer.write(text.replace("\n", "\r\n").encode("ascii", errors="replace"))

        writer.write(TELNET_GREETING + (spec.banner + "\r\n\r\n").encode(spec.banner_encoding))
        for attempt in range(3):
            send(f"{spec.hostname} login: ")
            await writer.drain()
            username = await lines.read(80)
            if username is None:
                return
            send("Password: ")
            await writer.drain()
            if await lines.read(128, echo=False) is None:
                return
            name = printable_preview(username, 80)
            accepted = bool(name) and (spec.authentication_mode == "accept-all" or name in spec.decoy_accounts)
            self.record(peer, session, "authentication_attempt", {"username": name, "result": "accepted" if accepted else "rejected",
                        "summary": "Telnet login attempt"}, "medium")
            if accepted:
                break
            send("\nLogin incorrect\n")
        else:
            return
        emulated = Shell(spec.hostname, name)
        send(emulated.motd())
        for number in range(spec.max_commands):
            send(emulated.prompt())
            await writer.drain()
            raw = await lines.read(limit)
            if raw is None:
                return
            line = raw.decode("ascii", errors="replace").strip()
            if not line:
                continue
            self.record(peer, session, "data_received", {"summary": "Shell command", "bytes_received": len(raw),
                        "input_preview": printable_preview(raw)}, command_severity(line))
            output, finished = emulated.run(line)
            send(output)
            if finished:
                break
        await writer.drain()

    async def tcp(self, reader, writer, peer, session):
        if self.spec.service_key == 'linux-sandbox':
            from .high import session as sandbox_session
            return await sandbox_session(self, reader, writer, peer, session)
        if self.spec.service_key == "telnet-shell":
            return await self.shell(reader, writer, peer, session)
        writer.write((self.spec.banner + "\r\n").encode(self.spec.banner_encoding))
        await writer.drain()
        if not self.spec.max_input_bytes:
            return
        data = await reader.read(self.spec.max_input_bytes)
        if data:
            self.record(peer, session, "data_received", {"summary": "Laboratory client sent data",
                        "bytes_received": len(data), "input_preview": printable_preview(data)}, "low")

    def authenticated(self, session):
        expires = self.sessions.get(session)
        if expires and expires > time.monotonic():
            return True
        self.sessions.pop(session, None)
        return False

    def open_session(self, session):
        if len(self.sessions) >= MAX_SESSIONS:
            self.sessions.pop(next(iter(self.sessions)))
        self.sessions[session] = time.monotonic() + self.spec.session_timeout

    def values(self):
        return {"{title}": self.spec.identity, "{description}": self.spec.site_description,
                "{account}": self.spec.decoy_accounts[0], "{status}": self.spec.status_message}

    async def http(self, reader, writer, peer, session):
        raw = await reader.readuntil(b"\r\n\r\n")
        if len(raw) > 8192:
            return
        lines = raw.decode("iso-8859-1").split("\r\n")
        method, target, version = lines[0].split(" ")
        if method not in {"GET", "POST"} or version not in {"HTTP/1.0", "HTTP/1.1"}:
            return
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.lower()] = value.strip()
        if "transfer-encoding" in headers:
            return
        length = int(headers.get("content-length", "0"))
        if length < 0 or length > 4096:
            return
        body = await reader.readexactly(length) if length else b""
        path = urlsplit(target).path[:256]
        for part in headers.get("cookie", "").split(";"):
            if part.strip().startswith("lab_session="):
                with contextlib.suppress(ValueError):
                    session = UUID(part.strip().split("=", 1)[1])
        if method == "GET" and path == "/static/site.css":
            return await self.respond(writer, session, 200, "text/css; charset=utf-8", STYLESHEET.encode())
        route = self.routes.get((method, path))
        status, content_type, content, location = 404, "text/html; charset=utf-8", b"", None
        if route is None:
            content = self.simple_page("Страница не найдена")
        elif route.requires_login and not self.authenticated(session):
            if route.response == "json":
                status, content_type, content = 401, "application/json", self.json({"error": "authentication_required"})
            else:
                status, location = 302, self.spec.login_path
        elif route.response == "login":
            status, content_type, content = self.login(route, headers, body, peer, session)
        elif route.response == "json":
            status, content_type, content = route.status, "application/json", self.json(route.json_body)
        else:
            status, content = route.status, self.render(self.pages[route.page])
        if route is None or route.log:
            self.record(peer, session, "http_request", {"method": method, "path": path, "status": status,
                        "summary": f"{method} {path}", "user_agent": headers.get("user-agent", "")[:200]})
        if route is not None and route.log and route.response == "page" and method == "GET" and status == 200 and path != "/":
            self.record(peer, session, "navigation", {"path": path, "summary": "Viewed synthetic page"})
        await self.respond(writer, session, status, content_type, content, location)

    def login(self, route, headers, body, peer, session):
        fields = {}
        if headers.get("content-type", "").startswith("application/json"):
            with contextlib.suppress(ValueError):
                parsed = json.loads(body.decode("utf8", errors="replace"))
                if isinstance(parsed, dict):
                    fields = {str(key): [str(value)] for key, value in list(parsed.items())[:10]}
        else:
            fields = parse_qs(body.decode("utf8", errors="replace"), max_num_fields=10)
        username = next((fields[name][0] for name in USERNAME_FIELDS if fields.get(name)), "")[:80]
        accepted = self.spec.authentication_mode == 'accept-all' or username in self.spec.decoy_accounts
        self.record(peer, session, "authentication_attempt", {"username": username,
                    "result": "simulated_success" if accepted else "simulated_failure",
                    "summary": "Synthetic administration login attempt"}, "medium")
        if accepted:
            self.open_session(session)
        page = route.page if accepted else route.failure_page
        if page:
            return 200, "text/html; charset=utf-8", self.render(self.pages[page])
        if route.page or route.failure_page:
            return (200 if accepted else 401), "text/html; charset=utf-8", self.simple_page(
                "Имитируемый сеанс создан." if accepted else "Тестовый вход отклонён.")
        return (200 if accepted else 401), "application/json", self.json(
            {"authenticated": accepted, "synthetic": True})

    @staticmethod
    def json(value):
        return json.dumps(value, ensure_ascii=False).encode()

    def render(self, page):
        return render_page(page, self.values(), self.spec.site_layout, self.spec.site_footer)

    def simple_page(self, message):
        return self.render(Page.model_validate({"title": "{title}", "components": [
            {"type": "heading", "text": "{title}", "level": 1}, {"type": "paragraph", "text": message}]}))

    async def respond(self, writer, session, status, content_type, content, location=None):
        head = [f"HTTP/1.1 {status} {REASONS[status]}", f"Content-Type: {content_type}",
                f"Content-Length: {len(content)}", "Connection: close",
                f"Set-Cookie: lab_session={session}; HttpOnly; SameSite=Strict; Max-Age={self.spec.session_timeout}",
                "X-Content-Type-Options: nosniff",
                "Content-Security-Policy: default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'"]
        if location:
            head.append("Location: " + location)
        writer.write(("\r\n".join(head) + "\r\n\r\n").encode("iso-8859-1") + content)
        await writer.drain()

    async def close(self):
        for task in tuple(self.active):
            task.cancel()
        if self.active:
            await asyncio.gather(*self.active, return_exceptions=True)
        if self.broker:
            await self.broker.close()


class Supervisor:
    def __init__(self, buffer, service_type, bind_address=None):
        self.buffer, self.service_type = buffer, service_type
        self.bind_address = bind_address
        try:
            self.ip_address = bind_address or socket.gethostbyname(socket.gethostname())
        except OSError:
            self.ip_address = None
        self.server = self.decoy = None
        self.applied = None
        self.generation = 0
        self.status = "stopped"
        self.error = None

    async def listen(self, spec, honeypot_id):
        decoy = Decoy(self.buffer, spec, honeypot_id)
        try:
            if spec.service_key == 'linux-sandbox':
                from .high import Broker
                decoy.broker = Broker()
                await decoy.broker.start()
            server = await asyncio.start_server(decoy.handle, self.bind_address or spec.listen_address, spec.port,
                                                limit=8192, backlog=64)
        except BaseException:
            await decoy.close()
            raise
        self.decoy, self.server = decoy, server

    async def apply(self, config):
        config = validate_configuration(config)
        if config == self.applied:
            return
        if not config.get("assigned"):
            await self.stop()
            self.status, self.generation, self.applied = "stopped", 0, config
            return
        spec = ProfileSpec.model_validate(config["spec"])
        if spec.service_type != self.service_type:
            raise ValueError("Тип сервиса не соответствует образу этого экземпляра")
        desired = config["desired_state"] == "running" and spec.enabled
        old = self.applied
        await self.stop()
        try:
            if desired:
                await self.listen(spec, config["honeypot_id"])
            self.status = "running" if desired else "stopped"
            self.generation, self.applied, self.error = config["generation"], config, None
        except OSError:
            if old and old.get("assigned") and old["desired_state"] == "running":
                await self.listen(ProfileSpec.model_validate(old["spec"]), old["honeypot_id"])
            raise

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            self.server = None
        if self.decoy:
            await self.decoy.close()
            self.decoy = None

    async def tick(self):
        config = self.buffer.get("configuration", {"assigned": False})
        try:
            await self.apply(config)
        except (ValueError, OSError) as exc:
            self.status, self.error = "error", f"Конфигурация отклонена: {type(exc).__name__}"
        capture = self.buffer.get("capture_error", {})
        error = self.error
        if time.time() - capture.get("at", 0) < 30:
            error = "Последняя ошибка записи события: " + capture["error"]
        status = self.status
        if self.decoy and self.decoy.broker and status == 'running' and not (self.decoy.broker.ready.is_set() or self.decoy.broker.in_use):
            status = 'pending'
        self.buffer.set("service_health", {"generation": self.generation, "status": status,
                                           "ip_address": self.ip_address,
                                           "honeypot_id": (self.applied or {}).get("honeypot_id"),
                                           "attempted_honeypot_id": config.get("honeypot_id"),
                                           "profile_version": (self.applied or {}).get("profile_version", 0),
                                           "attempted_generation": config.get("generation", 0),
                                           "connections": len(self.decoy.active) if self.decoy else 0,
                                           "error": error, "at": time.time()})


async def main():
    buffer = DurableBuffer(os.getenv("SPOOL_PATH", "/spool/events.db"))
    service = Supervisor(buffer, os.environ["SERVICE_TYPE"])
    try:
        while True:
            await service.tick()
            await asyncio.sleep(1)
    finally:
        await service.stop()


if __name__ == "__main__":
    asyncio.run(main())
