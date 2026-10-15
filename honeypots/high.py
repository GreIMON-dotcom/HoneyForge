"""Trusted capture gateway for a separate, networkless single-use Linux worker.

Network input is recorded here, outside the worker. Only terminal bytes and
bounded observations cross the socket; no configuration or identity is shared.
"""
import asyncio
import base64
import contextlib
import json
import os
from uuid import UUID
from shared.contracts import printable_preview
from .shell import severity

SOCKET = '/bridge/session.sock'
MAX_FRAME = 6144
MAX_CAPTURE = 262144


class Broker:
    def __init__(self, path=SOCKET):
        self.path, self.server, self.worker, self.in_use = path, None, None, False
        self.ready = asyncio.Event()

    async def start(self):
        with contextlib.suppress(FileNotFoundError):
            os.unlink(self.path)
        self.server = await asyncio.start_unix_server(self.accept, path=self.path, limit=MAX_FRAME + 1)
        os.chmod(self.path, 0o600)

    async def accept(self, reader, writer):
        if self.worker and self.worker[0].at_eof():
            self.worker[1].close()
            self.worker = None
            self.ready.clear()
        if self.worker:
            writer.close()
            return
        self.worker = reader, writer
        self.ready.set()

    async def acquire(self):
        if self.worker and self.worker[0].at_eof():
            self.worker[1].close()
            self.worker = None
            self.ready.clear()
        if self.in_use:
            raise ConnectionError('Sandbox is busy')
        self.in_use = True
        try:
            await asyncio.wait_for(self.ready.wait(), 15)
            self.ready.clear()
            worker, self.worker = self.worker, None
            return worker
        except BaseException:
            self.in_use = False
            raise

    async def close(self):
        if self.worker:
            self.worker[1].close()
            self.worker = None
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        self.ready.clear()
        with contextlib.suppress(FileNotFoundError):
            os.unlink(self.path)


async def session(decoy, reader, writer, peer, uid):
    from .service import TelnetLine, TELNET_GREETING
    spec, lines = decoy.spec, TelnetLine(reader, writer)
    writer.write(TELNET_GREETING + b'Linux sandbox\r\nlogin: ')
    await writer.drain()
    username = await lines.read(80)
    if username is None:
        return
    writer.write(b'Password: ')
    await writer.drain()
    if await lines.read(128, echo=False) is None:
        return
    name = printable_preview(username, 80)
    accepted = bool(name) and (spec.authentication_mode == 'accept-all' or name in spec.decoy_accounts)
    decoy.record(peer, uid, 'authentication_attempt', {'summary': 'Sandbox login attempt', 'username': name,
                 'result': 'accepted' if accepted else 'rejected'}, 'high')
    if not accepted:
        writer.write(b'Login incorrect\r\n')
        return
    sandbox_reader, sandbox_writer = await decoy.broker.acquire()
    total = 0

    async def send(value):
        sandbox_writer.write((json.dumps(value) + '\n').encode())
        await sandbox_writer.drain()

    async def inputs():
        for _ in range(spec.max_commands):
            raw = await lines.read(spec.max_input_bytes or 256)
            if raw is None:
                return
            decoy.record(peer, uid, 'data_received', {'summary': 'Shell command', 'bytes_received': len(raw),
                         'input_preview': printable_preview(raw, 1000)}, severity(raw.decode('ascii', 'replace')))
            for offset in range(0, len(raw), 1024):
                data = raw[offset:offset + 1024]
                decoy.record(peer, uid, 'data_received', {'summary': 'Sandbox input', 'stream': 'input',
                    'data': base64.b64encode(data).decode('ascii'), 'encoding': 'base64', 'bytes_received': len(data)}, 'info')
            await send({'kind': 'input', 'data': base64.b64encode(raw + b'\n').decode('ascii')})

    async def outputs():
        nonlocal total
        frames = 0
        while True:
            raw = await sandbox_reader.readline()
            if not raw:
                return
            if len(raw) > MAX_FRAME:
                raise ValueError('Worker frame limit')
            value = json.loads(raw)
            frames += 1
            if not isinstance(value, dict) or frames > 1024:
                raise ValueError('Worker frame count limit')
            kind = value.get('kind')
            if kind == 'ready':
                continue
            if kind not in {'output', 'syscall', 'artifact', 'artifact_chunk'}:
                raise ValueError('Unexpected worker frame')
            data = base64.b64decode(value.get('data', ''), validate=True)
            if len(data) > 1024:
                raise ValueError('Worker chunk limit')
            total += len(data)
            if total > MAX_CAPTURE:
                raise BufferError('Session capture limit')
            payload = {'summary': 'Sandbox ' + kind, 'stream': kind}
            if data:
                payload.update(data=base64.b64encode(data).decode('ascii'), encoding='base64', bytes_received=len(data))
            if kind.startswith('artifact'):
                path, sha = str(value.get('path', ''))[:300], str(value.get('sha256', ''))
                if len(sha) != 64 or any(c not in '0123456789abcdef' for c in sha):
                    raise ValueError('Invalid artifact digest')
                payload.update(artifact_path=path, sha256=sha, artifact_size=max(0, min(int(value.get('size', 0)), 65536)),
                               offset=max(0, int(value.get('offset', 0))))
            decoy.record(peer, uid, 'data_received', payload, 'high' if kind in {'syscall', 'artifact'} else 'info')
            if kind == 'output':
                writer.write(data)
                await writer.drain()

    tasks = []
    try:
        await send({'kind': 'open', 'session_id': str(uid), 'seconds': spec.connection_timeout})
        tasks = [asyncio.create_task(inputs()), asyncio.create_task(outputs())]
        done, _ = await asyncio.wait(tasks, timeout=spec.connection_timeout, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            task.result()
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        sandbox_writer.close()
        with contextlib.suppress(OSError):
            await sandbox_writer.wait_closed()
        decoy.broker.in_use = False
        decoy.record(peer, uid, 'data_received', {'summary': 'Sandbox session closed; reset required'}, 'info')
