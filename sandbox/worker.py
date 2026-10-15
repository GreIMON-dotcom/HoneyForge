"""Single-use Linux shell worker. Runs ONLY in an approved, networkless runsc container.

The gateway owns the Unix socket; this process only connects through a read-only
socket volume. It has no telemetry spool, management address, credentials or host mount.
Every exit is terminal: the controller destroys the container and starts a clean one.
"""
import asyncio
import base64
import contextlib
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import time
import sys

SOCKET = '/bridge/session.sock'
MAX_FRAME = 6144
MAX_SESSION_BYTES = 262144
MAX_ARTIFACT = 65536
WRITABLE = ('/home/lab', '/tmp')


async def frame(reader):
    raw = await reader.readline()
    if not raw or len(raw) > MAX_FRAME:
        raise ConnectionError('Bridge closed or frame too large')
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError('Invalid bridge frame')
    return value


def artifacts(known):
    """Inspect only bounded regular files in the ephemeral workspace; never follow symlinks."""
    result, visited = [], 0
    for root in WRITABLE:
        for directory, names, files, directory_fd in os.fwalk(root, follow_symlinks=False):
            names[:] = sorted(name for name in names if not Path(directory, name).is_symlink())[:16]
            if len(Path(directory).relative_to(root).parts) > 4:
                names[:] = []
            for name in sorted(files)[:64]:
                visited += 1
                if visited > 64:
                    return result
                path = Path(directory, name)
                try:
                    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
                    with os.fdopen(fd, 'rb') as source:
                        info = os.fstat(source.fileno())
                        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_ARTIFACT:
                            continue
                        content = source.read(MAX_ARTIFACT + 1)
                    if len(content) > MAX_ARTIFACT:
                        continue
                    sha = hashlib.sha256(content).hexdigest()
                    if known.get(str(path)) != sha:
                        known[str(path)] = sha
                        result.append((str(path), sha, content))
                except OSError:
                    continue
    return result


async def run_shell(reader, writer, opening):
    import pty
    import termios
    master, slave = pty.openpty()
    tty = termios.tcgetattr(slave)
    tty[3] &= ~(termios.ECHO | termios.ECHONL)
    termios.tcsetattr(slave, termios.TCSANOW, tty)
    trace_read, trace_write = os.pipe()
    os.set_blocking(master, False)
    os.set_blocking(trace_read, False)
    limit = max(1, min(int(opening.get('seconds', 180)), 600))
    env = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': '/home/lab', 'USER': 'lab',
           'LOGNAME': 'lab', 'TERM': 'dumb', 'LANG': 'C.UTF-8', 'PS1': 'lab@sandbox:\\w$ '}
    process = await asyncio.create_subprocess_exec(
        '/usr/bin/strace', '-f', '-qq', '-s', '200', '-e', 'trace=process,network',
        '-o', f'/proc/self/fd/{trace_write}', '/bin/bash', '--noprofile', '--norc', '-i',
        stdin=slave, stdout=slave, stderr=slave, env=env, cwd='/home/lab',
        pass_fds=(trace_write,), start_new_session=True)
    os.close(slave)
    os.close(trace_write)
    total = 0
    send_lock = asyncio.Lock()

    async def send(kind, data=b'', **metadata):
        nonlocal total
        total += len(data)
        if total > MAX_SESSION_BYTES:
            raise BufferError('Session capture limit reached')
        value = {'kind': kind, **metadata}
        if data:
            value['data'] = base64.b64encode(data).decode('ascii')
        async with send_lock:
            writer.write((json.dumps(value, ensure_ascii=True) + '\n').encode())
            await writer.drain()

    async def output(fd, kind):
        while True:
            try:
                data = os.read(fd, 1024)
            except BlockingIOError:
                await asyncio.sleep(.02)
                continue
            except OSError:
                return
            if not data:
                return
            await send(kind, data)

    async def inputs():
        while True:
            value = await frame(reader)
            if value.get('kind') != 'input' or not isinstance(value.get('data'), str):
                raise ValueError('Unexpected bridge request')
            data = base64.b64decode(value['data'], validate=True)
            if len(data) > 4097:
                raise ValueError('Input limit reached')
            while data:
                try:
                    sent = os.write(master, data[:512])
                    data = data[sent:]
                except BlockingIOError:
                    await asyncio.sleep(.02)

    known = {}

    async def scan_files():
        for path, sha, data in await asyncio.to_thread(artifacts, known):
            await send('artifact', path=path[:300], sha256=sha, size=len(data))
            for offset in range(0, len(data), 1024):
                await send('artifact_chunk', data[offset:offset + 1024], path=path[:300], sha256=sha, offset=offset)

    async def files():
        while True:
            await scan_files()
            await asyncio.sleep(.4)

    tasks = [asyncio.create_task(output(master, 'output')), asyncio.create_task(output(trace_read, 'syscall')),
             asyncio.create_task(inputs()), asyncio.create_task(files()), asyncio.create_task(process.wait())]
    try:
        await send('ready')
        done, _ = await asyncio.wait(tasks, timeout=limit, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            task.result()
        if any(task in done for task in (tasks[0], tasks[1], tasks[4])):
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(asyncio.shield(tasks[4]), 1)
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(asyncio.gather(tasks[0], tasks[1]), 1)
            tasks[3].cancel()
            await asyncio.gather(tasks[3], return_exceptions=True)
            await scan_files()
    finally:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        with contextlib.suppress(ProcessLookupError):
            process.kill()
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await process.wait()
        for fd in (master, trace_read):
            os.close(fd)


async def main():
    probe = sys.argv[1:] == ['--self-test']
    if probe:
        process = await asyncio.create_subprocess_exec('/usr/bin/strace', '-f', '-e', 'trace=execve,connect', '/bin/true',
                                                       stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        _, trace = await process.communicate()
        if process.returncode or b'execve(' not in trace or set(os.listdir('/sys/class/net')) - {'lo'}:
            raise RuntimeError('Sandbox isolation or tracing probe failed')
        if os.path.exists('/spool'):
            raise RuntimeError('Telemetry volume must not be visible in worker')
        try:
            Path('/bridge/write-test').write_text('must fail')
        except OSError:
            pass
        else:
            raise RuntimeError('Bridge mount must be read-only')
    deadline = time.monotonic() + 90
    while True:
        try:
            reader, writer = await asyncio.open_unix_connection(SOCKET, limit=MAX_FRAME + 1)
            break
        except (FileNotFoundError, ConnectionRefusedError):
            if time.monotonic() >= deadline:
                raise RuntimeError('Gateway is unavailable')
            await asyncio.sleep(.5)
    try:
        opening = await asyncio.wait_for(frame(reader), timeout=600)
        if opening.get('kind') != 'open':
            raise ValueError('Expected session request')
        await run_shell(reader, writer, opening)
    finally:
        writer.close()
        with contextlib.suppress(OSError):
            await writer.wait_closed()


if __name__ == '__main__':
    asyncio.run(main())
