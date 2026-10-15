"""No network listener: preflight verifies the read-only gVisor UDS bridge and real capture."""
import asyncio
import base64
import contextlib
import json
import os


async def main():
    result = asyncio.get_running_loop().create_future()

    async def check(reader, writer):
        try:
            for value in ({'kind': 'open', 'seconds': 10},
                          {'kind': 'input', 'data': base64.b64encode(b'printf HF-SANDBOX-PROBE; echo artifact > /home/lab/probe; sleep 1; exit\n').decode()}):
                writer.write((json.dumps(value) + '\n').encode())
            await writer.drain()
            output, kinds = bytearray(), set()
            async with asyncio.timeout(15):
                while raw := await reader.readline():
                    if len(raw) > 6144:
                        raise ValueError('Probe frame limit')
                    value = json.loads(raw)
                    kinds.add(value.get('kind'))
                    if value.get('kind') == 'output':
                        output += base64.b64decode(value.get('data', ''), validate=True)
            if b'HF-SANDBOX-PROBE' not in output or not {'syscall', 'artifact'} <= kinds:
                raise RuntimeError('Shell/capture/UDS probe failed')
            if not result.done():
                result.set_result(True)
        except BaseException as error:
            if not result.done():
                result.set_exception(error)
        finally:
            writer.close()

    with contextlib.suppress(FileNotFoundError):
        os.unlink('/bridge/session.sock')
    server = await asyncio.start_unix_server(check, path='/bridge/session.sock', limit=6145)
    os.chmod('/bridge/session.sock', 0o600)
    try:
        async with server:
            await asyncio.wait_for(result, 20)
    finally:
        server.close()
        await server.wait_closed()


if __name__ == '__main__':
    asyncio.run(main())
