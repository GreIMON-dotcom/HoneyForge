"""Сквозная демонстрация динамического конструктора на работающей лаборатории Compose.

Создаёт через API управления три TCP- и три HTTP-ловушки по двум профилям, проверяет
телеметрию каждого экземпляра, жизненный цикл, клонирование, сбой канала управления,
удаление с очисткой среды выполнения, восстановление после перезапуска сервера и изоляцию.
Все события создаёт настоящий трафик тестового клиента; в базу данных ничего не подставляется.

Ключ --keep оставляет созданные экземпляры работать для показа в интерфейсе.
"""
import argparse
import asyncio
import json
import os
import ssl
import subprocess
import sys
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')
import time
from pathlib import Path
from urllib.parse import urlsplit
import httpx
from dotenv import dotenv_values
from websockets.asyncio.client import connect
from isolation import verify_isolation, managed, LABEL

ROOT = Path(__file__).resolve().parents[2]
HOST = 'lab-docker'
step_number = 0


def step(text):
    global step_number
    step_number += 1
    print(f'[{step_number:02d}] {text}', flush=True)


def docker(*args, check=True):
    result = subprocess.run(['docker', *args], cwd=ROOT, capture_output=True, text=True, encoding='utf-8', errors='replace')
    if result.returncode and check:
        print(result.stderr, file=sys.stderr)
        result.check_returncode()
    return result.stdout.strip()


def compose(*args, check=True):
    return docker('compose', *args, check=check)


def probe(kind, alias, port, *extra, check=True):
    """One harmless interaction from the authorized laboratory client container."""
    return compose('--profile', 'demo', 'run', '--rm', 'test-client', kind, alias, str(port), *extra, check=check)


def containers(honeypot_id, role=None):
    filters = ['--filter', f'label={LABEL}honeypot={honeypot_id}']
    if role:
        filters += ['--filter', f'label={LABEL}role={role}']
    return docker('ps', '-aq', *filters).split()


async def wait_for(predicate, timeout=120, what='ожидаемое состояние'):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = await predicate()
        if value:
            return value
        await asyncio.sleep(1)
    raise TimeoutError('Лаборатория не перешла в состояние: ' + what)


async def main(keep):
    secrets = dotenv_values(ROOT / '.env')
    base_url = os.getenv('HONEYFORGE_DEMO_URL', 'https://localhost:8443').rstrip('/')
    address = urlsplit(base_url)
    if address.scheme != 'https' or address.hostname not in {'localhost', '127.0.0.1'} or address.username or address.password or address.path:
        raise ValueError('Для демонстрации требуется адрес лаборатории HTTPS на loopback')
    context = ssl.create_default_context(cafile=str(ROOT / 'infrastructure/certs/ca.crt'))
    step('Сборка и запуск плоскости управления (ловушки в Compose не описаны)')
    await asyncio.to_thread(compose, 'up', '--build', '-d', '--wait', '--remove-orphans')
    created = []
    async with httpx.AsyncClient(base_url=base_url, verify=context, timeout=15, trust_env=False,
                                 headers={'X-HoneyForge': '1', 'Origin': base_url}) as client:
        async def api(method, path, body=None, expected=(200, 201)):
            response = await client.request(method, '/api/v1' + path, json=body)
            if response.status_code not in expected:
                raise RuntimeError(f'{method} {path}: {response.status_code} {response.text[:300]}')
            return response.json()

        async def pot(identifier):
            return await api('GET', '/honeypots/' + identifier)

        async def running(identifiers):
            async def check():
                pots = [p for p in await api('GET', '/honeypots') if p['id'] in identifiers]
                failed = [p for p in pots if p['status'] == 'failed']
                if failed:
                    raise RuntimeError('Развёртывание завершилось ошибкой: ' + str(failed[0]['error']))
                return len(pots) == len(identifiers) and all(p['status'] == 'running' and p['synchronized'] for p in pots)
            await wait_for(check, what='все выбранные ловушки работают и синхронизированы')

        async def events(identifier):
            return (await api('GET', f'/events?honeypot_id={identifier}&page_size=200'))

        step('Вход администратора по TLS с проверкой сертификата лаборатории')
        await api('POST', '/auth/login', {'username': secrets.get('ADMIN_USERNAME', 'admin'), 'password': secrets['ADMIN_PASSWORD']})

        async def controller_ready():
            return any(h['id'] == HOST and h['controller_connected'] for h in await api('GET', '/hosts'))
        await wait_for(controller_ready, what='контроллер узла на связи')
        before = await api('GET', '/honeypots')
        step(f'Текущий состав: ловушек {len(before)}; типы сервисов в каталоге: '
             + ', '.join(s['key'] for s in await api('GET', '/service-types')))
        capacity = await api('GET', f'/hosts/{HOST}/capacity')
        if capacity['available']['instances'] < 7:
            raise RuntimeError('Для демонстрации нужно место для семи ловушек: удалите лишние экземпляры или увеличьте политику узла')

        stamp = time.strftime('%H%M%S')
        step('Создание двух многократно используемых профилей: TCP и HTTP')
        tcp_defaults = (await api('GET', '/service-types/tcp-banner'))['defaults']
        http_defaults = (await api('GET', '/service-types/http-admin'))['defaults']
        tcp_profile = await api('POST', '/profiles', tcp_defaults | {'name': f'Демо TCP {stamp}', 'banner': 'SSH-2.0-Demo_Profile', 'max_input_bytes': 64})
        http_profile = await api('POST', '/profiles', http_defaults | {'name': f'Демо HTTP {stamp}', 'identity': 'Демонстрационный портал'})

        step('Развёртывание трёх экземпляров по TCP-профилю и трёх по HTTP-профилю')
        for profile, kind in ((tcp_profile, 'TCP'), (http_profile, 'HTTP')):
            for number in (1, 2, 3):
                instance = await api('POST', '/honeypots', {'name': f'Демо {kind} {number} · {stamp}', 'profile_id': profile['id'],
                                                           'host_id': HOST, 'tags': ['демонстрация'], 'deploy': True})
                created.append(instance['id'])
        await running(created)
        pots = [await pot(identifier) for identifier in created]
        assert len({p['id'] for p in pots}) == 6 and len({p['agent']['id'] for p in pots}) == 6
        assert len({p['endpoint']['address'] for p in pots}) == 6 and len({p['runtime_identifier'] for p in pots}) == 6
        assert all(len(containers(p['id'])) == 2 for p in pots)
        step('Все шесть экземпляров работают; точки подключения:')
        for p in pots:
            print(f"       {p['name']:<28} {p['endpoint']['address']:<20} IP {p['ip_address']:<12} агент {p['agent']['id']}")

        step('Безвредные подключения тестового клиента к каждому экземпляру (живой канал WebSocket открыт)')
        cookie = 'hf_session=' + client.cookies.get('hf_session')
        live = set()
        async with connect(base_url.replace('https://', 'wss://', 1) + '/api/v1/ws', ssl=context, origin=base_url,
                           additional_headers={'Cookie': cookie}, proxy=None) as ws:
            assert json.loads(await ws.recv())['type'] == 'connected'
            for p in pots:
                kind = 'tcp' if p['service_type'] == 'tcp' else 'http'
                print('       ' + await asyncio.to_thread(probe, kind, p['endpoint']['alias'], p['endpoint']['port']))

            async def all_delivered():
                return all([(await events(identifier))['total'] > 0 for identifier in created])
            await wait_for(all_delivered, what='телеметрия от всех шести экземпляров')
            async with asyncio.timeout(30):
                while live != set(created):
                    message = json.loads(await ws.recv())
                    if message['type'] == 'events':
                        live.add(message['honeypot_id'])
        for p in pots:
            received = await events(p['id'])
            assert {e['destination_port'] for e in received['items']} == {p['endpoint']['port']}, p['name']
        print('       УСПЕШНО: события всех шести экземпляров сохранены в PostgreSQL, отнесены к своим ловушкам и доставлены по WebSocket')
        filtered = await api('GET', f"/events?honeypot_id={pots[3]['id']}&event_type=authentication_attempt")
        assert filtered['total'] == 1
        step(f"Фильтр событий по экземпляру «{pots[3]['name']}» и типу «попытка аутентификации»: {filtered['total']}")

        target = pots[1]
        step(f"Остановка одного экземпляра «{target['name']}»; остальные пять продолжают работать")
        await api('POST', f"/honeypots/{target['id']}/stop")

        async def stopped():
            state = await pot(target['id'])
            return state['status'] == 'stopped' and state['synchronized']
        await wait_for(stopped, what='экземпляр остановлен')
        refused = await asyncio.to_thread(probe, 'tcp', target['endpoint']['alias'], target['endpoint']['port'], check=False)
        assert 'баннер' not in refused
        for p in pots:
            if p['id'] != target['id']:
                await asyncio.to_thread(probe, 'tcp' if p['service_type'] == 'tcp' else 'http', p['endpoint']['alias'], p['endpoint']['port'])
        others = [p for p in await api('GET', '/honeypots') if p['id'] in created and p['id'] != target['id']]
        assert len(others) == 5 and all(p['status'] == 'running' for p in others)

        step('Повторный запуск и изменение собственных настроек экземпляра (профиль и соседи не меняются)')
        await api('POST', f"/honeypots/{target['id']}/restart")
        await running([target['id']])
        await api('PATCH', '/honeypots/' + target['id'], {'overrides': {'banner': 'SSH-2.0-Instance_Override'}})
        await running([target['id']])
        assert 'SSH-2.0-Instance_Override' in await asyncio.to_thread(probe, 'tcp', target['endpoint']['alias'], target['endpoint']['port'])
        assert 'SSH-2.0-Demo_Profile' in await asyncio.to_thread(probe, 'tcp', pots[0]['endpoint']['alias'], pots[0]['endpoint']['port'])

        step('Изменение профиля: экземпляры не обновляются молча, новая версия применяется явно')
        await api('PATCH', '/profiles/' + tcp_profile['id'], tcp_profile['spec'] | {'banner': 'SSH-2.0-Demo_Profile_v2'})
        pending = await pot(pots[0]['id'])
        assert pending['update_available'] and pending['status'] == 'running'
        await api('POST', f"/honeypots/{pots[0]['id']}/apply-updates")
        await running([pots[0]['id']])
        assert 'Demo_Profile_v2' in await asyncio.to_thread(probe, 'tcp', pots[0]['endpoint']['alias'], pots[0]['endpoint']['port'])
        assert 'Demo_Profile_v2' not in await asyncio.to_thread(probe, 'tcp', pots[2]['endpoint']['alias'], pots[2]['endpoint']['port'])

        source = pots[4]
        step(f"Клонирование «{source['name']}»: новый идентификатор, точка подключения, агент и пустая история")
        source_events = (await events(source['id']))['total']
        clone = await api('POST', f"/honeypots/{source['id']}/clone", {'name': f'Демо клон · {stamp}', 'deploy': True})
        created.append(clone['id'])
        await running([clone['id']])
        clone = await pot(clone['id'])
        assert clone['id'] != source['id'] and clone['endpoint']['address'] != source['endpoint']['address']
        assert clone['agent']['id'] != source['agent']['id'] and clone['event_count'] == 0
        await asyncio.to_thread(probe, 'http', clone['endpoint']['alias'], clone['endpoint']['port'])

        async def clone_reported():
            return (await events(clone['id']))['total'] > 0
        await wait_for(clone_reported, what='события клона')
        assert (await events(source['id']))['total'] == source_events
        print(f"       клон: {clone['endpoint']['address']}, агент {clone['agent']['id']}")

        victim = pots[2]
        step(f"Сбой канала управления для «{victim['name']}»: события копятся в очереди и доставляются один раз")

        async def drained():
            return (await pot(victim['id']))['queue_size'] == 0
        await asyncio.sleep(6)
        await wait_for(drained, what='очередь экземпляра пуста')
        baseline = (await events(victim['id']))['total']
        agent = containers(victim['id'], 'agent')[0]
        network = json.loads(docker('inspect', agent))[0]['HostConfig']['NetworkMode']
        await asyncio.to_thread(docker, 'network', 'disconnect', network, agent)
        try:
            await asyncio.to_thread(probe, 'tcp', victim['endpoint']['alias'], victim['endpoint']['port'])
            queued = await asyncio.to_thread(docker, 'exec', agent, 'python', '-c',
                                             "from shared.buffer import DurableBuffer; print(DurableBuffer('/spool/events.db').size())")
            assert int(queued) >= 1
            assert (await events(victim['id']))['total'] == baseline
        finally:
            await asyncio.to_thread(docker, 'network', 'connect', network, agent)

        async def recovered():
            return (await events(victim['id']))['total'] > baseline
        await wait_for(recovered, 150, 'события доставлены после восстановления связи')
        await asyncio.sleep(8)
        delivered = (await events(victim['id']))['total']
        assert delivered == baseline + int(queued), (delivered, baseline, queued)
        unique = await asyncio.to_thread(compose, 'exec', '-T', 'postgres', 'psql', '-U', 'honeyforge', '-d', 'honeyforge', '-tAc',
                                         'SELECT count(*) = count(DISTINCT (agent_id,event_uid)) FROM telemetry_events')
        assert unique.strip() == 't'
        print(f'       в очереди было событий: {queued}; после восстановления доставлены ровно один раз')

        removed = [pots[5], clone]
        step('Удаление двух экземпляров: контейнеры, том очереди и точка подключения освобождаются')
        for p in removed:
            await api('POST', f"/honeypots/{p['id']}/stop")
        for p in removed:
            async def halted(identifier=p['id']):
                return (await pot(identifier))['status'] == 'stopped'
            await wait_for(halted, what='экземпляр остановлен перед удалением')
            assert (await api('DELETE', '/honeypots/' + p['id']))['status'] == 'deleting'
        for p in removed:
            async def gone(identifier=p['id']):
                return (await client.get('/api/v1/honeypots/' + identifier)).status_code == 404
            await wait_for(gone, what='запись удалена после очистки среды выполнения')
            assert not containers(p['id'])
            assert not docker('volume', 'ls', '-q', '--filter', f"label={LABEL}honeypot={p['id']}")
            created.remove(p['id'])
        ports = {e['internal_port'] for e in await api('GET', '/network-endpoints')}
        assert removed[0]['endpoint']['port'] not in ports and clone['endpoint']['port'] not in ports

        step('Согласование: контейнер приманки удалён в обход системы — контроллер восстанавливает его')
        survivor = pots[3]
        old_container = containers(survivor['id'], 'decoy')[0]
        await asyncio.to_thread(docker, 'rm', '-f', old_container)

        async def recreated():
            current = containers(survivor['id'], 'decoy')
            state = await pot(survivor['id'])
            return current and current[0] != old_container and state['status'] == 'running' and state['synchronized']
        await wait_for(recreated, what='контейнер приманки создан заново')

        async def answers():
            return 'главная страница: 200' in await asyncio.to_thread(probe, 'http', survivor['endpoint']['alias'], survivor['endpoint']['port'], check=False)
        await wait_for(answers, 60, 'восстановленный экземпляр отвечает клиенту')

        step('Перезапуск сервера управления: экземпляры обнаруживаются заново, контейнеры не пересоздаются')
        runtime_before = {identifier: containers(identifier) for identifier in created}
        await asyncio.to_thread(compose, 'restart', 'backend')

        async def backend_ready():
            try:
                return (await client.get('/api/v1/ready')).status_code == 200
            except httpx.HTTPError:
                return False
        await wait_for(backend_ready, what='сервер управления готов')
        await asyncio.sleep(10)
        await running(created)
        assert {identifier: containers(identifier) for identifier in created} == runtime_before
        assert (await events(victim['id']))['total'] == delivered

        step('Ограничения ресурсов контейнеров соответствуют конфигурации экземпляров')
        for identifier in created:
            state = await pot(identifier)
            info = json.loads(docker('inspect', containers(identifier, 'decoy')[0]))[0]['HostConfig']
            assert info['Memory'] == state['configuration']['memory_mb'] * 1024 ** 2
            assert info['NanoCpus'] == round(state['configuration']['cpu_limit'] * 1e9)
        capacity = await api('GET', f'/hosts/{HOST}/capacity')
        print(f"       узел: ловушек {capacity['allocated']['instances']} из {capacity['policy']['max_instances']}, "
              f"память {capacity['allocated']['memory_mb']} из {capacity['policy']['memory_budget_mb']} МБ, "
              f"точек подключения {capacity['allocated']['endpoints']}")

        step('Проверка изоляции динамических экземпляров')
        await asyncio.to_thread(verify_isolation, docker, compose)

        audit = (await api('GET', '/audit'))['items']
        step('Последние записи журнала аудита:')
        for row in audit[:8]:
            print(f"       {row['timestamp'][:19]}  {row['actor'][:24]:<24} {row['action']}")
        actions = {row['action'] for page in range(1, 9) for row in (await api('GET', f'/audit?page={page}'))['items']}
        assert {'honeypot.register', 'deployment.create', 'honeypot.clone', 'honeypot.delete', 'agent.provisioned', 'runtime.recovered'} <= actions

        if keep:
            step(f'Экземпляры оставлены для показа в интерфейсе: {len(created)}')
        else:
            step('Очистка: удаление экземпляров и профилей, созданных демонстрацией')
            for identifier in created:
                await api('POST', f'/honeypots/{identifier}/stop')
            for identifier in created:
                async def halted(target_id=identifier):
                    return (await pot(target_id))['status'] == 'stopped'
                await wait_for(halted, what='экземпляр остановлен')
                await api('DELETE', '/honeypots/' + identifier)

            async def cleaned():
                return not [p for p in await api('GET', '/honeypots') if p['id'] in created]
            await wait_for(cleaned, what='экземпляры удалены')
            for profile in (tcp_profile, http_profile):
                await api('DELETE', '/profiles/' + profile['id'])
            assert not any(containers(identifier) for identifier in created)
        remaining = await api('GET', '/honeypots')
        assert {p['id'] for p in before} <= {p['id'] for p in remaining}
        print(f'Демонстрация завершена успешно. Ловушек в лаборатории: {len(remaining)}. Плоскость управления продолжает работать.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--keep', action='store_true', help='не удалять созданные экземпляры')
    asyncio.run(main(parser.parse_args().keep))
