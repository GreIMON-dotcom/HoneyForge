"""Verify the running lab's boundaries for dynamically created instances, using only its own addresses."""
import json

LABEL = 'io.honeyforge.'

TCP_PROBE = '''
import json, socket, sys
targets = json.loads(sys.argv[1])
expected_open = sys.argv[2] == 'open'
for host, port in targets:
    try:
        connection = socket.create_connection((host, port), timeout=1)
    except OSError:
        reachable = False
    else:
        connection.close()
        reachable = True
    if reachable != expected_open:
        raise SystemExit(f'Неожиданная доступность: {host}:{port}, reachable={reachable}')
print(f'Проверено адресов TCP: {len(targets)}; ожидаемый режим: {sys.argv[2]}')
'''

DECOY_POLICY_PROBE = '''
import socket
import sys
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')
from pathlib import Path
for name in ('backend', 'postgres', 'nginx', 'controller'):
    try:
        socket.getaddrinfo(name, None)
    except socket.gaierror:
        continue
    raise SystemExit(f'Ловушке доступно имя DNS управления: {name}')
for row in Path('/proc/net/route').read_text().splitlines()[1:]:
    fields = row.split()
    if fields[1] == '00000000' and int(fields[3], 16) & 1:
        raise SystemExit('У ловушки есть активный маршрут IPv4 по умолчанию')
for row in Path('/proc/net/ipv6_route').read_text().splitlines():
    fields = row.split()
    if fields[0] == '0' * 32 and fields[1] == '00' and fields[-1] != 'lo':
        raise SystemExit('У ловушки есть маршрут IPv6 по умолчанию')
if Path('/var/run/docker.sock').exists():
    raise SystemExit('В контейнере ловушки доступен сокет Docker')
print('DNS управления недоступен; исходящий маршрут по умолчанию и сокет Docker отсутствуют')
'''


def managed(docker, project, role):
    """Running instance containers of this laboratory, found by ownership labels, never by name."""
    output = docker('ps', '-q', '--filter', f'label={LABEL}managed=true', '--filter', f'label={LABEL}project={project}',
                    '--filter', f'label={LABEL}role={role}')
    return output.split()


def verify_isolation(docker, compose):
    """Call after readiness; positive controls prevent stopped-server false passes."""
    protected = []
    project = None
    for service, ports in [('backend', [8000]), ('postgres', [5432]), ('nginx', [8443, 9443])]:
        identifier = compose('ps', '-q', service)
        if not identifier or len(identifier.splitlines()) != 1:
            raise RuntimeError(f'Ожидался ровно один запущенный сервис {service}')
        info = json.loads(docker('inspect', identifier))[0]
        observed_project = info['Config']['Labels']['com.docker.compose.project']
        if project is not None and observed_project != project:
            raise RuntimeError('Проверяемые сервисы принадлежат разным проектам Compose')
        project = observed_project
        if not info['State']['Running']:
            raise RuntimeError(f'Сервис {service} остановлен')
        endpoints = []
        for network_name, network in info['NetworkSettings']['Networks'].items():
            if not network['IPAddress']:
                continue
            addresses = [(network['IPAddress'], port) for port in ports]
            if network_name == project + '_ingress':
                docker('run', '--rm', '--network', network_name, '--read-only', '--cap-drop', 'ALL',
                       '--security-opt', 'no-new-privileges:true', '--memory', '64m', '--pids-limit', '32',
                       'honeyforge:local', 'python', '-c', TCP_PROBE, json.dumps(addresses), 'open')
            else:
                origin = 'controller' if network_name == project + '_management' else 'backend'
                compose('exec', '-T', origin, 'python', '-c', TCP_PROBE, json.dumps(addresses), 'open')
            endpoints.extend(addresses)
        if not endpoints:
            raise RuntimeError(f'У сервиса {service} нет активного IP-адреса')
        protected.extend(endpoints)

    for name in ('database', 'control', 'management', 'decoy'):
        network = json.loads(docker('network', 'inspect', project + '_' + name))[0]
        if not network['Internal']:
            raise RuntimeError(f'Сеть {name} допускает внешнюю маршрутизацию')

    decoys, agents = managed(docker, project, 'decoy'), managed(docker, project, 'agent')
    if not decoys or len(decoys) != len(agents):
        raise RuntimeError('Ожидались работающие динамические экземпляры: у каждой приманки должен быть свой агент')
    for identifier in decoys + agents:
        info = json.loads(docker('inspect', identifier))[0]
        role = info['Config']['Labels'][LABEL + 'role']
        expected = project + ('_decoy' if role == 'decoy' else '_management')
        host = info['HostConfig']
        if list(info['NetworkSettings']['Networks']) != [expected]:
            raise RuntimeError(f'Контейнер {role} подключён к неожиданным сетям')
        if host['Privileged'] or host['Binds'] or host['PortBindings'] or host['CapDrop'] != ['ALL'] or not host['ReadonlyRootfs']:
            raise RuntimeError(f'Контейнер {role} создан с ослабленными ограничениями')
        if not host['Memory'] or not host['NanoCpus'] or info['Config']['User'] != '10001:10001':
            raise RuntimeError(f'У контейнера {role} нет ограничений ресурсов или он запущен от root')
        environment = ' '.join(info['Config']['Env'])
        if role == 'decoy' and ('AGENT_TOKEN' in environment or 'MANAGEMENT_URL' in environment):
            raise RuntimeError('Приманке переданы параметры канала управления')
    for identifier in decoys:
        docker('exec', identifier, 'python', '-c', TCP_PROBE, json.dumps(protected), 'closed')
        docker('exec', identifier, 'python', '-c', DECOY_POLICY_PROBE)
    compose('--profile', 'demo', 'run', '--rm', '--entrypoint', 'python', 'test-client', '-c', TCP_PROBE, json.dumps(protected), 'closed')
    compose('--profile', 'demo', 'run', '--rm', '--entrypoint', 'python', 'test-client', '-c', DECOY_POLICY_PROBE)
    print(f'УСПЕШНО: приманок проверено: {len(decoys)}; ни одна из них и тестовый клиент не могут подключиться к сервисам '
          'управления по IP; проверены сети, DNS, исходящие маршруты, ограничения контейнеров и отсутствие секретов управления')
