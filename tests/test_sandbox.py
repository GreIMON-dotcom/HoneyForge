"""Fail-closed admission, Docker policy, reset lifecycle, capture and artifact integrity.

Docker/API tests use an explicit fake Engine. Linux-only worker tests require
strace and exercise real child processes; they are skipped on Windows.
"""
import asyncio
import base64
from copy import deepcopy
import hashlib
import os
import secrets
import shutil
import sys
from types import SimpleNamespace
from uuid import uuid4
import httpx
import pytest
from backend.app.main import app
from controller.main import Controller
from controller.docker_api import Docker, Policy, DockerError, LABEL
from shared.catalog import PLUGINS
from shared.contracts import ProfileSpec
from conftest import create_pot, profile_for, provision, confirm
from test_controller import FakeDocker
from test_backend import event


def test_sandbox_configuration_requires_capture_and_single_session():
    original = PLUGINS['linux-sandbox'].default_spec()
    assert original['interaction_level'] == 'high'
    for patch in ({'max_connections': 2}, {'telemetry_enabled': False}, {'connection_logging': False},
                  {'authentication_logging': False}, {'logging_verbosity': 'metadata'}):
        with pytest.raises(ValueError):
            ProfileSpec.model_validate(original | patch)
    legacy = PLUGINS['telnet-shell'].default_spec() | {'interaction_level': 'high'}
    assert ProfileSpec.model_validate(legacy).interaction_level == 'medium'


async def test_center_node_cannot_deploy_a_real_shell(client, controller_headers):
    from conftest import controller_online, HOST
    await controller_online(client, controller_headers, sandbox={'ready': True, 'runtime': 'runsc'})
    profile = await profile_for(client, 'linux-sandbox')
    result = await client.post('/api/v1/honeypots', json={'name': 'Forbidden local shell', 'host_id': HOST,
                             'profile_id': profile['id'], 'deploy': True})
    assert result.status_code == 409 and 'отдельный' in result.text


async def separate_host(client, ready=True):
    token, host = secrets.token_urlsafe(32), 'sandbox-test'
    response = await client.post('/api/v1/hosts', json={'id': host, 'name': 'Separate test VM',
                                  'credential_sha256': hashlib.sha256(token.encode()).hexdigest()})
    assert response.status_code == 201, response.text
    headers = {'X-Controller-ID': host, 'Authorization': 'Bearer ' + token}
    response = await client.post('/api/v1/runtime/report', headers=headers, json={'sandbox': {'ready': ready, 'runtime': 'runsc' if ready else None}})
    assert response.status_code == 200, response.text
    return host, headers


async def test_unprepared_separate_node_is_rejected(client):
    host, _ = await separate_host(client, ready=False)
    profile = await profile_for(client, 'linux-sandbox')
    response = await client.post('/api/v1/honeypots', json={'name': 'Unprepared shell', 'host_id': host,
                                 'profile_id': profile['id'], 'deploy': True})
    assert response.status_code == 409


def settings(host='sandbox-test'):
    return SimpleNamespace(project='lab', host_id=host, image='honeyforge:local', decoy_network='lab_decoy',
        management_network='lab_management', management_url='https://nginx:9443', ca_pem='PUBLIC CA',
        orphan_policy='remove', volume_prefix='hf-lab-', interval=0, health_file=os.devnull,
        exposed_network='lab_exposed', publish_address='127.0.0.1', publish_ports=frozenset(),
        sandbox_node=True, sandbox_image='honeyforge-sandbox:local', center_vpn_ip='10.66.0.1')


def policy():
    return Policy('honeyforge:local', {'lab_decoy','lab_management'}, 'hf-lab-', sandbox_enabled=True)


@pytest.fixture
def worker_spec():
    controller = Controller(settings(), None, None)
    return controller.sandbox_spec({'honeypot_id': str(uuid4()), 'emulator': 'tcp', 'service_key': 'linux-sandbox'})


@pytest.mark.parametrize('mutate', [
    lambda s: s['HostConfig'].update(NetworkMode='host'),
    lambda s: s['HostConfig'].update(Runtime='runc'),
    lambda s: s['HostConfig'].update(Privileged=True),
    lambda s: s['HostConfig'].update(CapAdd=['SYS_ADMIN']),
    lambda s: s['HostConfig'].update(SecurityOpt=['no-new-privileges:true','seccomp=unconfined']),
    lambda s: s['HostConfig'].update(PidMode='host'),
    lambda s: s['HostConfig'].update(ReadonlyRootfs=False),
    lambda s: s['HostConfig']['Mounts'][0].update(ReadOnly=False),
    lambda s: s['HostConfig']['Mounts'][0].update(Target='/spool'),
    lambda s: s['HostConfig'].update(PortBindings={'8024/tcp': [{'HostPort':'8024'}]}),
    lambda s: s.update(Env=['AGENT_TOKEN=must-never-reach-shell']),
    lambda s: s.update(Image='foreign:image'),
    lambda s: s.update(Cmd=['bash']),
    lambda s: s['HostConfig'].update(Memory=0),
    lambda s: s['HostConfig'].update(ExtraHosts=['center:10.66.0.1']),
    lambda s: s.update(NetworkingConfig={'EndpointsConfig': {'lab_management': {}}}),
])
def test_worker_policy_rejects_every_escape_from_the_fixed_spec(worker_spec, mutate):
    policy().assert_safe(worker_spec)
    bad = deepcopy(worker_spec)
    mutate(bad)
    with pytest.raises(DockerError):
        policy().assert_safe(bad)


async def test_controller_creates_three_containers_and_replaces_used_worker(client):
    host, headers = await separate_host(client)
    pot, _ = await create_pot(client, 'linux-sandbox', 'real-shell', host_id=host, deploy=True)
    fake = FakeDocker()
    docker = Docker(httpx.AsyncClient(transport=httpx.MockTransport(fake.handle), base_url='http://docker'), policy())
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://test', headers=headers) as api:
        controller = Controller(settings(host), docker, api)
        controller.sandbox_ready = True
        await controller.cycle()
        roles = {item['spec']['Labels'][LABEL+'role']: key for key,item in fake.containers.items()}
        assert set(roles) == {'decoy','agent','sandbox'}
        worker = fake.containers[roles['sandbox']]['spec']
        gateway = fake.containers[roles['decoy']]['spec']
        agent = fake.containers[roles['agent']]['spec']
        assert worker['HostConfig']['NetworkMode'] == 'none'
        assert worker['HostConfig']['Mounts'][0]['ReadOnly'] is True
        assert [m['Target'] for m in gateway['HostConfig']['Mounts']] == ['/spool','/bridge']
        assert [m['Target'] for m in agent['HostConfig']['Mounts']] == ['/spool']
        assert agent['HostConfig']['ExtraHosts'] == ['nginx:10.66.0.1']
        assert len(fake.volumes) == 2
        usage = (await client.get('/api/v1/hosts/'+host+'/capacity')).json()['allocated']
        assert usage['memory_mb'] == 128+96+256 and usage['cpu'] == .5+.25+.5
        fake.containers[roles['sandbox']]['state'] = 'exited'
        await controller.cycle()
        assert roles['sandbox'] not in fake.containers and len(fake.containers) == 3
        assert roles['decoy'] in fake.containers and roles['agent'] in fake.containers
        await client.delete('/api/v1/honeypots/'+pot['id'], params={'force': True})
        await controller.cycle()
        assert not fake.containers and not fake.volumes


async def test_capture_artifact_integrity_and_viewer_restrictions(client):
    host, headers = await separate_host(client)
    pot, _ = await create_pot(client, 'linux-sandbox', host_id=host, deploy=True)
    agent = await provision(client, headers, pot['id'])
    session = str(uuid4())
    data = b'#!/bin/sh\nprintf harmless-demo\n'
    sha = hashlib.sha256(data).hexdigest()
    meta = {'summary': 'Sandbox artifact', 'stream':'artifact', 'artifact_path':'/home/lab/demo.sh', 'sha256':sha,'artifact_size':len(data)}
    chunk = {'summary':'Sandbox artifact_chunk','stream':'artifact_chunk','sha256':sha,'artifact_path':'/home/lab/demo.sh',
             'offset':0,'data':base64.b64encode(data).decode(),'encoding':'base64'}
    events = [event(honeypot_id=pot['id'],session_id=session,event_type='data_received',payload=payload) for payload in (meta,chunk)]
    response = await client.post(f'/api/v1/agents/{agent["X-Agent-ID"]}/telemetry',headers=agent,json={'events':events})
    assert response.status_code == 200, response.text
    path = f'/api/v1/sandbox/sessions/{pot["id"]}/{session}'
    response = await client.get(path+'/'+sha+'/artifact')
    assert response.content == data and response.headers['content-type'] == 'application/octet-stream'
    assert 'attachment' in response.headers['content-disposition']
    assert len((await client.get(path+'/capture')).json()['events']) == 2
    wrong = 'a'*64
    missing = event(honeypot_id=pot['id'],session_id=session,event_type='data_received',payload=meta|{'sha256':wrong})
    await client.post(f'/api/v1/agents/{agent["X-Agent-ID"]}/telemetry',headers=agent,json={'events':[missing]})
    assert (await client.get(path+'/'+wrong+'/artifact')).status_code == 409
    from test_insights import viewer_client
    viewer = await viewer_client(client)
    try:
        assert (await viewer.get(path+'/capture')).status_code == 403
        assert (await viewer.get(path+'/'+sha+'/artifact')).status_code == 403
        detail = (await viewer.get(f'/api/v1/sessions/{pot["id"]}/{session}')).json()
        assert all('data' not in row['payload'] and 'artifact_path' not in row['payload'] for row in detail['events'])
    finally:
        await viewer.aclose()


@pytest.mark.skipif(sys.platform != 'linux', reason='Unix socket gateway requires Linux')
async def test_broker_can_wait_for_a_replacement_worker(tmp_path):
    from honeypots.high import Broker
    broker = Broker(str(tmp_path/'session.sock'))
    await broker.start()
    try:
        waiting = asyncio.create_task(broker.acquire())
        await asyncio.sleep(.02)
        reader, writer = await asyncio.open_unix_connection(broker.path)
        actual = await asyncio.wait_for(waiting, 1)
        assert actual[1] is not None
        actual[1].close(); writer.close()
        broker.in_use = False
    finally:
        await broker.close()


@pytest.mark.skipif(sys.platform != 'linux', reason='Artifact scanner uses Linux openat/fwalk')
def test_artifact_scanner_excludes_symlinks_and_large_files(tmp_path, monkeypatch):
    from sandbox import worker
    inside = tmp_path/'inside'; inside.mkdir()
    (inside/'file').write_bytes(b'content')
    outside = tmp_path/'secret'; outside.write_bytes(b'not-in-sandbox-workspace')
    (inside/'link').symlink_to(outside)
    (inside/'large').write_bytes(b'x'*65537)
    monkeypatch.setattr(worker,'WRITABLE',(str(inside),))
    rows = worker.artifacts({})
    assert len(rows) == 1 and rows[0][0].endswith('/file') and rows[0][2] == b'content'
