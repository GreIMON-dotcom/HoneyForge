import asyncio
import json
import time
import httpx
import pytest
from uuid import uuid4
from shared.buffer import DurableBuffer
from shared.contracts import ProfileSpec, validate_configuration
from agent.main import AgentClient
from honeypots.service import Supervisor
from test_backend import event


async def test_configured_fictitious_accounts_response_and_capture_verbosity(tmp_path):
    queue = DurableBuffer(str(tmp_path/'events.db'))
    port = free_port()
    spec = ProfileSpec(name='Configured simulation', interaction_level='medium', service_type='http', port=port,
                       decoy_accounts=['demo_account'], authentication_mode='configured-accounts',
                       status_message='<synthetic> inventory')
    config = {'assigned':True, 'honeypot_id':str(uuid4()), 'profile_version':1, 'generation':1,
              'desired_state':'running', 'spec':spec.model_dump()}
    queue.set('configuration', config)
    supervisor = Supervisor(queue, 'http', bind_address='127.0.0.1')
    try:
        await supervisor.tick()
        assert queue.get('service_health')['ip_address']=='127.0.0.1'
        async with httpx.AsyncClient(base_url=f'http://127.0.0.1:{port}') as client:
            assert 'demo_account' in (await client.get('/')).text
            rejected = await client.post('/login', data={'username':'unknown','password':'discard-me'})
            assert 'Тестовый вход отклонён' in rejected.text
            accepted = await client.post('/login', data={'username':'demo_account','password':'discard-me'})
            assert 'Имитируемый сеанс создан' in accepted.text
            assert '&lt;synthetic&gt; inventory' in (await client.get('/status')).text
            logins = [e['payload'] for e in queue.batch() if e['event_type']=='authentication_attempt']
            assert [e['result'] for e in logins]==['simulated_failure','simulated_success']
            assert 'discard-me' not in json.dumps(queue.batch())
            queue.acknowledge([e['event_uid'] for e in queue.batch()])
            await supervisor.apply(config | {'generation':2,'profile_version':2,
                                   'spec':spec.model_dump() | {'logging_verbosity':'metadata'}})
            await client.post('/login', data={'username':'demo_account','password':'discard-me'})
            assert all(set(e['payload'])=={'summary'} for e in queue.batch())
    finally:
        await supervisor.stop()


def test_durable_queue_restart_limit_ack(tmp_path):
    path=str(tmp_path/'events.db')
    queue=DurableBuffer(path)
    item=event()
    queue.put(item,1)
    recovered=DurableBuffer(path)
    assert recovered.batch()==[item]
    with pytest.raises(BufferError):
        recovered.put(event(),1)
    recovered.acknowledge([item["event_uid"]])
    recovered.acknowledge([item["event_uid"]])
    assert recovered.size()==0


async def test_failed_transmission_then_recovery(tmp_path):
    queue=DurableBuffer(str(tmp_path/'events.db'))
    item=event()
    queue.put(item)
    failing=True
    def handler(request):
        if failing:
            return httpx.Response(503)
        return httpx.Response(200,json={"accepted":[item["event_uid"]]})
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler),base_url="https://lab") as client:
        agent=AgentClient(queue,client,'low')
        with pytest.raises(httpx.HTTPStatusError):
            await agent.transmit()
        assert queue.size()==1
        failing=False
        await agent.transmit()
        assert queue.size()==0 and queue.get('last_delivery')


async def test_invalid_ack_preserves_buffer(tmp_path):
    queue=DurableBuffer(str(tmp_path/'events.db'))
    queue.put(event())
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r:httpx.Response(200,json={"accepted":["unknown"]})),base_url="https://lab") as client:
        with pytest.raises(ValueError):
            await AgentClient(queue,client,'low').transmit()
    assert queue.size()==1


def free_port():
    import socket
    with socket.socket() as s:
        s.bind(('127.0.0.1',0))
        return s.getsockname()[1]


@pytest.mark.parametrize('kind,service',[('low','tcp'),('medium','http')])
async def test_real_decoy_connections_and_restart(tmp_path,kind,service):
    queue=DurableBuffer(str(tmp_path/'events.db'))
    port=free_port()
    config={"assigned":True,"honeypot_id":str(uuid4()),"profile_version":1,"generation":1,"desired_state":"running","spec":ProfileSpec(name='Test',interaction_level=kind,service_type=service,port=port).model_dump()}
    queue.set('configuration',config)
    supervisor=Supervisor(queue,service,bind_address='127.0.0.1')
    try:
        await supervisor.tick()
        assert queue.get('service_health')['status']=='running'
        if service=='tcp':
            reader,writer=await asyncio.open_connection('127.0.0.1',port)
            assert b'SSH-2.0' in await reader.readline()
            writer.close();await writer.wait_closed()
        else:
            async with httpx.AsyncClient() as client:
                assert (await client.get(f'http://127.0.0.1:{port}/')).status_code==200
                assert (await client.post(f'http://127.0.0.1:{port}/login',data={'username':'synthetic','password':'never-collect-me'})).status_code==200
                assert (await client.get(f'http://127.0.0.1:{port}/status')).status_code==200
            events=queue.batch()
            assert any(e['event_type']=='authentication_attempt' for e in events)
            assert 'never-collect-me' not in str(events)
            requests=[e for e in events if e['event_type']=='http_request']
            assert len({e['session_id'] for e in requests})==1
        assert queue.size()>0
        await supervisor.stop()
        recovered=Supervisor(DurableBuffer(queue.path),service,bind_address='127.0.0.1')
        await recovered.tick()
        assert recovered.status=='running'
        await recovered.apply(config|{'generation':2,'desired_state':'stopped'})
        assert recovered.status=='stopped'
        with pytest.raises(OSError):
            await asyncio.open_connection('127.0.0.1',port)
        await recovered.stop()
    finally:
        await supervisor.stop()


async def test_configuration_rejected_keeps_previous_listener(tmp_path):
    queue=DurableBuffer(str(tmp_path/'events.db'))
    port=free_port()
    supervisor=Supervisor(queue,'tcp',bind_address='127.0.0.1')
    config={"assigned":True,"honeypot_id":str(uuid4()),"profile_version":1,"generation":1,"desired_state":"running","spec":ProfileSpec(name='Test',port=port).model_dump()}
    try:
        await supervisor.apply(config)
        with pytest.raises(ValueError):
            await supervisor.apply(config|{'spec':config['spec']|{'port':1}})
        reader,writer=await asyncio.open_connection('127.0.0.1',port)
        assert b'SSH' in await reader.readline()
        writer.close();await writer.wait_closed()
    finally:
        await supervisor.stop()


async def test_heartbeat_continues_when_telemetry_fails(tmp_path,monkeypatch):
    queue=DurableBuffer(str(tmp_path/'events.db'))
    queue.put(event())
    calls=[]
    def handler(request):
        calls.append(request.url.path)
        if request.url.path.endswith('/configuration'):
            return httpx.Response(200,json={'assigned':False})
        if request.url.path.endswith('/telemetry'):
            return httpx.Response(503)
        return httpx.Response(200,json={'ok':True})
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler),base_url='https://lab') as client:
        task=asyncio.create_task(AgentClient(queue,client,'low').run())
        await asyncio.sleep(.1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):await task
    assert '/api/v1/agents/heartbeat' in calls
    assert queue.size()==1


@pytest.mark.parametrize('change', [
    {'schema_version': 2}, {'generation': 0}, {'desired_state': 'execute'},
    {'honeypot_id': 'not-a-uuid'}, {'profile_version': 0},
])
async def test_invalid_configuration_envelope_preserves_durable_state(tmp_path, change):
    queue = DurableBuffer(str(tmp_path/'events.db'))
    original = validate_configuration({'assigned': True, 'honeypot_id': str(uuid4()),
        'profile_version': 1, 'generation': 1, 'desired_state': 'stopped',
        'spec': ProfileSpec(name='Known configuration').model_dump()})
    queue.set('configuration', original)
    async with httpx.AsyncClient(base_url='https://lab', transport=httpx.MockTransport(
        lambda request: httpx.Response(200, json=original | change))) as client:
        with pytest.raises(ValueError):
            await AgentClient(queue, client, 'low').sync()
    assert DurableBuffer(queue.path).get('configuration') == original


async def test_rebind_failure_preserves_listener_assignment(tmp_path):
    queue = DurableBuffer(str(tmp_path/'events.db'))
    supervisor = Supervisor(queue, 'tcp', bind_address='127.0.0.1')
    original = {'assigned': True, 'honeypot_id': str(uuid4()), 'profile_version': 1,
                'generation': 1, 'desired_state': 'running',
                'spec': ProfileSpec(name='Prior listener', port=free_port()).model_dump()}
    occupied = await asyncio.start_server(lambda r, w: w.close(), '127.0.0.1', 0)
    try:
        await supervisor.apply(original)
        candidate = original | {'honeypot_id': str(uuid4()), 'generation': 2,
            'spec': original['spec'] | {'port': occupied.sockets[0].getsockname()[1]}}
        queue.set('configuration', candidate)
        await supervisor.tick()
        assert supervisor.status == 'error'
        reader, writer = await asyncio.open_connection('127.0.0.1', original['spec']['port'])
        assert b'SSH' in await reader.readline()
        writer.close()
        await writer.wait_closed()
        assert queue.batch()[0]['honeypot_id'] == original['honeypot_id']
        health = queue.get('service_health')
        assert health['honeypot_id'] == original['honeypot_id']
        assert health['attempted_honeypot_id'] == candidate['honeypot_id']
    finally:
        occupied.close()
        await occupied.wait_closed()
        await supervisor.stop()
