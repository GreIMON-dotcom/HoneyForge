"""An authenticated agent speaks for exactly one instance and only for its current assignment."""
from uuid import uuid4
from sqlalchemy import select
from backend.app.models import Agent, Audit
from backend.app.security import digest
from conftest import controller_online, create_pot, deployed_pot, running_pot, confirm, provision
from test_backend import event


async def test_telemetry_requires_capture_assignment(client, controller_headers):
    _, _, agent = await running_pot(client, controller_headers)
    captured = event()
    captured.pop('honeypot_id', None)
    response = await client.post(f'/api/v1/agents/{agent["X-Agent-ID"]}/telemetry', headers=agent, json={'events': [captured]})
    assert response.status_code == 422
    assert (await client.get('/api/v1/events')).json()['total'] == 0


async def test_heartbeat_requires_current_assignment(client, controller_headers):
    pot, _, agent = await deployed_pot(client, controller_headers)
    response = await client.post('/api/v1/agents/heartbeat', headers=agent,
        json={'generation': pot['generation'], 'status': 'running', 'queue_size': 0})
    assert response.status_code == 409
    result = (await client.get('/api/v1/honeypots/' + pot['id'])).json()
    assert result['last_seen'] is None and result['applied_generation'] == 0 and result['status'] == 'deploying'


async def test_mixed_assignment_batch_is_rejected_atomically(client, controller_headers):
    pot, _, agent = await running_pot(client, controller_headers)
    response = await client.post(f'/api/v1/agents/{agent["X-Agent-ID"]}/telemetry', headers=agent,
        json={'events': [event(honeypot_id=pot['id']), event(honeypot_id=str(uuid4()))]})
    assert response.status_code == 409
    assert (await client.get('/api/v1/events')).json()['total'] == 0


async def test_identity_of_a_deleted_instance_cannot_report_for_a_new_one(client, controller_headers):
    old, _, old_agent = await running_pot(client, controller_headers, name='reused-name')
    await client.post(f'/api/v1/honeypots/{old["id"]}/stop')
    await confirm(client, old_agent, old['id'])
    await client.delete('/api/v1/honeypots/' + old['id'])
    await controller_online(client, controller_headers, removed=[old['id']])
    new, _, new_agent = await deployed_pot(client, controller_headers, name='reused-name')
    assert old['id'] != new['id'] and new['endpoint']['port'] == old['endpoint']['port']
    heartbeat = {'honeypot_id': old['id'], 'generation': old['generation'], 'profile_version': 1, 'status': 'running', 'queue_size': 0}
    assert (await client.post('/api/v1/agents/heartbeat', headers=old_agent, json=heartbeat)).status_code == 401
    assert (await client.post('/api/v1/agents/heartbeat', headers=new_agent, json=heartbeat)).status_code == 409
    delayed = await client.post(f'/api/v1/agents/{new_agent["X-Agent-ID"]}/telemetry', headers=new_agent,
                                json={'events': [event(honeypot_id=old['id'])]})
    assert delayed.status_code == 409
    assert (await client.get('/api/v1/events')).json()['total'] == 0
    state = (await client.get('/api/v1/honeypots/' + new['id'])).json()
    assert state['last_seen'] is None and not state['synchronized']


async def test_future_generation_and_wrong_profile_version_cannot_ack(client, controller_headers):
    pot, _, agent = await deployed_pot(client, controller_headers)
    report = {'honeypot_id': pot['id'], 'generation': pot['generation'], 'profile_version': 1,
              'status': 'running', 'queue_size': 0}
    for invalid in [report | {'generation': pot['generation'] + 1}, report | {'profile_version': 2}]:
        response = await client.post('/api/v1/agents/heartbeat', headers=agent, json=invalid)
        assert response.status_code == 409
    valid = await client.post('/api/v1/agents/heartbeat', headers=agent, json=report)
    assert valid.status_code == 200
    state = (await client.get('/api/v1/honeypots/' + pot['id'])).json()
    assert state['applied_profile_version'] == 1 and state['synchronized']


async def test_agent_identity_is_provisioned_by_the_controller_and_revocable(client, controller_headers, factory):
    await controller_online(client, controller_headers)
    draft, _ = await create_pot(client, name='draft-only')
    credential = {'credential_sha256': digest('never-stored-in-plain-text')}
    assert (await client.post(f'/api/v1/runtime/instances/{draft["id"]}/credential', headers=controller_headers, json=credential)).status_code == 404
    assert (await client.post(f'/api/v1/runtime/instances/{uuid4()}/credential', headers=controller_headers, json=credential)).status_code == 404
    assert (await client.post(f'/api/v1/runtime/instances/{draft["id"]}/credential', headers=controller_headers, json={'token': 'x'})).status_code == 422
    pot, _, agent = await running_pot(client, controller_headers, name='with-agent')
    configuration = f'/api/v1/agents/{agent["X-Agent-ID"]}/configuration'
    assert (await client.get(configuration, headers=agent)).json()['honeypot_id'] == pot['id']
    listing = (await client.get('/api/v1/agent-enrollments')).json()
    assert [(a['id'], a['honeypot_name'], a['approved']) for a in listing] == [(agent['X-Agent-ID'], 'with-agent', True)]
    assert agent['Authorization'][7:] not in str(listing) and digest(agent['Authorization'][7:]) not in str(listing)
    approval = '/api/v1/agent-enrollments/' + agent['X-Agent-ID']
    assert (await client.patch(approval, json={'approved': False})).status_code == 200
    assert (await client.get(configuration, headers=agent)).status_code == 401
    assert (await client.post('/api/v1/agents/register', headers=agent)).json()['approved'] is False
    rotated = await provision(client, controller_headers, pot['id'])
    assert rotated['X-Agent-ID'] == agent['X-Agent-ID']
    assert (await client.get(configuration, headers=rotated)).status_code == 401
    assert (await client.patch(approval, json={'approved': True})).status_code == 200
    assert (await client.get(configuration, headers=rotated)).status_code == 200
    assert (await client.get(configuration, headers=agent)).status_code == 401
    async with factory() as db:
        stored = await db.get(Agent, agent['X-Agent-ID'])
        assert stored.token_hash == digest(rotated['Authorization'][7:]) and stored.honeypot_id == pot['id']
        actions = set((await db.scalars(select(Audit.action))).all())
        assert {'agent.provisioned', 'agent.revoke', 'agent.approve'} <= actions


async def test_viewer_cannot_manage_agents_or_hosts(client):
    await client.post('/api/v1/users', json={'username': 'viewer-agents', 'password': 'viewer-agents-test', 'role': 'viewer'})
    await client.post('/api/v1/auth/login', json={'username': 'viewer-agents', 'password': 'viewer-agents-test'})
    assert (await client.get('/api/v1/agent-enrollments')).status_code == 403
    assert (await client.patch('/api/v1/agent-enrollments/any', json={'approved': False})).status_code == 403
    assert (await client.post('/api/v1/hosts', json={'id': 'extra-lab', 'name': 'Target', 'credential_sha256': digest('test')})).status_code == 403
    assert (await client.delete('/api/v1/hosts/lab-docker')).status_code == 403
