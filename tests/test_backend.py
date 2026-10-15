import asyncio
import os
from datetime import datetime, timezone, timedelta
from uuid import uuid4
import httpx
import pytest
from sqlalchemy import select, func
from backend.app.main import app
from backend.app.models import Event, Honeypot, InteractionSession, now
from backend.app.services import maintenance_once, hub
from shared.contracts import ProfileSpec
from conftest import HOST, controller_online, create_pot, deployed_pot, running_pot, confirm, profile_for


def event(**changes):
    return {"event_uid":str(uuid4()), "honeypot_id":str(uuid4()), "session_id":str(uuid4()), "timestamp":datetime.now(timezone.utc).isoformat(),
            "source_ip":"192.0.2.10", "source_port":45000, "destination_port":8022, "protocol":"TCP",
            "event_type":"connection", "severity":"info", "payload":{"summary":"Synthetic connection"}, **changes}


async def test_authentication_timeline_excludes_other_activity(client, controller_headers):
    pot, _, agent = await running_pot(client, controller_headers)
    response = await client.post(f'/api/v1/agents/{agent["X-Agent-ID"]}/telemetry', headers=agent, json={'events':[
        event(honeypot_id=pot['id']), event(honeypot_id=pot['id'], event_type='authentication_attempt')]})
    assert response.status_code == 200
    overall = (await client.get('/api/v1/analytics/timeline')).json()
    auth = (await client.get('/api/v1/analytics/timeline?event_type=authentication_attempt')).json()
    assert len(auth)==24 and sum(p['count'] for p in auth)==1
    assert sum(p['count'] for p in overall)==2


async def test_auth_roles_csrf_logout(client):
    assert (await client.get("/api/v1/auth/me")).json()["role"] == "administrator"
    assert (await client.post("/api/v1/profiles", json=ProfileSpec(name="bad-origin").model_dump(), headers={"Origin":"http://evil"})).status_code == 403
    password="synthetic-test-password"
    response=await client.post("/api/v1/users",json={"username":"reader","password":password,"role":"viewer"})
    assert response.status_code==201
    await client.post("/api/v1/auth/logout")
    assert (await client.get("/api/v1/profiles")).status_code==401
    assert (await client.post("/api/v1/auth/login",json={"username":"reader","password":password})).status_code==200
    assert (await client.post("/api/v1/profiles",json=ProfileSpec(name="blocked").model_dump())).status_code==403
    assert (await client.get("/api/v1/audit")).status_code==403
    assert (await client.get("/api/v1/events/export")).status_code==403


async def test_login_failure_and_refresh(client):
    assert (await client.post("/api/v1/auth/login",json={"username":"admin","password":"wrong"})).status_code==401
    old=client.cookies.get("hf_session")
    assert (await client.post("/api/v1/auth/refresh")).status_code==200
    assert old!=client.cookies.get("hf_session")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app),base_url="http://test",cookies={"hf_session":old}) as expired:
        assert (await expired.get("/api/v1/auth/me")).status_code==401


@pytest.mark.parametrize("changes",[{"port":0},{"port":65536},{"interaction_level":"medium","service_type":"tcp"},{"banner":"bad\nheader"},
    {"outbound_policy":"allow"},{"banner":"привет","banner_encoding":"ascii"},{"max_input_bytes":100000},{"connection_timeout":0}])
async def test_profile_validation(client,changes):
    body=ProfileSpec(name="invalid").model_dump()|changes
    assert (await client.post("/api/v1/profiles",json=body)).status_code==422


async def test_profile_crud_and_audit(client):
    p=(await client.post("/api/v1/profiles",json=ProfileSpec(name="Custom TCP").model_dump())).json()
    assert p["service_key"]=="tcp-banner" and p["instances"]==0
    duplicate=await client.post(f'/api/v1/profiles/{p["id"]}/duplicate')
    assert duplicate.status_code==201
    assert (await client.delete(f'/api/v1/profiles/{duplicate.json()["id"]}')).status_code==200
    pot,profile=await create_pot(client)
    assert (await client.get('/api/v1/profiles/'+profile["id"])).json()["instances"]==1
    assert (await client.delete('/api/v1/profiles/'+profile["id"])).status_code==409
    other=ProfileSpec(name=profile["name"],service_key="http-admin").model_dump()
    assert (await client.patch('/api/v1/profiles/'+profile["id"],json=other)).status_code==409
    audit=(await client.get('/api/v1/audit')).json()["items"]
    assert {a["action"] for a in audit}>={"profile.create","profile.delete","honeypot.register"}


async def test_telemetry_dedup_filters_session_alerts(client,controller_headers,factory):
    pot,_,agent=await running_pot(client,controller_headers)
    telemetry=f'/api/v1/agents/{agent["X-Agent-ID"]}/telemetry'
    await client.post('/api/v1/alerts/rules',json={"name":"Connections","event_type":"connection","threshold":2,"window_seconds":60,"severity":"high"})
    e1,e2=event(honeypot_id=pot['id']),event(honeypot_id=pot['id'])
    e2["session_id"]=e1["session_id"]
    queue=asyncio.Queue()
    hub.clients.add(queue)
    try:
        response=await client.post(telemetry,headers=agent,json={"events":[e1,e2]})
        assert response.status_code==200,response.text
        assert response.json()["inserted"]==2
        live=await queue.get()
        assert live["type"]=="events" and live["honeypot_id"]==pot["id"]
        assert (await queue.get())["type"]=="alert"
        replay=await client.post(telemetry,headers=agent,json={"events":[e1,e2]})
        assert replay.json()["inserted"]==0
        assert queue.empty()
    finally:
        hub.clients.discard(queue)
    data=(await client.get('/api/v1/events',params={"source_ip":"192.0.2.10","honeypot_id":pot["id"],"interaction_level":"low","page_size":1})).json()
    assert data["total"]==2 and len(data["items"])==1
    assert (await client.get('/api/v1/events?interaction_level=medium')).json()["total"]==0
    assert (await client.get('/api/v1/events?severity=critical')).json()["total"]==0
    assert len((await client.get('/api/v1/alerts')).json())==1
    async with factory() as db:
        assert await db.scalar(select(func.count()).select_from(Event))==2
        session=await db.scalar(select(InteractionSession))
        assert session.event_count==2
    assert (await client.get('/api/v1/analytics/overview')).json()["events"]==2
    assert sum(p["count"] for p in (await client.get('/api/v1/analytics/timeline')).json())==2
    assert '192.0.2.10' in (await client.get('/api/v1/events/export')).text


async def test_agent_access_validation(client,controller_headers):
    pot,_,agent=await running_pot(client,controller_headers)
    other,_,other_agent=await running_pot(client,controller_headers)
    own=f'/api/v1/agents/{agent["X-Agent-ID"]}'
    assert (await client.get(own+'/configuration')).status_code==401
    assert (await client.get(own+'/configuration',headers=agent|{"Authorization":"Bearer wrong"})).status_code==401
    assert (await client.get(own+'/configuration',headers=other_agent)).status_code==403
    assert (await client.post(own+'/telemetry',headers=agent,json={"events":[event(honeypot_id=pot["id"],payload={"password":"do-not-store"})]})).status_code==422
    assert (await client.post(own+'/telemetry',headers=agent,json={"events":[event(honeypot_id=pot["id"],source_ip="bad-ip")]})).status_code==422
    assert (await client.get('/api/v1/events')).json()["total"]==0


async def test_real_state_commands_offline(client,controller_headers,factory):
    pot,_,agent=await deployed_pot(client,controller_headers)
    assert pot["status"]=="deploying" and not pot["synchronized"]
    detail=await confirm(client,agent,pot["id"],queue_size=3)
    assert detail["status"]=="running" and detail["synchronized"] and detail["queue_size"]==3
    assert detail["commands"][0]["status"]=="completed"
    assert detail["deployments"][0]["status"]=="running"
    assert detail["agent"]["connected"]
    assert (await client.delete('/api/v1/honeypots/'+pot["id"])).status_code==409
    async with factory() as db:
        obj=await db.get(Honeypot,pot["id"])
        obj.last_seen=now()-timedelta(minutes=10)
        await db.commit()
        await maintenance_once(db)
    assert (await client.get('/api/v1/honeypots/'+pot["id"])).json()["status"]=="offline"
    assert (await confirm(client,agent,pot["id"]))["status"]=="running"


async def test_deployment_requires_reachable_controller(client,controller_headers):
    profile=await profile_for(client,'tcp-banner')
    body={"name":"deployed","profile_id":profile["id"],"host_id":HOST}
    assert (await client.post('/api/v1/deployments',json=body)).status_code==409
    assert (await client.get('/api/v1/honeypots')).json()==[]
    await controller_online(client,controller_headers)
    response=await client.post('/api/v1/deployments',json=body)
    assert response.status_code==201,response.text
    assert response.json()["status"]=="pending" and response.json()["operation"]=="deploy"
    assert (await client.post('/api/v1/deployments',json=body)).status_code==409
    assert (await client.post('/api/v1/deployments',json=body|{"name":"deployed-2"})).status_code==201
    logs=(await client.get(f'/api/v1/deployments/{response.json()["id"]}/logs')).json()
    assert [row["code"] for row in logs][:1]==["deployment.requested"]


async def test_viewer_redacts_captured_username(client,controller_headers):
    pot,_,agent=await running_pot(client,controller_headers)
    response=await client.post(f'/api/v1/agents/{agent["X-Agent-ID"]}/telemetry',headers=agent,json={"events":[event(honeypot_id=pot['id'],payload={"username":"synthetic_name","summary":"Test","input_preview":"secret"})]})
    assert response.status_code==200
    await client.post('/api/v1/users',json={"username":"viewer","password":"viewer-test-only","role":"viewer"})
    await client.post('/api/v1/auth/login',json={"username":"viewer","password":"viewer-test-only"})
    payload=(await client.get('/api/v1/events')).json()["items"][0]["payload"]
    assert "username" not in payload and "input_preview" not in payload


@pytest.mark.parametrize('query',['page=0','source_ip=not-an-ip','start=2026-01-01T12:00:00','start=2026-02-01T00:00:00Z&end=2026-01-01T00:00:00Z'])
async def test_invalid_event_filters(client,query):
    assert (await client.get('/api/v1/events?'+query)).status_code==422


async def test_ioc_export_and_offline_api_docs(client):
    result=await client.get('/api/v1/events/export?format=ioc')
    assert result.status_code==200,result.text
    assert result.json()['type']=='source_ip_observations'
    assert (await client.get('/docs')).status_code==200
    assert (await client.get('/api-docs.js')).status_code==200


async def test_failed_configuration_records_outcome(client,controller_headers):
    pot,_,agent=await deployed_pot(client,controller_headers)
    await client.post('/api/v1/agents/heartbeat',headers=agent,json={
        'honeypot_id':pot['id'],'generation':0,'attempted_generation':pot['generation'],'status':'error','queue_size':0,'error':'Port unavailable'})
    detail=(await client.get('/api/v1/honeypots/'+pot['id'])).json()
    assert detail['status']=='failed' and detail['error']=='Port unavailable'
    assert detail['commands'][0]['status']=='failed' and detail['deployments'][0]['status']=='failed'
    assert not detail['synchronized']
    assert any(row['code']=='instance.failed' for row in (await client.get(f'/api/v1/honeypots/{pot["id"]}/logs')).json())
    assert (await client.post(f'/api/v1/honeypots/{pot["id"]}/deploy')).status_code==200


@pytest.mark.skipif(not os.getenv('TEST_DATABASE_URL','').startswith('postgresql'),reason='PostgreSQL concurrency semantics')
async def test_concurrent_retries_and_lifecycle_generations(client,controller_headers):
    pot,_,agent=await running_pot(client,controller_headers)
    body={'events':[event(honeypot_id=pot['id'])]}
    path=f'/api/v1/agents/{agent["X-Agent-ID"]}/telemetry'
    responses=await asyncio.gather(*(client.post(path,headers=agent,json=body) for _ in range(5)))
    assert all(r.status_code==200 for r in responses)
    assert sum(r.json()['inserted'] for r in responses)==1
    results=await asyncio.gather(*(client.post('/api/v1/honeypots/'+pot['id']+'/restart') for _ in range(3)))
    assert all(r.status_code==200 for r in results)
    generations=sorted(r.json()['generation'] for r in results)
    assert generations==[pot['generation']+1,pot['generation']+2,pot['generation']+3]
