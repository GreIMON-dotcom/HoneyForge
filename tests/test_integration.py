"""Live TLS sockets: decoy -> durable queue -> agent -> API -> database -> WebSocket."""
import asyncio
import contextlib
import ipaddress
import os
import ssl
from datetime import datetime, timezone, timedelta
import httpx
import pytest
import uvicorn
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from websockets.asyncio.client import connect
from backend.app.main import app
import backend.app.api as api_module
from agent.main import AgentClient
from honeypots.service import Supervisor
from shared.buffer import DurableBuffer
from conftest import HOST, controller_online, create_pot, provision
from test_agent import free_port


def tls_certificate(tmp_path):
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'HoneyForge integration test')])
    now=datetime.now(timezone.utc)
    cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(days=1))
          .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),False)
          .sign(key,hashes.SHA256()))
    cert_path,key_path=tmp_path/'test.crt',tmp_path/'test.key'
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    return cert_path,key_path


class SwitchableTransport(httpx.AsyncBaseTransport):
    def __init__(self,context):
        self.transport=httpx.AsyncHTTPTransport(verify=context)
        self.online=True

    async def handle_async_request(self,request):
        if not self.online:
            raise httpx.ConnectError('Controlled management outage',request=request)
        return await self.transport.handle_async_request(request)

    async def aclose(self):
        await self.transport.aclose()


async def test_tls_end_to_end_outage_recovery_websocket(factory,client,controller_headers,tmp_path,monkeypatch):
    """Four live instances (two share one TCP profile) over real TLS, with an outage for each."""
    monkeypatch.setattr(api_module,'Session',factory)
    port=free_port()
    cert,key=tls_certificate(tmp_path)
    context=ssl.create_default_context(cafile=str(cert))
    config=uvicorn.Config(app,host='127.0.0.1',port=port,ssl_certfile=str(cert),ssl_keyfile=str(key),lifespan='off',log_level='error')
    server=uvicorn.Server(config)
    task=asyncio.create_task(server.serve())
    supervisors=[]
    try:
        for _ in range(100):
            if server.started:break
            await asyncio.sleep(.05)
        assert server.started
        await client.patch('/api/v1/hosts/'+HOST,json={'port_range_start':1024,'port_range_end':65535})
        cookie='hf_session='+client.cookies.get('hf_session')
        async with connect(f'wss://127.0.0.1:{port}/api/v1/ws',ssl=context,origin='http://test',additional_headers={'Cookie':cookie}) as ws:
            import json
            assert json.loads(await ws.recv())['type']=='connected'
            counts={}
            for name,service_key in [('tcp-a','tcp-banner'),('tcp-b','tcp-banner'),('web-admin','http-admin'),('web-api','http-api')]:
                service_port=free_port()
                await controller_online(client,controller_headers)
                pot,profile=await create_pot(client,service_key,name,deploy=True,port_mode='manual',port=service_port,
                                             overrides={'banner':'SSH-2.0-'+name} if service_key=='tcp-banner' else {})
                credentials=await provision(client,controller_headers,pot['id'])
                queue=DurableBuffer(str(tmp_path/(name+'.db')))
                transport=SwitchableTransport(context)
                async with httpx.AsyncClient(base_url=f'https://127.0.0.1:{port}',transport=transport,headers=credentials) as machine:
                    agent=AgentClient(queue,machine,credentials['X-Agent-ID'])
                    await agent.sync()
                    supervisor=Supervisor(queue,profile['spec']['service_type'],bind_address='127.0.0.1')
                    supervisors.append(supervisor)
                    await supervisor.tick()
                    await agent.heartbeat()
                    state=(await client.get('/api/v1/honeypots/'+pot['id'])).json()
                    assert state['status']=='running' and state['synchronized'] and state['ip_address']=='127.0.0.1'
                    transport.online=False
                    if service_key=='tcp-banner':
                        reader,writer=await asyncio.open_connection('127.0.0.1',service_port)
                        assert (await reader.readline()).decode().strip()=='SSH-2.0-'+name
                        writer.close();await writer.wait_closed()
                    else:
                        async with httpx.AsyncClient() as test_client:
                            path='/login' if service_key=='http-admin' else '/api/v1/login'
                            result=await test_client.post(f'http://127.0.0.1:{service_port}{path}',data={'username':'synthetic','password':'discard-this'})
                            assert result.status_code==200
                    await asyncio.sleep(.05)
                    count=queue.size()
                    assert count>0
                    with pytest.raises(httpx.ConnectError):await agent.transmit()
                    assert queue.size()==count
                    batch=queue.batch()
                    assert {e['honeypot_id'] for e in batch}=={pot['id']}
                    transport.online=True
                    recovered=AgentClient(DurableBuffer(queue.path),machine,credentials['X-Agent-ID'])
                    await recovered.transmit()
                    assert queue.size()==0
                    replay=await machine.post(f'/api/v1/agents/{credentials["X-Agent-ID"]}/telemetry',json={'events':batch})
                    assert replay.json()['inserted']==0
                    events=(await client.get('/api/v1/events',params={'honeypot_id':pot['id']})).json()
                    assert events['total']==count and {e['destination_port'] for e in events['items']}=={service_port}
                    assert 'discard-this' not in str(events)
                    counts[pot['id']]=count
                    for _ in range(10):
                        message=json.loads(await asyncio.wait_for(ws.recv(),5))
                        if message['type']=='events' and message['honeypot_id']==pot['id']:break
                    assert message['type']=='events' and message['honeypot_id']==pot['id']
            overview=(await client.get('/api/v1/analytics/overview')).json()
            assert overview['honeypots']==4 and overview['active']==4 and overview['authentication_attempts']==2
            assert {row['label']:row['count'] for row in overview['by_honeypot']}==counts
            inventory=(await client.get('/api/v1/honeypots')).json()
            assert {p['id']:p['event_count'] for p in inventory}==counts
    finally:
        for supervisor in supervisors:await supervisor.stop()
        server.should_exit=True
        await asyncio.wait_for(task,10)
