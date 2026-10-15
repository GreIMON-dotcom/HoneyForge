import json
import re
from pathlib import Path
import httpx
from sqlalchemy import select
from backend.app.main import app
from backend.app.models import Profile, Honeypot, AlertRule, Audit
from shared.contracts import ProfileSpec

ROOT = Path(__file__).resolve().parents[1]


def test_dictionary_keys_and_utf8():
    def unique(pairs):
        value = {}
        for key, item in pairs:
            assert key not in value, f'Duplicate translation: {key}'
            value[key] = item
        return value
    dictionary = json.loads((ROOT/'frontend/locales/ru.json').read_text(encoding='utf8'), object_pairs_hook=unique)
    def lookup(key):
        node = dictionary
        for part in key.split('.'):
            node = node[part]
        return node
    for file in (ROOT/'frontend').glob('*.js'):
        source = file.read_text(encoding='utf8')
        assert '\ufffd' not in source
        for key in re.findall(r"\bt\(['\"]([\w.]+)['\"]", source):
            assert isinstance(lookup(key),str), (file.name,key)
        for key in re.findall(r"\bplural\(['\"]([\w.]+)['\"]", source):
            assert set(lookup(key)) == {'one','few','many','other'}
    for name in ['index.html','api-docs.html']:
        source=(ROOT/'frontend'/name).read_text(encoding='utf8')
        assert 'lang="ru"' in source and 'charset="UTF-8"' in source


async def test_russian_errors_and_openapi(client):
    invalid = await client.post('/api/v1/profiles',json={'name':'Проверка','port':1})
    assert invalid.status_code == 422
    error = invalid.json()['detail'][0]
    assert error['type']=='greater_than_equal' and error['loc']==['body','port']
    assert error['msg']=='Значение должно быть ≥ 1024'
    invalid = await client.post('/api/v1/profiles',json={'name':'Проверка','service_type':'http','interaction_level':'low'})
    assert invalid.status_code == 422 and 'Тип сервиса не соответствует' in invalid.json()['detail'][0]['msg']
    missing = await client.get('/api/v1/profiles/missing')
    assert missing.status_code==404 and missing.json()['detail']=='Ресурс не найден'
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://test') as anonymous:
        denied=await anonymous.get('/api/v1/profiles')
        assert denied.status_code==401 and denied.json()['detail']=='Требуется авторизация'
    spec=(await client.get('/openapi.json')).json()
    for operations in spec['paths'].values():
        for operation in operations.values():
            assert re.search('[А-Яа-я]',operation['summary'])
    assert spec['components']['schemas']['ProfileSpec']['properties']['interaction_level']['enum']==['low','medium','high']


async def test_cyrillic_roundtrip_database_and_search(client,factory,controller_headers):
    from test_backend import event
    from conftest import HOST, controller_online, provision
    profile=ProfileSpec(name='Лабораторный профиль «Кириллица»',description='Профиль для обнаружения подключений')
    response=await client.post('/api/v1/profiles',json=profile.model_dump())
    assert response.status_code==201
    profile_id=response.json()['id']
    await controller_online(client,controller_headers)
    pot=(await client.post('/api/v1/honeypots',json={'name':'Лабораторная ловушка','host_id':HOST,'profile_id':profile_id,
        'description':'Ловушка для проверки кириллицы','tags':['учебная'],'deploy':True})).json()
    agent=await provision(client,controller_headers,pot['id'])
    rule=(await client.post('/api/v1/alerts/rules',json={'name':'Система мониторинга','event_type':'connection','threshold':1,'window_seconds':60,'severity':'medium'})).json()
    result=await client.post(f'/api/v1/agents/{agent["X-Agent-ID"]}/telemetry',headers=agent,json={'events':[event(honeypot_id=pot['id'],payload={'summary':'Тестовое подключение: ёж'})]})
    assert result.status_code==200
    found=(await client.get('/api/v1/events',params={'q':'подключение: ёж'})).json()
    assert found['total']==1 and found['items'][0]['payload']['summary']=='Тестовое подключение: ёж'
    async with factory() as db:
        assert (await db.get(Profile,profile_id)).spec['description']==profile.description
        stored=await db.get(Honeypot,pot['id'])
        assert stored.name=='Лабораторная ловушка' and stored.tags==['учебная']
        assert (await db.get(AlertRule,rule['id'])).name=='Система мониторинга'
        assert await db.scalar(select(Audit.id).where(Audit.resource==profile_id,Audit.action=='profile.create'))
    assert (await client.get('/api/v1/profiles/'+profile_id)).json()['spec']==profile.model_dump()
