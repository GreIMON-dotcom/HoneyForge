"""Availability incidents and global counters must reflect persisted faults, not just telemetry rules."""
from backend.app.models import Alert, AlertRule, Honeypot, now
from backend.app.services import maintenance_once, HEALTH_RULES
from conftest import running_pot


async def test_fault_creates_one_incident_and_recovery_resolves_it(client, controller_headers, factory):
    pot, _, _ = await running_pot(client, controller_headers)
    async with factory() as db:
        model = await db.get(Honeypot, pot['id'])
        model.status, model.error = 'failed', 'Listener failed'
        await db.commit()
        await maintenance_once(db)
        await maintenance_once(db)
    alerts = (await client.get('/api/v1/alerts')).json()
    assert len(alerts) == 1 and alerts[0]['severity'] == 'critical'
    assert alerts[0]['details']['system'] is True
    totals = (await client.get('/api/v1/alerts/summary')).json()
    assert totals['open'] == 1 and totals['enabled_rules'] == 2
    await client.post('/api/v1/alerts/' + alerts[0]['id'] + '/acknowledge')
    async with factory() as db:
        await maintenance_once(db)
    assert (await client.get('/api/v1/alerts/summary')).json()['acknowledged'] == 1
    async with factory() as db:
        model = await db.get(Honeypot, pot['id'])
        model.status, model.error, model.last_seen = 'running', None, now()
        await db.commit()
        await maintenance_once(db)
    assert (await client.get('/api/v1/alerts/summary')).json()['resolved'] == 1
    async with factory() as db:
        model = await db.get(Honeypot, pot['id'])
        model.status, model.error = 'failed', 'Listener failed'
        await db.commit()
        await maintenance_once(db)
    assert (await client.get('/api/v1/alerts/summary')).json()['total'] == 2


async def test_disabled_system_rule_is_respected(client, controller_headers, factory):
    pot, _, _ = await running_pot(client, controller_headers)
    async with factory() as db:
        await maintenance_once(db)
        rule = await db.get(AlertRule, HEALTH_RULES['failed'][0])
        rule.enabled = False
        model = await db.get(Honeypot, pot['id'])
        model.status, model.error = 'failed', 'Listener failed'
        await db.commit()
        await maintenance_once(db)
    assert (await client.get('/api/v1/alerts/summary')).json()['total'] == 0


async def test_summary_counts_beyond_history_limit(client, controller_headers, factory):
    pot, _, _ = await running_pot(client, controller_headers)
    rule = (await client.post('/api/v1/alerts/rules', json={
        'name': 'Counter regression', 'event_type': 'connection', 'threshold': 1,
        'window_seconds': 60, 'severity': 'medium'})).json()
    async with factory() as db:
        for number in range(205):
            db.add(Alert(rule_id=rule['id'], honeypot_id=pot['id'], severity='medium',
                         status='open' if number < 201 else 'resolved', details={}))
        await db.commit()
    assert len((await client.get('/api/v1/alerts')).json()) == 200
    totals = (await client.get('/api/v1/alerts/summary')).json()
    assert totals['total'] == 205 and totals['open'] == 201 and totals['resolved'] == 4
