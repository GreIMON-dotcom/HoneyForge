"""Operator-only retrieval of recorded sandbox bytes. Artifacts are never executed or rendered."""
import base64
import hashlib
import json
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy import select
from .db import database
from .models import Event, InteractionSession
from .security import roles
from .services import audit, as_utc

router = APIRouter(prefix='/api/v1/sandbox')
operator = roles('administrator', 'operator')


async def recorded(db, pot, session):
    known = await db.scalar(select(InteractionSession).where(InteractionSession.honeypot_id == str(pot), InteractionSession.session_uid == str(session)))
    if not known:
        raise HTTPException(404, 'Сеанс не найден')
    return (await db.scalars(select(Event).where(Event.honeypot_id == str(pot), Event.session_id == str(session)).order_by(Event.id).limit(2049))).all()


@router.get('/sessions/{pot}/{session}/capture', summary='Записанный ввод, вывод и наблюдения сеанса sandbox')
async def capture(pot: UUID, session: UUID, user=Depends(operator), db=Depends(database)):
    rows = await recorded(db, pot, session)
    if len(rows) > 2048:
        raise HTTPException(409, 'Сеанс превышает предел выгрузки')
    body = {'honeypot_id': str(pot), 'session_id': str(session), 'events': [
        {'id': event.id, 'timestamp': as_utc(event.timestamp).isoformat(), 'event_type': event.event_type, 'payload': event.payload} for event in rows]}
    audit(db, user.id, 'sandbox.capture_export', str(pot), {'session_id': str(session)})
    await db.commit()
    return Response(json.dumps(body, ensure_ascii=False), media_type='application/json',
                    headers={'Content-Disposition': 'attachment; filename="honeyforge-session.json"'})


@router.get('/sessions/{pot}/{session}/{sha}/artifact', summary='Сохранённый файл sandbox, проверенный по SHA-256')
async def artifact(pot: UUID, session: UUID, sha: str, user=Depends(operator), db=Depends(database)):
    if len(sha) != 64 or any(char not in '0123456789abcdef' for char in sha):
        raise HTTPException(422, 'Некорректный SHA-256')
    chunks, size = {}, None
    for event in await recorded(db, pot, session):
        payload = event.payload
        if payload.get('sha256') != sha:
            continue
        if payload.get('stream') == 'artifact':
            size = payload.get('artifact_size')
        elif payload.get('stream') == 'artifact_chunk':
            try:
                offset = int(payload['offset'])
                data = base64.b64decode(payload['data'], validate=True)
                if not 0 <= offset < 65536 or len(data) > 1024:
                    raise ValueError()
                if offset in chunks and chunks[offset] != data:
                    raise ValueError()
                chunks[offset] = data
            except (ValueError, KeyError, TypeError):
                raise HTTPException(409, 'Файл записан не полностью или повреждён')
    if not isinstance(size, int) or not 0 <= size <= 65536:
        raise HTTPException(404, 'Запись файла не найдена')
    content = bytearray()
    for offset, data in sorted(chunks.items()):
        if offset != len(content):
            raise HTTPException(409, 'В записи файла есть пропущенные фрагменты')
        content += data
    if len(content) != size or hashlib.sha256(content).hexdigest() != sha:
        raise HTTPException(409, 'Проверка целостности файла не пройдена')
    audit(db, user.id, 'sandbox.artifact_export', str(pot), {'session_id': str(session), 'sha256': sha})
    await db.commit()
    return Response(bytes(content), media_type='application/octet-stream', headers={
        'Content-Disposition': f'attachment; filename="{sha}.bin"', 'X-Content-Type-Options': 'nosniff'})
