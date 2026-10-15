"""Machine identities of instance agents: visibility and administrator revocation.

Agents are provisioned by the host controller as part of an administrator's
deployment (see runtime.py). An administrator can revoke any identity at once;
its instance keeps the last valid configuration and buffers events meanwhile.
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from .db import database
from .models import Agent, Honeypot
from .security import roles
from .services import audit, required, hub

router = APIRouter(prefix='/api/v1')
admin = roles('administrator')


@router.get('/agent-enrollments', summary="Удостоверения агентов")
async def enrollments(user=Depends(admin), db=Depends(database)):
    rows = (await db.execute(select(Agent, Honeypot.name).outerjoin(Honeypot, Honeypot.id == Agent.honeypot_id)
                             .order_by(Agent.created_at.desc()))).all()
    return [{'id': agent.id, 'honeypot_id': agent.honeypot_id, 'honeypot_name': name, 'host_id': agent.host_id,
             'approved': agent.approved, 'retired': agent.retired, 'version': agent.version,
             'last_seen': agent.last_seen, 'created_at': agent.created_at} for agent, name in rows]


class Approval(BaseModel):
    model_config = ConfigDict(extra='forbid')
    approved: bool


@router.patch('/agent-enrollments/{identifier}', summary="Отзыв или восстановление доступа агента")
async def approve_agent(identifier: str, body: Approval, user=Depends(admin), db=Depends(database)):
    agent = await required(db, Agent, identifier, lock=True)
    if agent.retired or not agent.honeypot_id:
        raise HTTPException(409, 'Удостоверение выведено из эксплуатации и не может быть восстановлено')
    agent.approved = body.approved
    audit(db, user.id, 'agent.approve' if body.approved else 'agent.revoke', agent.id)
    await db.commit()
    hub.publish({'type': 'status'})
    return {'id': agent.id, 'approved': agent.approved}
